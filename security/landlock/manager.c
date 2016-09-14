/*
 * Landlock LSM - seccomp and cgroups managers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/atomic.h> /* atomic_*() */
#include <asm/page.h> /* PAGE_SIZE */
#include <asm/uaccess.h> /* copy_from_user() */
#include <linux/bitops.h> /* BIT_ULL() */
#include <linux/bpf.h> /* bpf_prog_put() */
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/kernel.h> /* round_up() */
#include <linux/landlock.h>
#include <linux/sched.h> /* current_cred(), task_no_new_privs() */
#include <linux/security.h> /* security_capable_noaudit() */
#include <linux/slab.h> /* alloc(), kfree() */
#include <linux/types.h> /* atomic_t */

#ifdef CONFIG_SECCOMP_FILTER
#include <linux/seccomp.h> /* struct seccomp_filter */
#endif /* CONFIG_SECCOMP_FILTER */

#ifdef CONFIG_CGROUP_BPF
#include <linux/bpf-cgroup.h> /* struct cgroup_bpf */
#include <linux/cgroup-defs.h> /* struct cgroup */
#endif /* CONFIG_CGROUP_BPF */

#include "common.h"

static void put_landlock_rule(struct landlock_rule *rule)
{
	struct landlock_rule *orig = rule;

	/* Clean up single-reference branches iteratively. */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct landlock_rule *freeme = orig;

#ifdef CONFIG_SECCOMP_FILTER
		put_seccomp_filter(orig->thread_filter);
#endif /* CONFIG_SECCOMP_FILTER */
		bpf_prog_put(orig->prog);
		orig = orig->prev;
		kfree(freeme);
	}
}

void put_landlock_hooks(struct landlock_hooks *hooks)
{
	if (!hooks)
		return;

	if (atomic_dec_and_test(&hooks->usage)) {
		int i;

		for (i = 0; i < ARRAY_SIZE(hooks->rules); i++)
			put_landlock_rule(hooks->rules[i]);
		kfree(hooks);
	}
}

#ifdef CONFIG_SECCOMP_FILTER
void put_landlock_ret(struct landlock_seccomp_ret *landlock_ret)
{
	struct landlock_seccomp_ret *orig = landlock_ret;

	while (orig) {
		struct landlock_seccomp_ret *freeme = orig;

		put_seccomp_filter(orig->filter);
		orig = orig->prev;
		kfree(freeme);
	}
}
#endif /* CONFIG_SECCOMP_FILTER */

struct landlock_hooks *new_landlock_hooks(void)
{
	struct landlock_hooks *ret;

	/* array filled with NULL values */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);
	atomic_set(&ret->usage, 1);
	return ret;
}

inline void get_landlock_hooks(struct landlock_hooks *hooks)
{
	if (hooks)
		atomic_inc(&hooks->usage);
}

/* Limit Landlock hooks to 256KB. */
#define LANDLOCK_HOOKS_MAX_PAGES (1 << 6)

/**
 * landlock_set_hook - attach a Landlock program to @current_hooks
 *
 * @current_hooks: landlock_hooks pointer, must be locked (if needed) to
 *                 prevent a concurrent put/free. This pointer must not be
 *                 freed after the call.
 * @prog: non-NULL Landlock program to append to @current_hooks. @prog will be
 *        owned by landlock_set_hook() and freed if an error happened.
 * @thread_filter: pointer to the seccomp filter of the current thread, if any
 *
 * Return @current_hooks or a new pointer when OK. Return a pointer error
 * otherwise.
 */
static struct landlock_hooks *landlock_set_hook(
		struct landlock_hooks *current_hooks, struct bpf_prog *prog,
		struct seccomp_filter *thread_filter)
{
	struct landlock_hooks *new_hooks = current_hooks;
	unsigned long pages;
	struct landlock_rule *rule;
	u32 hook_idx;

	if (prog->type != BPF_PROG_TYPE_LANDLOCK) {
		new_hooks = ERR_PTR(-EINVAL);
		goto put_prog;
	}

	/* validate allocated memory */
	pages = prog->pages;
	if (current_hooks) {
		int i;
		struct landlock_rule *walker;

		for (i = 0; i < ARRAY_SIZE(current_hooks->rules); i++) {
			for (walker = current_hooks->rules[i]; walker;
					walker = walker->prev) {
				/* TODO: add penalty for each prog? */
				pages += walker->prog->pages;
			}
		}
		/* count landlock_hooks if we will allocate it */
		if (atomic_read(&current_hooks->usage) != 1)
			pages += round_up(sizeof(*current_hooks), PAGE_SIZE) /
				PAGE_SIZE;
	}
	if (pages > LANDLOCK_HOOKS_MAX_PAGES) {
		new_hooks = ERR_PTR(-E2BIG);
		goto put_prog;
	}

	rule = kmalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		new_hooks = ERR_PTR(-ENOMEM);
		goto put_prog;
	}
	rule->prev = NULL;
	rule->prog = prog;
	/* attach the filters from the same thread, if any */
	rule->thread_filter = thread_filter;
	if (rule->thread_filter)
		atomic_inc(&rule->thread_filter->usage);
	atomic_set(&rule->usage, 1);

	if (!current_hooks) {
		/* add a new landlock_hooks, if needed */
		new_hooks = new_landlock_hooks();
		if (IS_ERR(new_hooks))
			goto put_rule;
	} else if (atomic_read(&current_hooks->usage) > 1) {
		int i;

		/* copy landlock_hooks, if shared */
		new_hooks = new_landlock_hooks();
		if (IS_ERR(new_hooks))
			goto put_rule;
		for (i = 0; i < ARRAY_SIZE(new_hooks->rules); i++) {
			new_hooks->rules[i] =
				current_hooks->rules[i];
			if (new_hooks->rules[i])
				atomic_inc(&new_hooks->rules[i]->usage);
		}
		/*
		 * @current_hooks will not be freed here because it's usage
		 * field is > 1. It is only prevented to be freed by another
		 * subject thanks to the caller of landlock_set_hook() which
		 * should be locked if needed.
		 */
		put_landlock_hooks(current_hooks);
	}

	/* subtype.landlock_hook.id > 0 for loaded programs */
	hook_idx = get_index(rule->prog->subtype.landlock_hook.id);
	rule->prev = new_hooks->rules[hook_idx];
	new_hooks->rules[hook_idx] = rule;
	return new_hooks;

put_prog:
	bpf_prog_put(prog);
	return new_hooks;

put_rule:
	put_landlock_rule(rule);
	return new_hooks;
}

/**
 * landlock_set_hook - attach a Landlock program to the current process
 *
 * current->seccomp.landlock_hooks is lazily allocated. When a process fork,
 * only a pointer is copied. When a new hook is added by a process, if there is
 * other references to this process' landlock_hooks, then a new allocation is
 * made to contains an array pointing to Landlock program lists. This design
 * has low-performance impact and memory efficiency while keeping the property
 * of append-only programs.
 *
 * @flags: not used for now, but could be used for TSYNC
 * @user_bpf_fd: file descriptor pointing to a loaded/checked eBPF program
 *               dedicated to Landlock
 */
#ifdef CONFIG_SECCOMP_FILTER
int landlock_seccomp_set_hook(unsigned int flags, const char __user *user_bpf_fd)
{
	struct landlock_hooks *new_hooks;
	struct bpf_prog *prog;
	int bpf_fd;

	if (!task_no_new_privs(current) &&
	    security_capable_noaudit(current_cred(),
				     current_user_ns(), CAP_SYS_ADMIN) != 0)
		return -EPERM;
	if (!user_bpf_fd)
		return -EINVAL;
	if (flags)
		return -EINVAL;
	if (copy_from_user(&bpf_fd, user_bpf_fd, sizeof(user_bpf_fd)))
		return -EFAULT;
	prog = bpf_prog_get(bpf_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	/*
	 * We don't need to lock anything for the current process hierarchy,
	 * everything is guarded by the atomic counters.
	 */
	new_hooks = landlock_set_hook(current->seccomp.landlock_hooks, prog,
			current->seccomp.thread_filter);
	/* @prog is managed/freed by landlock_set_hook() */
	if (IS_ERR(new_hooks))
		return PTR_ERR(new_hooks);
	current->seccomp.landlock_hooks = new_hooks;
	return 0;
}
#endif /* CONFIG_SECCOMP_FILTER */

/**
 * landlock_cgroup_set_hook - attach a Landlock program to a cgroup
 *
 * Must be called with cgroup_mutex held.
 *
 * @crgp: non-NULL cgroup pointer to attach to
 * @prog: Landlock program pointer
 */
#ifdef CONFIG_CGROUP_BPF
struct landlock_hooks *landlock_cgroup_set_hook(struct cgroup *cgrp,
		struct bpf_prog *prog)
{
	if (!prog)
		return ERR_PTR(-EINVAL);

	/* check no_new_privs for tasks in the cgroup */
	if (!(cgrp->flags & BIT_ULL(CGRP_NO_NEW_PRIVS)) &&
			security_capable_noaudit(current_cred(),
				current_user_ns(), CAP_SYS_ADMIN) != 0)
		return ERR_PTR(-EPERM);

	/* copy the inherited hooks and append a new one */
	return landlock_set_hook(cgrp->bpf.effective[BPF_CGROUP_LANDLOCK].hooks,
			prog, NULL);
}
#endif /* CONFIG_CGROUP_BPF */
