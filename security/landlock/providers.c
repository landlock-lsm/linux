/*
 * Landlock LSM - seccomp provider
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/page.h> /* PAGE_SIZE */
#include <linux/atomic.h> /* atomic_*(), smp_store_release() */
#include <linux/bpf.h> /* bpf_prog_put() */
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/kernel.h> /* round_up() */
#include <linux/landlock.h>
#include <linux/sched.h> /* current_cred(), task_no_new_privs() */
#include <linux/security.h> /* security_capable_noaudit() */
#include <linux/slab.h> /* alloc(), kfree() */
#include <linux/types.h> /* atomic_t */
#include <linux/uaccess.h> /* copy_from_user() */

#include "common.h"

static void put_landlock_rule(struct landlock_rule *rule)
{
	struct landlock_rule *orig = rule;

	/* clean up single-reference branches iteratively */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct landlock_rule *freeme = orig;

		bpf_prog_put(orig->prog);
		orig = orig->prev;
		kfree(freeme);
	}
}

void put_landlock_events(struct landlock_events *events)
{
	if (events && atomic_dec_and_test(&events->usage)) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(events->rules); i++)
			/* XXX: Do we need to use lockless_dereference() here? */
			put_landlock_rule(events->rules[i]);
		kfree(events);
	}
}

static struct landlock_events *new_landlock_events(void)
{
	struct landlock_events *ret;

	/* array filled with NULL values */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);
	atomic_set(&ret->usage, 1);
	return ret;
}

static void add_landlock_rule(struct landlock_events *events,
		struct landlock_rule *rule)
{
	/* subtype.landlock_rule.event > 0 for loaded programs */
	u32 event_idx = get_index(rule->prog->subtype.landlock_rule.event);

	rule->prev = events->rules[event_idx];
	WARN_ON(atomic_read(&rule->usage));
	atomic_set(&rule->usage, 1);
	/* do not increment the previous rule usage */
	smp_store_release(&events->rules[event_idx], rule);
}

/* limit Landlock events to 256KB */
#define LANDLOCK_EVENTS_MAX_PAGES (1 << 6)

/**
 * landlock_append_prog - attach a Landlock rule to @current_events
 *
 * @current_events: landlock_events pointer, must be locked (if needed) to
 *                  prevent a concurrent put/free. This pointer must not be
 *                  freed after the call.
 * @prog: non-NULL Landlock rule to append to @current_events. @prog will be
 *        owned by landlock_append_prog() and freed if an error happened.
 *
 * Return @current_events or a new pointer when OK. Return a pointer error
 * otherwise.
 */
static struct landlock_events *landlock_append_prog(
		struct landlock_events *current_events, struct bpf_prog *prog)
{
	struct landlock_events *new_events = current_events;
	unsigned long pages;
	struct landlock_rule *rule;
	u32 event_idx;

	if (prog->type != BPF_PROG_TYPE_LANDLOCK) {
		new_events = ERR_PTR(-EINVAL);
		goto put_prog;
	}

	/* validate memory size allocation */
	pages = prog->pages;
	if (current_events) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(current_events->rules); i++) {
			struct landlock_rule *walker_r;

			for (walker_r = current_events->rules[i]; walker_r;
					walker_r = walker_r->prev)
				pages += walker_r->prog->pages;
		}
		/* count a struct landlock_events if we need to allocate one */
		if (atomic_read(&current_events->usage) != 1)
			pages += round_up(sizeof(*current_events), PAGE_SIZE) /
				PAGE_SIZE;
	}
	if (pages > LANDLOCK_EVENTS_MAX_PAGES) {
		new_events = ERR_PTR(-E2BIG);
		goto put_prog;
	}

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		new_events = ERR_PTR(-ENOMEM);
		goto put_prog;
	}
	rule->prog = prog;

	/* subtype.landlock_rule.event > 0 for loaded programs */
	event_idx = get_index(rule->prog->subtype.landlock_rule.event);

	if (!new_events) {
		/*
		 * If there is no Landlock events used by the current task,
		 * then create a new one.
		 */
		new_events = new_landlock_events();
		if (IS_ERR(new_events))
			goto put_rule;
	} else if (atomic_read(&current_events->usage) > 1) {
		/*
		 * If the current task is not the sole user of its Landlock
		 * events, then duplicate them.
		 */
		size_t i;

		new_events = new_landlock_events();
		if (IS_ERR(new_events))
			goto put_rule;
		for (i = 0; i < ARRAY_SIZE(new_events->rules); i++) {
			new_events->rules[i] =
				lockless_dereference(current_events->rules[i]);
			if (new_events->rules[i])
				atomic_inc(&new_events->rules[i]->usage);
		}

		/*
		 * Landlock events from the current task will not be freed here
		 * because the usage is strictly greater than 1. It is only
		 * prevented to be freed by another subject thanks to the
		 * caller of landlock_append_prog() which should be locked if
		 * needed.
		 */
		put_landlock_events(current_events);
	}
	add_landlock_rule(new_events, rule);
	return new_events;

put_prog:
	bpf_prog_put(prog);
	return new_events;

put_rule:
	put_landlock_rule(rule);
	return new_events;
}

/**
 * landlock_seccomp_append_prog - attach a Landlock rule to the current process
 *
 * current->seccomp.landlock_events is lazily allocated. When a process fork,
 * only a pointer is copied. When a new event is added by a process, if there
 * is other references to this process' landlock_events, then a new allocation
 * is made to contain an array pointing to Landlock rule lists. This design
 * enable low-performance impact and is memory efficient while keeping the
 * property of append-only rules.
 *
 * @flags: not used for now, but could be used for TSYNC
 * @user_bpf_fd: file descriptor pointing to a loaded Landlock rule
 */
#ifdef CONFIG_SECCOMP_FILTER
int landlock_seccomp_append_prog(unsigned int flags,
		const char __user *user_bpf_fd)
{
	struct landlock_events *new_events;
	struct bpf_prog *prog;
	int bpf_fd;

	/* force no_new_privs to limit privilege escalation */
	if (!task_no_new_privs(current))
		return -EPERM;
	/* will be removed in the future to allow unprivileged tasks */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/* enable to check if Landlock is supported with early EFAULT */
	if (!user_bpf_fd)
		return -EFAULT;
	if (flags)
		return -EINVAL;
	if (copy_from_user(&bpf_fd, user_bpf_fd, sizeof(bpf_fd)))
		return -EFAULT;
	prog = bpf_prog_get(bpf_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	/*
	 * We don't need to lock anything for the current process hierarchy,
	 * everything is guarded by the atomic counters.
	 */
	new_events = landlock_append_prog(current->seccomp.landlock_events,
			prog);
	/* @prog is managed/freed by landlock_append_prog() */
	if (IS_ERR(new_events))
		return PTR_ERR(new_events);
	current->seccomp.landlock_events = new_events;
	return 0;
}
#endif /* CONFIG_SECCOMP_FILTER */
