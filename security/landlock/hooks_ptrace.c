// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - ptrace hooks
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019 ANSSI
 */

#include <asm/current.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>
#include <uapi/linux/landlock.h>

#include "bpf_run.h"
#include "common.h"
#include "hooks_ptrace.h"

struct landlock_hook_ctx_ptrace {
	struct landlock_context_ptrace prog_ctx;
};

const struct landlock_context_ptrace *landlock_get_ctx_ptrace(
		const struct landlock_hook_ctx_ptrace *hook_ctx)
{
	if (WARN_ON(!hook_ctx))
		return NULL;

	return &hook_ctx->prog_ctx;
}

static int check_ptrace(struct landlock_domain *domain,
		struct task_struct *tracer, struct task_struct *tracee)
{
	struct landlock_hook_ctx_ptrace ctx_ptrace = {
		.prog_ctx = {
			.tracer = (uintptr_t)tracer,
			.tracee = (uintptr_t)tracee,
		},
	};
	struct landlock_hook_ctx hook_ctx = {
		.type = LANDLOCK_HOOK_PTRACE,
		.ctx_ptrace = &ctx_ptrace,
	};

	return landlock_access_denied(domain, &hook_ctx) ? -EPERM : 0;
}

/**
 * hook_ptrace_access_check - determine whether the current process may access
 *			      another
 *
 * @child: the process to be accessed
 * @mode: the mode of attachment
 *
 * If the current task (i.e. tracer) has one or multiple BPF_LANDLOCK_PTRACE
 * programs, then run them with the `struct landlock_context_ptrace` context.
 * If one of these programs return LANDLOCK_RET_DENY, then deny access with
 * -EPERM, else allow it by returning 0.
 */
static int hook_ptrace_access_check(struct task_struct *child,
		unsigned int mode)
{
	struct landlock_domain *dom_current;
	const size_t hook = get_hook_index(LANDLOCK_HOOK_PTRACE);

	dom_current = landlock_cred(current_cred())->domain;
	if (!(dom_current && dom_current->programs[hook]))
		return 0;
	return check_ptrace(dom_current, current, child);
}

/**
 * hook_ptrace_traceme - determine whether another process may trace the
 *			 current one
 *
 * @parent: the task proposed to be the tracer
 *
 * If the parent task (i.e. tracer) has one or multiple BPF_LANDLOCK_PTRACE
 * programs, then run them with the `struct landlock_context_ptrace` context.
 * If one of these programs return LANDLOCK_RET_DENY, then deny access with
 * -EPERM, else allow it by returning 0.
 */
static int hook_ptrace_traceme(struct task_struct *parent)
{
	struct landlock_domain *dom_parent;
	const size_t hook = get_hook_index(LANDLOCK_HOOK_PTRACE);
	int ret;

	rcu_read_lock();
	dom_parent = landlock_cred(__task_cred(parent))->domain;
	if (!(dom_parent && dom_parent->programs[hook])) {
		ret = 0;
		goto put_rcu;
	}
	ret = check_ptrace(dom_parent, parent, current);

put_rcu:
	rcu_read_unlock();
	return ret;
}

static struct security_hook_list landlock_hooks[] = {
	LSM_HOOK_INIT(ptrace_access_check, hook_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, hook_ptrace_traceme),
};

__init void landlock_add_hooks_ptrace(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
