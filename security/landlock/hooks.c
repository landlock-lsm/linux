/*
 * Landlock LSM - hooks helpers
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <asm/processor.h> /* task_pt_regs() */
#include <asm/syscall.h> /* syscall_get_nr(), syscall_get_arch() */
#include <linux/bpf.h> /* enum bpf_access_type, struct landlock_context */
#include <linux/err.h> /* EPERM */
#include <linux/filter.h> /* BPF_PROG_RUN() */
#include <linux/landlock.h> /* struct landlock_rule */
#include <linux/lsm_hooks.h>
#include <linux/rculist.h> /* list_add_tail_rcu */
#include <linux/stddef.h> /* offsetof */

#include "common.h" /* get_index() */
#include "hooks.h" /* CTX_ARG_NB */


__init void landlock_register_hooks(struct security_hook_list *hooks, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		hooks[i].lsm = "landlock";
		list_add_tail_rcu(&hooks[i].list, hooks[i].head);
	}
}

bool landlock_is_valid_access(int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type,
		enum bpf_reg_type ctx_types[CTX_ARG_NB],
		union bpf_prog_subtype *prog_subtype)
{
	int max_size;

	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct landlock_context))
		return false;
	if (size <= 0 || size > sizeof(__u64))
		return false;

	/* set max size */
	switch (off) {
	case offsetof(struct landlock_context, arch):
	case offsetof(struct landlock_context, syscall_nr):
	case offsetof(struct landlock_context, syscall_cmd):
	case offsetof(struct landlock_context, event):
		max_size = sizeof(__u32);
		break;
	case offsetof(struct landlock_context, status):
	case offsetof(struct landlock_context, arg1):
	case offsetof(struct landlock_context, arg2):
		max_size = sizeof(__u64);
		break;
	default:
		return false;
	}

	/* set register type */
	switch (off) {
	case offsetof(struct landlock_context, arg1):
		*reg_type = ctx_types[0];
		break;
	case offsetof(struct landlock_context, arg2):
		*reg_type = ctx_types[1];
		break;
	default:
		*reg_type = UNKNOWN_VALUE;
	}

	/* check memory range access */
	switch (*reg_type) {
	case NOT_INIT:
		return false;
	case UNKNOWN_VALUE:
	case CONST_IMM:
		/* allow partial raw value */
		if (size > max_size)
			return false;
		break;
	default:
		/* deny partial pointer */
		if (size != max_size)
			return false;
	}

	return true;
}

/**
 * landlock_event_deny - run Landlock rules tied to an event
 *
 * @event_idx: event index in the rules array
 * @ctx: non-NULL eBPF context
 * @events: Landlock events pointer
 *
 * Return true if at least one rule deny the event.
 */
static bool landlock_event_deny(u32 event_idx, const struct landlock_context *ctx,
		struct landlock_events *events)
{
	struct landlock_rule *rule;

	if (!events)
		return false;

	for (rule = events->rules[event_idx]; rule; rule = rule->prev) {
		u32 ret;

		if (WARN_ON(!rule->prog))
			continue;
		rcu_read_lock();
		ret = BPF_PROG_RUN(rule->prog, (void *)ctx);
		rcu_read_unlock();
		/* deny access if a program returns a value different than 0 */
		if (ret)
			return true;
	}
	return false;
}

int landlock_decide(enum landlock_subtype_event event,
		__u64 ctx_values[CTX_ARG_NB], u32 cmd, const char *hook)
{
	bool deny = false;
	u32 event_idx = get_index(event);

	struct landlock_context ctx = {
		.status = 0,
		.arch = syscall_get_arch(),
		.syscall_nr = syscall_get_nr(current, task_pt_regs(current)),
		.syscall_cmd = cmd,
		.event = event,
		.arg1 = ctx_values[0],
		.arg2 = ctx_values[1],
	};

#ifdef CONFIG_SECCOMP_FILTER
	deny = landlock_event_deny(event_idx, &ctx,
			current->seccomp.landlock_events);
#endif /* CONFIG_SECCOMP_FILTER */

	return deny ? -EPERM : 0;
}
