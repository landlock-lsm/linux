// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - eBPF ptrace
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019 ANSSI
 */

#include <linux/bpf.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <uapi/linux/landlock.h>

#include "bpf_ptrace.h"
#include "common.h"

bool landlock_is_valid_access_ptrace(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size)
{
	if (type != BPF_READ)
		return false;

	switch (off) {
	case offsetof(struct landlock_context_ptrace, tracer):
		/* fall through */
	case offsetof(struct landlock_context_ptrace, tracee):
		*reg_type = PTR_TO_TASK;
		*max_size = sizeof(u64);
		return true;
	default:
		return false;
	}
}

/**
 * domain_ptrace_ancestor - check domain ordering according to ptrace
 *
 * @parent: a parent domain
 * @child: a potential child of @parent
 *
 * Check if the @parent domain is less or equal to (i.e. a subset of) the
 * @child domain.
 */
static int domain_ptrace_ancestor(const struct landlock_domain *parent,
		const struct landlock_domain *child)
{
	const struct landlock_prog_list *child_progs, *parent_progs;
	const size_t hook = get_hook_index(LANDLOCK_HOOK_PTRACE);

	if (!parent || !child)
		/* @parent or @child has no ptrace restriction */
		return -EINVAL;
	parent_progs = parent->programs[hook];
	child_progs = child->programs[hook];
	if (!parent_progs || !child_progs)
		/* @parent or @child has no ptrace restriction */
		return -EINVAL;
	if (child_progs == parent_progs)
		/* @parent is at the same level as @child */
		return 0;
	for (child_progs = child_progs->prev; child_progs;
			child_progs = child_progs->prev) {
		if (child_progs == parent_progs)
			/* @parent is one of the ancestors of @child */
			return 1;
	}
	/*
	 * Either there is no relationship between @parent and @child, or
	 * @child is one of the ancestors of @parent.
	 */
	return -ENOENT;
}

/*
 * Cf. include/uapi/linux/bpf.h - bpf_task_landlock_ptrace_ancestor
 */
BPF_CALL_2(bpf_task_landlock_ptrace_ancestor, const struct task_struct *,
		parent, const struct task_struct *, child)
{
	const struct landlock_domain *dom_parent, *dom_child;

	WARN_ON_ONCE(!rcu_read_lock_held());
	if (WARN_ON(!parent || !child))
		return -EFAULT;
	dom_parent = landlock_cred(__task_cred(parent))->domain;
	dom_child = landlock_cred(__task_cred(child))->domain;
	return domain_ptrace_ancestor(dom_parent, dom_child);
}

const struct bpf_func_proto bpf_task_landlock_ptrace_ancestor_proto = {
	.func		= bpf_task_landlock_ptrace_ancestor,
	.gpl_only	= false,
	.pkt_access	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TASK,
	.arg2_type	= ARG_PTR_TO_TASK,
};
