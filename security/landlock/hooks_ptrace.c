/*
 * Landlock LSM - ptrace hooks
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <linux/errno.h>
#include <linux/kernel.h> /* ARRAY_SIZE */
#include <linux/lsm_hooks.h>
#include <linux/sched.h> /* struct task_struct */
#include <linux/seccomp.h>

#include "common.h" /* struct landlock_prog_set */
#include "hooks.h" /* landlocked() */
#include "hooks_ptrace.h"

static bool progs_are_subset(const struct landlock_prog_set *parent,
		const struct landlock_prog_set *child)
{
	size_t i;

	if (!parent || !child)
		return false;
	if (parent == child)
		return true;

	for (i = 0; i < ARRAY_SIZE(child->programs); i++) {
		struct landlock_prog_list *walker;
		bool found_parent = false;

		if (!parent->programs[i])
			continue;
		for (walker = child->programs[i]; walker;
				walker = walker->prev) {
			if (walker == parent->programs[i]) {
				found_parent = true;
				break;
			}
		}
		if (!found_parent)
			return false;
	}
	return true;
}

static bool task_has_subset_progs(const struct task_struct *parent,
		const struct task_struct *child)
{
#ifdef CONFIG_SECCOMP_FILTER
	if (progs_are_subset(parent->seccomp.landlock_prog_set,
				child->seccomp.landlock_prog_set))
		/* must be ANDed with other providers (i.e. cgroup) */
		return true;
#endif /* CONFIG_SECCOMP_FILTER */
	return false;
}

static int task_ptrace(const struct task_struct *parent,
		const struct task_struct *child)
{
	if (!landlocked(parent))
		return 0;

	if (!landlocked(child))
		return -EPERM;

	if (task_has_subset_progs(parent, child))
		return 0;

	return -EPERM;
}

/**
 * hook_ptrace_access_check - determine whether the current process may access
 *			      another
 *
 * @child: the process to be accessed
 * @mode: the mode of attachment
 *
 * If the current task has Landlock programs, then the child must have at least
 * the same programs.  Else denied.
 *
 * Determine whether a process may access another, returning 0 if permission
 * granted, -errno if denied.
 */
static int hook_ptrace_access_check(struct task_struct *child,
		unsigned int mode)
{
	return task_ptrace(current, child);
}

/**
 * hook_ptrace_traceme - determine whether another process may trace the
 *			 current one
 *
 * @parent: the task proposed to be the tracer
 *
 * If the parent has Landlock programs, then the current task must have the
 * same or more programs.
 * Else denied.
 *
 * Determine whether the nominated task is permitted to trace the current
 * process, returning 0 if permission is granted, -errno if denied.
 */
static int hook_ptrace_traceme(struct task_struct *parent)
{
	return task_ptrace(parent, current);
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
