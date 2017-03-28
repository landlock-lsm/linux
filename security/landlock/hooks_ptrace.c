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
#include <linux/kernel.h> /* ARRAY_SIZE */
#include <linux/landlock.h> /* struct landlock_events */
#include <linux/lsm_hooks.h>
#include <linux/sched.h> /* struct task_struct */
#include <linux/seccomp.h>

#include "hooks.h" /* landlocked() */

#include "hooks_ptrace.h"


static bool landlock_events_are_subset(const struct landlock_events *parent,
		const struct landlock_events *child)
{
	size_t i;

	if (!parent || !child)
		return false;
	if (parent == child)
		return true;

	for (i = 0; i < ARRAY_SIZE(child->rules); i++) {
		struct landlock_rule *walker;
		bool found_parent = false;

		if (!parent->rules[i])
			continue;
		for (walker = child->rules[i]; walker; walker = walker->prev) {
			if (walker == parent->rules[i]) {
				found_parent = true;
				break;
			}
		}
		if (!found_parent)
			return false;
	}
	return true;
}

static bool landlock_task_has_subset_events(const struct task_struct *parent,
		const struct task_struct *child)
{
#ifdef CONFIG_SECCOMP_FILTER
	if (landlock_events_are_subset(parent->seccomp.landlock_events,
				child->seccomp.landlock_events))
		/* must be ANDed with other providers (i.e. cgroup) */
		return true;
#endif /* CONFIG_SECCOMP_FILTER */
	return false;
}

/**
 * landlock_ptrace_access_check - determine whether the current process may
 *				  access another
 *
 * @child: the process to be accessed
 * @mode: the mode of attachment
 *
 * If the current task has Landlock rules, then the child must have at least
 * the same rules.  Else denied.
 *
 * Determine whether a process may access another, returning 0 if permission
 * granted, -errno if denied.
 */
static int landlock_ptrace_access_check(struct task_struct *child,
		unsigned int mode)
{
	if (!landlocked(current))
		return 0;

	if (!landlocked(child))
		return -EPERM;

	if (landlock_task_has_subset_events(current, child))
		return 0;

	return -EPERM;
}

/**
 * landlock_ptrace_traceme - determine whether another process may trace the
 *			     current one
 *
 * @parent: the task proposed to be the tracer
 *
 * If the parent has Landlock rules, then the current task must have the same
 * or more rules.
 * Else denied.
 *
 * Determine whether the nominated task is permitted to trace the current
 * process, returning 0 if permission is granted, -errno if denied.
 */
static int landlock_ptrace_traceme(struct task_struct *parent)
{
	if (!landlocked(parent))
		return 0;

	if (!landlocked(current))
		return -EPERM;

	if (landlock_task_has_subset_events(parent, current))
		return 0;

	return -EPERM;
}

static struct security_hook_list landlock_hooks[] = {
	LSM_HOOK_INIT(ptrace_access_check, landlock_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, landlock_ptrace_traceme),
};

__init void landlock_add_hooks_ptrace(void)
{
	landlock_register_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks));
}
