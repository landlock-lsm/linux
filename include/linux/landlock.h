/*
 * Landlock LSM - public kernel headers
 *
 * Copyright © 2016-2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H

#include <linux/errno.h>
#include <linux/sched.h> /* task_struct */

#ifdef CONFIG_SECURITY_LANDLOCK
struct landlock_events;
#endif /* CONFIG_SECURITY_LANDLOCK */

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_SECURITY_LANDLOCK)
extern int landlock_seccomp_prepend_rule(unsigned int flags,
		const char __user *user_bpf_fd);
extern void put_seccomp_landlock(struct task_struct *tsk);
extern void get_seccomp_landlock(struct task_struct *tsk);
#else /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */
static inline int landlock_seccomp_prepend_rule(unsigned int flags,
		const char __user *user_bpf_fd)
{
		return -EINVAL;
}
static inline void put_seccomp_landlock(struct task_struct *tsk)
{
	return;
}
static inline void get_seccomp_landlock(struct task_struct *tsk)
{
	return;
}
#endif /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */

#endif /* _LINUX_LANDLOCK_H */
