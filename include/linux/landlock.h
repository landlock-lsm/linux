/*
 * Landlock LSM - public kernel headers
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H

#include <linux/errno.h>
#include <linux/sched.h> /* task_struct */

struct inode;
struct landlock_chain;
struct landlock_tag_object;

#ifdef CONFIG_SECURITY_LANDLOCK
extern u64 landlock_get_inode_tag(const struct inode *inode,
		const struct landlock_chain *chain);
extern int landlock_set_object_tag(struct landlock_tag_object *tag_obj,
		struct landlock_chain *chain, u64 value);
#else /* CONFIG_SECURITY_LANDLOCK */
static inline u64 landlock_get_inode_tag(const struct inode *inode,
		const struct landlock_chain *chain)
{
	WARN_ON(1);
	return 0;
}
static inline int landlock_set_object_tag(struct landlock_tag_object *tag_obj,
		struct landlock_chain *chain, u64 value)
{
	WARN_ON(1);
	return -ENOTSUPP;
}
#endif /* CONFIG_SECURITY_LANDLOCK */

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_SECURITY_LANDLOCK)
extern int landlock_seccomp_prepend_prog(unsigned int flags,
		const int __user *user_bpf_fd);
extern void put_seccomp_landlock(struct task_struct *tsk);
extern void get_seccomp_landlock(struct task_struct *tsk);
#else /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */
static inline int landlock_seccomp_prepend_prog(unsigned int flags,
		const int __user *user_bpf_fd)
{
		return -EINVAL;
}
static inline void put_seccomp_landlock(struct task_struct *tsk)
{
}
static inline void get_seccomp_landlock(struct task_struct *tsk)
{
}
#endif /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */

#endif /* _LINUX_LANDLOCK_H */
