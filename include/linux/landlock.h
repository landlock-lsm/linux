/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Landlock LSM - public kernel headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H

#include <linux/errno.h>

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_SECURITY_LANDLOCK)
extern int landlock_seccomp_prepend_prog(unsigned int flags,
		const int __user *user_bpf_fd);
#else /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */
static inline int landlock_seccomp_prepend_prog(unsigned int flags,
		const int __user *user_bpf_fd)
{
		return -EINVAL;
}
#endif /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */

#endif /* _LINUX_LANDLOCK_H */
