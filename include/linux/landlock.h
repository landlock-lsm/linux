/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Landlock LSM - public kernel headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H

#include <linux/fs.h>

#ifdef CONFIG_SECURITY_LANDLOCK
extern void landlock_release_inodes(struct super_block *sb);
#else
static inline void landlock_release_inodes(struct super_block *sb)
{
}
#endif

#endif /* _LINUX_LANDLOCK_H */
