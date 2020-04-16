/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Filesystem management and hooks
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_FS_H
#define _SECURITY_LANDLOCK_FS_H

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/rcupdate.h>

#include "ruleset.h"
#include "setup.h"

struct landlock_inode_security {
	/*
	 * @object: Weak pointer to an allocated object.  All writes (i.e.
	 * creating a new object or removing one) are protected by the
	 * underlying inode->i_lock.  Disassociating @object from the inode is
	 * additionally protected by @object->lock, from the time @object's
	 * usage refcount drops to zero to the time this pointer is nulled out.
	 * Cf. release_inode().
	 */
	struct landlock_object __rcu *object;
};

static inline struct landlock_inode_security *inode_landlock(
		const struct inode *const inode)
{
	return inode->i_security + landlock_blob_sizes.lbs_inode;
}

__init void landlock_add_hooks_fs(void);

int landlock_append_fs_rule(struct landlock_ruleset *const ruleset,
		const struct path *const path, u32 access_hierarchy);

#endif /* _SECURITY_LANDLOCK_FS_H */
