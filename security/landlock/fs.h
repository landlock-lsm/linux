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
	 * We need an allocated object to be able to safely untie a rule from
	 * an object (i.e. unlink then free a rule), cf. put_rule().  This
	 * object is guarded by the underlying object's lock.
	 */
	struct landlock_object __rcu *object;
};

static inline struct landlock_inode_security *inode_landlock(
		const struct inode *inode)
{
	return inode->i_security + landlock_blob_sizes.lbs_inode;
}

__init void landlock_add_hooks_fs(void);

void landlock_release_inode(struct inode *inode,
		struct landlock_object *object);

int landlock_append_fs_rule(struct landlock_ruleset *ruleset,
		struct path *path, u64 actions);

#endif /* _SECURITY_LANDLOCK_FS_H */
