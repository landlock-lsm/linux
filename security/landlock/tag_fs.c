/*
 * Landlock LSM - tag FS helpers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/fs.h> /* struct inode */
#include <linux/landlock.h> /* landlock_get_inode_tag */
#include <linux/slab.h>

#include "tag_fs.h"
#include "tag.h"

u64 landlock_get_inode_tag(const struct inode *inode,
		const struct landlock_chain *chain)
{
	return landlock_get_tag(inode->i_security, chain);
}

/* never return NULL */
struct landlock_tag_fs *landlock_new_tag_fs(struct inode *inode)
{
	struct landlock_tag_fs *tag_fs;

	tag_fs = kmalloc(sizeof(*tag_fs), GFP_KERNEL);
	if (!tag_fs)
		return ERR_PTR(-ENOMEM);
	ihold(inode);
	tag_fs->inode = inode;
	tag_fs->ref = NULL;
	return tag_fs;
}

void landlock_reset_tag_fs(struct landlock_tag_fs *tag_fs, struct inode *inode)
{
	if (WARN_ON(!tag_fs))
		return;
	landlock_free_tag_ref(tag_fs->ref, (struct landlock_tag_root **)
			&tag_fs->inode->i_security, &tag_fs->inode->i_lock);
	iput(tag_fs->inode);
	ihold(inode);
	tag_fs->inode = inode;
	tag_fs->ref = NULL;
}

void landlock_free_tag_fs(struct landlock_tag_fs *tag_fs)
{
	if (!tag_fs)
		return;
	landlock_free_tag_ref(tag_fs->ref, (struct landlock_tag_root **)
			&tag_fs->inode->i_security, &tag_fs->inode->i_lock);
	iput(tag_fs->inode);
	kfree(tag_fs);
}
