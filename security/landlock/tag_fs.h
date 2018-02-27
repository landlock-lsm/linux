/*
 * Landlock LSM - tag FS headers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_TAG_FS_H
#define _SECURITY_LANDLOCK_TAG_FS_H

#include <linux/fs.h> /* struct inode */

struct landlock_tag_fs {
	struct inode *inode;
	struct landlock_tag_ref *ref;
};

struct landlock_tag_fs *landlock_new_tag_fs(struct inode *inode);
void landlock_reset_tag_fs(struct landlock_tag_fs *tag_fs, struct inode *inode);
void landlock_free_tag_fs(struct landlock_tag_fs *tag_fs);

#endif /* _SECURITY_LANDLOCK_TAG_FS_H */
