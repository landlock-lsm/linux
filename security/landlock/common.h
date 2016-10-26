/*
 * Landlock LSM - private headers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h> /* enum landlock_hook */
#include <linux/fs.h> /* struct file, struct inode */
#include <linux/path.h> /* struct path */

/**
 * for_each_handle - iterate over all handles of an arraymap
 *
 * @i: index in the arraymap
 * @handle: struct map_landlock_handle pointer
 * @array: struct bpf_array pointer to walk through
 */
#define for_each_handle(i, handle, array)				\
	for (i = 0; i < atomic_read(&array->n_entries) &&		\
			(handle = *((struct map_landlock_handle **)	\
				(array->value + array->elem_size * i)));\
		i++)

enum landlock_argtype {
	LANDLOCK_ARGTYPE_NONE,
	LANDLOCK_ARGTYPE_FILE,
	LANDLOCK_ARGTYPE_INODE,
	LANDLOCK_ARGTYPE_PATH,
};

struct landlock_arg_fs {
	enum landlock_argtype type;
	union {
		struct file *file;
		struct inode *inode;
		const struct path *path;
	};
};

/**
 * get_index - get an index for the rules of struct landlock_hooks
 *
 * @hook: a Landlock hook ID
 */
static inline int get_index(enum landlock_hook hook)
{
	/* hook ID > 0 for loaded programs */
	return hook - 1;
}

#endif /* _SECURITY_LANDLOCK_COMMON_H */
