/*
 * Landlock LSM - File System Checkers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_map_array_op */
#include <linux/errno.h>
#include <linux/filter.h> /* BPF_CALL*() */
#include <linux/fs.h> /* path_is_under() */
#include <linux/path.h> /* struct path */

#include "common.h" /* struct landlock_arg_fs */
#include "checker_fs.h"

/*
 * bpf_landlock_cmp_fs_beneath
 *
 * Cf. include/uapi/linux/bpf.h
 */
BPF_CALL_4(bpf_landlock_cmp_fs_beneath, u8, option, struct bpf_map *, map,
		enum bpf_map_array_op, map_op,
		struct landlock_arg_fs *, arg_fs)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	const struct path *p1 = NULL, *p2 = NULL;
	struct dentry *d1 = NULL, *d2 = NULL;
	struct map_landlock_handle *handle;
	size_t i;

	if (WARN_ON(!map))
		return -EFAULT;
	if (WARN_ON(!arg_fs))
		return -EFAULT;
	if (unlikely((option | _LANDLOCK_FLAG_OPT_MASK) != _LANDLOCK_FLAG_OPT_MASK))
		return -EINVAL;

	if (!arg_fs->file) {
		/* file can be null for anonymous mmap */
		WARN_ON(arg_fs->type != LANDLOCK_ARGTYPE_FILE);
		return -ENOENT;
	}

	/* for now, only handle OP_OR */
	switch (map_op) {
	case BPF_MAP_ARRAY_OP_OR:
		break;
	case BPF_MAP_ARRAY_OP_UNSPEC:
	case BPF_MAP_ARRAY_OP_AND:
	case BPF_MAP_ARRAY_OP_XOR:
	default:
		return -EINVAL;
	}
	switch (arg_fs->type) {
		case LANDLOCK_ARGTYPE_FILE:
			p1 = &arg_fs->file->f_path;
			break;
		case LANDLOCK_ARGTYPE_PATH:
			p1 = arg_fs->path;
			break;
		case LANDLOCK_ARGTYPE_INODE:
			d1 = d_find_alias(arg_fs->inode);
			if (WARN_ON(!d1))
				return -ENOENT;
			break;
		case LANDLOCK_ARGTYPE_NONE:
		default:
			WARN_ON(1);
			return -EFAULT;
	}
	/* {p,d}1 and {p,d}2 will be set correctly in the loop */
	p2 = p1;
	d2 = d1;

	if (p1) {
		for_each_handle(i, handle, array) {
			if (WARN_ON(handle->type != BPF_MAP_HANDLE_TYPE_LANDLOCK_FS_FD))
				return -EINVAL;

			if (option & LANDLOCK_FLAG_OPT_REVERSE)
				p2 = &handle->path;
			else
				p1 = &handle->path;

			if (path_is_under(p2, p1))
				return 0;
		}
	} else if (d1) {
		for_each_handle(i, handle, array) {
			if (WARN_ON(handle->type != BPF_MAP_HANDLE_TYPE_LANDLOCK_FS_FD))
				return -EINVAL;

			if (option & LANDLOCK_FLAG_OPT_REVERSE)
				d2 = handle->path.dentry;
			else
				d1 = handle->path.dentry;

			if (is_subdir(d2, d1))
				return 0;
		}
	}
	return 1;
}

const struct bpf_func_proto bpf_landlock_cmp_fs_beneath_proto = {
	.func		= bpf_landlock_cmp_fs_beneath,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_CONST_PTR_TO_LANDLOCK_HANDLE_FS,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_CONST_PTR_TO_LANDLOCK_ARG_FS,
};

BPF_CALL_1(bpf_landlock_get_fs_mode, struct landlock_arg_fs *, arg_fs)
{
	if (WARN_ON(!arg_fs))
		return -EFAULT;
	if (!arg_fs->file) {
		/* file can be null for anonymous mmap */
		WARN_ON(arg_fs->type != LANDLOCK_ARGTYPE_FILE);
		return -ENOENT;
	}
	switch (arg_fs->type) {
		case LANDLOCK_ARGTYPE_FILE:
			if (WARN_ON(!arg_fs->file->f_inode))
				return -ENOENT;
			return arg_fs->file->f_inode->i_mode;
		case LANDLOCK_ARGTYPE_INODE:
			return arg_fs->inode->i_mode;
		case LANDLOCK_ARGTYPE_PATH:
			if (WARN_ON(!arg_fs->path->dentry ||
					!arg_fs->path->dentry->d_inode))
				return -ENOENT;
			return arg_fs->path->dentry->d_inode->i_mode;
		case LANDLOCK_ARGTYPE_NONE:
		default:
			WARN_ON(1);
			return -EFAULT;
	}
}

const struct bpf_func_proto bpf_landlock_get_fs_mode_proto = {
	.func		= bpf_landlock_get_fs_mode,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_PTR_TO_LANDLOCK_ARG_FS,
};
