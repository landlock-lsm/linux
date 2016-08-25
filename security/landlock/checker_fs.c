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
#include <linux/fs.h> /* path_is_under() */
#include <linux/path.h> /* struct path */

#include "checker_fs.h"

#define EQUAL_NOT_NULL(a, b) (a && a == b)

/*
 * bpf_landlock_cmp_fs_prop_with_struct_file
 *
 * Cf. include/uapi/linux/bpf.h
 */
static inline u64 bpf_landlock_cmp_fs_prop_with_struct_file(u64 r1_property,
		u64 r2_map, u64 r3_map_op, u64 r4_file, u64 r5)
{
	u8 property = (u8) r1_property;
	struct bpf_map *map = (struct bpf_map *) (unsigned long) r2_map;
	enum bpf_map_array_op map_op = r3_map_op;
	struct file *file = (struct file *) (unsigned long) r4_file;
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct path *p1, *p2;
	struct map_landlock_handle *handle;
	int i;
	bool result_dentry = !(property & LANDLOCK_FLAG_FS_DENTRY);
	bool result_inode = !(property & LANDLOCK_FLAG_FS_INODE);
	bool result_device = !(property & LANDLOCK_FLAG_FS_DEVICE);
	bool result_mount = !(property & LANDLOCK_FLAG_FS_MOUNT);

	/* ARG_CONST_PTR_TO_LANDLOCK_HANDLE_FS is a arraymap */
	if (unlikely(!map)) {
		WARN_ON(1);
		return -EFAULT;
	}
	if (unlikely(!file))
		return -ENOENT;
	if (unlikely((property | _LANDLOCK_FLAG_FS_MASK) != _LANDLOCK_FLAG_FS_MASK))
		return -EINVAL;

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

	synchronize_rcu();

	for (i = 0; i < array->n_entries; i++) {
		handle = (struct map_landlock_handle *)
				(array->value + array->elem_size * i);

		if (handle->type != BPF_MAP_HANDLE_TYPE_LANDLOCK_FS_FD) {
			WARN_ON(1);
			return -EFAULT;
		}

		p1 = &handle->file->f_path;
		p2 = &file->f_path;
		if (unlikely(!p1 || !p2)) {
			WARN_ON(1);
			return -EFAULT;
		}

		if (!result_dentry && p1->dentry == p2->dentry)
			result_dentry = true;
		/* TODO: use d_inode_rcu() instead? */
		if (!result_inode
		    && EQUAL_NOT_NULL(d_inode(p1->dentry)->i_ino,
				      d_inode(p2->dentry)->i_ino))
			result_inode = true;
		/* check superblock instead of device major/minor */
		if (!result_device
		    && EQUAL_NOT_NULL(d_inode(p1->dentry)->i_sb,
				      d_inode(p2->dentry)->i_sb))
			result_device = true;
		if (!result_mount && EQUAL_NOT_NULL(p1->mnt, p2->mnt))
			result_mount = true;
		if (result_dentry && result_inode && result_device && result_mount)
			return 0;
	}
	return 1;
}

const struct bpf_func_proto bpf_landlock_cmp_fs_prop_with_struct_file_proto = {
	.func		= bpf_landlock_cmp_fs_prop_with_struct_file,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_CONST_PTR_TO_LANDLOCK_HANDLE_FS,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_STRUCT_FILE,
};

/*
 * bpf_landlock_cmp_fs_beneath_with_struct_file
 *
 * Cf. include/uapi/linux/bpf.h
 */
static inline u64 bpf_landlock_cmp_fs_beneath_with_struct_file(u64 r1_option,
		u64 r2_map, u64 r3_map_op, u64 r4_file, u64 r5)
{
	u8 option = (u8) r1_option;
	struct bpf_map *map = (struct bpf_map *) (unsigned long) r2_map;
	enum bpf_map_array_op map_op = r3_map_op;
	struct file *file = (struct file *) (unsigned long) r4_file;
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct path *p1, *p2;
	struct map_landlock_handle *handle;
	int i;

	/* ARG_CONST_PTR_TO_LANDLOCK_HANDLE_FS is an arraymap */
	if (unlikely(!map)) {
		WARN_ON(1);
		return -EFAULT;
	}
	/* @file can be null for anonymous mmap */
	if (unlikely(!file))
		return -ENOENT;
	if (unlikely((option | _LANDLOCK_FLAG_OPT_MASK) != _LANDLOCK_FLAG_OPT_MASK))
		return -EINVAL;

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

	synchronize_rcu();

	for (i = 0; i < array->n_entries; i++) {
		handle = (struct map_landlock_handle *)
				(array->value + array->elem_size * i);

		/* protected by the proto types, should not happen */
		if (unlikely(handle->type != BPF_MAP_HANDLE_TYPE_LANDLOCK_FS_FD)) {
			WARN_ON(1);
			return -EINVAL;
		}

		if (option & LANDLOCK_FLAG_OPT_REVERSE) {
			p1 = &file->f_path;
			p2 = &handle->file->f_path;
		} else {
			p1 = &handle->file->f_path;
			p2 = &file->f_path;
		}

		if (path_is_under(p2, p1))
			return 0;
	}
	return 1;
}

const struct bpf_func_proto bpf_landlock_cmp_fs_beneath_with_struct_file_proto = {
	.func		= bpf_landlock_cmp_fs_beneath_with_struct_file,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_CONST_PTR_TO_LANDLOCK_HANDLE_FS,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_STRUCT_FILE,
};
