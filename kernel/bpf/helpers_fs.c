/*
 * BPF filesystem helpers
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* struct bpf_handle_fs */
#include <linux/errno.h>
#include <linux/filter.h> /* BPF_CALL*() */

BPF_CALL_1(bpf_handle_fs_get_mode, struct bpf_handle_fs *, handle_fs)
{
	if (WARN_ON(!handle_fs))
		return -EFAULT;
	if (!handle_fs->file) {
		/* file can be null for anonymous mmap */
		WARN_ON(handle_fs->type != BPF_HANDLE_FS_TYPE_FILE);
		return -ENOENT;
	}
	switch (handle_fs->type) {
		case BPF_HANDLE_FS_TYPE_FILE:
			if (WARN_ON(!handle_fs->file->f_inode))
				return -ENOENT;
			return handle_fs->file->f_inode->i_mode;
		case BPF_HANDLE_FS_TYPE_INODE:
			return handle_fs->inode->i_mode;
		case BPF_HANDLE_FS_TYPE_PATH:
			if (WARN_ON(!handle_fs->path->dentry ||
					!handle_fs->path->dentry->d_inode))
				return -ENOENT;
			return handle_fs->path->dentry->d_inode->i_mode;
		case BPF_HANDLE_FS_TYPE_DENTRY:
			if (WARN_ON(!handle_fs->dentry->d_inode))
				return -ENOENT;
			return handle_fs->dentry->d_inode->i_mode;
		case BPF_HANDLE_FS_TYPE_NONE:
		default:
			WARN_ON(1);
			return -EFAULT;
	}
}

const struct bpf_func_proto bpf_handle_fs_get_mode_proto = {
	.func		= bpf_handle_fs_get_mode,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_PTR_TO_HANDLE_FS,
};
