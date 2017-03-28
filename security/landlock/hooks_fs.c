/*
 * Landlock LSM - filesystem hooks
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h> /* ARRAY_SIZE */
#include <linux/lsm_hooks.h>
#include <linux/types.h> /* uintptr_t */

/* permissions translation */
#include <linux/fs.h> /* MAY_* */
#include <linux/mman.h> /* PROT_* */

/* hook arguments */
#include <linux/cred.h>
#include <linux/dcache.h> /* struct dentry */
#include <linux/fs.h> /* struct inode, struct iattr */
#include <linux/mm_types.h> /* struct vm_area_struct */
#include <linux/mount.h> /* struct vfsmount */
#include <linux/path.h> /* struct path */
#include <linux/sched.h> /* struct task_struct */
#include <linux/time.h> /* struct timespec */

#include "hooks.h"

#include "hooks_fs.h"


#define HOOK_NEW_FS(...) HOOK_NEW(1, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS2(...) HOOK_NEW(2, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS3(...) HOOK_NEW(3, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS4(...) HOOK_NEW(4, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS_CMD(...) HOOK_NEW(1, FS, 2, __VA_ARGS__)
#define HOOK_INIT_FS(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_1)
#define HOOK_INIT_FS2(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_2)
#define HOOK_INIT_FS3(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_3)
#define HOOK_INIT_FS4(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_4)

/* WRAP_TYPE_FS */
#define WRAP_TYPE_FS_BPF	CONST_PTR_TO_HANDLE_FS
#define WRAP_TYPE_FS_C		const struct bpf_handle_fs

/* WRAP_ARG_FILE */
#define WRAP_ARG_FILE_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_FILE_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_FILE, .file = arg };
#define WRAP_ARG_FILE_VAL(arg)	((uintptr_t)&wrap_##arg)
#define WRAP_ARG_FILE_OK(arg)	(arg)

/* WRAP_ARG_VMAF */
#define WRAP_ARG_VMAF_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_VMAF_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_FILE, .file = arg->vm_file };
#define WRAP_ARG_VMAF_VAL(arg)	((uintptr_t)&wrap_##arg)
#define WRAP_ARG_VMAF_OK(arg)	(arg && arg->vm_file)

/* WRAP_ARG_INODE */
#define WRAP_ARG_INODE_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_INODE_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_INODE, .inode = arg };
#define WRAP_ARG_INODE_VAL(arg)	((uintptr_t)&wrap_##arg)
#define WRAP_ARG_INODE_OK(arg)	(arg)

/* WRAP_ARG_PATH */
#define WRAP_ARG_PATH_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_PATH_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_PATH, .path = arg };
#define WRAP_ARG_PATH_VAL(arg)	((uintptr_t)&wrap_##arg)
#define WRAP_ARG_PATH_OK(arg)	(arg)

/* WRAP_ARG_DENTRY */
#define WRAP_ARG_DENTRY_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_DENTRY_DEC(arg)				\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_DENTRY, .dentry = arg };
#define WRAP_ARG_DENTRY_VAL(arg)	((uintptr_t)&wrap_##arg)
#define WRAP_ARG_DENTRY_OK(arg)	(arg)

/* WRAP_ARG_SB */
#define WRAP_ARG_SB_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_SB_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_DENTRY, .dentry = arg->s_root };
#define WRAP_ARG_SB_VAL(arg)	((uintptr_t)&wrap_##arg)
#define WRAP_ARG_SB_OK(arg)	(arg && arg->s_root)

/* WRAP_ARG_MNTROOT */
#define WRAP_ARG_MNTROOT_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_MNTROOT_DEC(arg)				\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_DENTRY, .dentry = arg->mnt_root };
#define WRAP_ARG_MNTROOT_VAL(arg)	((uintptr_t)&wrap_##arg)
#define WRAP_ARG_MNTROOT_OK(arg)	(arg && arg->mnt_root)


static inline u64 fs_may_to_access(int fs_may)
{
	u64 ret = 0;

	if (fs_may & MAY_EXEC)
		ret |= LANDLOCK_ACTION_FS_EXEC;
	if (fs_may & MAY_READ)
		ret |= LANDLOCK_ACTION_FS_READ;
	if (fs_may & MAY_WRITE)
		ret |= LANDLOCK_ACTION_FS_WRITE;
	if (fs_may & MAY_APPEND)
		ret |= LANDLOCK_ACTION_FS_WRITE;
	if (fs_may & MAY_OPEN)
		ret |= LANDLOCK_ACTION_FS_GET;
	/* ignore MAY_CHDIR and MAY_ACCESS */

	return ret;
}

static u64 mem_prot_to_access(unsigned long prot, bool private)
{
	u64 ret = 0;

	/* private mapping do not write to files */
	if (!private && (prot & PROT_WRITE))
		ret |= LANDLOCK_ACTION_FS_WRITE;
	if (prot & PROT_READ)
		ret |= LANDLOCK_ACTION_FS_READ;
	if (prot & PROT_EXEC)
		ret |= LANDLOCK_ACTION_FS_EXEC;

	return ret;
}

/* hook definitions */

HOOK_ACCESS(FS, 2, WRAP_TYPE_FS, WRAP_TYPE_RAW);

/* binder_* hooks */

HOOK_NEW_FS(binder_transfer_file, 3,
	struct task_struct *, from,
	struct task_struct *, to,
	struct file *, file,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

/* sb_* hooks */

HOOK_NEW_FS(sb_statfs, 1,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

/*
 * Being able to mount on a path means being able to override the underlying
 * filesystem view of this path, hence the need for a write access right.
 */
HOOK_NEW_FS(sb_mount, 5,
	const char *, dev_name,
	const struct path *, path,
	const char *, type,
	unsigned long, flags,
	void *, data,
	WRAP_ARG_PATH, path,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(sb_remount, 2,
	struct super_block *, sb,
	void *, data,
	WRAP_ARG_SB, sb,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(sb_umount, 2,
	struct vfsmount *, mnt,
	int, flags,
	WRAP_ARG_MNTROOT, mnt,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

/*
 * The old_path is similar to a destination mount point.
 */
HOOK_NEW_FS(sb_pivotroot, 2,
	const struct path *, old_path,
	const struct path *, new_path,
	WRAP_ARG_PATH, old_path,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

/* inode_* hooks */

/* a directory inode contains only one dentry */
HOOK_NEW_FS(inode_create, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_create, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_link, 3,
	struct dentry *, old_dentry,
	struct inode *, dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, old_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS2(inode_link, 3,
	struct dentry *, old_dentry,
	struct inode *, dir,
	struct dentry *, new_dentry,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS3(inode_link, 3,
	struct dentry *, old_dentry,
	struct inode *, dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, new_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_unlink, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_unlink, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_REMOVE
);

HOOK_NEW_FS(inode_symlink, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	const char *, old_name,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_symlink, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	const char *, old_name,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_mkdir, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_mkdir, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_rmdir, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_rmdir, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_REMOVE
);

HOOK_NEW_FS(inode_mknod, 4,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	dev_t, dev,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_mknod, 4,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	dev_t, dev,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_INODE, old_dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, old_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_REMOVE
);

HOOK_NEW_FS3(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_INODE, new_dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS4(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, new_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_readlink, 1,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

// XXX: handle inode?
HOOK_NEW_FS(inode_follow_link, 3,
	struct dentry *, dentry,
	struct inode *, inode,
	bool, rcu,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_permission, 2,
	struct inode *, inode,
	int, mask,
	WRAP_ARG_INODE, inode,
	WRAP_ARG_RAW, fs_may_to_access(mask)
);

HOOK_NEW_FS(inode_setattr, 2,
	struct dentry *, dentry,
	struct iattr *, attr,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(inode_getattr, 1,
	const struct path *, path,
	WRAP_ARG_PATH, path,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_setxattr, 5,
	struct dentry *, dentry,
	const char *, name,
	const void *, value,
	size_t, size,
	int, flags,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(inode_getxattr, 2,
	struct dentry *, dentry,
	const char *, name,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_listxattr, 1,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_removexattr, 2,
	struct dentry *, dentry,
	const char *, name,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(inode_getsecurity, 4,
	struct inode *, inode,
	const char *, name,
	void **, buffer,
	bool, alloc,
	WRAP_ARG_INODE, inode,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_setsecurity, 5,
	struct inode *, inode,
	const char *, name,
	const void *, value,
	size_t, size,
	int, flag,
	WRAP_ARG_INODE, inode,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

/* file_* hooks */

HOOK_NEW_FS(file_permission, 2,
	struct file *, file,
	int, mask,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, fs_may_to_access(mask)
);

/*
 * An ioctl command can be a read or a write. This can be checked with _IOC*()
 * for some commands but a Landlock rule should check the ioctl command to
 * whitelist them.
 */
HOOK_NEW_FS_CMD(file_ioctl, 3,
	struct file *, file,
	unsigned int, cmd,
	unsigned long, arg,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_IOCTL,
	cmd
);

HOOK_NEW_FS_CMD(file_lock, 2,
	struct file *, file,
	unsigned int, cmd,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_LOCK,
	cmd
);

HOOK_NEW_FS_CMD(file_fcntl, 3,
	struct file *, file,
	unsigned int, cmd,
	unsigned long, arg,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_FCNTL,
	cmd
);

HOOK_NEW_FS(mmap_file, 4,
	struct file *, file,
	unsigned long, reqprot,
	unsigned long, prot,
	unsigned long, flags,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, mem_prot_to_access(prot, flags & MAP_PRIVATE)
);

HOOK_NEW_FS(file_mprotect, 3,
	struct vm_area_struct *, vma,
	unsigned long, reqprot,
	unsigned long, prot,
	WRAP_ARG_VMAF, vma,
	WRAP_ARG_RAW, mem_prot_to_access(prot, !(vma->vm_flags & VM_SHARED))
);

HOOK_NEW_FS(file_receive, 1,
	struct file *, file,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_GET
);

HOOK_NEW_FS(file_open, 2,
	struct file *, file,
	const struct cred *, cred,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_GET
);

static struct security_hook_list landlock_hooks[] = {
	HOOK_INIT_FS(binder_transfer_file),

	HOOK_INIT_FS(sb_statfs),
	HOOK_INIT_FS(sb_mount),
	HOOK_INIT_FS(sb_remount),
	HOOK_INIT_FS(sb_umount),
	HOOK_INIT_FS(sb_pivotroot),

	HOOK_INIT_FS(inode_create),
	HOOK_INIT_FS2(inode_create),
	HOOK_INIT_FS(inode_link),
	HOOK_INIT_FS2(inode_link),
	HOOK_INIT_FS3(inode_link),
	HOOK_INIT_FS(inode_unlink),
	HOOK_INIT_FS2(inode_unlink),
	HOOK_INIT_FS(inode_symlink),
	HOOK_INIT_FS2(inode_symlink),
	HOOK_INIT_FS(inode_mkdir),
	HOOK_INIT_FS2(inode_mkdir),
	HOOK_INIT_FS(inode_rmdir),
	HOOK_INIT_FS2(inode_rmdir),
	HOOK_INIT_FS(inode_mknod),
	HOOK_INIT_FS2(inode_mknod),
	HOOK_INIT_FS(inode_rename),
	HOOK_INIT_FS2(inode_rename),
	HOOK_INIT_FS3(inode_rename),
	HOOK_INIT_FS4(inode_rename),
	HOOK_INIT_FS(inode_readlink),
	HOOK_INIT_FS(inode_follow_link),
	HOOK_INIT_FS(inode_permission),
	HOOK_INIT_FS(inode_setattr),
	HOOK_INIT_FS(inode_getattr),
	HOOK_INIT_FS(inode_setxattr),
	HOOK_INIT_FS(inode_getxattr),
	HOOK_INIT_FS(inode_listxattr),
	HOOK_INIT_FS(inode_removexattr),
	HOOK_INIT_FS(inode_getsecurity),
	HOOK_INIT_FS(inode_setsecurity),

	HOOK_INIT_FS(file_permission),
	HOOK_INIT_FS(file_ioctl),
	HOOK_INIT_FS(file_lock),
	HOOK_INIT_FS(file_fcntl),
	HOOK_INIT_FS(mmap_file),
	HOOK_INIT_FS(file_mprotect),
	HOOK_INIT_FS(file_receive),
	HOOK_INIT_FS(file_open),
};

__init void landlock_add_hooks_fs(void)
{
	landlock_register_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks));
}
