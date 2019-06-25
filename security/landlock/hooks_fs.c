// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - filesystem hooks
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/bpf.h> /* enum bpf_access_type */
#include <linux/kernel.h> /* ARRAY_SIZE */
#include <linux/lsm_hooks.h>
#include <linux/rcupdate.h> /* synchronize_rcu() */
#include <linux/stat.h> /* S_ISDIR */
#include <linux/stddef.h> /* offsetof */
#include <linux/types.h> /* uintptr_t */
#include <linux/workqueue.h> /* INIT_WORK() */

/* permissions translation */
#include <linux/fs.h> /* MAY_* */
#include <linux/mman.h> /* PROT_* */
#include <linux/namei.h>

/* hook arguments */
#include <linux/dcache.h> /* struct dentry */
#include <linux/fs.h> /* struct inode, struct iattr */
#include <linux/mm_types.h> /* struct vm_area_struct */
#include <linux/mount.h> /* struct vfsmount */
#include <linux/path.h> /* struct path */
#include <linux/sched.h> /* struct task_struct */
#include <linux/time.h> /* struct timespec */

#include "common.h"
#include "hooks_fs.h"
#include "hooks.h"

/* fs_pick */

#include <asm/page.h> /* PAGE_SIZE */
#include <asm/syscall.h>
#include <linux/dcache.h> /* d_path, dentry_path_raw */
#include <linux/err.h> /* *_ERR */
#include <linux/gfp.h> /* __get_free_page, GFP_KERNEL */
#include <linux/path.h> /* struct path */

bool landlock_is_valid_access_fs_pick(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size)
{
	switch (off) {
	case offsetof(struct landlock_ctx_fs_pick, inode):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_INODE;
		*max_size = sizeof(u64);
		return true;
	default:
		return false;
	}
}

bool landlock_is_valid_access_fs_walk(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size)
{
	switch (off) {
	case offsetof(struct landlock_ctx_fs_walk, inode):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_INODE;
		*max_size = sizeof(u64);
		return true;
	default:
		return false;
	}
}

/* fs_walk */

struct landlock_hook_ctx_fs_walk {
	struct landlock_ctx_fs_walk prog_ctx;
};

const struct landlock_ctx_fs_walk *landlock_get_ctx_fs_walk(
		const struct landlock_hook_ctx_fs_walk *hook_ctx)
{
	if (WARN_ON(!hook_ctx))
		return NULL;

	return &hook_ctx->prog_ctx;
}

static int decide_fs_walk(int may_mask, struct inode *inode)
{
	struct landlock_hook_ctx_fs_walk fs_walk = {};
	struct landlock_hook_ctx hook_ctx = {
		.fs_walk = &fs_walk,
	};
	const enum landlock_hook_type hook_type = LANDLOCK_HOOK_FS_WALK;

	if (!current_has_prog_type(hook_type))
		/* no fs_walk */
		return 0;
	if (WARN_ON(!inode))
		return -EFAULT;

	/* init common data: inode, is_dot, is_dotdot, is_root */
	fs_walk.prog_ctx.inode = (uintptr_t)inode;
	return landlock_decide(hook_type, &hook_ctx, 0);
}

/* fs_pick */

struct landlock_hook_ctx_fs_pick {
	__u64 triggers;
	struct landlock_ctx_fs_pick prog_ctx;
};

const struct landlock_ctx_fs_pick *landlock_get_ctx_fs_pick(
		const struct landlock_hook_ctx_fs_pick *hook_ctx)
{
	if (WARN_ON(!hook_ctx))
		return NULL;

	return &hook_ctx->prog_ctx;
}

static int decide_fs_pick(__u64 triggers, struct inode *inode)
{
	struct landlock_hook_ctx_fs_pick fs_pick = {};
	struct landlock_hook_ctx hook_ctx = {
		.fs_pick = &fs_pick,
	};
	const enum landlock_hook_type hook_type = LANDLOCK_HOOK_FS_PICK;

	if (WARN_ON(!triggers))
		return 0;
	if (!current_has_prog_type(hook_type))
		/* no fs_pick */
		return 0;
	if (WARN_ON(!inode))
		return -EFAULT;

	fs_pick.triggers = triggers,
	/* init common data: inode */
	fs_pick.prog_ctx.inode = (uintptr_t)inode;
	return landlock_decide(hook_type, &hook_ctx, fs_pick.triggers);
}

/* helpers */

static u64 fs_may_to_triggers(int may_mask, umode_t mode)
{
	u64 ret = 0;

	if (may_mask & MAY_EXEC)
		ret |= LANDLOCK_TRIGGER_FS_PICK_EXECUTE;
	if (may_mask & MAY_READ) {
		if (S_ISDIR(mode))
			ret |= LANDLOCK_TRIGGER_FS_PICK_READDIR;
		else
			ret |= LANDLOCK_TRIGGER_FS_PICK_READ;
	}
	if (may_mask & MAY_WRITE)
		ret |= LANDLOCK_TRIGGER_FS_PICK_WRITE;
	if (may_mask & MAY_APPEND)
		ret |= LANDLOCK_TRIGGER_FS_PICK_APPEND;
	if (may_mask & MAY_OPEN)
		ret |= LANDLOCK_TRIGGER_FS_PICK_OPEN;
	if (may_mask & MAY_CHROOT)
		ret |= LANDLOCK_TRIGGER_FS_PICK_CHROOT;
	else if (may_mask & MAY_CHDIR)
		ret |= LANDLOCK_TRIGGER_FS_PICK_CHDIR;
	/* XXX: ignore MAY_ACCESS */
	WARN_ON(!ret);
	return ret;
}

static inline u64 mem_prot_to_triggers(unsigned long prot, bool private)
{
	u64 ret = LANDLOCK_TRIGGER_FS_PICK_MAP;

	/* private mapping do not write to files */
	if (!private && (prot & PROT_WRITE))
		ret |= LANDLOCK_TRIGGER_FS_PICK_WRITE;
	if (prot & PROT_READ)
		ret |= LANDLOCK_TRIGGER_FS_PICK_READ;
	if (prot & PROT_EXEC)
		ret |= LANDLOCK_TRIGGER_FS_PICK_EXECUTE;
	WARN_ON(!ret);
	return ret;
}

/* binder hooks */

static int hook_binder_transfer_file(struct task_struct *from,
		struct task_struct *to, struct file *file)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_TRANSFER,
			file_inode(file));
}

/* sb hooks */

static int hook_sb_statfs(struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			dentry->d_inode);
}

/* TODO: handle mount source and remount */
static int hook_sb_mount(const char *dev_name, const struct path *path,
		const char *type, unsigned long flags, void *data)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!path))
		return 0;
	if (WARN_ON(!path->dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_MOUNTON,
			path->dentry->d_inode);
}

/*
 * The @old_path is similar to a destination mount point.
 */
static int hook_sb_pivotroot(const struct path *old_path,
		const struct path *new_path)
{
	int err;

	if (!landlocked(current))
		return 0;
	if (WARN_ON(!old_path))
		return 0;
	if (WARN_ON(!old_path->dentry))
		return 0;
	err = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_MOUNTON,
			old_path->dentry->d_inode);
	if (err)
		return err;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CHROOT,
			new_path->dentry->d_inode);
}

/* inode hooks */

/* a directory inode contains only one dentry */
static int hook_inode_create(struct inode *dir, struct dentry *dentry,
		umode_t mode)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!old_dentry)) {
		int ret = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_LINK,
				old_dentry->d_inode);
		if (ret)
			return ret;
	}
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_LINKTO, dir);
}

static int hook_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_UNLINK,
			dentry->d_inode);
}

static int hook_inode_symlink(struct inode *dir, struct dentry *dentry,
		const char *old_name)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_mkdir(struct inode *dir, struct dentry *dentry,
		umode_t mode)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RMDIR, dentry->d_inode);
}

static int hook_inode_mknod(struct inode *dir, struct dentry *dentry,
		umode_t mode, dev_t dev)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	if (!landlocked(current))
		return 0;
	/* TODO: add artificial walk session from old_dir to old_dentry */
	if (!WARN_ON(!old_dentry)) {
		int ret = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RENAME,
				old_dentry->d_inode);
		if (ret)
			return ret;
	}
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RENAMETO, new_dir);
}

static int hook_inode_readlink(struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_READ, dentry->d_inode);
}

/*
 * ignore the inode_follow_link hook (could set is_symlink in the fs_walk
 * context)
 */

static int hook_inode_permission(struct inode *inode, int mask)
{
	u64 triggers;

	if (!landlocked(current))
		return 0;
	if (WARN_ON(!inode))
		return 0;

	triggers = fs_may_to_triggers(mask, inode->i_mode);
	/*
	 * decide_fs_walk() is exclusive with decide_fs_pick(): in a path walk,
	 * ignore execute-only access on directory for any fs_pick program
	 */
	if (triggers == LANDLOCK_TRIGGER_FS_PICK_EXECUTE &&
			S_ISDIR(inode->i_mode))
		return decide_fs_walk(mask, inode);

	return decide_fs_pick(triggers, inode);
}

static int hook_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR,
			dentry->d_inode);
}

static int hook_inode_getattr(const struct path *path)
{
	/* TODO: link parent inode and path */
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!path))
		return 0;
	if (WARN_ON(!path->dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			path->dentry->d_inode);
}

static int hook_inode_setxattr(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR,
			dentry->d_inode);
}

static int hook_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			dentry->d_inode);
}

static int hook_inode_listxattr(struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			dentry->d_inode);
}

static int hook_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR,
			dentry->d_inode);
}

static int hook_inode_getsecurity(struct inode *inode, const char *name,
		void **buffer, bool alloc)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR, inode);
}

static int hook_inode_setsecurity(struct inode *inode, const char *name,
		const void *value, size_t size, int flag)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR, inode);
}

static int hook_inode_listsecurity(struct inode *inode, char *buffer,
		size_t buffer_size)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR, inode);
}

/* file hooks */

static int hook_file_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_IOCTL,
			file_inode(file));
}

static int hook_file_lock(struct file *file, unsigned int cmd)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_LOCK, file_inode(file));
}

static int hook_file_fcntl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_FCNTL,
			file_inode(file));
}

static int hook_mmap_file(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags)
{
	if (!landlocked(current))
		return 0;
	/* file can be null for anonymous mmap */
	if (!file)
		return 0;
	return decide_fs_pick(mem_prot_to_triggers(prot, flags & MAP_PRIVATE),
			file_inode(file));
}

static int hook_file_mprotect(struct vm_area_struct *vma,
		unsigned long reqprot, unsigned long prot)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!vma))
		return 0;
	if (!vma->vm_file)
		return 0;
	return decide_fs_pick(mem_prot_to_triggers(prot,
				!(vma->vm_flags & VM_SHARED)),
			file_inode(vma->vm_file));
}

static int hook_file_receive(struct file *file)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RECEIVE,
			file_inode(file));
}

static struct security_hook_list landlock_hooks[] = {
	LSM_HOOK_INIT(binder_transfer_file, hook_binder_transfer_file),

	LSM_HOOK_INIT(sb_statfs, hook_sb_statfs),
	LSM_HOOK_INIT(sb_mount, hook_sb_mount),
	LSM_HOOK_INIT(sb_pivotroot, hook_sb_pivotroot),

	LSM_HOOK_INIT(inode_create, hook_inode_create),
	LSM_HOOK_INIT(inode_link, hook_inode_link),
	LSM_HOOK_INIT(inode_unlink, hook_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, hook_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, hook_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, hook_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, hook_inode_mknod),
	LSM_HOOK_INIT(inode_rename, hook_inode_rename),
	LSM_HOOK_INIT(inode_readlink, hook_inode_readlink),
	LSM_HOOK_INIT(inode_permission, hook_inode_permission),
	LSM_HOOK_INIT(inode_setattr, hook_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, hook_inode_getattr),
	LSM_HOOK_INIT(inode_setxattr, hook_inode_setxattr),
	LSM_HOOK_INIT(inode_getxattr, hook_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, hook_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, hook_inode_removexattr),
	LSM_HOOK_INIT(inode_getsecurity, hook_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, hook_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, hook_inode_listsecurity),

	/* do not handle file_permission for now */
	LSM_HOOK_INIT(file_ioctl, hook_file_ioctl),
	LSM_HOOK_INIT(file_lock, hook_file_lock),
	LSM_HOOK_INIT(file_fcntl, hook_file_fcntl),
	LSM_HOOK_INIT(mmap_file, hook_mmap_file),
	LSM_HOOK_INIT(file_mprotect, hook_file_mprotect),
	LSM_HOOK_INIT(file_receive, hook_file_receive),
	/* file_open is not handled, use inode_permission instead */
};

__init void landlock_add_hooks_fs(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
