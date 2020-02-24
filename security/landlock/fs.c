// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Filesystem management and hooks
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <linux/compiler_types.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/landlock.h>
#include <linux/lsm_hooks.h>
#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>
#include <uapi/linux/landlock.h>

#include "cred.h"
#include "fs.h"
#include "object.h"
#include "ruleset.h"
#include "setup.h"

/* Underlying object management */

void landlock_release_inode(struct inode *inode, struct landlock_object *object)
{
	/*
	 * A call to landlock_put_object() or release_object() might sleep, but
	 * landlock_release_object() can not sleep because it is called with a
	 * reference to the inode.  However, we can still mark this function as
	 * such because this should not bother landlock_release_object()
	 * callers (e.g. landlock_release_inodes()).
	 */
	might_sleep();
	/*
	 * We must check that no one else replaced the pinned object in the
	 * window between the reset of @object->underlying_object and now.
	 */
	spin_lock(&inode->i_lock);
	if (rcu_access_pointer(inode_landlock(inode)->object) == object)
		rcu_assign_pointer(inode_landlock(inode)->object, NULL);
	spin_unlock(&inode->i_lock);
	/*
	 * Because we first NULL the reference to the object, calling iput()
	 * won't trigger a call to landlock_put_object() (via
	 * put_underlying_object).
	 */
	iput(inode);
}

/*
 * Release the inodes used in a security policy.
 *
 * It is much more clean to have a dedicated call in generic_shutdown_super()
 * than a hacky sb_free_security hook, especially with the locked sb_lock.
 *
 * Cf. fsnotify_unmount_inodes()
 */
void landlock_release_inodes(struct super_block *sb)
{
	struct inode *inode, *next, *iput_inode = NULL;

	if (!landlock_initialized)
		return;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry_safe(inode, next, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		if (!atomic_read(&inode->i_count)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);
		/*
		 * We can now actually put the previous inode, which is not
		 * needed anymore for the loop walk.  Because this inode should
		 * only be referenced by Landlock for this super block, iput()
		 * should trigger a call to hook_inode_free_security().
		 */
		if (iput_inode)
			iput(iput_inode);

		landlock_release_object(inode_landlock(inode)->object);

		iput_inode = inode;
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	if (iput_inode)
		iput(iput_inode);
}

/* Ruleset management */

static struct landlock_object *get_inode_object(struct inode *inode)
	__acquires(object->usage)
{
	struct landlock_object *object, *new_object;

	/* Let's first try a lockless access. */
	rcu_read_lock();
	object = landlock_get_object(rcu_dereference(
				inode_landlock(inode)->object));
	rcu_read_unlock();
	if (object)
		return object;

	__release(object->usage);
	/*
	 * If there is no object tied to @inode, then create a new one (outside
	 * of a locked block).
	 */
	new_object = landlock_create_object(LANDLOCK_OBJECT_INODE, inode);

	spin_lock(&inode->i_lock);
	object = landlock_get_object(rcu_dereference_protected(
				inode_landlock(inode)->object,
				lockdep_is_held(&inode->i_lock)));
	if (unlikely(object)) {
		/*
		 * Do not try to iput(inode) because it is not held yet.
		 */
		landlock_drop_object(new_object);
	} else {
		__release(object->usage);
		object = landlock_get_object(new_object);
		rcu_assign_pointer(inode_landlock(inode)->object, object);
		/*
		 * @inode will be released by landlock_release_inodes() on its
		 * super-block shutdown.
		 */
		ihold(inode);
	}
	spin_unlock(&inode->i_lock);
	return object;
}

/*
 * @path: Should have been checked by get_path_from_fd().
 */
int landlock_append_fs_rule(struct landlock_ruleset *ruleset,
		struct path *path, u64 access_hierarchy)
{
	int err;
	struct landlock_access access;
	struct landlock_object *object;

	/*
	 * Checks that @access_hierarchy matches the @ruleset constraints, but
	 * allow empty @access_hierarchy i.e., deny @ruleset->fs_access_mask .
	 */
	if ((ruleset->fs_access_mask | access_hierarchy) !=
			ruleset->fs_access_mask)
		return -EINVAL;
	/* Transforms relative access rights to absolute ones. */
	access_hierarchy |= _LANDLOCK_ACCESS_FS_MASK &
		~ruleset->fs_access_mask;
	access.self = access_hierarchy;
	access.beneath = access_hierarchy;
	object = get_inode_object(d_backing_inode(path->dentry));
	mutex_lock(&ruleset->lock);
	err = landlock_insert_ruleset_rule(ruleset, object, &access, NULL);
	mutex_unlock(&ruleset->lock);
	/*
	 * No need to check for an error because landlock_put_object() handles
	 * empty object and will terminate it if necessary.
	 */
	landlock_put_object(object);
	return err;
}

/* Access-control management */

static bool check_access_path_continue(
		const struct landlock_ruleset *domain,
		const struct path *path, u32 access_request,
		const bool check_self, bool *allow)
{
	const struct landlock_access *access;
	bool next = true;

	rcu_read_lock();
	access = landlock_find_access(domain, rcu_dereference(inode_landlock(
				d_backing_inode(path->dentry))->object));
	if (access) {
		next = ((check_self ? access->self : access->beneath) &
				access_request) == access_request;
		*allow = next;
	}
	rcu_read_unlock();
	return next;
}

static int check_access_path(const struct landlock_ruleset *domain,
		const struct path *path, u32 access_request)
{
	bool allow = false;
	struct path walker_path;

	if (WARN_ON_ONCE(!path))
		return 0;
	/* An access request not handled by the domain should be allowed. */
	access_request &= domain->fs_access_mask;
	if (access_request == 0)
		return 0;
	walker_path = *path;
	path_get(&walker_path);
	if (check_access_path_continue(domain, &walker_path, access_request,
				true, &allow)) {
		/*
		 * We need to walk through all the hierarchy to not miss any
		 * relevant restriction.  This could be optimized with a future
		 * commit.
		 */
		do {
			struct dentry *parent_dentry;

jump_up:
			/*
			 * Does not work with orphaned/private mounts like
			 * overlayfs layers for now (cf. ovl_path_real() and
			 * ovl_path_open()).
			 */
			if (walker_path.dentry == walker_path.mnt->mnt_root) {
				if (follow_up(&walker_path))
					/* Ignores hidden mount points. */
					goto jump_up;
				else
					/* Stops at the real root. */
					break;
			}
			parent_dentry = dget_parent(walker_path.dentry);
			dput(walker_path.dentry);
			walker_path.dentry = parent_dentry;
		} while (check_access_path_continue(domain, &walker_path,
					access_request, false, &allow));
	}
	path_put(&walker_path);
	return allow ? 0 : -EACCES;
}

static inline int current_check_access_path(const struct path *path,
		u32 access_request)
{
	struct landlock_ruleset *dom;

	dom = landlock_get_current_domain();
	if (!dom)
		return 0;
	return check_access_path(dom, path, access_request);
}

/* Super-block hooks */

/*
 * Because a Landlock security policy is defined according to the filesystem
 * layout (i.e. the mount namespace), changing it may grant access to files not
 * previously allowed.
 *
 * To make it simple, deny any filesystem layout modification by landlocked
 * processes.  Non-landlocked processes may still change the namespace of a
 * landlocked process, but this kind of threat must be handled by a system-wide
 * access-control security policy.
 *
 * This could be lifted in the future if Landlock can safely handle mount
 * namespace updates requested by a landlocked process.  Indeed, we could
 * update the current domain (which is currently read-only) by taking into
 * account the accesses of the source and the destination of a new mount point.
 * However, it would also require to make all the child domains dynamically
 * inherit these new constraints.  Anyway, for backward compatibility reasons,
 * a dedicated user space option would be required (e.g. as a ruleset command
 * option).
 */
static int hook_sb_mount(const char *dev_name, const struct path *path,
		const char *type, unsigned long flags, void *data)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

static int hook_move_mount(const struct path *from_path,
		const struct path *to_path)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

/*
 * Removing a mount point may reveal a previously hidden file hierarchy, which
 * may then grant access to files, which may have previously been forbidden.
 */
static int hook_sb_umount(struct vfsmount *mnt, int flags)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

static int hook_sb_remount(struct super_block *sb, void *mnt_opts)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

/*
 * pivot_root(2), like mount(2), changes the current mount namespace.  It must
 * then be forbidden for a landlocked process.
 *
 * However, chroot(2) may be allowed because it only changes the relative root
 * directory of the current process.
 */
static int hook_sb_pivotroot(const struct path *old_path,
		const struct path *new_path)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

/* Path hooks */

static int hook_path_link(struct dentry *old_dentry,
		const struct path *new_dir, struct dentry *new_dentry)
{
	return current_check_access_path(new_dir, LANDLOCK_ACCESS_FS_LINK_TO);
}

static int hook_path_mkdir(const struct path *dir, struct dentry *dentry,
		umode_t mode)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_DIR);
}

static inline u32 get_mode_access(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFLNK:
		return LANDLOCK_ACCESS_FS_MAKE_SYM;
	case S_IFREG:
		return LANDLOCK_ACCESS_FS_MAKE_REG;
	case S_IFDIR:
		return LANDLOCK_ACCESS_FS_MAKE_DIR;
	case S_IFCHR:
		return LANDLOCK_ACCESS_FS_MAKE_CHAR;
	case S_IFBLK:
		return LANDLOCK_ACCESS_FS_MAKE_BLOCK;
	case S_IFIFO:
		return LANDLOCK_ACCESS_FS_MAKE_FIFO;
	case S_IFSOCK:
		return LANDLOCK_ACCESS_FS_MAKE_SOCK;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}
}

static int hook_path_mknod(const struct path *dir, struct dentry *dentry,
		umode_t mode, unsigned int dev)
{
	return current_check_access_path(dir, get_mode_access(mode));
}

static int hook_path_symlink(const struct path *dir, struct dentry *dentry,
				const char *old_name)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_SYM);
}

static int hook_path_truncate(const struct path *path)
{
	return current_check_access_path(path, LANDLOCK_ACCESS_FS_TRUNCATE);
}

static int hook_path_unlink(const struct path *dir, struct dentry *dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_UNLINK);
}

static int hook_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_RMDIR);
}

static int hook_path_rename(const struct path *old_dir,
		struct dentry *old_dentry, const struct path *new_dir,
		struct dentry *new_dentry)
{
	struct landlock_ruleset *dom;
	int err;

	dom = landlock_get_current_domain();
	if (!dom)
		return 0;
	err = check_access_path(dom, old_dir, LANDLOCK_ACCESS_FS_RENAME_FROM);
	if (err)
		return err;
	return check_access_path(dom, new_dir, LANDLOCK_ACCESS_FS_RENAME_TO);
}

static int hook_path_chmod(const struct path *path, umode_t mode)
{
	return current_check_access_path(path, LANDLOCK_ACCESS_FS_CHMOD);
}

static int hook_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	struct landlock_ruleset *dom;
	int err;

	dom = landlock_get_current_domain();
	if (!dom)
		return 0;
	if (uid_valid(uid)) {
		err = check_access_path(dom, path, LANDLOCK_ACCESS_FS_CHOWN);
		if (err)
			return err;
	}
	if (gid_valid(gid)) {
		err = check_access_path(dom, path, LANDLOCK_ACCESS_FS_CHGRP);
		if (err)
			return err;
	}
	return 0;
}

static int hook_path_chroot(const struct path *path)
{
	return current_check_access_path(path, LANDLOCK_ACCESS_FS_CHROOT);
}

/* Inode hooks */

static int hook_inode_alloc_security(struct inode *inode)
{
	inode_landlock(inode)->object = NULL;
	return 0;
}

static void hook_inode_free_security(struct inode *inode)
{
	WARN_ON_ONCE(rcu_access_pointer(inode_landlock(inode)->object));
}

static int hook_inode_getattr(const struct path *path)
{
	return current_check_access_path(path, LANDLOCK_ACCESS_FS_GETATTR);
}

/* File hooks */

static inline u32 get_file_access(const struct file *file)
{
	u32 access = 0;

	if (file->f_mode & FMODE_READ) {
		/* A directory can only be opened in read mode. */
		if (S_ISDIR(file_inode(file)->i_mode))
			access |= LANDLOCK_ACCESS_FS_READDIR;
		else
			access |= LANDLOCK_ACCESS_FS_READ;
	}
	/*
	 * A LANDLOCK_ACCESS_FS_APPEND could be added be we also need to check
	 * fcntl(2).
	 */
	if (file->f_mode & FMODE_WRITE)
		access |= LANDLOCK_ACCESS_FS_WRITE;
	/* __FMODE_EXEC is indeed part of f_flags, not f_mode. */
	if (file->f_flags & __FMODE_EXEC)
		access |= LANDLOCK_ACCESS_FS_EXECUTE;
	return access;
}

static int hook_file_open(struct file *file)
{
	if (WARN_ON_ONCE(!file))
		return 0;
	if (!file_inode(file))
		return -ENOENT;
	return current_check_access_path(&file->f_path,
			LANDLOCK_ACCESS_FS_OPEN | get_file_access(file));
}

static inline u32 get_mem_access(unsigned long prot, bool private)
{
	u32 access = LANDLOCK_ACCESS_FS_MAP;

	/* Private mapping do not write to files. */
	if (!private && (prot & PROT_WRITE))
		access |= LANDLOCK_ACCESS_FS_WRITE;
	if (prot & PROT_READ)
		access |= LANDLOCK_ACCESS_FS_READ;
	if (prot & PROT_EXEC)
		access |= LANDLOCK_ACCESS_FS_EXECUTE;
	return access;
}

static int hook_mmap_file(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags)
{
	/* @file can be null for anonymous mmap. */
	if (!file)
		return 0;
	return current_check_access_path(&file->f_path,
			get_mem_access(prot, flags & MAP_PRIVATE));
}

static int hook_file_mprotect(struct vm_area_struct *vma,
		unsigned long reqprot, unsigned long prot)
{
	if (WARN_ON_ONCE(!vma))
		return 0;
	if (!vma->vm_file)
		return 0;
	return current_check_access_path(&vma->vm_file->f_path,
			get_mem_access(prot, !(vma->vm_flags & VM_SHARED)));
}

static int hook_file_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	if (WARN_ON_ONCE(!file))
		return 0;
	return current_check_access_path(&file->f_path,
			LANDLOCK_ACCESS_FS_IOCTL);
}

static int hook_file_lock(struct file *file, unsigned int cmd)
{
	if (WARN_ON_ONCE(!file))
		return 0;
	return current_check_access_path(&file->f_path,
			LANDLOCK_ACCESS_FS_LOCK);
}

static struct security_hook_list landlock_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(sb_mount, hook_sb_mount),
	LSM_HOOK_INIT(move_mount, hook_move_mount),
	LSM_HOOK_INIT(sb_umount, hook_sb_umount),
	LSM_HOOK_INIT(sb_remount, hook_sb_remount),
	LSM_HOOK_INIT(sb_pivotroot, hook_sb_pivotroot),

	LSM_HOOK_INIT(path_link, hook_path_link),
	LSM_HOOK_INIT(path_mkdir, hook_path_mkdir),
	LSM_HOOK_INIT(path_mknod, hook_path_mknod),
	LSM_HOOK_INIT(path_symlink, hook_path_symlink),
	LSM_HOOK_INIT(path_truncate, hook_path_truncate),
	LSM_HOOK_INIT(path_unlink, hook_path_unlink),
	LSM_HOOK_INIT(path_rmdir, hook_path_rmdir),
	LSM_HOOK_INIT(path_rename, hook_path_rename),
	LSM_HOOK_INIT(path_chmod, hook_path_chmod),
	LSM_HOOK_INIT(path_chown, hook_path_chown),
	LSM_HOOK_INIT(path_chroot, hook_path_chroot),

	LSM_HOOK_INIT(inode_alloc_security, hook_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, hook_inode_free_security),
	LSM_HOOK_INIT(inode_getattr, hook_inode_getattr),

	LSM_HOOK_INIT(file_open, hook_file_open),
	LSM_HOOK_INIT(mmap_file, hook_mmap_file),
	LSM_HOOK_INIT(file_mprotect, hook_file_mprotect),
	LSM_HOOK_INIT(file_ioctl, hook_file_ioctl),
	LSM_HOOK_INIT(file_lock, hook_file_lock),
};

__init void landlock_add_hooks_fs(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
