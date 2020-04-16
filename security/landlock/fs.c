// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Filesystem management and hooks
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <linux/atomic.h>
#include <linux/compiler_types.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/landlock.h>
#include <linux/list.h>
#include <linux/lsm_hooks.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/prefetch.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/wait_bit.h>
#include <linux/workqueue.h>
#include <uapi/linux/landlock.h>

#include "common.h"
#include "cred.h"
#include "fs.h"
#include "object.h"
#include "ruleset.h"
#include "setup.h"

/* Underlying object management */

static void release_inode(struct landlock_object *const object)
	__releases(object->lock)
{
	struct inode *const inode = object->underobj;
	struct super_block *sb;

	if (!inode) {
		spin_unlock(&object->lock);
		return;
	}

	spin_lock(&inode->i_lock);
	/*
	 * Make sure that if the filesystem is concurrently unmounted,
	 * landlock_release_inodes() will wait for us to finish iput().
	 */
	sb = inode->i_sb;
	atomic_long_inc(&sb->s_landlock_inode_refs);
	rcu_assign_pointer(inode_landlock(inode)->object, NULL);
	spin_unlock(&inode->i_lock);
	spin_unlock(&object->lock);
	/*
	 * Now, new rules can safely be tied to @inode.
	 */

	iput(inode);
	if (atomic_long_dec_and_test(&sb->s_landlock_inode_refs))
		wake_up_var(&sb->s_landlock_inode_refs);
}

static const struct landlock_object_underops landlock_fs_underops = {
	.release = release_inode
};

/*
 * Release the inodes used in a security policy.
 *
 * Cf. fsnotify_unmount_inodes()
 */
void landlock_release_inodes(struct super_block *const sb)
{
	struct inode *inode, *iput_inode = NULL;

	if (!landlock_initialized)
		return;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct landlock_inode_security *inode_sec =
			inode_landlock(inode);
		struct landlock_object *object;
		bool do_put = false;

		rcu_read_lock();
		object = rcu_dereference(inode_sec->object);
		if (!object) {
			rcu_read_unlock();
			continue;
		}

		spin_lock(&object->lock);
		if (object->underobj) {
			object->underobj = NULL;
			do_put = true;
			spin_lock(&inode->i_lock);
			rcu_assign_pointer(inode_sec->object, NULL);
			spin_unlock(&inode->i_lock);
		}
		spin_unlock(&object->lock);
		rcu_read_unlock();
		if (!do_put)
			/*
			 * A concurrent iput() in release_inode() is ongoing
			 * and we will just wait for it to finish.
			 */
			continue;

		/*
		 * At this point, we own the ihold() reference that was
		 * originally set up by get_inode_object(). Therefore we can
		 * drop the list lock and know that the inode won't disappear
		 * from under us until the next loop walk.
		 */
		spin_unlock(&sb->s_inode_list_lock);
		/*
		 * We can now actually put the previous inode, which is not
		 * needed anymore for the loop walk.
		 */
		if (iput_inode)
			iput(iput_inode);
		iput_inode = inode;
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	if (iput_inode)
		iput(iput_inode);

	/*
	 * Wait for pending iput() in release_inode().
	 */
	wait_var_event(&sb->s_landlock_inode_refs,
			!atomic_long_read(&sb->s_landlock_inode_refs));
}

/* Ruleset management */

static struct landlock_object *get_inode_object(struct inode *const inode)
{
	struct landlock_object *object, *new_object;
	struct landlock_inode_security *inode_sec = inode_landlock(inode);

	rcu_read_lock();
retry:
	object = rcu_dereference(inode_sec->object);
	if (object) {
		if (likely(refcount_inc_not_zero(&object->usage))) {
			rcu_read_unlock();
			return object;
		}
		/*
		 * We're racing with release_inode(), the object is going away.
		 * Wait for release_inode(), then retry.
		 */
		spin_lock(&object->lock);
		spin_unlock(&object->lock);
		goto retry;
	}
	rcu_read_unlock();

	/*
	 * If there is no object tied to @inode, then create a new one (without
	 * holding any locks).
	 */
	new_object = landlock_create_object(&landlock_fs_underops, inode);

	spin_lock(&inode->i_lock);
	object = rcu_dereference_protected(inode_sec->object,
			lockdep_is_held(&inode->i_lock));
	if (unlikely(object)) {
		/* Someone else just created the object, bail out and retry. */
		kfree(new_object);
		spin_unlock(&inode->i_lock);

		rcu_read_lock();
		goto retry;
	} else {
		rcu_assign_pointer(inode_sec->object, new_object);
		/*
		 * @inode will be released by landlock_release_inodes() on its
		 * super-block shutdown.
		 */
		ihold(inode);
		spin_unlock(&inode->i_lock);
		return new_object;
	}
}

/* All access rights which can be tied to files. */
#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE)

/*
 * @path: Should have been checked by get_path_from_fd().
 */
int landlock_append_fs_rule(struct landlock_ruleset *const ruleset,
		const struct path *const path, u32 access_rights)
{
	int err;
	struct landlock_rule rule = {};

	/* Files only get access rights that make sense. */
	if (!d_is_dir(path->dentry) && (access_rights | ACCESS_FILE) !=
			ACCESS_FILE)
		return -EINVAL;

	/* Transforms relative access rights to absolute ones. */
	access_rights |= _LANDLOCK_ACCESS_FS_MASK & ~ruleset->fs_access_mask;
	rule.access = access_rights;
	rule.object = get_inode_object(d_backing_inode(path->dentry));
	mutex_lock(&ruleset->lock);
	err = landlock_insert_rule(ruleset, &rule, false);
	mutex_unlock(&ruleset->lock);
	/*
	 * No need to check for an error because landlock_insert_rule()
	 * increment the refcount for the new rule, if any.
	 */
	landlock_put_object(rule.object);
	return err;
}

/* Access-control management */

static bool check_access_path_continue(
		const struct landlock_ruleset *const domain,
		const struct path *const path, const u32 access_request,
		bool *const allow, u64 *const layer_mask)
{
	const struct landlock_rule *rule;
	const struct inode *inode;
	bool next = true;

	prefetch(path->dentry->d_parent);
	if (d_is_negative(path->dentry))
		/* Continues to walk while there is no mapped inode. */
		return true;
	inode = d_backing_inode(path->dentry);
	rcu_read_lock();
	rule = landlock_find_rule(domain,
			rcu_dereference(inode_landlock(inode)->object));
	rcu_read_unlock();

	/* Checks for matching layers. */
	if (rule && (rule->layers | *layer_mask)) {
		*allow = (rule->access & access_request) == access_request;
		if (*allow) {
			*layer_mask &= ~rule->layers;
			/* Stops when a rule from each layer granted access. */
			next = !!*layer_mask;
		} else {
			next = false;
		}
	}
	return next;
}

static int check_access_path(const struct landlock_ruleset *const domain,
		const struct path *const path, u32 access_request)
{
	bool allow = false;
	struct path walker_path;
	u64 layer_mask;

	if (WARN_ON_ONCE(!path))
		return 0;
	/*
	 * Allows access to pseudo filesystems that will never be mountable
	 * (e.g. sockfs, pipefs), but can still be reachable through
	 * /proc/self/fd .
	 */
	if ((path->dentry->d_sb->s_flags & SB_NOUSER) ||
			(d_is_positive(path->dentry) &&
			 unlikely(IS_PRIVATE(d_backing_inode(path->dentry)))))
		return 0;
	if (WARN_ON_ONCE(domain->nb_layers < 1))
		return -EACCES;

	layer_mask = GENMASK_ULL(domain->nb_layers - 1, 0);
	/*
	 * An access request which is not handled by the domain should be
	 * allowed.
	 */
	access_request &= domain->fs_access_mask;
	if (access_request == 0)
		return 0;
	walker_path = *path;
	path_get(&walker_path);
	/*
	 * We need to walk through all the hierarchy to not miss any relevant
	 * restriction.
	 */
	while (check_access_path_continue(domain, &walker_path, access_request,
				&allow, &layer_mask)) {
		struct dentry *parent_dentry;

jump_up:
		/*
		 * Does not work with orphaned/private mounts like overlayfs
		 * layers for now (cf. ovl_path_real() and ovl_path_open()).
		 */
		if (walker_path.dentry == walker_path.mnt->mnt_root) {
			if (follow_up(&walker_path)) {
				/* Ignores hidden mount points. */
				goto jump_up;
			} else {
				/*
				 * Stops at the real root.  Denies access
				 * because not all layers have granted access.
				 */
				allow = false;
				break;
			}
		}
		if (unlikely(IS_ROOT(walker_path.dentry))) {
			/*
			 * Stops at disconnected root directories.  Only allows
			 * access to internal filesystems (e.g. nsfs which is
			 * reachable through /proc/self/ns).
			 */
			allow = !!(walker_path.mnt->mnt_flags & MNT_INTERNAL);
			break;
		}
		parent_dentry = dget_parent(walker_path.dentry);
		dput(walker_path.dentry);
		walker_path.dentry = parent_dentry;
	}
	path_put(&walker_path);
	return allow ? 0 : -EACCES;
}

static inline int current_check_access_path(const struct path *const path,
		const u32 access_request)
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
static int hook_sb_mount(const char *const dev_name,
		const struct path *const path, const char *const type,
		const unsigned long flags, void *const data)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

static int hook_move_mount(const struct path *const from_path,
		const struct path *const to_path)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

/*
 * Removing a mount point may reveal a previously hidden file hierarchy, which
 * may then grant access to files, which may have previously been forbidden.
 */
static int hook_sb_umount(struct vfsmount *const mnt, const int flags)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

static int hook_sb_remount(struct super_block *const sb, void *const mnt_opts)
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
static int hook_sb_pivotroot(const struct path *const old_path,
		const struct path *const new_path)
{
	if (!landlock_get_current_domain())
		return 0;
	return -EPERM;
}

/* Path hooks */

static inline u32 get_mode_access(const umode_t mode)
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

/*
 * Creating multiple links or renaming may lead to privilege escalations if not
 * handled properly.  Indeed, we must be sure that the source doesn't gain more
 * privileges by being accessible from the destination.  This is getting more
 * complex when dealing with multiple layers.  The whole picture can be seen as
 * a multilayer partial ordering problem.  A future version of Landlock will
 * deal with that.
 */
static int hook_path_link(struct dentry *const old_dentry,
		const struct path *const new_dir,
		struct dentry *const new_dentry)
{
	struct landlock_ruleset *dom;

	dom = landlock_get_current_domain();
	if (!dom)
		return 0;
	/* The mount points are the same for old and new paths, cf. EXDEV. */
	if (old_dentry->d_parent != new_dir->dentry)
		/* For now, forbid reparenting. */
		return -EACCES;
	if (unlikely(d_is_negative(old_dentry)))
		return -EACCES;
	return check_access_path(dom, new_dir,
			get_mode_access(d_backing_inode(old_dentry)->i_mode));
}

static inline u32 maybe_remove(const struct dentry *const dentry)
{
	if (d_is_negative(dentry))
		return 0;
	return d_is_dir(dentry) ? LANDLOCK_ACCESS_FS_REMOVE_DIR :
		LANDLOCK_ACCESS_FS_REMOVE_FILE;
}

static int hook_path_rename(const struct path *const old_dir,
		struct dentry *const old_dentry,
		const struct path *const new_dir,
		struct dentry *const new_dentry)
{
	struct landlock_ruleset *dom;

	dom = landlock_get_current_domain();
	if (!dom)
		return 0;
	/* The mount points are the same for old and new paths, cf. EXDEV. */
	if (old_dir->dentry != new_dir->dentry)
		/* For now, forbid reparenting. */
		return -EACCES;
	if (WARN_ON_ONCE(d_is_negative(old_dentry)))
		return -EACCES;
	/* RENAME_EXCHANGE is handled because directories are the same. */
	return check_access_path(dom, old_dir, maybe_remove(old_dentry) |
			maybe_remove(new_dentry) |
			get_mode_access(d_backing_inode(old_dentry)->i_mode));
}

static int hook_path_mkdir(const struct path *const dir,
		struct dentry *const dentry, const umode_t mode)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_DIR);
}

static int hook_path_mknod(const struct path *const dir,
		struct dentry *const dentry, const umode_t mode,
		const unsigned int dev)
{
	return current_check_access_path(dir, get_mode_access(mode));
}

static int hook_path_symlink(const struct path *const dir,
		struct dentry *const dentry, const char *const old_name)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_SYM);
}

static int hook_path_unlink(const struct path *const dir,
		struct dentry *const dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_REMOVE_FILE);
}

static int hook_path_rmdir(const struct path *const dir,
		struct dentry *const dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_REMOVE_DIR);
}

static int hook_path_chroot(const struct path *const path)
{
	return current_check_access_path(path, LANDLOCK_ACCESS_FS_CHROOT);
}

/* File hooks */

static inline u32 get_file_access(const struct file *const file)
{
	u32 access = 0;

	if (file->f_mode & FMODE_READ) {
		/* A directory can only be opened in read mode. */
		if (S_ISDIR(file_inode(file)->i_mode))
			return LANDLOCK_ACCESS_FS_READ_DIR;
		access = LANDLOCK_ACCESS_FS_READ_FILE;
	}
	/*
	 * A LANDLOCK_ACCESS_FS_APPEND could be added but we also need to check
	 * fcntl(2).
	 */
	if (file->f_mode & FMODE_WRITE)
		access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	/* __FMODE_EXEC is indeed part of f_flags, not f_mode. */
	if (file->f_flags & __FMODE_EXEC)
		access |= LANDLOCK_ACCESS_FS_EXECUTE;
	return access;
}

static int hook_file_open(struct file *const file)
{
	if (WARN_ON_ONCE(!file))
		return 0;
	if (!file_inode(file))
		return -ENOENT;
	/*
	 * Because a file may be opened with O_PATH, get_file_access() may
	 * return 0.  This case will be handled with a future Landlock
	 * evolution.
	 */
	return current_check_access_path(&file->f_path, get_file_access(file));
}

static struct security_hook_list landlock_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(sb_mount, hook_sb_mount),
	LSM_HOOK_INIT(move_mount, hook_move_mount),
	LSM_HOOK_INIT(sb_umount, hook_sb_umount),
	LSM_HOOK_INIT(sb_remount, hook_sb_remount),
	LSM_HOOK_INIT(sb_pivotroot, hook_sb_pivotroot),

	LSM_HOOK_INIT(path_link, hook_path_link),
	LSM_HOOK_INIT(path_rename, hook_path_rename),
	LSM_HOOK_INIT(path_mkdir, hook_path_mkdir),
	LSM_HOOK_INIT(path_mknod, hook_path_mknod),
	LSM_HOOK_INIT(path_symlink, hook_path_symlink),
	LSM_HOOK_INIT(path_unlink, hook_path_unlink),
	LSM_HOOK_INIT(path_rmdir, hook_path_rmdir),
	LSM_HOOK_INIT(path_chroot, hook_path_chroot),

	LSM_HOOK_INIT(file_open, hook_file_open),
};

__init void landlock_add_hooks_fs(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
