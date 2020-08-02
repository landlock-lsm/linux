// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - System call and user space interfaces
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <asm/current.h>
#include <linux/anon_inodes.h>
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/compiler_types.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/linux/landlock.h>

#include "cred.h"
#include "fs.h"
#include "ruleset.h"
#include "setup.h"

/**
 * copy_struct_if_any_from_user - Safe future-proof argument copying
 *
 * Extend copy_struct_from_user() to handle NULL @src, which allows for future
 * use of @src even if it is not used right now.
 *
 * @dst: Kernel space pointer or NULL.
 * @ksize: Actual size of the data pointed to by @dst.
 * @ksize_min: Minimal required size to be copied.
 * @src: User space pointer or NULL.
 * @usize: (Alleged) size of the data pointed to by @src.
 */
static int copy_struct_if_any_from_user(void *const dst, const size_t ksize,
		const size_t ksize_min, const void __user *const src,
		const size_t usize)
{
	int ret;

	/* Checks kernel buffer size inconsistencies. */
	if (dst) {
		if (WARN_ON_ONCE(ksize == 0))
			return -EFAULT;
	} else {
		if (WARN_ON_ONCE(ksize != 0))
			return -EFAULT;
	}

	/* Checks minimal size. */
	if (WARN_ON_ONCE(ksize < ksize_min))
		return -EFAULT;
	if (usize < ksize_min)
		return -EINVAL;

	/* Handles empty user buffer. */
	if (!src) {
		if (usize != 0)
			return -EFAULT;
		if (dst)
			memset(dst, 0, ksize);
		return 0;
	}

	/* Checks user buffer size inconsistency and limit. */
	if (usize == 0)
		return -ENODATA;
	if (usize > PAGE_SIZE)
		return -E2BIG;

	/* Copies user buffer and fills with zeros. */
	if (dst)
		return copy_struct_from_user(dst, ksize, src, usize);

	/* Checks unknown user data. */
	ret = check_zeroed_user(src, usize);
	if (ret <= 0)
		return ret ?: -E2BIG;
	return 0;
}

/* Features */

/*
 * This function only contains arithmetic operations with constants, leading to
 * BUILD_BUG_ON().  The related code is evaluated and checked at build time,
 * but it is then ignored thanks to compiler optimizations.
 */
static void build_check_abi(void)
{
	size_t size_features, size_ruleset, size_path_beneath;

	/*
	 * For each user space ABI structures, first checks that there is no
	 * hole in them, then checks that all architectures have the same
	 * struct size.
	 */
	size_features = sizeof_field(struct landlock_attr_features, options_get_features);
	size_features += sizeof_field(struct landlock_attr_features, options_create_ruleset);
	size_features += sizeof_field(struct landlock_attr_features, options_add_rule);
	size_features += sizeof_field(struct landlock_attr_features, options_enforce_ruleset);
	size_features += sizeof_field(struct landlock_attr_features, access_fs);
	size_features += sizeof_field(struct landlock_attr_features, size_attr_features);
	size_features += sizeof_field(struct landlock_attr_features, size_attr_ruleset);
	size_features += sizeof_field(struct landlock_attr_features, size_attr_path_beneath);
	size_features += sizeof_field(struct landlock_attr_features, last_rule_type);
	size_features += sizeof_field(struct landlock_attr_features, last_target_type);
	BUILD_BUG_ON(sizeof(struct landlock_attr_features) != size_features);
	BUILD_BUG_ON(sizeof(struct landlock_attr_features) != 32);

	size_ruleset = sizeof_field(struct landlock_attr_ruleset, handled_access_fs);
	BUILD_BUG_ON(sizeof(struct landlock_attr_ruleset) != size_ruleset);
	BUILD_BUG_ON(sizeof(struct landlock_attr_ruleset) != 8);

	size_path_beneath = sizeof_field(struct landlock_attr_path_beneath, allowed_access);
	size_path_beneath += sizeof_field(struct landlock_attr_path_beneath, parent_fd);
	BUILD_BUG_ON(sizeof(struct landlock_attr_path_beneath) != size_path_beneath);
	BUILD_BUG_ON(sizeof(struct landlock_attr_path_beneath) != 12);
}

/**
 * sys_landlock_get_features - Identify the supported Landlock features
 *
 * @features_ptr: Pointer to a &struct landlock_attr_features (allocated by
 *                user space) to be filled by the supported features.
 * @features_size: Size of the pointed &struct landlock_attr_features (needed
 *		   for backward and forward compatibility).
 * @options: Must be 0.
 *
 * This system call enables to ask for the Landlock features effectively
 * handled by the running kernel.  This enables backward compatibility for
 * applications which are developed on a newer kernel than the one running the
 * application.  This helps avoid hard errors that may entirely disable the use
 * of Landlock features because some of them may not be supported.  Indeed,
 * because Landlock is a security feature, even if the kernel doesn't support
 * all the requested features, user space applications should still use the
 * subset which is supported by the running kernel.  Indeed, a partial security
 * policy can still improve the security of the application and better protect
 * the user (i.e. best-effort approach).  Handling of &struct
 * landlock_attr_features with sys_landlock_get_features() is future-proof
 * because the future unknown fields requested by user space (i.e. a larger
 * &struct landlock_attr_features) can still be filled with zeros.
 *
 * The other Landlock syscalls will fail if an unsupported option or access is
 * requested.  By firstly requesting the supported options and accesses, it is
 * quite easy for the developer to binary AND these returned bitmasks with the
 * used options and accesses from the attribute structs (e.g. &struct
 * landlock_attr_ruleset).  This enables to create applications doing their
 * best to sandbox themselves regardless of the running kernel.
 *
 * Possible returned errors are:
 *
 * - EOPNOTSUPP: Landlock is supported by the kernel but disabled at boot time;
 * - EINVAL: @options is not 0;
 * - ENODATA, E2BIG or EFAULT: @features_ptr or @feature_size inconsistencies.
 */
SYSCALL_DEFINE3(landlock_get_features,
		struct landlock_attr_features __user *const, features_ptr,
		const size_t, features_size, const __u32, options)
{
	size_t data_size, fill_size;
	const struct landlock_attr_features supported = {
		.options_get_features = 0,
		.options_create_ruleset = 0,
		.options_add_rule = 0,
		.options_enforce_ruleset = 0,
		.access_fs = _LANDLOCK_ACCESS_FS_MASK,
		.size_attr_features = sizeof(struct landlock_attr_features),
		.size_attr_ruleset = sizeof(struct landlock_attr_ruleset),
		.size_attr_path_beneath = sizeof(struct landlock_attr_path_beneath),
		.last_rule_type = LANDLOCK_RULE_PATH_BENEATH,
		.last_target_type = LANDLOCK_TARGET_CURRENT_THREAD,
	};

	BUILD_BUG_ON(!__same_type(supported.access_fs,
		((struct landlock_attr_ruleset *)NULL)->handled_access_fs));
	BUILD_BUG_ON(!__same_type(supported.access_fs,
		((struct landlock_attr_path_beneath *)NULL)->allowed_access));
	build_check_abi();

	/*
	 * Enables user space to identify if Landlock is disabled, thanks to a
	 * specific error code.
	 */
	if (!landlock_initialized)
		return -EOPNOTSUPP;

	/* No option for now. */
	if (options)
		return -EINVAL;

	/* Checks argument consistency. */
	if (features_size == 0)
		return -ENODATA;
	if (features_size > PAGE_SIZE)
		return -E2BIG;

	/* Copy a subset of features to user space. */
	data_size = min(sizeof(supported), features_size);
	if (copy_to_user(features_ptr, &supported, data_size))
		return -EFAULT;

	/* Fills with zeros. */
	fill_size = features_size - data_size;
	if (fill_size > 0 && clear_user((void __user *)features_ptr + data_size, fill_size))
		return -EFAULT;
	return 0;
}

/* Ruleset handling */

static int fop_ruleset_release(struct inode *const inode,
		struct file *const filp)
{
	struct landlock_ruleset *ruleset = filp->private_data;

	landlock_put_ruleset(ruleset);
	return 0;
}

static ssize_t fop_dummy_read(struct file *const filp, char __user *const buf,
		const size_t size, loff_t *const ppos)
{
	/* Dummy handler to enable FMODE_CAN_READ. */
	return -EINVAL;
}

static ssize_t fop_dummy_write(struct file *const filp,
		const char __user *const buf, const size_t size,
		loff_t *const ppos)
{
	/* Dummy handler to enable FMODE_CAN_WRITE. */
	return -EINVAL;
}

/*
 * A ruleset file descriptor enables to build a ruleset by adding (i.e.
 * writing) rule after rule, without relying on the task's context.  This
 * reentrant design is also used in a read way to enforce the ruleset on the
 * current task.
 */
static const struct file_operations ruleset_fops = {
	.release = fop_ruleset_release,
	.read = fop_dummy_read,
	.write = fop_dummy_write,
};

/**
 * sys_landlock_create_ruleset - Create a new ruleset
 *
 * @ruleset_ptr: Pointer to a &struct landlock_attr_ruleset identifying the
 *		 scope of the new ruleset.
 * @ruleset_size: Size of the pointed &struct landlock_attr_ruleset (needed for
 *		  backward and forward compatibility).
 * @options: Must be 0.
 *
 * This system call enables to create a new Landlock ruleset, and returns the
 * related file descriptor on success.
 *
 * Possible returned errors are:
 *
 * - EOPNOTSUPP: Landlock is supported by the kernel but disabled at boot time;
 * - EINVAL: @options is not 0, or unknown access, or too small @ruleset_size;
 * - ENODATA, E2BIG or EFAULT: @ruleset_ptr or @ruleset_size inconsistencies;
 * - ENOMSG: empty &landlock_attr_ruleset.handled_access_fs.
 */
SYSCALL_DEFINE3(landlock_create_ruleset,
		const struct landlock_attr_ruleset __user *const, ruleset_ptr,
		const size_t, ruleset_size, const __u32, options)
{
	struct landlock_attr_ruleset attr_ruleset;
	struct landlock_ruleset *ruleset;
	int err, ruleset_fd;

	if (!landlock_initialized)
		return -EOPNOTSUPP;

	/* No option for now. */
	if (options)
		return -EINVAL;

	/* Copies raw user space buffer. */
	err = copy_struct_if_any_from_user(&attr_ruleset, sizeof(attr_ruleset),
			offsetofend(typeof(attr_ruleset), handled_access_fs),
			ruleset_ptr, ruleset_size);
	if (err)
		return err;

	/* Checks content (and 32-bits cast). */
	if ((attr_ruleset.handled_access_fs | _LANDLOCK_ACCESS_FS_MASK) !=
			_LANDLOCK_ACCESS_FS_MASK)
		return -EINVAL;

	/* Checks arguments and transforms to kernel struct. */
	ruleset = landlock_create_ruleset(attr_ruleset.handled_access_fs);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	/* Creates anonymous FD referring to the ruleset. */
	ruleset_fd = anon_inode_getfd("landlock-ruleset", &ruleset_fops,
			ruleset, O_RDWR | O_CLOEXEC);
	if (ruleset_fd < 0)
		landlock_put_ruleset(ruleset);
	return ruleset_fd;
}

/*
 * Returns an owned ruleset from a FD. It is thus needed to call
 * landlock_put_ruleset() on the return value.
 */
static struct landlock_ruleset *get_ruleset_from_fd(const int fd,
		const fmode_t mode)
{
	struct fd ruleset_f;
	struct landlock_ruleset *ruleset;
	int err;

	ruleset_f = fdget(fd);
	if (!ruleset_f.file)
		return ERR_PTR(-EBADF);

	/* Checks FD type and access right. */
	err = 0;
	if (ruleset_f.file->f_op != &ruleset_fops)
		err = -EBADFD;
	else if (!(ruleset_f.file->f_mode & mode))
		err = -EPERM;
	if (!err) {
		ruleset = ruleset_f.file->private_data;
		landlock_get_ruleset(ruleset);
	}
	fdput(ruleset_f);
	return err ? ERR_PTR(err) : ruleset;
}

/* Path handling */

/*
 * @path: Must call put_path(@path) after the call if it succeeded.
 */
static int get_path_from_fd(const s32 fd, struct path *const path)
{
	struct fd f;
	int err = 0;

	BUILD_BUG_ON(!__same_type(fd,
		((struct landlock_attr_path_beneath *)NULL)->parent_fd));

	/* Handles O_PATH. */
	f = fdget_raw(fd);
	if (!f.file)
		return -EBADF;
	/*
	 * Only allows O_PATH file descriptor: enables to restrict ambient
	 * filesystem access without requiring to open and risk leaking or
	 * misusing a file descriptor.  Forbid internal filesystems (e.g.
	 * nsfs), including pseudo filesystems that will never be mountable
	 * (e.g. sockfs, pipefs).
	 */
	if (!(f.file->f_mode & FMODE_PATH) ||
			(f.file->f_path.mnt->mnt_flags & MNT_INTERNAL) ||
			(f.file->f_path.dentry->d_sb->s_flags & SB_NOUSER) ||
			d_is_negative(f.file->f_path.dentry) ||
			IS_PRIVATE(d_backing_inode(f.file->f_path.dentry))) {
		err = -EBADFD;
		goto out_fdput;
	}
	path->mnt = f.file->f_path.mnt;
	path->dentry = f.file->f_path.dentry;
	path_get(path);

out_fdput:
	fdput(f);
	return err;
}

/**
 * sys_landlock_add_rule - Add a new rule to a ruleset
 *
 * @ruleset_fd: File descriptor tied to the ruleset which should be extended
 *		with the new rule.
 * @rule_type: Identify the structure type pointed to by @rule_ptr.
 * @rule_ptr: Pointer to a rule (the currently only supported rule is &struct
 *	      landlock_attr_path_beneath).
 * @rule_size: Size of the struct pointed to by @rule_ptr.
 * @options: Must be 0.
 *
 * This system call enables to define a new rule and add it to an existing
 * ruleset.
 *
 * Possible returned errors are:
 *
 * - EOPNOTSUPP: Landlock is supported by the kernel but disabled at boot time;
 * - EINVAL: @options is not 0, or inconsistent access in the rule (i.e.
 *   &landlock_attr_path_beneath.allowed_access is not a subset of the rule's
 *   accesses), or too small @rule_size (according to the underlying rule
 *   type);
 * - EBADF: @ruleset_fd is not a file descriptor for the current thread;
 * - EBADFD: @ruleset_fd is not a ruleset file descriptor;
 * - EPERM: @ruleset_fd has no write access to the underlying ruleset;
 * - ENODATA, E2BIG or EFAULT: @rule_ptr or @rule_size inconsistencies;
 */
SYSCALL_DEFINE5(landlock_add_rule,
		const int, ruleset_fd, const enum landlock_rule_type, rule_type,
		const void __user *const, rule_ptr, const size_t, rule_size,
		const __u32, options)
{
	struct landlock_attr_path_beneath attr_path_beneath;
	struct path path;
	struct landlock_ruleset *ruleset;
	int err;

	if (!landlock_initialized)
		return -EOPNOTSUPP;

	/* No option for now. */
	if (options)
		return -EINVAL;

	if (rule_type != LANDLOCK_RULE_PATH_BENEATH)
		return -EINVAL;

	/* Copies raw user space buffer. */
	err = copy_struct_if_any_from_user(&attr_path_beneath,
			sizeof(attr_path_beneath),
			offsetofend(typeof(attr_path_beneath), allowed_access),
			rule_ptr, rule_size);
	if (err)
		return err;

	/* Gets and checks the ruleset. */
	ruleset = get_ruleset_from_fd(ruleset_fd, FMODE_CAN_WRITE);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	/*
	 * Checks that allowed_access matches the @ruleset constraints
	 * (ruleset->fs_access_mask is automatically upgraded to 64-bits).
	 * Allows empty allowed_access i.e., deny @ruleset->fs_access_mask .
	 */
	if ((attr_path_beneath.allowed_access | ruleset->fs_access_mask) !=
			ruleset->fs_access_mask) {
		err = -EINVAL;
		goto out_put_ruleset;
	}

	/* Gets and checks the new rule. */
	err = get_path_from_fd(attr_path_beneath.parent_fd, &path);
	if (err)
		goto out_put_ruleset;

	/* Imports the new rule. */
	err = landlock_append_fs_rule(ruleset, &path,
			attr_path_beneath.allowed_access);
	path_put(&path);

out_put_ruleset:
	landlock_put_ruleset(ruleset);
	return err;
}

/* Enforcement */

/**
 * sys_landlock_enforce_ruleset - Enforce a ruleset
 *
 * @ruleset_fd: File descriptor tied to the ruleset to merge with the target.
 * @target_type: Identify which type of target to enforce the ruleset on,
 *		 currently only the current thread is supported (i.e.
 *		 seccomp-like).
 * @target_fd: Must be -1.
 * @options: Must be 0.
 *
 * This system call enables to enforce a Landlock ruleset on the current
 * thread.  Enforcing a ruleset requires that the task has CAP_SYS_ADMIN in its
 * namespace or be running with no_new_privs.  This avoids scenarios where
 * unprivileged tasks can affect the behavior of privileged children.
 *
 * Possible returned errors are:
 *
 * - EOPNOTSUPP: Landlock is supported by the kernel but disabled at boot time;
 * - EINVAL: @options is not 0, or @target_type is not
 *   %LANDLOCK_TARGET_CURRENT_THREAD, or @target_fd is not -1;
 * - EBADF: @ruleset_fd is not a file descriptor for the current thread;
 * - EBADFD: @ruleset_fd is not a ruleset file descriptor;
 * - EPERM: @ruleset_fd has no read access to the underlying ruleset, or the
 *   current thread is not running with no_new_privs (or doesn't have
 *   CAP_SYS_ADMIN in its namespace).
 */
SYSCALL_DEFINE4(landlock_enforce_ruleset,
		const int, ruleset_fd, const enum landlock_target_type, target_type,
		const int, target_fd, const __u32, options)
{
	struct landlock_ruleset *new_dom, *ruleset;
	struct cred *new_cred;
	struct landlock_cred_security *new_llcred;
	int err;

	if (!landlock_initialized)
		return -EOPNOTSUPP;

	/* No option for now. */
	if (options)
		return -EINVAL;

	/* Only target the current thread for now. */
	if (target_type != LANDLOCK_TARGET_CURRENT_THREAD)
		return -EINVAL;
	if (target_fd != -1)
		return -EINVAL;

	/*
	 * Similar checks as for seccomp(2), except that an -EPERM may be
	 * returned.
	 */
	if (!task_no_new_privs(current)) {
		err = security_capable(current_cred(), current_user_ns(),
				CAP_SYS_ADMIN, CAP_OPT_NOAUDIT);
		if (err)
			return err;
	}

	/* Gets and checks the ruleset. */
	ruleset = get_ruleset_from_fd(ruleset_fd, FMODE_CAN_READ);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	/* Prepares new credentials. */
	new_cred = prepare_creds();
	if (!new_cred) {
		err = -ENOMEM;
		goto out_put_ruleset;
	}
	new_llcred = landlock_cred(new_cred);

	/*
	 * There is no possible race condition while copying and manipulating
	 * the current credentials because they are dedicated per thread.
	 */
	new_dom = landlock_merge_ruleset(new_llcred->domain, ruleset);
	if (IS_ERR(new_dom)) {
		err = PTR_ERR(new_dom);
		goto out_put_creds;
	}

	/* Replaces the old (prepared) domain. */
	landlock_put_ruleset(new_llcred->domain);
	new_llcred->domain = new_dom;

	landlock_put_ruleset(ruleset);
	return commit_creds(new_cred);

out_put_creds:
	abort_creds(new_cred);
	return err;

out_put_ruleset:
	landlock_put_ruleset(ruleset);
	return err;
}
