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
#include <linux/landlock.h>
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

#define _LANDLOCK_OPT_GET_FEATURES_LAST		LANDLOCK_OPT_GET_FEATURES
#define _LANDLOCK_OPT_GET_FEATURES_MASK		((_LANDLOCK_OPT_GET_FEATURES_LAST << 1) - 1)

#define _LANDLOCK_OPT_CREATE_RULESET_LAST	LANDLOCK_OPT_CREATE_RULESET
#define _LANDLOCK_OPT_CREATE_RULESET_MASK	((_LANDLOCK_OPT_CREATE_RULESET_LAST << 1) - 1)

#define _LANDLOCK_OPT_ADD_RULE_LAST		LANDLOCK_OPT_ADD_RULE_PATH_BENEATH
#define _LANDLOCK_OPT_ADD_RULE_MASK		((_LANDLOCK_OPT_ADD_RULE_LAST << 1) - 1)

#define _LANDLOCK_OPT_ENFORCE_RULESET_LAST	LANDLOCK_OPT_ENFORCE_RULESET
#define _LANDLOCK_OPT_ENFORCE_RULESET_MASK	((_LANDLOCK_OPT_ENFORCE_RULESET_LAST << 1) - 1)

static int syscall_get_features(const size_t attr_size,
		void __user *const attr_ptr)
{
	size_t data_size, fill_size;
	const struct landlock_attr_features supported = {
		.options_get_features = _LANDLOCK_OPT_GET_FEATURES_MASK,
		.options_create_ruleset = _LANDLOCK_OPT_CREATE_RULESET_MASK,
		.options_add_rule = _LANDLOCK_OPT_ADD_RULE_MASK,
		.options_enforce_ruleset = _LANDLOCK_OPT_ENFORCE_RULESET_MASK,
		.access_fs = _LANDLOCK_ACCESS_FS_MASK,
		.size_attr_ruleset = sizeof(struct landlock_attr_ruleset),
		.size_attr_path_beneath = sizeof(struct
				landlock_attr_path_beneath),
		.size_attr_enforce = sizeof(struct landlock_attr_enforce),
	};

	BUILD_BUG_ON(!__same_type(supported.access_fs,
		((struct landlock_attr_ruleset *)NULL)->handled_access_fs));
	BUILD_BUG_ON(!__same_type(supported.access_fs,
		((struct landlock_attr_path_beneath *)NULL)->allowed_access));

	/* Checks attribute consistency. */
	if (attr_size == 0)
		/* Allows to get a subset of struct landlock_attr_features. */
		return -ENODATA;
	if (attr_size > PAGE_SIZE)
		return -E2BIG;

	/* Copy features to user space. */
	data_size = min(sizeof(supported), attr_size);
	if (copy_to_user(attr_ptr, &supported, data_size))
		return -EFAULT;

	/* Fills with zeros. */
	fill_size = attr_size - data_size;
	if (fill_size > 0 && clear_user(attr_ptr + data_size, fill_size))
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

static int syscall_create_ruleset(const size_t attr_size,
		const void __user *const attr_ptr)
{
	struct landlock_attr_ruleset attr_ruleset;
	struct landlock_ruleset *ruleset;
	int err, ruleset_fd;

	/* Copies raw user space buffer. */
	err = copy_struct_if_any_from_user(&attr_ruleset, sizeof(attr_ruleset),
			offsetofend(typeof(attr_ruleset), handled_access_fs),
			attr_ptr, attr_size);
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
static struct landlock_ruleset *get_ruleset_from_fd(const u64 fd,
		const fmode_t mode)
{
	struct fd ruleset_f;
	struct landlock_ruleset *ruleset;
	int err;

	BUILD_BUG_ON(!__same_type(fd,
		((struct landlock_attr_path_beneath *)NULL)->ruleset_fd));
	BUILD_BUG_ON(!__same_type(fd,
		((struct landlock_attr_enforce *)NULL)->ruleset_fd));

	/* Checks 32-bits overflow. fdget() checks for INT_MAX/FD. */
	if (fd > U32_MAX)
		return ERR_PTR(-EINVAL);
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
static int get_path_from_fd(const u64 fd, struct path *const path)
{
	struct fd f;
	int err = 0;

	BUILD_BUG_ON(!__same_type(fd,
		((struct landlock_attr_path_beneath *)NULL)->parent_fd));

	/* Checks 32-bits overflow.  fdget_raw() checks for INT_MAX/FD. */
	if (fd > U32_MAX)
		return -EINVAL;
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

static int syscall_add_rule_path_beneath(const size_t attr_size,
		const void __user *const attr_ptr)
{
	struct landlock_attr_path_beneath attr_path_beneath;
	struct path path;
	struct landlock_ruleset *ruleset;
	int err;

	/* Copies raw user space buffer. */
	err = copy_struct_if_any_from_user(&attr_path_beneath,
			sizeof(attr_path_beneath),
			offsetofend(typeof(attr_path_beneath), allowed_access),
			attr_ptr, attr_size);
	if (err)
		return err;

	/* Gets and checks the ruleset. */
	ruleset = get_ruleset_from_fd(attr_path_beneath.ruleset_fd,
			FMODE_CAN_WRITE);
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

static int syscall_enforce_ruleset(const size_t attr_size,
		const void __user *const attr_ptr)
{
	struct landlock_ruleset *new_dom, *ruleset;
	struct cred *new_cred;
	struct landlock_cred_security *new_llcred;
	struct landlock_attr_enforce attr_enforce;
	int err;

	/*
	 * Enforcing a Landlock ruleset requires that the task has
	 * CAP_SYS_ADMIN in its namespace or be running with no_new_privs.
	 * This avoids scenarios where unprivileged tasks can affect the
	 * behavior of privileged children.  These are similar checks as for
	 * seccomp(2), except that an -EPERM may be returned.
	 */
	if (!task_no_new_privs(current)) {
		err = security_capable(current_cred(), current_user_ns(),
				CAP_SYS_ADMIN, CAP_OPT_NOAUDIT);
		if (err)
			return err;
	}

	/* Copies raw user space buffer. */
	err = copy_struct_if_any_from_user(&attr_enforce, sizeof(attr_enforce),
			offsetofend(typeof(attr_enforce), ruleset_fd),
			attr_ptr, attr_size);
	if (err)
		return err;

	/* Gets and checks the ruleset. */
	ruleset = get_ruleset_from_fd(attr_enforce.ruleset_fd, FMODE_CAN_READ);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	/* Informs about useless ruleset. */
	if (ruleset->nb_rules == 0) {
		err = -ENOMSG;
		goto out_put_ruleset;
	}

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

/**
 * landlock - System call to enable a process to safely sandbox itself
 *
 * @command: Landlock command to perform miscellaneous, but safe, actions. Cf.
 *           `Commands`_.
 * @options: Bitmask of options dedicated to one command. Cf. `Options`_.
 * @attr1_size: First attribute size (i.e. size of the struct).
 * @attr1_ptr: Pointer to the first attribute. Cf. `Attributes`_.
 * @attr2_size: Unused for now.
 * @attr2_ptr: Unused for now.
 *
 * The @command and @options arguments enable a seccomp-bpf policy to control
 * the requested actions.  However, it should be noted that Landlock is
 * designed from the ground to enable unprivileged process to drop privileges
 * and accesses in a way that can not harm other processes.  This syscall and
 * all its arguments should then be allowed for any process, which will then
 * enable applications to strengthen the security of the whole system.
 *
 * @attr2_size and @attr2_ptr describe a second attribute which could be used
 * in the future to compose with the first attribute (e.g. a
 * landlock_attr_path_beneath with a landlock_attr_ioctl).
 *
 * The order of return errors begins with ENOPKG (disabled Landlock),
 * EOPNOTSUPP (unknown command or option) and then EINVAL (invalid attribute).
 * The other error codes may be specific to each command.
 */
SYSCALL_DEFINE6(landlock, const unsigned int, command,
		const unsigned int, options,
		const size_t, attr1_size, void __user *const, attr1_ptr,
		const size_t, attr2_size, void __user *const, attr2_ptr)
{
	/*
	 * Enables user space to identify if Landlock is disabled, thanks to a
	 * specific error code.
	 */
	if (!landlock_initialized)
		return -ENOPKG;

	switch ((enum landlock_cmd)command) {
	case LANDLOCK_CMD_GET_FEATURES:
		if (options == LANDLOCK_OPT_GET_FEATURES) {
			if (attr2_size || attr2_ptr)
				return -EINVAL;
			return syscall_get_features(attr1_size, attr1_ptr);
		}
		return -EOPNOTSUPP;

	case LANDLOCK_CMD_CREATE_RULESET:
		if (options == LANDLOCK_OPT_CREATE_RULESET) {
			if (attr2_size || attr2_ptr)
				return -EINVAL;
			return syscall_create_ruleset(attr1_size, attr1_ptr);
		}
		return -EOPNOTSUPP;

	case LANDLOCK_CMD_ADD_RULE:
		/*
		 * A future extension could add a
		 * LANDLOCK_OPT_ADD_RULE_PATH_RANGE.
		 */
		if (options == LANDLOCK_OPT_ADD_RULE_PATH_BENEATH) {
			if (attr2_size || attr2_ptr)
				return -EINVAL;
			return syscall_add_rule_path_beneath(attr1_size,
					attr1_ptr);
		}
		return -EOPNOTSUPP;

	case LANDLOCK_CMD_ENFORCE_RULESET:
		if (options == LANDLOCK_OPT_ENFORCE_RULESET) {
			if (attr2_size || attr2_ptr)
				return -EINVAL;
			return syscall_enforce_ruleset(attr1_size, attr1_ptr);
		}
		return -EOPNOTSUPP;
	}
	return -EOPNOTSUPP;
}
