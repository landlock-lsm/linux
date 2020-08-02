/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Landlock - UAPI headers
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _UAPI__LINUX_LANDLOCK_H__
#define _UAPI__LINUX_LANDLOCK_H__

#include <linux/types.h>

/**
 * enum landlock_rule_type - Landlock rule type
 *
 * Argument of sys_landlock_add_rule().
 */
enum landlock_rule_type {
	/**
	 * @LANDLOCK_RULE_PATH_BENEATH: Type of a &struct
	 * landlock_attr_path_beneath .
	 */
	LANDLOCK_RULE_PATH_BENEATH = 1,
};

/**
 * enum landlock_target_type - Landlock target type
 *
 * Argument of sys_landlock_enforce_ruleset().
 */
enum landlock_target_type {
	/**
	 * @LANDLOCK_TARGET_CURRENT_THREAD: Enforce a ruleset on the thread
	 * asking for (i.e. seccomp-like).
	 */
	LANDLOCK_TARGET_CURRENT_THREAD = 1,
};

/**
 * struct landlock_attr_features - Receives the supported features
 *
 * Argument of sys_landlock_get_features().
 */
struct landlock_attr_features {
	/**
	 * @options_get_features: Options supported by
	 * sys_landlock_get_features().
	 */
	__u32 options_get_features;
	/**
	 * @options_create_ruleset: Options supported by
	 * sys_landlock_create_ruleset().
	 */
	__u32 options_create_ruleset;
	/**
	 * @options_add_rule: Options supported by sys_landlock_add_rule().
	 */
	__u32 options_add_rule;
	/**
	 * @options_enforce_ruleset: Options supported by
	 * sys_landlock_enforce_ruleset().
	 */
	__u32 options_enforce_ruleset;
	/**
	 * @access_fs: Subset of file system access supported by the running
	 * kernel, used in &landlock_attr_ruleset.handled_access_fs and
	 * &landlock_attr_path_beneath.allowed_access .  Cf. `Filesystem
	 * flags`_.
	 */
	__u64 access_fs;
	/**
	 * @size_attr_features: Size of the &struct landlock_attr_features
	 * (current struct) as known by the kernel (i.e. ``sizeof(struct
	 * landlock_attr_features)``).
	 */
	__u16 size_attr_features;
	/**
	 * @size_attr_ruleset: Size of the &struct landlock_attr_ruleset as
	 * known by the kernel (i.e. ``sizeof(struct
	 * landlock_attr_ruleset)``).
	 */
	__u16 size_attr_ruleset;
	/**
	 * @size_attr_path_beneath: Size of the &struct
	 * landlock_attr_path_beneath as known by the kernel (i.e.
	 * ``sizeof(struct landlock_attr_path_beneath)``).
	 */
	__u16 size_attr_path_beneath;
	/**
	 * @last_rule_type: Indicate the last entry of &enum
	 * landlock_rule_type.
	 */
	__u8 last_rule_type;
	/**
	 * @last_target_type: Indicate the last entry of &enum
	 * landlock_target_type.
	 */
	__u8 last_target_type;
};

/**
 * struct landlock_attr_ruleset- Defines a new ruleset
 *
 * Argument of sys_landlock_create_ruleset().
 */
struct landlock_attr_ruleset {
	/**
	 * @handled_access_fs: Bitmask of actions (cf. `Filesystem flags`_)
	 * that is handled by this ruleset and should then be forbidden if no
	 * rule explicitly allow them.  This is needed for backward
	 * compatibility reasons.  The user space code should check the
	 * effectively supported actions thanks to sys_landlock_get_features()
	 * and then adjust the arguments of the next calls to
	 * sys_landlock_create_ruleset() accordingly.
	 */
	__u64 handled_access_fs;
};

/**
 * struct landlock_attr_path_beneath - Defines a path hierarchy
 *
 * Argument of sys_landlock_add_rule().
 */
struct landlock_attr_path_beneath {
	/**
	 * @allowed_access: Bitmask of allowed actions for this file hierarchy
	 * (cf. `Filesystem flags`_).
	 */
	__u64 allowed_access;
	/**
	 * @parent_fd: File descriptor, open with ``O_PATH``, which identify
	 * the parent directory of a file hierarchy, or just a file.
	 */
	__s32 parent_fd;
	/*
	 * This struct is packed to enable to append future members without
	 * requiring to have dummy reserved members.
	 * Cf. security/landlock/syscall.c:build_check_abi()
	 */
} __attribute__((packed));

/**
 * DOC: fs_access
 *
 * A set of actions on kernel objects may be defined by an attribute (e.g.
 * &struct landlock_attr_path_beneath) and a bitmask of access.
 *
 * Filesystem flags
 * ~~~~~~~~~~~~~~~~
 *
 * These flags enable to restrict a sandbox process to a set of actions on
 * files and directories.  Files or directories opened before the sandboxing
 * are not subject to these restrictions.
 *
 * A file can only receive these access rights:
 *
 * - %LANDLOCK_ACCESS_FS_EXECUTE: Execute a file.
 * - %LANDLOCK_ACCESS_FS_WRITE_FILE: Open a file with write access.
 * - %LANDLOCK_ACCESS_FS_READ_FILE: Open a file with read access.
 *
 * A directory can receive access rights related to files or directories.  This
 * set of access rights is applied to the directory itself, and the directories
 * beneath it:
 *
 * - %LANDLOCK_ACCESS_FS_READ_DIR: Open a directory or list its content.
 * - %LANDLOCK_ACCESS_FS_CHROOT: Change the root directory of the current
 *   process.
 *
 * However, the following access rights only apply to the content of a
 * directory, not the directory itself:
 *
 * - %LANDLOCK_ACCESS_FS_REMOVE_DIR: Remove an empty directory or rename one.
 * - %LANDLOCK_ACCESS_FS_REMOVE_FILE: Unlink (or rename) a file.
 * - %LANDLOCK_ACCESS_FS_MAKE_CHAR: Create (or rename or link) a character
 *   device.
 * - %LANDLOCK_ACCESS_FS_MAKE_DIR: Create (or rename) a directory.
 * - %LANDLOCK_ACCESS_FS_MAKE_REG: Create (or rename or link) a regular file.
 * - %LANDLOCK_ACCESS_FS_MAKE_SOCK: Create (or rename or link) a UNIX domain
 *   socket.
 * - %LANDLOCK_ACCESS_FS_MAKE_FIFO: Create (or rename or link) a named pipe.
 * - %LANDLOCK_ACCESS_FS_MAKE_BLOCK: Create (or rename or link) a block device.
 * - %LANDLOCK_ACCESS_FS_MAKE_SYM: Create (or rename or link) a symbolic link.
 *
 * .. warning::
 *
 *   It is currently not possible to restrict some file-related actions
 *   accessible through these syscall families: :manpage:`chdir(2)`,
 *   :manpage:`truncate(2)`, :manpage:`stat(2)`, :manpage:`flock(2)`,
 *   :manpage:`chmod(2)`, :manpage:`chown(2)`, :manpage:`setxattr(2)`,
 *   :manpage:`ioctl(2)`, :manpage:`fcntl(2)`.
 *   Future Landlock evolutions will enable to restrict them.
 */
#define LANDLOCK_ACCESS_FS_EXECUTE			(1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE			(1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE			(1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR			(1ULL << 3)
#define LANDLOCK_ACCESS_FS_CHROOT			(1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR			(1ULL << 5)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE			(1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR			(1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_DIR			(1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_REG			(1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK			(1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO			(1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK			(1ULL << 12)
#define LANDLOCK_ACCESS_FS_MAKE_SYM			(1ULL << 13)

#endif /* _UAPI__LINUX_LANDLOCK_H__ */
