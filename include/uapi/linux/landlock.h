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
 * enum landlock_cmd - Landlock commands
 *
 * First argument of sys_landlock().
 */
enum landlock_cmd {
	/**
	 * @LANDLOCK_CMD_GET_FEATURES: Asks the kernel for supported Landlock
	 * features.  The option argument must contains
	 * %LANDLOCK_OPT_GET_FEATURES.  This commands fills the &struct
	 * landlock_attr_features provided as first attribute.
	 */
	LANDLOCK_CMD_GET_FEATURES = 1,
	/**
	 * @LANDLOCK_CMD_CREATE_RULESET: Creates a new ruleset and return its
	 * file descriptor on success.  The option argument must contains
	 * %LANDLOCK_OPT_CREATE_RULESET.  The ruleset is defined by the &struct
	 * landlock_attr_ruleset provided as first attribute.
	 */
	LANDLOCK_CMD_CREATE_RULESET,
	/**
	 * @LANDLOCK_CMD_ADD_RULE: Adds a rule to a ruleset.  The option
	 * argument must contains %LANDLOCK_OPT_ADD_RULE_PATH_BENEATH.  The
	 * ruleset and the rule are both defined by the &struct
	 * landlock_attr_path_beneath provided as first attribute.
	 */
	LANDLOCK_CMD_ADD_RULE,
	/**
	 * @LANDLOCK_CMD_ENFORCE_RULESET: Enforces a ruleset on the current
	 * process.  The option argument must contains
	 * %LANDLOCK_OPT_ENFORCE_RULESET.  The ruleset is defined by the
	 * &struct landlock_attr_enforce provided as first attribute.
	 */
	LANDLOCK_CMD_ENFORCE_RULESET,
};

/**
 * DOC: options_intro
 *
 * These options may be used as second argument of sys_landlock().  Each
 * command have a dedicated set of options, represented as bitmasks.  For two
 * different commands, their options may overlap.  Each command have at least
 * one option defining the used attribute type.  This also enables to always
 * have a usable &struct landlock_attr_features (i.e. filled with bits).
 */

/**
 * DOC: options_get_features
 *
 * Options for ``LANDLOCK_CMD_GET_FEATURES``
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * - %LANDLOCK_OPT_GET_FEATURES: the attr type is `struct
 *   landlock_attr_features`.
 */
#define LANDLOCK_OPT_GET_FEATURES			(1ULL << 0)

/**
 * DOC: options_create_ruleset
 *
 * Options for ``LANDLOCK_CMD_CREATE_RULESET``
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * - %LANDLOCK_OPT_CREATE_RULESET: the attr type is `struct
 *   landlock_attr_ruleset`.
 */
#define LANDLOCK_OPT_CREATE_RULESET			(1ULL << 0)

/**
 * DOC: options_add_rule
 *
 * Options for ``LANDLOCK_CMD_ADD_RULE``
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * - %LANDLOCK_OPT_ADD_RULE_PATH_BENEATH: the attr type is `struct
 *   landlock_attr_path_beneath`.
 */
#define LANDLOCK_OPT_ADD_RULE_PATH_BENEATH		(1ULL << 0)

/**
 * DOC: options_enforce_ruleset
 *
 * Options for ``LANDLOCK_CMD_ENFORCE_RULESET``
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * - %LANDLOCK_OPT_ENFORCE_RULESET: the attr type is `struct
 *   landlock_attr_enforce`.
 */
#define LANDLOCK_OPT_ENFORCE_RULESET			(1ULL << 0)

/**
 * struct landlock_attr_features - Receives the supported features
 *
 * This struct should be allocated by user space but it will be filled by the
 * kernel to indicate the subset of Landlock features effectively handled by
 * the running kernel.  This enables backward compatibility for applications
 * which are developed on a newer kernel than the one running the application.
 * This helps avoid hard errors that may entirely disable the use of Landlock
 * features because some of them may not be supported.  Indeed, because
 * Landlock is a security feature, even if the kernel doesn't support all the
 * requested features, user space applications should still use the subset
 * which is supported by the running kernel.  Indeed, a partial security policy
 * can still improve the security of the application and better protect the
 * user (i.e. best-effort approach).  The %LANDLOCK_CMD_GET_FEATURES command
 * and &struct landlock_attr_features are future-proof because the future
 * unknown fields requested by user space (i.e. a larger &struct
 * landlock_attr_features) can still be filled with zeros.
 *
 * The Landlock commands will fail if an unsupported option or access is
 * requested.  By firstly requesting the supported options and accesses, it is
 * quite easy for the developer to binary AND these returned bitmasks with the
 * used options and accesses from the attribute structs (e.g. &struct
 * landlock_attr_ruleset), and even infer the supported Landlock commands.
 * Indeed, because each command must support at least one option, the options_*
 * fields are always filled if the related commands are supported.  The
 * supported attributes are also discoverable thanks to the size_* fields.  All
 * this data enable to create applications doing their best to sandbox
 * themselves regardless of the running kernel.
 */
struct landlock_attr_features {
	/**
	 * @options_get_features: Options supported by the
	 * %LANDLOCK_CMD_GET_FEATURES command. Cf. `Options`_.
	 */
	__aligned_u64 options_get_features;
	/**
	 * @options_create_ruleset: Options supported by the
	 * %LANDLOCK_CMD_CREATE_RULESET command. Cf. `Options`_.
	 */
	__aligned_u64 options_create_ruleset;
	/**
	 * @options_add_rule: Options supported by the %LANDLOCK_CMD_ADD_RULE
	 * command. Cf. `Options`_.
	 */
	__aligned_u64 options_add_rule;
	/**
	 * @options_enforce_ruleset: Options supported by the
	 * %LANDLOCK_CMD_ENFORCE_RULESET command. Cf. `Options`_.
	 */
	__aligned_u64 options_enforce_ruleset;
	/**
	 * @access_fs: Subset of file system access supported by the running
	 * kernel, used in &struct landlock_attr_ruleset and &struct
	 * landlock_attr_path_beneath.  Cf. `Filesystem flags`_.
	 */
	__aligned_u64 access_fs;
	/**
	 * @size_attr_ruleset: Size of the &struct landlock_attr_ruleset as
	 * known by the kernel (i.e.  ``sizeof(struct
	 * landlock_attr_ruleset)``).
	 */
	__aligned_u64 size_attr_ruleset;
	/**
	 * @size_attr_path_beneath: Size of the &struct
	 * landlock_attr_path_beneath as known by the kernel (i.e.
	 * ``sizeof(struct landlock_path_beneath)``).
	 */
	__aligned_u64 size_attr_path_beneath;
	/**
	 * @size_attr_enforce: Size of the &struct landlock_attr_enforce as
	 * known by the kernel (i.e.  ``sizeof(struct landlock_enforce)``).
	 */
	__aligned_u64 size_attr_enforce;
};

/**
 * struct landlock_attr_ruleset- Defines a new ruleset
 *
 * Used as first attribute for the %LANDLOCK_CMD_CREATE_RULESET command and
 * with the %LANDLOCK_OPT_CREATE_RULESET option.
 */
struct landlock_attr_ruleset {
	/**
	 * @handled_access_fs: Bitmask of actions (cf. `Filesystem flags`_)
	 * that is handled by this ruleset and should then be forbidden if no
	 * rule explicitly allow them.  This is needed for backward
	 * compatibility reasons.  The user space code should check the
	 * effectively supported actions thanks to %LANDLOCK_CMD_GET_SUPPORTED
	 * and &struct landlock_attr_features, and then adjust the arguments of
	 * the next calls to sys_landlock() accordingly.
	 */
	__aligned_u64 handled_access_fs;
};

/**
 * struct landlock_attr_path_beneath - Defines a path hierarchy
 */
struct landlock_attr_path_beneath {
	/**
	 * @ruleset_fd: File descriptor tied to the ruleset which should be
	 * extended with this new access.
	 */
	__aligned_u64 ruleset_fd;
	/**
	 * @parent_fd: File descriptor, open with ``O_PATH``, which identify
	 * the parent directory of a file hierarchy, or just a file.
	 */
	__aligned_u64 parent_fd;
	/**
	 * @allowed_access: Bitmask of allowed actions for this file hierarchy
	 * (cf. `Filesystem flags`_).
	 */
	__aligned_u64 allowed_access;
};

/**
 * struct landlock_attr_enforce - Describes the enforcement
 */
struct landlock_attr_enforce {
	/**
	 * @ruleset_fd: File descriptor tied to the ruleset to merge with the
	 * current domain.
	 */
	__aligned_u64 ruleset_fd;
};

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
 * - %LANDLOCK_ACCESS_FS_WRITE_FILE: Write to a file.
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
 * - %LANDLOCK_ACCESS_FS_MAKE_DIR: Create (or rename or link) a directory.
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
#define LANDLOCK_ACCESS_FS_EXECUTE		(1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE		(1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE		(1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR		(1ULL << 3)
#define LANDLOCK_ACCESS_FS_CHROOT		(1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR		(1ULL << 5)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE		(1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR		(1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_DIR		(1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_REG		(1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK		(1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO		(1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK		(1ULL << 12)
#define LANDLOCK_ACCESS_FS_MAKE_SYM		(1ULL << 13)

#endif /* _UAPI__LINUX_LANDLOCK_H__ */
