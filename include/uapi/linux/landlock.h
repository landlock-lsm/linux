/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Landlock - UAPI headers
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _UAPI__LINUX_LANDLOCK_H__
#define _UAPI__LINUX_LANDLOCK_H__

/**
 * DOC: fs_access
 *
 * A set of actions on kernel objects may be defined by an attribute (e.g.
 * &struct landlock_attr_path_beneath) and a bitmask of access.
 *
 * Filesystem flags
 * ~~~~~~~~~~~~~~~~
 *
 * These flags enable to restrict a sandbox process to a set of of actions on
 * files and directories.  Files or directories opened before the sandboxing
 * are not subject to these restrictions.
 *
 * - %LANDLOCK_ACCESS_FS_EXECUTE: Execute a file.
 * - %LANDLOCK_ACCESS_FS_WRITE_FILE: Write to a file.
 * - %LANDLOCK_ACCESS_FS_READ_FILE: Open a file with read access.
 * - %LANDLOCK_ACCESS_FS_READ_DIR: Open a directory or list its content.
 * - %LANDLOCK_ACCESS_FS_LINK_TO: Link a file into a directory.
 * - %LANDLOCK_ACCESS_FS_RENAME_FROM: Rename a file or a directory.
 * - %LANDLOCK_ACCESS_FS_RENAME_TO: Rename a file or a directory.
 * - %LANDLOCK_ACCESS_FS_RMDIR: Remove an empty directory.
 * - %LANDLOCK_ACCESS_FS_UNLINK: Remove a file.
 * - %LANDLOCK_ACCESS_FS_MAKE_CHAR: Create a character device.
 * - %LANDLOCK_ACCESS_FS_MAKE_DIR: Create a directory.
 * - %LANDLOCK_ACCESS_FS_MAKE_REG: Create a regular file.
 * - %LANDLOCK_ACCESS_FS_MAKE_SOCK: Create a UNIX domain socket.
 * - %LANDLOCK_ACCESS_FS_MAKE_FIFO: Create a named pipe.
 * - %LANDLOCK_ACCESS_FS_MAKE_BLOCK: Create a block device.
 * - %LANDLOCK_ACCESS_FS_MAKE_SYM: Create a symbolic link.
 * - %LANDLOCK_ACCESS_FS_CHROOT: Change the root directory of the current
 *   process.
 *
 * .. warning::
 *
 *   It is currently not possible to restrict some file-related actions
 *   accessible through these syscall families: :manpage:`chdir(2)`,
 *   :manpage:`truncate(2)`, :manpage:`stat(2)`, :manpage:`flock(2)`,
 *   :manpage:`chmod(2)`, :manpage:`chown(2)`, :manpage:`setxattr(2)`,
 *   :manpage:`ioctl(2)`, :manpage:`fcntl(2)`.
 *   Future evolutions of Landlock will make possible to restrict them.
 */
#define LANDLOCK_ACCESS_FS_EXECUTE		(1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE		(1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE		(1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR		(1ULL << 3)
#define LANDLOCK_ACCESS_FS_LINK_TO		(1ULL << 4)
#define LANDLOCK_ACCESS_FS_RENAME_FROM		(1ULL << 5)
#define LANDLOCK_ACCESS_FS_RENAME_TO		(1ULL << 6)
#define LANDLOCK_ACCESS_FS_RMDIR		(1ULL << 7)
#define LANDLOCK_ACCESS_FS_UNLINK		(1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR		(1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_DIR		(1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_REG		(1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK		(1ULL << 12)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO		(1ULL << 13)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK		(1ULL << 14)
#define LANDLOCK_ACCESS_FS_MAKE_SYM		(1ULL << 15)
#define LANDLOCK_ACCESS_FS_CHROOT		(1ULL << 16)

/*
 * Potential future access:
 * - %LANDLOCK_ACCESS_FS_OPEN (for O_PATH)
 * - %LANDLOCK_ACCESS_FS_GETATTR
 * - %LANDLOCK_ACCESS_FS_SETATTR
 * - %LANDLOCK_ACCESS_FS_LOCK
 * - %LANDLOCK_ACCESS_FS_CHMOD
 * - %LANDLOCK_ACCESS_FS_CHOWN
 * - %LANDLOCK_ACCESS_FS_CHGRP
 * - %LANDLOCK_ACCESS_FS_APPEND
 * - %LANDLOCK_ACCESS_FS_TRUNCATE
 * - %LANDLOCK_ACCESS_FS_LINK_FROM
 * - %LANDLOCK_ACCESS_FS_MOUNT_FROM
 * - %LANDLOCK_ACCESS_FS_MOUNT_TO
 * - %LANDLOCK_ACCESS_FS_UNMOUNT
 * - %LANDLOCK_ACCESS_FS_TRANSFER
 * - %LANDLOCK_ACCESS_FS_RECEIVE
 * - %LANDLOCK_ACCESS_FS_CHDIR
 * - %LANDLOCK_ACCESS_FS_FCNTL
 * - %LANDLOCK_ACCESS_FS_IOCTL
 */

#endif /* _UAPI__LINUX_LANDLOCK_H__ */
