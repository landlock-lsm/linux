/*
 * Landlock - UAPI headers
 *
 * Copyright © 2017-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _UAPI__LINUX_LANDLOCK_H__
#define _UAPI__LINUX_LANDLOCK_H__

#include <linux/types.h>

#define LANDLOCK_RET_ALLOW	0
#define LANDLOCK_RET_DENY	1

/**
 * enum landlock_hook_type - hook type for which a Landlock program is called
 *
 * A hook is a policy decision point which exposes the same context type for
 * each program evaluation.
 *
 * @LANDLOCK_HOOK_FS_PICK: called for the last element of a file path
 * @LANDLOCK_HOOK_FS_WALK: called for each directory of a file path (excluding
 *			   the directory passed to fs_pick, if any)
 * @LANDLOCK_HOOK_FS_GET: called for file opening or receiveing or when
 *			  changing directory or root
 */
enum landlock_hook_type {
	LANDLOCK_HOOK_FS_PICK = 1,
	LANDLOCK_HOOK_FS_WALK,
	LANDLOCK_HOOK_FS_GET,
};

/**
 * DOC: landlock_subtype_options
 *
 * - %LANDLOCK_OPTION_PREVIOUS: specify a previous file descriptor in the
 *			        dedicated field
 */
#define LANDLOCK_OPTION_PREVIOUS			(1ULL << 0)

/**
 * DOC: landlock_triggers
 *
 * A landlock trigger is used as a bitmask in subtype.landlock_hook.triggers
 * for a fs_pick program.  It defines a set of actions for which the program
 * should verify an access request.
 *
 * - %LANDLOCK_TRIGGER_FS_PICK_APPEND
 * - %LANDLOCK_TRIGGER_FS_PICK_CHDIR
 * - %LANDLOCK_TRIGGER_FS_PICK_CHROOT
 * - %LANDLOCK_TRIGGER_FS_PICK_CREATE
 * - %LANDLOCK_TRIGGER_FS_PICK_EXECUTE
 * - %LANDLOCK_TRIGGER_FS_PICK_FCNTL
 * - %LANDLOCK_TRIGGER_FS_PICK_GETATTR
 * - %LANDLOCK_TRIGGER_FS_PICK_IOCTL
 * - %LANDLOCK_TRIGGER_FS_PICK_LINK
 * - %LANDLOCK_TRIGGER_FS_PICK_LINKTO
 * - %LANDLOCK_TRIGGER_FS_PICK_LOCK
 * - %LANDLOCK_TRIGGER_FS_PICK_MAP
 * - %LANDLOCK_TRIGGER_FS_PICK_MOUNTON
 * - %LANDLOCK_TRIGGER_FS_PICK_OPEN
 * - %LANDLOCK_TRIGGER_FS_PICK_READ
 * - %LANDLOCK_TRIGGER_FS_PICK_READDIR
 * - %LANDLOCK_TRIGGER_FS_PICK_RECEIVE
 * - %LANDLOCK_TRIGGER_FS_PICK_RENAME
 * - %LANDLOCK_TRIGGER_FS_PICK_RENAMETO
 * - %LANDLOCK_TRIGGER_FS_PICK_RMDIR
 * - %LANDLOCK_TRIGGER_FS_PICK_SETATTR
 * - %LANDLOCK_TRIGGER_FS_PICK_TRANSFER
 * - %LANDLOCK_TRIGGER_FS_PICK_UNLINK
 * - %LANDLOCK_TRIGGER_FS_PICK_WRITE
 */
#define LANDLOCK_TRIGGER_FS_PICK_APPEND			(1ULL << 0)
#define LANDLOCK_TRIGGER_FS_PICK_CHDIR			(1ULL << 1)
#define LANDLOCK_TRIGGER_FS_PICK_CHROOT			(1ULL << 2)
#define LANDLOCK_TRIGGER_FS_PICK_CREATE			(1ULL << 3)
#define LANDLOCK_TRIGGER_FS_PICK_EXECUTE		(1ULL << 4)
#define LANDLOCK_TRIGGER_FS_PICK_FCNTL			(1ULL << 5)
#define LANDLOCK_TRIGGER_FS_PICK_GETATTR		(1ULL << 6)
#define LANDLOCK_TRIGGER_FS_PICK_IOCTL			(1ULL << 7)
#define LANDLOCK_TRIGGER_FS_PICK_LINK			(1ULL << 8)
#define LANDLOCK_TRIGGER_FS_PICK_LINKTO			(1ULL << 9)
#define LANDLOCK_TRIGGER_FS_PICK_LOCK			(1ULL << 10)
#define LANDLOCK_TRIGGER_FS_PICK_MAP			(1ULL << 11)
#define LANDLOCK_TRIGGER_FS_PICK_MOUNTON		(1ULL << 12)
#define LANDLOCK_TRIGGER_FS_PICK_OPEN			(1ULL << 13)
#define LANDLOCK_TRIGGER_FS_PICK_READ			(1ULL << 14)
#define LANDLOCK_TRIGGER_FS_PICK_READDIR		(1ULL << 15)
#define LANDLOCK_TRIGGER_FS_PICK_RECEIVE		(1ULL << 16)
#define LANDLOCK_TRIGGER_FS_PICK_RENAME			(1ULL << 17)
#define LANDLOCK_TRIGGER_FS_PICK_RENAMETO		(1ULL << 18)
#define LANDLOCK_TRIGGER_FS_PICK_RMDIR			(1ULL << 19)
#define LANDLOCK_TRIGGER_FS_PICK_SETATTR		(1ULL << 20)
#define LANDLOCK_TRIGGER_FS_PICK_TRANSFER		(1ULL << 21)
#define LANDLOCK_TRIGGER_FS_PICK_UNLINK			(1ULL << 22)
#define LANDLOCK_TRIGGER_FS_PICK_WRITE			(1ULL << 23)

/* inode_lookup */
/* LOOKUP_ROOT can only be seen for the first fs_walk call */
#define LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_ROOT		1
#define LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOT		2
#define LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOTDOT	3

/**
 * struct landlock_ctx_fs_pick - context accessible to a fs_pick program
 *
 * @cookie: value saved and restored between calls to chained programs
 * @chain: chain pointer to identify the current chain
 * @inode: pointer to the current kernel object that can be used with
 *	   bpf_inode_get_tag()
 * @inode_lookup: bitflags to identify how we got there
 */
struct landlock_ctx_fs_pick {
	__u64 cookie;
	__u64 chain;
	__u64 inode;
	__u8 inode_lookup;
};

/**
 * struct landlock_ctx_fs_walk - context accessible to a fs_walk program
 *
 * @cookie: value saved and restored between calls to chained programs
 * @chain: chain pointer to identify the current chain
 * @inode: pointer to the current kernel object that can be used with
 *	   bpf_inode_get_tag()
 * @inode_lookup: bitflags to identify how we got there
 */
struct landlock_ctx_fs_walk {
	__u64 cookie;
	__u64 chain;
	__u64 inode;
	__u8 inode_lookup;
};

/**
 * struct landlock_ctx_fs_get - context accessible to a fs_get program
 *
 * @cookie: value saved and restored between calls to chained programs
 * @chain: chain pointer to identify the current chain
 * @tag_object: pointer that can be used to tag a file/inode with
 *		bpf_landlock_set_tag()
 */
struct landlock_ctx_fs_get {
	__u64 cookie;
	__u64 chain;
	__u64 tag_object;
};

#endif /* _UAPI__LINUX_LANDLOCK_H__ */
