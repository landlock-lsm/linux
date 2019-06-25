// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock sample 1 - whitelist of read only or read-write file hierarchy
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 */

/*
 * This file contains a function that will be compiled to eBPF bytecode thanks
 * to LLVM/Clang.
 *
 * Each SEC() means that the following function or variable will be part of a
 * custom ELF section. This sections are then processed by the userspace part
 * (see landlock1_user.c) to extract eBPF bytecode and take into account
 * variables describing the eBPF program subtype or its license.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/landlock.h>

#include "bpf_helpers.h"
#include "landlock1.h" /* MAP_FLAG_DENY */

#define MAP_MAX_ENTRIES		20

SEC("maps")
struct bpf_map_def inode_map = {
	.type = BPF_MAP_TYPE_INODE,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = MAP_MAX_ENTRIES,
};

static __always_inline __u64 get_access(void *inode)
{
	if (bpf_inode_map_lookup(&inode_map, inode) & MAP_FLAG_DENY)
		return LANDLOCK_RET_DENY;
	return LANDLOCK_RET_ALLOW;
}

SEC("subtype/landlock1")
static union bpf_prog_subtype _subtype1 = {
	.landlock_hook = {
		.type = LANDLOCK_HOOK_FS_WALK,
	}
};

/*
 * The function fs_walk() is a simple Landlock program enforced on a set of
 * processes. This program will be run for each walk through a file path.
 *
 * The argument ctx contains the context of the program when it is run, which
 * enable to evaluate the file path.  This context can change for each run of
 * the program.
 */
SEC("landlock1")
int fs_walk(struct landlock_ctx_fs_walk *ctx)
{
	return get_access((void *)ctx->inode);
}

SEC("subtype/landlock2")
static union bpf_prog_subtype _subtype2 = {
	.landlock_hook = {
		.type = LANDLOCK_HOOK_FS_PICK,
		/*
		 * allowed:
		 * - LANDLOCK_TRIGGER_FS_PICK_LINK
		 * - LANDLOCK_TRIGGER_FS_PICK_LINKTO
		 * - LANDLOCK_TRIGGER_FS_PICK_RECEIVE
		 * - LANDLOCK_TRIGGER_FS_PICK_MOUNTON
		 */
		.triggers =
			    LANDLOCK_TRIGGER_FS_PICK_APPEND |
			    LANDLOCK_TRIGGER_FS_PICK_CHDIR |
			    LANDLOCK_TRIGGER_FS_PICK_CHROOT |
			    LANDLOCK_TRIGGER_FS_PICK_CREATE |
			    LANDLOCK_TRIGGER_FS_PICK_EXECUTE |
			    LANDLOCK_TRIGGER_FS_PICK_FCNTL |
			    LANDLOCK_TRIGGER_FS_PICK_GETATTR |
			    LANDLOCK_TRIGGER_FS_PICK_IOCTL |
			    LANDLOCK_TRIGGER_FS_PICK_LOCK |
			    LANDLOCK_TRIGGER_FS_PICK_MAP |
			    LANDLOCK_TRIGGER_FS_PICK_OPEN |
			    LANDLOCK_TRIGGER_FS_PICK_READ |
			    LANDLOCK_TRIGGER_FS_PICK_READDIR |
			    LANDLOCK_TRIGGER_FS_PICK_RENAME |
			    LANDLOCK_TRIGGER_FS_PICK_RENAMETO |
			    LANDLOCK_TRIGGER_FS_PICK_RMDIR |
			    LANDLOCK_TRIGGER_FS_PICK_SETATTR |
			    LANDLOCK_TRIGGER_FS_PICK_TRANSFER |
			    LANDLOCK_TRIGGER_FS_PICK_UNLINK |
			    LANDLOCK_TRIGGER_FS_PICK_WRITE,
	}
};

SEC("landlock2")
int fs_pick_ro(struct landlock_ctx_fs_pick *ctx)
{
	return get_access((void *)ctx->inode);
}

SEC("license")
static const char _license[] = "GPL";
