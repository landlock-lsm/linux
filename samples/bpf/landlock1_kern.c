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
 * (see landlock1_user.c) to extract eBPF bytecode and metadata.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/landlock.h>

#include "bpf_helpers.h"
#include "landlock1.h" /* MAP_FLAG_DENY */

#define MAP_MAX_ENTRIES		20

struct bpf_map_def SEC("maps") inode_map = {
	.type = BPF_MAP_TYPE_INODE,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = MAP_MAX_ENTRIES,
	.map_flags = BPF_F_RDONLY_PROG,
};

static __always_inline __u64 get_access(void *inode)
{
	u64 *flags;

	flags = bpf_inode_map_lookup_elem(&inode_map, inode);
	if (flags && (*flags & MAP_FLAG_DENY))
		return LANDLOCK_RET_DENY;
	return LANDLOCK_RET_ALLOW;
}

SEC("landlock/fs_walk")
int fs_walk(struct landlock_ctx_fs_walk *ctx)
{
	return get_access((void *)ctx->inode);
}

SEC("landlock/fs_pick")
int fs_pick_ro(struct landlock_ctx_fs_pick *ctx)
{
	return get_access((void *)ctx->inode);
}

static const char SEC("license") _license[] = "GPL";
