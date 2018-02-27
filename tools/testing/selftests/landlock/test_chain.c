/*
 * Landlock tests - chain
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <errno.h>

#include "test.h"

static int new_prog(struct __test_metadata *_metadata, int is_valid,
		__u32 hook_type, int prev)
{
	const struct bpf_insn prog_accept[] = {
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_prog_subtype subtype = {
		.landlock_hook = {
			.type = hook_type,
			.triggers = hook_type == LANDLOCK_HOOK_FS_PICK ?
				LANDLOCK_TRIGGER_FS_PICK_OPEN : 0,
		}
	};
	int prog;
	char log[256] = "";

	if (prev != -1) {
		subtype.landlock_hook.options = LANDLOCK_OPTION_PREVIOUS;
		subtype.landlock_hook.previous = prev;
	}
	prog = bpf_load_program(BPF_PROG_TYPE_LANDLOCK_HOOK,
			(const struct bpf_insn *)&prog_accept,
			sizeof(prog_accept) / sizeof(struct bpf_insn), "GPL",
			0, log, sizeof(log), &subtype);
	if (is_valid) {
		ASSERT_NE(-1, prog) {
			TH_LOG("Failed to load program: %s\n%s",
					strerror(errno), log);
		}
	} else {
		ASSERT_EQ(-1, prog) {
			TH_LOG("Successfully loaded a wrong program\n");
		}
		ASSERT_EQ(errno, EINVAL);
	}
	return prog;
}

static void apply_chain(struct __test_metadata *_metadata, int is_valid,
		int prog)
{
	if (is_valid) {
		ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &prog)) {
			TH_LOG("Failed to apply chain: %s", strerror(errno));
		}
	} else {
		ASSERT_NE(0, seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &prog)) {
			TH_LOG("Successfully applied a wrong chain");
		}
		ASSERT_EQ(errno, EINVAL);
	}
}

TEST(chain_fs_good_walk_pick)
{
	/* fs_walk1 -> [fs_pick1] */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	apply_chain(_metadata, 1, fs_pick1);
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_good_pick_pick)
{
	/* fs_pick1 -> [fs_pick2] */
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, -1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	apply_chain(_metadata, 1, fs_pick2);
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
}

TEST(chain_fs_wrong_pick_walk)
{
	/* fs_pick1 -> fs_walk1 */
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, -1);
	new_prog(_metadata, 0, LANDLOCK_HOOK_FS_WALK, fs_pick1);
	EXPECT_EQ(0, close(fs_pick1));
}

TEST(chain_fs_wrong_walk_walk)
{
	/* fs_walk1 -> fs_walk2 */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	new_prog(_metadata, 0, LANDLOCK_HOOK_FS_WALK, fs_walk1);
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_good_pick_get)
{
	/* fs_pick1 -> [fs_get1] */
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, -1);
	int fs_get1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_GET, fs_pick1);
	apply_chain(_metadata, 1, fs_get1);
	EXPECT_EQ(0, close(fs_get1));
	EXPECT_EQ(0, close(fs_pick1));
}

TEST(chain_fs_wrong_get_get)
{
	/* fs_get1 -> [fs_get2] */
	int fs_get1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	new_prog(_metadata, 0, LANDLOCK_HOOK_FS_GET, fs_get1);
	EXPECT_EQ(0, close(fs_get1));
}

TEST(chain_fs_wrong_tree_1)
{
	/* [fs_walk1] -> { [fs_pick1] , [fs_pick2] } */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	apply_chain(_metadata, 1, fs_walk1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	apply_chain(_metadata, 0, fs_pick1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	apply_chain(_metadata, 0, fs_pick2);
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_wrong_tree_2)
{
	/* fs_walk1 -> { [fs_pick1] , [fs_pick2] } */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	apply_chain(_metadata, 1, fs_pick1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	apply_chain(_metadata, 0, fs_pick2);
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_wrong_tree_3)
{
	/* fs_walk1 -> [fs_pick1] -> [fs_pick2] */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	apply_chain(_metadata, 1, fs_pick1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	apply_chain(_metadata, 0, fs_pick2);
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_wrong_tree_4)
{
	/* fs_walk1 -> fs_pick1 -> fs_pick2 -> { [fs_get1] , [fs_get2] } */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	int fs_get1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_GET, fs_pick2);
	apply_chain(_metadata, 1, fs_get1);
	int fs_get2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_GET, fs_pick2);
	apply_chain(_metadata, 0, fs_get2);
	EXPECT_EQ(0, close(fs_get2));
	EXPECT_EQ(0, close(fs_get1));
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_wrong_tree_5)
{
	/* fs_walk1 -> fs_pick1 -> { [fs_pick2] , [fs_pick3] } */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	apply_chain(_metadata, 1, fs_pick2);
	int fs_pick3 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	apply_chain(_metadata, 0, fs_pick3);
	EXPECT_EQ(0, close(fs_pick3));
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_wrong_tree_6)
{
	/* thread 1: fs_walk1 -> fs_pick1 -> [fs_pick2] */
	/* thread 2: fs_walk1 -> fs_pick1 -> [fs_pick2] -> [fs_get1] */
	int child;
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	apply_chain(_metadata, 1, fs_pick2);
	child = fork();
	if (child) {
		/* parent */
		int status;
		waitpid(child, &status, 0);
		EXPECT_TRUE(WIFEXITED(status) && !WEXITSTATUS(status));
	} else {
		/* child */
		int fs_get1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_GET,
				fs_pick2);
		apply_chain(_metadata, 0, fs_get1);
		_exit(0);
	}
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_good_tree_1)
{
	/* fs_walk1 -> fs_pick1 -> [fs_pick2] */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	apply_chain(_metadata, 1, fs_pick2);
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST(chain_fs_good_tree_2)
{
	/* fs_walk1 -> fs_pick1 -> [fs_pick2] -> [fs_get1] */
	int fs_walk1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_WALK, -1);
	int fs_pick1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_walk1);
	int fs_pick2 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_PICK, fs_pick1);
	apply_chain(_metadata, 1, fs_pick2);
	int fs_get1 = new_prog(_metadata, 1, LANDLOCK_HOOK_FS_GET, fs_pick2);
	apply_chain(_metadata, 1, fs_get1);
	EXPECT_EQ(0, close(fs_get1));
	EXPECT_EQ(0, close(fs_pick2));
	EXPECT_EQ(0, close(fs_pick1));
	EXPECT_EQ(0, close(fs_walk1));
}

TEST_HARNESS_MAIN
