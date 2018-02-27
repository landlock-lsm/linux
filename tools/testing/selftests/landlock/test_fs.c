/*
 * Landlock tests - file system
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <fcntl.h> /* O_DIRECTORY */
#include <sys/stat.h> /* statbuf */
#include <unistd.h> /* faccessat() */

#include "test.h"

#define TEST_PATH_TRIGGERS ( \
		LANDLOCK_TRIGGER_FS_PICK_OPEN | \
		LANDLOCK_TRIGGER_FS_PICK_READDIR | \
		LANDLOCK_TRIGGER_FS_PICK_EXECUTE | \
		LANDLOCK_TRIGGER_FS_PICK_GETATTR)

static void enforce_depth(struct __test_metadata *_metadata, int depth)
{
	const struct bpf_insn prog_walk[] = {
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,
			offsetof(struct landlock_ctx_fs_walk, cookie)),
		BPF_LDX_MEM(BPF_B, BPF_REG_7, BPF_REG_1,
			offsetof(struct landlock_ctx_fs_walk, inode_lookup)),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_7,
				LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOTDOT, 3),
		/* assume 1 is the root */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 1, 4),
		BPF_ALU64_IMM(BPF_SUB, BPF_REG_6, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, 2),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_7,
				LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOT, 1),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_walk, cookie)),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn prog_pick[] = {
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,
			offsetof(struct landlock_ctx_fs_pick, cookie)),
		/* allow without fs_walk */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 11),
		BPF_LDX_MEM(BPF_B, BPF_REG_7, BPF_REG_1,
			offsetof(struct landlock_ctx_fs_walk, inode_lookup)),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_7,
				LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOTDOT, 3),
		/* assume 1 is the root */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 1, 4),
		BPF_ALU64_IMM(BPF_SUB, BPF_REG_6, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, 2),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_7,
				LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOT, 1),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_walk, cookie)),
		/* with fs_walk */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, depth + 1, 2),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_DENY),
		BPF_EXIT_INSN(),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
	};
	union bpf_prog_subtype subtype = {
		.landlock_hook = {
			.type = LANDLOCK_HOOK_FS_WALK,
		}
	};
	int fd_walk, fd_pick;
	char log[1030] = "";

	fd_walk = bpf_load_program(BPF_PROG_TYPE_LANDLOCK_HOOK,
			(const struct bpf_insn *)&prog_walk,
			sizeof(prog_walk) / sizeof(struct bpf_insn), "GPL",
			0, log, sizeof(log), &subtype);
	ASSERT_NE(-1, fd_walk) {
		TH_LOG("Failed to load fs_walk program: %s\n%s",
				strerror(errno), log);
	}

	subtype.landlock_hook.type = LANDLOCK_HOOK_FS_PICK;
	subtype.landlock_hook.options = LANDLOCK_OPTION_PREVIOUS;
	subtype.landlock_hook.previous = fd_walk;
	subtype.landlock_hook.triggers = TEST_PATH_TRIGGERS;
	fd_pick = bpf_load_program(BPF_PROG_TYPE_LANDLOCK_HOOK,
			(const struct bpf_insn *)&prog_pick,
			sizeof(prog_pick) / sizeof(struct bpf_insn), "GPL",
			0, log, sizeof(log), &subtype);
	ASSERT_NE(-1, fd_pick) {
		TH_LOG("Failed to load fs_pick program: %s\n%s",
				strerror(errno), log);
	}

	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &fd_pick)) {
		TH_LOG("Failed to apply Landlock chain: %s", strerror(errno));
	}
	EXPECT_EQ(0, close(fd_pick));
	EXPECT_EQ(0, close(fd_walk));
}

static void test_path_rel(struct __test_metadata *_metadata, int dirfd,
		const char *path, int ret)
{
	int fd;
	struct stat statbuf;

	ASSERT_EQ(ret, faccessat(dirfd, path, R_OK | X_OK, 0));
	ASSERT_EQ(ret, fstatat(dirfd, path, &statbuf, 0));
	fd = openat(dirfd, path, O_DIRECTORY);
	if (ret) {
		ASSERT_EQ(-1, fd);
	} else {
		ASSERT_NE(-1, fd);
		EXPECT_EQ(0, close(fd));
	}
}

static void test_path(struct __test_metadata *_metadata, const char *path,
		int ret)
{
	return test_path_rel(_metadata, AT_FDCWD, path, ret);
}

const char d1[] = "/usr";
const char d1_dotdot1[] = "/usr/share/..";
const char d1_dotdot2[] = "/usr/../usr/share/..";
const char d1_dotdot3[] = "/usr/../../usr/share/..";
const char d1_dotdot4[] = "/usr/../../../usr/share/..";
const char d1_dotdot5[] = "/usr/../../../usr/share/../.";
const char d1_dotdot6[] = "/././usr/./share/..";
const char d2[] = "/usr/share";
const char d2_dotdot1[] = "/usr/share/doc/..";
const char d2_dotdot2[] = "/usr/../usr/share";
const char d3[] = "/usr/share/doc";
const char d4[] = "/etc";

TEST(fs_depth_free)
{
	test_path(_metadata, d1, 0);
	test_path(_metadata, d2, 0);
	test_path(_metadata, d3, 0);
}

TEST(fs_depth_1)
{
	enforce_depth(_metadata, 1);
	test_path(_metadata, d1, 0);
	test_path(_metadata, d1_dotdot1, 0);
	test_path(_metadata, d1_dotdot2, 0);
	test_path(_metadata, d1_dotdot3, 0);
	test_path(_metadata, d1_dotdot4, 0);
	test_path(_metadata, d1_dotdot5, 0);
	test_path(_metadata, d1_dotdot6, 0);
	test_path(_metadata, d2, -1);
	test_path(_metadata, d2_dotdot1, -1);
	test_path(_metadata, d2_dotdot2, -1);
	test_path(_metadata, d3, -1);
}

TEST(fs_depth_2)
{
	enforce_depth(_metadata, 2);
	test_path(_metadata, d1, -1);
	test_path(_metadata, d1_dotdot1, -1);
	test_path(_metadata, d1_dotdot2, -1);
	test_path(_metadata, d1_dotdot3, -1);
	test_path(_metadata, d1_dotdot4, -1);
	test_path(_metadata, d1_dotdot5, -1);
	test_path(_metadata, d1_dotdot6, -1);
	test_path(_metadata, d2, 0);
	test_path(_metadata, d2_dotdot2, 0);
	test_path(_metadata, d2_dotdot1, 0);
	test_path(_metadata, d3, -1);
}

#define MAP_VALUE_ALLOW 1
#define COOKIE_VALUE_ALLOW 2

static int create_inode_map(struct __test_metadata *_metadata,
		const char *const dirs[])
{
	int map, key, i;
	__u64 value = MAP_VALUE_ALLOW;

	ASSERT_NE(NULL, dirs) {
		TH_LOG("No directory list\n");
	}
	ASSERT_NE(NULL, dirs[0]) {
		TH_LOG("Empty directory list\n");
	}
	for (i = 0; dirs[i]; i++);
	map = bpf_create_map(BPF_MAP_TYPE_INODE, sizeof(key), sizeof(value),
			i, 0);
	ASSERT_NE(-1, map) {
		TH_LOG("Failed to create a map of %d elements: %s\n", i,
				strerror(errno));
	}
	for (i = 0; dirs[i]; i++) {
		key = open(dirs[i], O_RDONLY | O_CLOEXEC | O_DIRECTORY);
		ASSERT_NE(-1, key) {
			TH_LOG("Failed to open directory \"%s\": %s\n", dirs[i],
					strerror(errno));
		}
		ASSERT_EQ(0, bpf_map_update_elem(map, &key, &value, BPF_ANY)) {
			TH_LOG("Failed to update the map with \"%s\": %s\n",
					dirs[i], strerror(errno));
		}
		close(key);
	}
	return map;
}

#define TAG_VALUE_ALLOW 1

static void enforce_map(struct __test_metadata *_metadata, int map,
		bool subpath, bool tag)
{
	/* do not handle dot nor dotdot */
	const struct bpf_insn prog_walk[] = {
		BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_1),
		/* look at the inode's tag */
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_walk, inode)),
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_walk, chain)),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_inode_get_tag),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, TAG_VALUE_ALLOW, 5),
		/* look for the requested inode in the map */
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_walk, inode)),
		BPF_LD_MAP_FD(BPF_REG_1, map), /* 2 instructions */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_inode_map_lookup),
		/* if it is there, then mark the session as such */
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, MAP_VALUE_ALLOW, 2),
		BPF_MOV64_IMM(BPF_REG_7, COOKIE_VALUE_ALLOW),
		BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_7,
			offsetof(struct landlock_ctx_fs_walk, cookie)),
		/* allow to walk anything... but not to pick anything */
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
	};
	/* do not handle dot nor dotdot */
	const struct bpf_insn prog_pick[] = {
		BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_1),
		/* allow if the inode's tag is mark as such */
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_pick, inode)),
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_pick, chain)),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_inode_get_tag),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, TAG_VALUE_ALLOW, 9),
		/* look if the walk saw an inode in the whitelist */
		BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_pick, cookie)),
		/* if it was there, then allow access */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, COOKIE_VALUE_ALLOW, 7),
		/* otherwise, look for the requested inode in the map */
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_pick, inode)),
		BPF_LD_MAP_FD(BPF_REG_1, map), /* 2 instructions */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_inode_map_lookup),
		/* if it is there, then allow access */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, MAP_VALUE_ALLOW, 2),
		/* otherwise deny access */
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_DENY),
		BPF_EXIT_INSN(),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn prog_get[] = {
		BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_1),
		/* if prog_pick allowed this prog_get, then keep the state in
		 * the inode's tag */
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_get, tag_object)),
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_get, chain)),
		BPF_MOV64_IMM(BPF_REG_3, TAG_VALUE_ALLOW),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_landlock_set_tag),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
		/* for this test, deny on error */
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_DENY),
		BPF_EXIT_INSN(),
		/* the check was previously performed by prog_pick */
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
	};
	union bpf_prog_subtype subtype = {};
	int fd_walk = -1, fd_pick, fd_get, fd_last;
	char log[1024] = "";

	if (subpath) {
		subtype.landlock_hook.type = LANDLOCK_HOOK_FS_WALK;
		fd_walk = bpf_load_program(BPF_PROG_TYPE_LANDLOCK_HOOK,
				(const struct bpf_insn *)&prog_walk,
				sizeof(prog_walk) / sizeof(struct bpf_insn),
				"GPL", 0, log, sizeof(log), &subtype);
		ASSERT_NE(-1, fd_walk) {
			TH_LOG("Failed to load fs_walk program: %s\n%s",
					strerror(errno), log);
		}
		subtype.landlock_hook.options = LANDLOCK_OPTION_PREVIOUS;
		subtype.landlock_hook.previous = fd_walk;
	}

	subtype.landlock_hook.type = LANDLOCK_HOOK_FS_PICK;
	subtype.landlock_hook.triggers = TEST_PATH_TRIGGERS;
	fd_pick = bpf_load_program(BPF_PROG_TYPE_LANDLOCK_HOOK,
			(const struct bpf_insn *)&prog_pick,
			sizeof(prog_pick) / sizeof(struct bpf_insn), "GPL", 0,
			log, sizeof(log), &subtype);
	ASSERT_NE(-1, fd_pick) {
		TH_LOG("Failed to load fs_pick program: %s\n%s",
				strerror(errno), log);
	}
	fd_last = fd_pick;

	if (tag) {
		subtype.landlock_hook.type = LANDLOCK_HOOK_FS_GET;
		subtype.landlock_hook.triggers = 0;
		subtype.landlock_hook.options = LANDLOCK_OPTION_PREVIOUS;
		subtype.landlock_hook.previous = fd_pick;
		fd_get = bpf_load_program(BPF_PROG_TYPE_LANDLOCK_HOOK,
				(const struct bpf_insn *)&prog_get,
				sizeof(prog_get) / sizeof(struct bpf_insn),
				"GPL", 0, log, sizeof(log), &subtype);
		ASSERT_NE(-1, fd_get) {
			TH_LOG("Failed to load fs_get program: %s\n%s",
					strerror(errno), log);
		}
		fd_last = fd_get;
	}

	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &fd_last)) {
		TH_LOG("Failed to apply Landlock chain: %s", strerror(errno));
	}
	if (tag)
		EXPECT_EQ(0, close(fd_get));
	EXPECT_EQ(0, close(fd_pick));
	if (subpath)
		EXPECT_EQ(0, close(fd_walk));
}

/* do not handle dot nor dotdot */
static void check_map_whitelist(struct __test_metadata *_metadata,
		bool subpath)
{
	int map = create_inode_map(_metadata, (const char *const [])
			{ d2, NULL });
	ASSERT_NE(-1, map);
	enforce_map(_metadata, map, subpath, false);
	test_path(_metadata, d1, -1);
	test_path(_metadata, d2, 0);
	test_path(_metadata, d3, subpath ? 0 : -1);
	EXPECT_EQ(0, close(map));
}

TEST(fs_map_whitelist_literal)
{
	check_map_whitelist(_metadata, false);
}

TEST(fs_map_whitelist_subpath)
{
	check_map_whitelist(_metadata, true);
}

const char r2[] = ".";
const char r3[] = "./doc";

enum relative_access {
	REL_OPEN,
	REL_CHDIR,
	REL_CHROOT,
};

static void check_tag(struct __test_metadata *_metadata,
		bool enforce, bool with_tag, enum relative_access rel)
{
	int dirfd;
	int map = -1;
	int access_beneath, access_absolute;

	if (rel == REL_CHROOT) {
		/* do not tag with the chdir, only with the chroot */
		ASSERT_NE(-1, chdir(d2));
	}
	if (enforce) {
		map = create_inode_map(_metadata, (const char *const [])
				{ d1, NULL });
		ASSERT_NE(-1, map);
		enforce_map(_metadata, map, true, with_tag);
	}
	switch (rel) {
	case REL_OPEN:
		dirfd = open(d2, O_DIRECTORY);
		ASSERT_NE(-1, dirfd);
		break;
	case REL_CHDIR:
		ASSERT_NE(-1, chdir(d2));
		dirfd = AT_FDCWD;
		break;
	case REL_CHROOT:
		ASSERT_NE(-1, chroot(d2)) {
			TH_LOG("Failed to chroot: %s\n", strerror(errno));
		}
		dirfd = AT_FDCWD;
		break;
	default:
		ASSERT_TRUE(false);
		return;
	}

	access_beneath = (!enforce || with_tag) ? 0 : -1;
	test_path_rel(_metadata, dirfd, r2, access_beneath);
	test_path_rel(_metadata, dirfd, r3, access_beneath);

	access_absolute = (enforce || rel == REL_CHROOT) ? -1 : 0;
	test_path(_metadata, d4, access_absolute);
	test_path_rel(_metadata, dirfd, d4, access_absolute);

	if (rel == REL_OPEN)
		EXPECT_EQ(0, close(dirfd));
	if (enforce)
		EXPECT_EQ(0, close(map));
}

TEST(fs_notag_allow_open)
{
	/* no enforcement, via open */
	check_tag(_metadata, false, false, REL_OPEN);
}

TEST(fs_notag_allow_chdir)
{
	/* no enforcement, via chdir */
	check_tag(_metadata, false, false, REL_CHDIR);
}

TEST(fs_notag_allow_chroot)
{
	/* no enforcement, via chroot */
	check_tag(_metadata, false, false, REL_CHROOT);
}

TEST(fs_notag_deny_open)
{
	/* enforcement without tag, via open */
	check_tag(_metadata, true, false, REL_OPEN);
}

TEST(fs_notag_deny_chdir)
{
	/* enforcement without tag, via chdir */
	check_tag(_metadata, true, false, REL_CHDIR);
}

TEST(fs_notag_deny_chroot)
{
	/* enforcement without tag, via chroot */
	check_tag(_metadata, true, false, REL_CHROOT);
}

TEST(fs_tag_allow_open)
{
	/* enforcement with tag, via open */
	check_tag(_metadata, true, true, REL_OPEN);
}

TEST(fs_tag_allow_chdir)
{
	/* enforcement with tag, via chdir */
	check_tag(_metadata, true, true, REL_CHDIR);
}

TEST(fs_tag_allow_chroot)
{
	/* enforcement with tag, via chroot */
	check_tag(_metadata, true, true, REL_CHROOT);
}

TEST_HARNESS_MAIN
