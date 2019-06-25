// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - file system
 *
 * Copyright © 2018-2019 Mickaël Salaün <mic@digikod.net>
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

static const char d1[] = "/usr";
static const char d2[] = "/usr/share";
static const char d3[] = "/usr/share/doc";

TEST(fs_base)
{
	test_path(_metadata, d1, 0);
	test_path(_metadata, d2, 0);
	test_path(_metadata, d3, 0);
}

#define MAP_VALUE_DENY 1

static int create_denied_inode_map(struct __test_metadata *_metadata,
		const char *const dirs[])
{
	int map, key, dirs_len, i;
	__u64 value = MAP_VALUE_DENY;

	ASSERT_NE(NULL, dirs) {
		TH_LOG("No directory list\n");
	}
	ASSERT_NE(NULL, dirs[0]) {
		TH_LOG("Empty directory list\n");
	}

	/* get the number of dir entries */
	for (dirs_len = 0; dirs[dirs_len]; dirs_len++);
	map = bpf_create_map(BPF_MAP_TYPE_INODE, sizeof(key), sizeof(value),
			dirs_len, 0);
	ASSERT_NE(-1, map) {
		TH_LOG("Failed to create a map of %d elements: %s\n", dirs_len,
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

static void enforce_map(struct __test_metadata *_metadata, int map,
		bool subpath)
{
	const struct bpf_insn prog_deny[] = {
		BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_1),
		/* look for the requested inode in the map */
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
			offsetof(struct landlock_ctx_fs_walk, inode)),
		BPF_LD_MAP_FD(BPF_REG_1, map), /* 2 instructions */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_inode_map_lookup),
		/* if it is there, then deny access to the inode, otherwise
		 * allow it */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, MAP_VALUE_DENY, 2),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_DENY),
		BPF_EXIT_INSN(),
	};
	union bpf_prog_subtype subtype = {};
	int fd_walk = -1, fd_pick;
	char log[1024] = "";

	if (subpath) {
		subtype.landlock_hook.type = LANDLOCK_HOOK_FS_WALK;
		fd_walk = ll_bpf_load_program((const struct bpf_insn *)&prog_deny,
				sizeof(prog_deny) / sizeof(struct bpf_insn),
				log, sizeof(log), &subtype);
		ASSERT_NE(-1, fd_walk) {
			TH_LOG("Failed to load fs_walk program: %s\n%s",
					strerror(errno), log);
		}
		ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &fd_walk)) {
			TH_LOG("Failed to apply Landlock program: %s", strerror(errno));
		}
		EXPECT_EQ(0, close(fd_walk));
	}

	subtype.landlock_hook.type = LANDLOCK_HOOK_FS_PICK;
	subtype.landlock_hook.triggers = TEST_PATH_TRIGGERS;
	fd_pick = ll_bpf_load_program((const struct bpf_insn *)&prog_deny,
			sizeof(prog_deny) / sizeof(struct bpf_insn), log,
			sizeof(log), &subtype);
	ASSERT_NE(-1, fd_pick) {
		TH_LOG("Failed to load fs_pick program: %s\n%s",
				strerror(errno), log);
	}
	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &fd_pick)) {
		TH_LOG("Failed to apply Landlock program: %s", strerror(errno));
	}
	EXPECT_EQ(0, close(fd_pick));
}

static void check_map_blacklist(struct __test_metadata *_metadata,
		bool subpath)
{
	int map = create_denied_inode_map(_metadata, (const char *const [])
			{ d2, NULL });
	ASSERT_NE(-1, map);
	enforce_map(_metadata, map, subpath);
	test_path(_metadata, d1, 0);
	test_path(_metadata, d2, -1);
	test_path(_metadata, d3, subpath ? -1 : 0);
	EXPECT_EQ(0, close(map));
}

TEST(fs_map_blacklist_literal)
{
	check_map_blacklist(_metadata, false);
}

TEST(fs_map_blacklist_subpath)
{
	check_map_blacklist(_metadata, true);
}

static const char r2[] = ".";
static const char r3[] = "./doc";

enum relative_access {
	REL_OPEN,
	REL_CHDIR,
	REL_CHROOT,
};

static void check_access(struct __test_metadata *_metadata,
		bool enforce, enum relative_access rel)
{
	int dirfd;
	int map = -1;

	if (rel == REL_CHROOT)
		ASSERT_NE(-1, chdir(d2));
	if (enforce) {
		map = create_denied_inode_map(_metadata, (const char *const [])
				{ d3, NULL });
		ASSERT_NE(-1, map);
		enforce_map(_metadata, map, true);
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

	test_path_rel(_metadata, dirfd, r2, 0);
	test_path_rel(_metadata, dirfd, r3, enforce ? -1 : 0);

	if (rel == REL_OPEN)
		EXPECT_EQ(0, close(dirfd));
	if (enforce)
		EXPECT_EQ(0, close(map));
}

TEST(fs_allow_open)
{
	/* no enforcement, via open */
	check_access(_metadata, false, REL_OPEN);
}

TEST(fs_allow_chdir)
{
	/* no enforcement, via chdir */
	check_access(_metadata, false, REL_CHDIR);
}

TEST(fs_allow_chroot)
{
	/* no enforcement, via chroot */
	check_access(_metadata, false, REL_CHROOT);
}

TEST(fs_deny_open)
{
	/* enforcement without tag, via open */
	check_access(_metadata, true, REL_OPEN);
}

TEST(fs_deny_chdir)
{
	/* enforcement without tag, via chdir */
	check_access(_metadata, true, REL_CHDIR);
}

TEST(fs_deny_chroot)
{
	/* enforcement without tag, via chroot */
	check_access(_metadata, true, REL_CHROOT);
}

TEST_HARNESS_MAIN
