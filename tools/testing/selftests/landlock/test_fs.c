// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - filesystem
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/landlock.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test.h"

#define TMP_PREFIX "tmp_"

/* Paths (sibling number and depth) */
const char dir_s0_d1[] = TMP_PREFIX "a0";
const char dir_s0_d2[] = TMP_PREFIX "a0/b0";
const char dir_s0_d3[] = TMP_PREFIX "a0/b0/c0";
const char dir_s1_d1[] = TMP_PREFIX "a1";
const char dir_s2_d1[] = TMP_PREFIX "a2";
const char dir_s2_d2[] = TMP_PREFIX "a2/b2";

/* dir_s3_d1 is a tmpfs mount. */
const char dir_s3_d1[] = TMP_PREFIX "a3";
const char dir_s3_d2[] = TMP_PREFIX "a3/b3";

/* dir_s4_d2 is a tmpfs mount. */
const char dir_s4_d1[] = TMP_PREFIX "a4";
const char dir_s4_d2[] = TMP_PREFIX "a4/b4";

static void cleanup_layout1(void)
{
	rmdir(dir_s2_d2);
	rmdir(dir_s2_d1);
	rmdir(dir_s1_d1);
	rmdir(dir_s0_d3);
	rmdir(dir_s0_d2);
	rmdir(dir_s0_d1);

	/* dir_s3_d2 may be bind mounted */
	umount(dir_s3_d2);
	rmdir(dir_s3_d2);
	umount(dir_s3_d1);
	rmdir(dir_s3_d1);

	umount(dir_s4_d2);
	rmdir(dir_s4_d2);
	rmdir(dir_s4_d1);
}

FIXTURE(layout1) {
};

FIXTURE_SETUP(layout1)
{
	cleanup_layout1();

	/* Do not pollute the rest of the system. */
	ASSERT_NE(-1, unshare(CLONE_NEWNS));

	ASSERT_EQ(0, mkdir(dir_s0_d1, 0600));
	ASSERT_EQ(0, mkdir(dir_s0_d2, 0600));
	ASSERT_EQ(0, mkdir(dir_s0_d3, 0600));
	ASSERT_EQ(0, mkdir(dir_s1_d1, 0600));
	ASSERT_EQ(0, mkdir(dir_s2_d1, 0600));
	ASSERT_EQ(0, mkdir(dir_s2_d2, 0600));

	ASSERT_EQ(0, mkdir(dir_s3_d1, 0600));
	ASSERT_EQ(0, mount("tmp", dir_s3_d1, "tmpfs", 0, NULL));
	ASSERT_EQ(0, mkdir(dir_s3_d2, 0600));

	ASSERT_EQ(0, mkdir(dir_s4_d1, 0600));
	ASSERT_EQ(0, mkdir(dir_s4_d2, 0600));
	ASSERT_EQ(0, mount("tmp", dir_s4_d2, "tmpfs", 0, NULL));
}

FIXTURE_TEARDOWN(layout1)
{
	/*
	 * cleanup_layout1() would be denied here, use TEST(cleanup) instead.
	 */
}

static void test_path_rel(struct __test_metadata *_metadata, int dirfd,
		const char *path, int ret)
{
	int fd;
	struct stat statbuf;

	/* faccessat() can not be restricted for now */
	ASSERT_EQ(ret, fstatat(dirfd, path, &statbuf, 0)) {
		TH_LOG("fstatat path \"%s\" returned %s\n", path,
				strerror(errno));
	}
	if (ret) {
		ASSERT_EQ(EACCES, errno);
	}
	fd = openat(dirfd, path, O_DIRECTORY);
	if (ret) {
		ASSERT_EQ(-1, fd);
		ASSERT_EQ(EACCES, errno);
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

TEST_F(layout1, no_restriction)
{
	test_path(_metadata, dir_s0_d1, 0);
	test_path(_metadata, dir_s0_d2, 0);
	test_path(_metadata, dir_s0_d3, 0);
	test_path(_metadata, dir_s1_d1, 0);
	test_path(_metadata, dir_s2_d2, 0);
}

TEST_F(ruleset_rw, inval)
{
	int err;
	struct landlock_attr_path_beneath path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ |
			LANDLOCK_ACCESS_FS_WRITE,
		.parent_fd = -1,
	};
	struct landlock_attr_enforce attr_enforce;

	path_beneath.ruleset_fd = self->ruleset_fd;
	path_beneath.parent_fd = open(dir_s0_d2, O_PATH | O_NOFOLLOW |
			O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(err, 0);
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Tests without O_PATH. */
	path_beneath.parent_fd = open(dir_s0_d2, O_NOFOLLOW | O_DIRECTORY |
			O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(err, -1);
	ASSERT_EQ(errno, EBADR);
	errno = 0;
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Checks un-handled access. */
	path_beneath.parent_fd = open(dir_s0_d2, O_PATH | O_NOFOLLOW |
			O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	path_beneath.allowed_access |= LANDLOCK_ACCESS_FS_EXECUTE;
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(errno, EINVAL);
	errno = 0;
	ASSERT_EQ(err, -1);
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	err = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(err, 0);

	attr_enforce.ruleset_fd = self->ruleset_fd;
	err = landlock(LANDLOCK_CMD_ENFORCE_RULESET,
			LANDLOCK_OPT_ENFORCE_RULESET, sizeof(attr_enforce),
			&attr_enforce);
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(err, 0);
}

TEST_F(ruleset_rw, nsfs)
{
	struct landlock_attr_path_beneath path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ |
			LANDLOCK_ACCESS_FS_WRITE,
		.ruleset_fd = self->ruleset_fd,
	};
	int err;

	path_beneath.parent_fd = open("/proc/self/ns/mnt", O_PATH | O_NOFOLLOW |
			O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(err, 0);
	ASSERT_EQ(0, close(path_beneath.parent_fd));
}

static void add_path_beneath(struct __test_metadata *_metadata, int ruleset_fd,
		__u64 allowed_access, const char *path)
{
	int err;
	struct landlock_attr_path_beneath path_beneath = {
		.ruleset_fd = ruleset_fd,
		.allowed_access = allowed_access,
	};

	path_beneath.parent_fd = open(path, O_PATH | O_NOFOLLOW | O_DIRECTORY |
			O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0) {
		TH_LOG("Failed to open directory \"%s\": %s\n", path,
				strerror(errno));
	}
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(err, 0) {
		TH_LOG("Failed to update the ruleset with \"%s\": %s\n",
				path, strerror(errno));
	}
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(0, close(path_beneath.parent_fd));
}

static int create_ruleset(struct __test_metadata *_metadata,
		const char *const dirs[])
{
	int ruleset_fd, dirs_len, i;
	struct landlock_attr_features attr_features;
	struct landlock_attr_ruleset attr_ruleset = {
		.handled_access_fs =
			LANDLOCK_ACCESS_FS_OPEN |
			LANDLOCK_ACCESS_FS_READ |
			LANDLOCK_ACCESS_FS_WRITE |
			LANDLOCK_ACCESS_FS_EXECUTE |
			LANDLOCK_ACCESS_FS_GETATTR
	};
	__u64 allowed_access =
			LANDLOCK_ACCESS_FS_OPEN |
			LANDLOCK_ACCESS_FS_READ |
			LANDLOCK_ACCESS_FS_GETATTR;

	ASSERT_NE(NULL, dirs) {
		TH_LOG("No directory list\n");
	}
	ASSERT_NE(NULL, dirs[0]) {
		TH_LOG("Empty directory list\n");
	}
	/* Gets the number of dir entries. */
	for (dirs_len = 0; dirs[dirs_len]; dirs_len++);

	ASSERT_EQ(0, landlock(LANDLOCK_CMD_GET_FEATURES,
				LANDLOCK_OPT_GET_FEATURES,
				sizeof(attr_features), &attr_features));
	/* Only for test, use a binary AND for real application instead. */
	ASSERT_EQ(attr_ruleset.handled_access_fs,
			attr_ruleset.handled_access_fs &
			attr_features.access_fs);
	ASSERT_EQ(allowed_access, allowed_access & attr_features.access_fs);
	ruleset_fd = landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, sizeof(attr_ruleset),
			&attr_ruleset);
	ASSERT_GE(ruleset_fd, 0) {
		TH_LOG("Failed to create a ruleset: %s\n", strerror(errno));
	}

	for (i = 0; dirs[i]; i++) {
		add_path_beneath(_metadata, ruleset_fd, allowed_access,
				dirs[i]);
	}
	return ruleset_fd;
}

static void enforce_ruleset(struct __test_metadata *_metadata, int ruleset_fd)
{
	struct landlock_attr_enforce attr_enforce = {
		.ruleset_fd = ruleset_fd,
	};
	int err;

	err = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(err, 0);

	err = landlock(LANDLOCK_CMD_ENFORCE_RULESET,
			LANDLOCK_OPT_ENFORCE_RULESET, sizeof(attr_enforce),
			&attr_enforce);
	ASSERT_EQ(err, 0) {
		TH_LOG("Failed to enforce ruleset: %s\n", strerror(errno));
	}
	ASSERT_EQ(errno, 0);
}

TEST_F(layout1, whitelist)
{
	int ruleset_fd = create_ruleset(_metadata,
			(const char *const []){ dir_s0_d2, dir_s1_d1, NULL });
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, "/", -1);
	test_path(_metadata, dir_s0_d1, -1);
	test_path(_metadata, dir_s0_d2, 0);
	test_path(_metadata, dir_s0_d3, 0);
}

TEST_F(layout1, unhandled_access)
{
	int ruleset_fd = create_ruleset(_metadata,
			(const char *const []){ dir_s0_d2, NULL });
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/*
	 * Because the policy does not handled LANDLOCK_ACCESS_FS_CHROOT,
	 * chroot(2) should be allowed.
	 */
	ASSERT_EQ(0, chroot(dir_s0_d1));
	ASSERT_EQ(0, chroot(dir_s0_d2));
	ASSERT_EQ(0, chroot(dir_s0_d3));
}

TEST_F(layout1, ruleset_overlap)
{
	struct stat statbuf;
	int open_fd;
	int ruleset_fd = create_ruleset(_metadata,
			(const char *const []){ dir_s1_d1, NULL });
	ASSERT_NE(-1, ruleset_fd);
	/* These rules should be ORed among them. */
	add_path_beneath(_metadata, ruleset_fd,
			LANDLOCK_ACCESS_FS_GETATTR, dir_s0_d2);
	add_path_beneath(_metadata, ruleset_fd,
			LANDLOCK_ACCESS_FS_OPEN, dir_s0_d2);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d1, &statbuf, 0));
	ASSERT_EQ(-1, openat(AT_FDCWD, dir_s0_d1, O_DIRECTORY));
	ASSERT_EQ(0, fstatat(AT_FDCWD, dir_s0_d2, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d2, O_DIRECTORY);
	ASSERT_LE(0, open_fd);
	EXPECT_EQ(0, close(open_fd));
	ASSERT_EQ(0, fstatat(AT_FDCWD, dir_s0_d3, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d3, O_DIRECTORY);
	ASSERT_LE(0, open_fd);
	EXPECT_EQ(0, close(open_fd));
}

TEST_F(layout1, inherit_superset)
{
	struct stat statbuf;
	int ruleset_fd, open_fd;

	ruleset_fd = create_ruleset(_metadata,
			(const char *const []){ dir_s1_d1, NULL });
	ASSERT_NE(-1, ruleset_fd);
	add_path_beneath(_metadata, ruleset_fd,
			LANDLOCK_ACCESS_FS_OPEN, dir_s0_d2);
	enforce_ruleset(_metadata, ruleset_fd);

	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d1, &statbuf, 0));
	ASSERT_EQ(-1, openat(AT_FDCWD, dir_s0_d1, O_DIRECTORY));

	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d2, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d2, O_DIRECTORY);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d3, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d3, O_DIRECTORY);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/*
	 * Test shared rule extension: the following rules should not grant any
	 * new access, only remove some.  Once enforced, these rules are ANDed
	 * with the previous ones.
	 */
	add_path_beneath(_metadata, ruleset_fd, LANDLOCK_ACCESS_FS_GETATTR,
			dir_s0_d2);
	/*
	 * In ruleset_fd, dir_s0_d2 should now have the LANDLOCK_ACCESS_FS_OPEN
	 * and LANDLOCK_ACCESS_FS_GETATTR access rights (even if this directory
	 * is opened a second time).  However, when enforcing this updated
	 * ruleset, the ruleset tied to the current process will still only
	 * have the dir_s0_d2 with LANDLOCK_ACCESS_FS_OPEN access,
	 * LANDLOCK_ACCESS_FS_GETATTR must not be allowed because it would be a
	 * privilege escalation.
	 */
	enforce_ruleset(_metadata, ruleset_fd);

	/* Same tests and results as above. */
	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d1, &statbuf, 0));
	ASSERT_EQ(-1, openat(AT_FDCWD, dir_s0_d1, O_DIRECTORY));

	/* It is still forbiden to fstat(dir_s0_d2). */
	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d2, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d2, O_DIRECTORY);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d3, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d3, O_DIRECTORY);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/*
	 * Now, dir_s0_d3 get a new rule tied to it, only allowing
	 * LANDLOCK_ACCESS_FS_GETATTR.  The kernel internal difference is that
	 * there was no rule tied to it before.
	 */
	add_path_beneath(_metadata, ruleset_fd, LANDLOCK_ACCESS_FS_GETATTR,
			dir_s0_d3);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/*
	 * Same tests and results as above, except for open(dir_s0_d3) which is
	 * now denied because the new rule mask the rule previously inherited
	 * from dir_s0_d2.
	 */
	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d1, &statbuf, 0));
	ASSERT_EQ(-1, openat(AT_FDCWD, dir_s0_d1, O_DIRECTORY));

	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d2, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d2, O_DIRECTORY);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/* It is still forbiden to fstat(dir_s0_d3). */
	ASSERT_EQ(-1, fstatat(AT_FDCWD, dir_s0_d3, &statbuf, 0));
	open_fd = openat(AT_FDCWD, dir_s0_d3, O_DIRECTORY);
	/* open(dir_s0_d3) is now forbidden. */
	ASSERT_EQ(-1, open_fd);
	ASSERT_EQ(EACCES, errno);
}

TEST_F(layout1, extend_ruleset_with_denied_path)
{
	struct landlock_attr_path_beneath path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_GETATTR,
	};

	path_beneath.ruleset_fd = create_ruleset(_metadata,
			(const char *const []){ dir_s0_d2, NULL });
	ASSERT_NE(-1, path_beneath.ruleset_fd);
	enforce_ruleset(_metadata, path_beneath.ruleset_fd);

	ASSERT_EQ(-1, open(dir_s0_d1, O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	/*
	 * Tests that we can't create a rule for which we are not allowed to
	 * open its path.
	 */
	path_beneath.parent_fd = open(dir_s0_d1, O_PATH | O_NOFOLLOW
			| O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_ADD_RULE,
				LANDLOCK_OPT_CREATE_RULESET,
				sizeof(path_beneath), &path_beneath));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, close(path_beneath.parent_fd));
	EXPECT_EQ(0, close(path_beneath.ruleset_fd));
}

TEST_F(layout1, rule_on_mountpoint)
{
	int ruleset_fd = create_ruleset(_metadata,
			(const char *const []){ dir_s0_d1, dir_s3_d1, NULL });
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, dir_s1_d1, -1);
	test_path(_metadata, dir_s0_d1, 0);
	test_path(_metadata, dir_s3_d1, 0);
}

TEST_F(layout1, rule_over_mountpoint)
{
	int ruleset_fd = create_ruleset(_metadata,
			(const char *const []){ dir_s4_d1, dir_s0_d1, NULL });
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, dir_s4_d2, 0);
	test_path(_metadata, dir_s0_d1, 0);
	test_path(_metadata, dir_s4_d1, 0);
}

/*
 * This test verifies that we can apply a landlock rule on the root (/), it
 * might require special handling.
 */
TEST_F(layout1, rule_over_root)
{
	int ruleset_fd = create_ruleset(_metadata,
		(const char *const []){ "/", NULL });
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, "/", 0);
	test_path(_metadata, dir_s0_d1, 0);
}

TEST_F(layout1, rule_inside_mount_ns)
{
	ASSERT_NE(-1, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	ASSERT_NE(-1, syscall(SYS_pivot_root, dir_s3_d1, dir_s3_d2));
	ASSERT_NE(-1, chdir("/"));

	int ruleset_fd = create_ruleset(_metadata,
		(const char *const []){ "b3", NULL });
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, "b3", 0);
	test_path(_metadata, "/", -1);
}

TEST_F(layout1, mount_and_pivot)
{
	int ruleset_fd = create_ruleset(_metadata,
		(const char *const []){ dir_s3_d1, NULL });
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	ASSERT_EQ(-1, syscall(SYS_pivot_root, dir_s3_d1, dir_s3_d2));
}

enum relative_access {
	REL_OPEN,
	REL_CHDIR,
	REL_CHROOT,
};

static void check_access(struct __test_metadata *_metadata,
		bool enforce, enum relative_access rel)
{
	int dirfd;
	int ruleset_fd = -1;

	if (enforce) {
		ruleset_fd = create_ruleset(_metadata, (const char *const []){
				dir_s0_d2, dir_s1_d1, NULL });
		ASSERT_NE(-1, ruleset_fd);
		if (rel == REL_CHROOT)
			ASSERT_NE(-1, chdir(dir_s0_d2));
		enforce_ruleset(_metadata, ruleset_fd);
	} else if (rel == REL_CHROOT)
		ASSERT_NE(-1, chdir(dir_s0_d2));
	switch (rel) {
	case REL_OPEN:
		dirfd = open(dir_s0_d2, O_DIRECTORY);
		ASSERT_NE(-1, dirfd);
		break;
	case REL_CHDIR:
		ASSERT_NE(-1, chdir(dir_s0_d2));
		dirfd = AT_FDCWD;
		break;
	case REL_CHROOT:
		ASSERT_NE(-1, chroot(".")) {
			TH_LOG("Failed to chroot: %s\n", strerror(errno));
		}
		dirfd = AT_FDCWD;
		break;
	default:
		ASSERT_TRUE(false);
		return;
	}

	test_path_rel(_metadata, dirfd, "..", (rel == REL_CHROOT) ? 0 : -1);
	test_path_rel(_metadata, dirfd, ".", 0);
	if (rel != REL_CHROOT) {
		test_path_rel(_metadata, dirfd, "./c0", 0);
		test_path_rel(_metadata, dirfd, "../../" TMP_PREFIX "a1", 0);
		test_path_rel(_metadata, dirfd, "../../" TMP_PREFIX "a2", -1);
	}

	if (rel == REL_OPEN)
		EXPECT_EQ(0, close(dirfd));
	if (enforce)
		EXPECT_EQ(0, close(ruleset_fd));
}

TEST_F(layout1, deny_open)
{
	check_access(_metadata, true, REL_OPEN);
}

TEST_F(layout1, deny_chdir)
{
	check_access(_metadata, true, REL_CHDIR);
}

TEST_F(layout1, deny_chroot)
{
	check_access(_metadata, true, REL_CHROOT);
}

TEST(cleanup)
{
	cleanup_layout1();
}

TEST_HARNESS_MAIN
