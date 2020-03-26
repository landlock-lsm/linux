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
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "common.h"

#define TMP_DIR "tmp/"
#define FILE_NAME "file"
#define BINARY_PATH "./true"

/* Paths (sibling number and depth) */
static const char dir_s1d1[] = TMP_DIR "s1d1";
static const char file_s1d1[] = TMP_DIR "s1d1/" FILE_NAME;
static const char dir_s1d2[] = TMP_DIR "s1d1/s1d2";
static const char file_s1d2[] = TMP_DIR "s1d1/s1d2/" FILE_NAME;
static const char dir_s1d3[] = TMP_DIR "s1d1/s1d2/s1d3";
static const char file_s1d3[] = TMP_DIR "s1d1/s1d2/s1d3/" FILE_NAME;

static const char dir_s2d1[] = TMP_DIR "s2d1";
static const char file_s2d1[] = TMP_DIR "s2d1/" FILE_NAME;
static const char dir_s2d2[] = TMP_DIR "s2d1/s2d2";
static const char file_s2d2[] = TMP_DIR "s2d1/s2d2/" FILE_NAME;
static const char dir_s2d3[] = TMP_DIR "s2d1/s2d2/s2d3";
static const char file_s2d3[] = TMP_DIR "s2d1/s2d2/s2d3/" FILE_NAME;

static const char dir_s3d1[] = TMP_DIR "s3d1";
/* dir_s3d2 is a mount point. */
static const char dir_s3d2[] = TMP_DIR "s3d1/s3d2";
static const char dir_s3d3[] = TMP_DIR "s3d1/s3d2/s3d3";

static void create_dir_and_file(struct __test_metadata *const _metadata,
		const char *const dir_path)
{
	int file_fd;
	const size_t file_name_len = sizeof(FILE_NAME);
	char *const file_path = alloca(strlen(dir_path) + file_name_len + 2);

	strcpy(file_path, dir_path);
	strcat(file_path, "/");
	strcat(file_path, FILE_NAME);

	ASSERT_EQ(0, mkdir(dir_path, 0700)) {
		TH_LOG("Failed to create directory \"%s\": %s\n", dir_path,
				strerror(errno));
	}
	file_fd = open(file_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			0700);
	ASSERT_LE(0, file_fd);
	ASSERT_EQ(0, close(file_fd));
}

static void delete_dir_and_file(const char *const dir_path)
{
	char *const file_path = alloca(strlen(dir_path) +
			sizeof(FILE_NAME) + 2);

	strcpy(file_path, dir_path);
	strcat(file_path, "/");
	strcat(file_path, FILE_NAME);

	unlink(file_path);
	/* file_path may be a directory, cf. layout1/make_directory. */
	rmdir(file_path);
	rmdir(dir_path);
}

static void cleanup_layout1(void)
{
	delete_dir_and_file(dir_s1d3);
	delete_dir_and_file(dir_s1d2);
	delete_dir_and_file(dir_s1d1);

	delete_dir_and_file(dir_s2d3);
	delete_dir_and_file(dir_s2d2);
	delete_dir_and_file(dir_s2d1);

	delete_dir_and_file(dir_s3d3);
	umount(dir_s3d2);
	delete_dir_and_file(dir_s3d2);
	delete_dir_and_file(dir_s3d1);

	delete_dir_and_file(TMP_DIR);
}

FIXTURE(layout1) {
};

FIXTURE_SETUP(layout1)
{
	cleanup_layout1();

	/* Do not pollute the rest of the system. */
	ASSERT_NE(-1, unshare(CLONE_NEWNS));
	umask(0077);
	create_dir_and_file(_metadata, TMP_DIR);

	create_dir_and_file(_metadata, dir_s1d1);
	create_dir_and_file(_metadata, dir_s1d2);
	create_dir_and_file(_metadata, dir_s1d3);

	create_dir_and_file(_metadata, dir_s2d1);
	create_dir_and_file(_metadata, dir_s2d2);
	create_dir_and_file(_metadata, dir_s2d3);

	create_dir_and_file(_metadata, dir_s3d1);
	create_dir_and_file(_metadata, dir_s3d2);
	ASSERT_EQ(0, mount("tmp", dir_s3d2, "tmpfs", 0, "size=4m,mode=700"));
	create_dir_and_file(_metadata, dir_s3d3);
}

FIXTURE_TEARDOWN(layout1)
{
	/*
	 * cleanup_layout1() would be denied here, use TEST(cleanup) instead.
	 */
}

static void test_path_rel(struct __test_metadata *const _metadata,
		const int dirfd, const char *const path, const int ret)
{
	int fd;

	/* Works with file and directories. */
	fd = openat(dirfd, path, O_RDONLY | O_CLOEXEC);
	if (ret) {
		ASSERT_EQ(-1, fd) {
			TH_LOG("Successfully opened \"%s\": %s\n", path,
					strerror(errno));
		}
		ASSERT_EQ(EACCES, errno) {
			TH_LOG("Wrong error code to open \"%s\": %s\n", path,
					strerror(errno));
		}
	} else {
		ASSERT_NE(-1, fd) {
			TH_LOG("Failed to open \"%s\": %s\n", path,
					strerror(errno));
		}
		EXPECT_EQ(0, close(fd));
	}
}

static void test_path(struct __test_metadata *const _metadata,
		const char *const path, const int ret)
{
	return test_path_rel(_metadata, AT_FDCWD, path, ret);
}

TEST_F(layout1, no_restriction)
{
	test_path(_metadata, dir_s1d1, 0);
	test_path(_metadata, file_s1d1, 0);
	test_path(_metadata, dir_s1d2, 0);
	test_path(_metadata, file_s1d2, 0);
	test_path(_metadata, dir_s1d3, 0);
	test_path(_metadata, file_s1d3, 0);

	test_path(_metadata, dir_s2d1, 0);
	test_path(_metadata, file_s2d1, 0);
	test_path(_metadata, dir_s2d2, 0);
	test_path(_metadata, file_s2d2, 0);
	test_path(_metadata, dir_s2d3, 0);
	test_path(_metadata, file_s2d3, 0);

	test_path(_metadata, dir_s3d1, 0);
	test_path(_metadata, dir_s3d2, 0);
	test_path(_metadata, dir_s3d3, 0);
}

TEST_F(ruleset_rw, inval)
{
	int err;
	struct landlock_attr_path_beneath path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_WRITE_FILE,
		.parent_fd = -1,
	};
	struct landlock_attr_enforce attr_enforce;

	path_beneath.ruleset_fd = self->ruleset_fd;
	path_beneath.parent_fd = open(dir_s1d2, O_PATH | O_DIRECTORY |
			O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(err, 0);
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Tests without O_PATH. */
	path_beneath.parent_fd = open(dir_s1d2, O_DIRECTORY |
			O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(err, -1);
	ASSERT_EQ(errno, EBADR);
	errno = 0;
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Checks unhandled allowed_access. */
	path_beneath.parent_fd = open(dir_s1d2, O_PATH | O_DIRECTORY |
			O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);

	/* Test with legitimate values. */
	path_beneath.allowed_access |= LANDLOCK_ACCESS_FS_EXECUTE;
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	path_beneath.allowed_access &= ~LANDLOCK_ACCESS_FS_EXECUTE;
	ASSERT_EQ(errno, EINVAL);
	errno = 0;
	ASSERT_EQ(err, -1);

	/* Test with unknown (64-bits) value. */
	path_beneath.allowed_access |= (1ULL << 60);
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	path_beneath.allowed_access &= ~(1ULL << 60);
	ASSERT_EQ(errno, EINVAL);
	errno = 0;
	ASSERT_EQ(err, -1);

	/* Test with no access. */
	path_beneath.allowed_access = 0;
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	path_beneath.allowed_access &= ~(1ULL << 60);
	ASSERT_EQ(err, 0);

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
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_WRITE_FILE,
		.ruleset_fd = self->ruleset_fd,
	};
	int err;

	path_beneath.parent_fd = open("/proc/self/ns/mnt", O_PATH | O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0);
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(err, 0);
	ASSERT_EQ(0, close(path_beneath.parent_fd));
}

static void add_path_beneath(struct __test_metadata *const _metadata,
		const int ruleset_fd, const __u64 allowed_access,
		const char *const path)
{
	int err;
	struct landlock_attr_path_beneath path_beneath = {
		.ruleset_fd = ruleset_fd,
		.allowed_access = allowed_access,
	};

	path_beneath.parent_fd = open(path, O_PATH | O_CLOEXEC);
	ASSERT_GE(path_beneath.parent_fd, 0) {
		TH_LOG("Failed to open directory \"%s\": %s\n", path,
				strerror(errno));
	}
	err = landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath);
	ASSERT_EQ(err, 0) {
		TH_LOG("Failed to update the ruleset with \"%s\": %s\n", path,
				strerror(errno));
	}
	ASSERT_EQ(errno, 0);
	ASSERT_EQ(0, close(path_beneath.parent_fd));
}

struct rule {
	const char *path;
	__u64 access;
};

#define ACCESS_RO ( \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_RW ( \
	ACCESS_RO | \
	LANDLOCK_ACCESS_FS_WRITE_FILE)

static int create_ruleset(struct __test_metadata *const _metadata,
		const __u64 handled_access_fs, const struct rule rules[])
{
	int ruleset_fd, i;
	struct landlock_attr_features attr_features;
	struct landlock_attr_ruleset attr_ruleset = {
		.handled_access_fs = handled_access_fs,
	};

	ASSERT_NE(NULL, rules) {
		TH_LOG("No rule list\n");
	}
	ASSERT_NE(NULL, rules[0].path) {
		TH_LOG("Empty rule list\n");
	}

	ASSERT_EQ(0, landlock(LANDLOCK_CMD_GET_FEATURES,
				LANDLOCK_OPT_GET_FEATURES,
				sizeof(attr_features), &attr_features));
	/* Only for test, use a binary AND for real application instead. */
	ASSERT_EQ(attr_ruleset.handled_access_fs,
			attr_ruleset.handled_access_fs &
			attr_features.access_fs);
	ruleset_fd = landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, sizeof(attr_ruleset),
			&attr_ruleset);
	ASSERT_GE(ruleset_fd, 0) {
		TH_LOG("Failed to create a ruleset: %s\n", strerror(errno));
	}

	for (i = 0; rules[i].path; i++) {
		ASSERT_EQ(rules[i].access, rules[i].access &
				attr_features.access_fs);
		add_path_beneath(_metadata, ruleset_fd, rules[i].access,
				rules[i].path);
	}
	return ruleset_fd;
}

static void enforce_ruleset(struct __test_metadata *const _metadata,
		const int ruleset_fd)
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
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = ACCESS_RO,
		},
		{
			.path = file_s2d2,
			.access = ACCESS_RO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Tests on a directory. */
	test_path(_metadata, "/", -1);
	test_path(_metadata, dir_s1d1, -1);
	test_path(_metadata, file_s1d1, -1);
	test_path(_metadata, dir_s1d2, 0);
	test_path(_metadata, file_s1d2, 0);
	test_path(_metadata, dir_s1d3, 0);
	test_path(_metadata, file_s1d3, 0);

	/* Tests on a file. */
	test_path(_metadata, dir_s2d2, -1);
	test_path(_metadata, file_s2d2, 0);
}

TEST_F(layout1, unhandled_access)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = ACCESS_RO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/*
	 * Because the policy does not handle LANDLOCK_ACCESS_FS_CHROOT,
	 * chroot(2) should be allowed.
	 */
	ASSERT_EQ(0, chroot(dir_s1d1));
	ASSERT_EQ(0, chroot(dir_s1d2));
	ASSERT_EQ(0, chroot(dir_s1d3));
}

TEST_F(layout1, ruleset_overlap)
{
	const struct rule rules[] = {
		/* These rules should be ORed among them. */
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{},
	};
	int open_fd;
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, open(file_s1d1, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, open(dir_s1d1, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	open_fd = open(file_s1d2, O_WRONLY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	EXPECT_EQ(0, close(open_fd));
	open_fd = open(dir_s1d2, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	EXPECT_EQ(0, close(open_fd));

	open_fd = open(file_s1d3, O_WRONLY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	EXPECT_EQ(0, close(open_fd));
	open_fd = open(dir_s1d3, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	EXPECT_EQ(0, close(open_fd));
}

TEST_F(layout1, inherit_superset)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE |
				LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{},
	};
	int open_fd;
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);

	ASSERT_EQ(-1, open(file_s1d1, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, open(dir_s1d1, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	/* Write access is forbidden. */
	ASSERT_EQ(-1, open(file_s1d2, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	/* Readdir access is allowed. */
	open_fd = open(dir_s1d2, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/* Write access is forbidden. */
	ASSERT_EQ(-1, open(file_s1d3, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	/* Readdir access is allowed. */
	open_fd = open(dir_s1d3, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/*
	 * Tests shared rule extension: the following rules should not grant
	 * any new access, only remove some.  Once enforced, these rules are
	 * ANDed with the previous ones.
	 */
	add_path_beneath(_metadata, ruleset_fd, LANDLOCK_ACCESS_FS_WRITE_FILE,
			dir_s1d2);
	/*
	 * According to ruleset_fd, dir_s1d2 should now have the
	 * LANDLOCK_ACCESS_FS_READ_FILE and LANDLOCK_ACCESS_FS_WRITE_FILE
	 * access rights (even if this directory is opened a second time).
	 * However, when enforcing this updated ruleset, the ruleset tied to
	 * the current process (i.e. its domain) will still only have the
	 * dir_s1d2 with LANDLOCK_ACCESS_FS_READ_FILE and
	 * LANDLOCK_ACCESS_FS_READ_DIR accesses, but
	 * LANDLOCK_ACCESS_FS_WRITE_FILE must not be allowed because it would
	 * be a privilege escalation.
	 */
	enforce_ruleset(_metadata, ruleset_fd);

	/* Same tests and results as above. */
	ASSERT_EQ(-1, open(file_s1d1, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, open(dir_s1d1, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	/* It is still forbidden to write in file_s1d2. */
	ASSERT_EQ(-1, open(file_s1d2, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	/* Readdir access is still allowed. */
	open_fd = open(dir_s1d2, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/* It is still forbidden to write in file_s1d3. */
	ASSERT_EQ(-1, open(file_s1d3, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	/* Readdir access is still allowed. */
	open_fd = open(dir_s1d3, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/*
	 * Try to get more privileges by adding new access rights to the parent
	 * directory: dir_s1d1.
	 */
	add_path_beneath(_metadata, ruleset_fd, ACCESS_RW, dir_s1d1);
	enforce_ruleset(_metadata, ruleset_fd);

	/* Same tests and results as above. */
	ASSERT_EQ(-1, open(file_s1d1, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, open(dir_s1d1, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	/* It is still forbidden to write in file_s1d2. */
	ASSERT_EQ(-1, open(file_s1d2, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	/* Readdir access is still allowed. */
	open_fd = open(dir_s1d2, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/* It is still forbidden to write in file_s1d3. */
	ASSERT_EQ(-1, open(file_s1d3, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	/* Readdir access is still allowed. */
	open_fd = open(dir_s1d3, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/*
	 * Now, dir_s1d3 get a new rule tied to it, only allowing
	 * LANDLOCK_ACCESS_FS_WRITE_FILE.  The (kernel internal) difference is
	 * that there was no rule tied to it before.
	 */
	add_path_beneath(_metadata, ruleset_fd, LANDLOCK_ACCESS_FS_WRITE_FILE,
			dir_s1d3);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/*
	 * Same tests and results as above, except for open(dir_s1d3) which is
	 * now denied because the new rule mask the rule previously inherited
	 * from dir_s1d2.
	 */

	/* Same tests and results as above. */
	ASSERT_EQ(-1, open(file_s1d1, O_WRONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, open(dir_s1d1, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	/* It is still forbidden to write in file_s1d2. */
	ASSERT_EQ(-1, open(file_s1d2, O_WRONLY | O_CLOEXEC));
	/* Readdir access is still allowed. */
	open_fd = open(dir_s1d2, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_NE(-1, open_fd);
	ASSERT_EQ(0, close(open_fd));

	/* It is still forbidden to write in file_s1d3. */
	ASSERT_EQ(-1, open(file_s1d3, O_WRONLY | O_CLOEXEC));
	open_fd = open(dir_s1d3, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	/* Readdir of dir_s1d3 is now forbidden too. */
	ASSERT_EQ(-1, open_fd);
	ASSERT_EQ(EACCES, errno);
}

TEST_F(layout1, rule_on_mountpoint)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d1,
			.access = ACCESS_RO,
		},
		{
			/* dir_s3d2 is a mount point. */
			.path = dir_s3d2,
			.access = ACCESS_RO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, dir_s1d1, 0);

	test_path(_metadata, dir_s2d1, -1);

	test_path(_metadata, dir_s3d1, -1);
	test_path(_metadata, dir_s3d2, 0);
	test_path(_metadata, dir_s3d3, 0);
}

TEST_F(layout1, rule_over_mountpoint)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d1,
			.access = ACCESS_RO,
		},
		{
			/* dir_s3d2 is a mount point. */
			.path = dir_s3d1,
			.access = ACCESS_RO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, dir_s1d1, 0);

	test_path(_metadata, dir_s2d1, -1);

	test_path(_metadata, dir_s3d1, 0);
	test_path(_metadata, dir_s3d2, 0);
	test_path(_metadata, dir_s3d3, 0);
}

/*
 * This test verifies that we can apply a landlock rule on the root (/), it
 * might require special handling.
 */
TEST_F(layout1, rule_over_root)
{
	const struct rule rules[] = {
		{
			.path = "/",
			.access = ACCESS_RO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, "/", 0);
	test_path(_metadata, dir_s1d1, 0);
}

TEST_F(layout1, rule_inside_mount_ns)
{
	const struct rule rules[] = {
		{
			.path = "s3d3",
			.access = ACCESS_RO,
		},
		{},
	};
	int ruleset_fd;

	ASSERT_NE(-1, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	ASSERT_NE(-1, syscall(SYS_pivot_root, dir_s3d2, dir_s3d3)) {
		TH_LOG("Failed to pivot_root into \"%s\": %s\n", dir_s3d2,
				strerror(errno));
	};
	ASSERT_NE(-1, chdir("/"));

	ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);
	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_path(_metadata, "s3d3", 0);
	test_path(_metadata, "/", -1);
}

TEST_F(layout1, mount_and_pivot)
{
	const struct rule rules[] = {
		{
			.path = dir_s3d2,
			.access = ACCESS_RO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	ASSERT_EQ(-1, syscall(SYS_pivot_root, dir_s3d2, dir_s3d3));
}

enum relative_access {
	REL_OPEN,
	REL_CHDIR,
	REL_CHROOT_ONLY,
	REL_CHROOT_CHDIR,
};

static void test_relative_path(struct __test_metadata *const _metadata,
		const enum relative_access rel)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = ACCESS_RO,
		},
		{
			.path = dir_s2d2,
			.access = ACCESS_RO,
		},
		{},
	};
	int dirfd;
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_NE(-1, ruleset_fd);
	switch (rel) {
	case REL_OPEN:
	case REL_CHDIR:
		break;
	case REL_CHROOT_ONLY:
		ASSERT_EQ(0, chdir(dir_s2d2));
		break;
	case REL_CHROOT_CHDIR:
		ASSERT_EQ(0, chdir(dir_s1d2));
		break;
	default:
		ASSERT_TRUE(false);
		return;
	}
	enforce_ruleset(_metadata, ruleset_fd);

	switch (rel) {
	case REL_OPEN:
		dirfd = open(dir_s1d2, O_DIRECTORY);
		ASSERT_NE(-1, dirfd);
		break;
	case REL_CHDIR:
		ASSERT_NE(-1, chdir(dir_s1d2));
		dirfd = AT_FDCWD;
		break;
	case REL_CHROOT_ONLY:
		/* Do chroot into dir_s1d2 (relative to dir_s2d2). */
		ASSERT_NE(-1, chroot("../../s1d1/s1d2")) {
			TH_LOG("Failed to chroot: %s\n", strerror(errno));
		}
		dirfd = AT_FDCWD;
		break;
	case REL_CHROOT_CHDIR:
		/* Do chroot into dir_s1d2. */
		ASSERT_NE(-1, chroot(".")) {
			TH_LOG("Failed to chroot: %s\n", strerror(errno));
		}
		dirfd = AT_FDCWD;
		break;
	}

	test_path_rel(_metadata, dirfd, "..",
			(rel == REL_CHROOT_CHDIR) ? 0 : -1);
	test_path_rel(_metadata, dirfd, ".", 0);

	if (rel == REL_CHROOT_ONLY)
		/* The current directory is dir_s2d2. */
		test_path_rel(_metadata, dirfd, "./s2d3", 0);
	else
		/* The current directory is dir_s1d2. */
		test_path_rel(_metadata, dirfd, "./s1d3", 0);

	if (rel != REL_CHROOT_CHDIR) {
		test_path_rel(_metadata, dirfd, "../../s1d1", -1);
		test_path_rel(_metadata, dirfd, "../../s1d1/s1d2", 0);
		test_path_rel(_metadata, dirfd, "../../s1d1/s1d2/s1d3", 0);

		test_path_rel(_metadata, dirfd, "../../s2d1", -1);
		test_path_rel(_metadata, dirfd, "../../s2d1/s2d2", 0);
		test_path_rel(_metadata, dirfd, "../../s2d1/s2d2/s2d3", 0);
	}

	if (rel == REL_OPEN)
		EXPECT_EQ(0, close(dirfd));
	EXPECT_EQ(0, close(ruleset_fd));
}

TEST_F(layout1, relative_open)
{
	test_relative_path(_metadata, REL_OPEN);
}

TEST_F(layout1, relative_chdir)
{
	test_relative_path(_metadata, REL_CHDIR);
}

TEST_F(layout1, relative_chroot_only)
{
	test_relative_path(_metadata, REL_CHROOT_ONLY);
}

TEST_F(layout1, relative_chroot_chdir)
{
	test_relative_path(_metadata, REL_CHROOT_CHDIR);
}

TEST_F(layout1, chroot)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_CHROOT,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_CHROOT, rules);

	ASSERT_NE(-1, ruleset_fd);

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, chroot(dir_s1d1));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, chroot(dir_s1d2)) {
		TH_LOG("Failed to chroot into \"%s\": %s\n", file_s1d2,
				strerror(errno));
	};
	/* This chroot still works because we didn't chdir(dir_s1d2). */
	ASSERT_EQ(0, chroot(dir_s1d3));
}

static void copy_binary(struct __test_metadata *const _metadata,
		const char *const dst_path)
{
	int dst_fd, src_fd;
	struct stat statbuf;

	dst_fd = open(dst_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	ASSERT_LE(0, dst_fd) {
		TH_LOG("Failed to open \"%s\": %s\n", dst_path,
				strerror(errno));
	}
	src_fd = open(BINARY_PATH, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, src_fd) {
		TH_LOG("Failed to open \"" BINARY_PATH "\": %s\n",
				strerror(errno));
	}
	ASSERT_EQ(0, fstat(src_fd, &statbuf));
	ASSERT_LE(0, sendfile(dst_fd, src_fd, 0, statbuf.st_size));
	ASSERT_EQ(0, close(src_fd));
	ASSERT_EQ(0, close(dst_fd));
}

static void test_execute(struct __test_metadata *const _metadata,
		const char *const path, const int ret)
{
	int status;
	char *const argv[] = {(char *)path, NULL};
	const pid_t child = fork();

	ASSERT_LE(0, child);
	if (child == 0) {
		ASSERT_EQ(ret, execve(path, argv, NULL)) {
			TH_LOG("Failed to execute \"%s\": %s\n", path,
					strerror(errno));
		};
		ASSERT_EQ(EACCES, errno);
		_exit(_metadata->passed ? EXIT_SUCCESS : EXIT_FAILURE);
		return;
	}
	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_EQ(1, WIFEXITED(status));
	ASSERT_EQ(0, WEXITSTATUS(status)) {
		TH_LOG("Unexpected return code for \"%s\": %s\n", path,
				strerror(errno));
	};
}

TEST_F(layout1, execute)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d1,
			.access = LANDLOCK_ACCESS_FS_EXECUTE,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_EXECUTE, rules);

	ASSERT_NE(-1, ruleset_fd);
	copy_binary(_metadata, file_s1d1);
	copy_binary(_metadata, file_s1d2);
	copy_binary(_metadata, file_s1d3);

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_execute(_metadata, file_s1d1, -1);
	test_execute(_metadata, file_s1d2, 0);
	test_execute(_metadata, file_s1d3, 0);
}

TEST_F(layout1, link_to)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_LINK_TO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_LINK_TO, rules);

	ASSERT_NE(-1, ruleset_fd);

	ASSERT_EQ(0, unlink(file_s1d1));
	ASSERT_EQ(0, unlink(file_s1d2));
	ASSERT_EQ(0, unlink(file_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, link(file_s2d1, file_s1d1));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, link(file_s2d1, file_s1d2)) {
		TH_LOG("Failed to link file to \"%s\": %s\n", file_s1d2,
				strerror(errno));
	};
	ASSERT_EQ(0, link(file_s2d1, file_s1d3));
}

static void test_rename(struct __test_metadata *const _metadata)
{
	/* Renames files. */
	ASSERT_EQ(-1, rename(file_s2d1, file_s1d1));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, rename(file_s2d2, file_s1d2)) {
		TH_LOG("Failed to rename file \"%s\": %s\n", file_s2d3,
				strerror(errno));
	};
	ASSERT_EQ(0, rename(file_s2d3, file_s1d3));

	/* Renames directories (reverse order). */
	ASSERT_EQ(0, unlink(file_s1d3));
	ASSERT_EQ(0, rename(dir_s2d3, dir_s1d3)) {
		TH_LOG("Failed to rename directory \"%s\": %s\n", dir_s2d3,
				strerror(errno));
	};

	ASSERT_EQ(0, rmdir(dir_s1d3));
	ASSERT_EQ(0, unlink(file_s1d2));
	ASSERT_EQ(-1, rename(dir_s2d2, dir_s1d2));
	ASSERT_EQ(EACCES, errno);

	ASSERT_EQ(0, rmdir(dir_s1d2));
	ASSERT_EQ(0, unlink(file_s1d1));
	ASSERT_EQ(-1, rename(dir_s2d1, dir_s1d1));
	ASSERT_EQ(EACCES, errno);
}

TEST_F(layout1, rename_from)
{
	const struct rule rules[] = {
		{
			.path = dir_s2d2,
			.access = LANDLOCK_ACCESS_FS_RENAME_FROM,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_RENAME_FROM, rules);

	ASSERT_NE(-1, ruleset_fd);

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_rename(_metadata);
}

TEST_F(layout1, rename_to)
{
	/*
	 * Same tests as layout1/rename_from, except the rename_from access
	 * rule is on dir_s1d2.
	 */
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_RENAME_TO,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_RENAME_TO, rules);

	ASSERT_NE(-1, ruleset_fd);

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_rename(_metadata);
}

TEST_F(layout1, rmdir)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_RMDIR,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_RMDIR, rules);

	ASSERT_NE(-1, ruleset_fd);

	ASSERT_EQ(0, unlink(file_s1d1));
	ASSERT_EQ(0, unlink(file_s1d2));
	ASSERT_EQ(0, unlink(file_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, rmdir(dir_s1d3)) {
		TH_LOG("Failed to remove directory \"%s\": %s\n", file_s1d2,
				strerror(errno));
	}
	ASSERT_EQ(-1, rmdir(dir_s1d2));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, rmdir(dir_s1d1));
	ASSERT_EQ(EACCES, errno);
}

TEST_F(layout1, unlink)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_UNLINK,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_UNLINK, rules);

	ASSERT_NE(-1, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, unlink(file_s1d1));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, unlink(file_s1d2)) {
		TH_LOG("Failed to unlink file \"%s\": %s\n", file_s1d2,
				strerror(errno));
	};
	ASSERT_EQ(0, unlink(file_s1d3));
}

static void test_make_file(struct __test_metadata *const _metadata,
		const __u64 access, const mode_t mode, const dev_t dev)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = access,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata, access, rules);

	ASSERT_NE(-1, ruleset_fd);

	ASSERT_EQ(0, unlink(file_s1d1));
	ASSERT_EQ(0, unlink(file_s1d2));
	ASSERT_EQ(0, unlink(file_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, mknod(file_s1d1, mode | 0400, dev));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, mknod(file_s1d2, mode | 0400, dev)) {
		TH_LOG("Failed to make file \"%s\": %s\n",
				file_s1d2, strerror(errno));
	};
	ASSERT_EQ(0, mknod(file_s1d3, mode | 0400, dev));
}

TEST_F(layout1, make_char)
{
	/* Creates a /dev/null device. */
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_CHAR, S_IFCHR,
			major(1) | minor(3));
}

TEST_F(layout1, make_block)
{
	/* Creates a /dev/loop0 device. */
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_BLOCK, S_IFBLK,
			major(7) | minor(0));
}

TEST_F(layout1, make_reg)
{
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_REG, S_IFREG, 0);
}

TEST_F(layout1, make_sock)
{
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_SOCK, S_IFSOCK, 0);
}

TEST_F(layout1, make_fifo)
{
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_FIFO, S_IFIFO, 0);
}

TEST_F(layout1, make_sym)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_MAKE_SYM,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_MAKE_SYM, rules);

	ASSERT_NE(-1, ruleset_fd);

	ASSERT_EQ(0, unlink(file_s1d1));
	ASSERT_EQ(0, unlink(file_s1d2));
	ASSERT_EQ(0, unlink(file_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, symlink("none", file_s1d1));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, symlink("none", file_s1d2)) {
		TH_LOG("Failed to make symlink \"%s\": %s\n",
				file_s1d2, strerror(errno));
	};
	ASSERT_EQ(0, symlink("none", file_s1d3));
}

TEST_F(layout1, make_dir)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_MAKE_DIR,
		},
		{},
	};
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_MAKE_DIR, rules);

	ASSERT_NE(-1, ruleset_fd);

	ASSERT_EQ(0, unlink(file_s1d1));
	ASSERT_EQ(0, unlink(file_s1d2));
	ASSERT_EQ(0, unlink(file_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Uses file_* as directory names. */
	ASSERT_EQ(-1, mkdir(file_s1d1, 0700));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, mkdir(file_s1d2, 0700)) {
		TH_LOG("Failed to make directory \"%s\": %s\n",
				file_s1d2, strerror(errno));
	};
	ASSERT_EQ(0, mkdir(file_s1d3, 0700));
}

TEST(cleanup)
{
	cleanup_layout1();
}

TEST_HARNESS_MAIN
