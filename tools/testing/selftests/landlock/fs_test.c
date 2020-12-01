// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Filesystem
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/landlock.h>
#include <sched.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "common.h"

#define TMP_DIR "tmp/"
#define FILE_1 "file1"
#define FILE_2 "file2"
#define BINARY_PATH "./true"

/* Paths (sibling number and depth) */
static const char dir_s1d1[] = TMP_DIR "s1d1";
static const char file1_s1d1[] = TMP_DIR "s1d1/" FILE_1;
static const char file2_s1d1[] = TMP_DIR "s1d1/" FILE_2;
static const char dir_s1d2[] = TMP_DIR "s1d1/s1d2";
static const char file1_s1d2[] = TMP_DIR "s1d1/s1d2/" FILE_1;
static const char file2_s1d2[] = TMP_DIR "s1d1/s1d2/" FILE_2;
static const char dir_s1d3[] = TMP_DIR "s1d1/s1d2/s1d3";
static const char file1_s1d3[] = TMP_DIR "s1d1/s1d2/s1d3/" FILE_1;
static const char file2_s1d3[] = TMP_DIR "s1d1/s1d2/s1d3/" FILE_2;

static const char dir_s2d1[] = TMP_DIR "s2d1";
static const char file1_s2d1[] = TMP_DIR "s2d1/" FILE_1;
static const char dir_s2d2[] = TMP_DIR "s2d1/s2d2";
static const char file1_s2d2[] = TMP_DIR "s2d1/s2d2/" FILE_1;
static const char dir_s2d3[] = TMP_DIR "s2d1/s2d2/s2d3";
static const char file1_s2d3[] = TMP_DIR "s2d1/s2d2/s2d3/" FILE_1;
static const char file2_s2d3[] = TMP_DIR "s2d1/s2d2/s2d3/" FILE_2;

static const char dir_s3d1[] = TMP_DIR "s3d1";
/* dir_s3d2 is a mount point. */
static const char dir_s3d2[] = TMP_DIR "s3d1/s3d2";
static const char dir_s3d3[] = TMP_DIR "s3d1/s3d2/s3d3";

static void create_dir_and_file(struct __test_metadata *const _metadata,
		const char *const dir_path)
{
	int file_fd;
	char *const file1_path = alloca(strlen(dir_path) + sizeof(FILE_1) + 2);
	char *const file2_path = alloca(strlen(dir_path) + sizeof(FILE_2) + 2);

	strcpy(file1_path, dir_path);
	strcat(file1_path, "/");
	strcat(file1_path, FILE_1);

	strcpy(file2_path, dir_path);
	strcat(file2_path, "/");
	strcat(file2_path, FILE_2);

	ASSERT_EQ(0, mkdir(dir_path, 0700)) {
		TH_LOG("Failed to create directory \"%s\": %s", dir_path,
				strerror(errno));
	}
	file_fd = open(file1_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			0700);
	ASSERT_LE(0, file_fd);
	ASSERT_EQ(0, close(file_fd));

	file_fd = open(file2_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			0700);
	ASSERT_LE(0, file_fd);
	ASSERT_EQ(0, close(file_fd));
}

static void delete_dir_and_file(const char *const dir_path)
{
	char *const file1_path = alloca(strlen(dir_path) +
			sizeof(FILE_1) + 2);
	char *const file2_path = alloca(strlen(dir_path) +
			sizeof(FILE_2) + 2);

	strcpy(file1_path, dir_path);
	strcat(file1_path, "/");
	strcat(file1_path, FILE_1);

	strcpy(file2_path, dir_path);
	strcat(file2_path, "/");
	strcat(file2_path, FILE_2);

	unlink(file1_path);
	unlink(file2_path);
	/* file1_path may be a directory, cf. layout1/make_directory. */
	rmdir(file1_path);
	rmdir(dir_path);
}

static void cleanup_layout1(struct __test_metadata *const _metadata)
{
	delete_dir_and_file(dir_s1d3);
	delete_dir_and_file(dir_s1d2);
	delete_dir_and_file(dir_s1d1);

	delete_dir_and_file(dir_s2d3);
	delete_dir_and_file(dir_s2d2);
	delete_dir_and_file(dir_s2d1);

	delete_dir_and_file(dir_s3d3);
	set_cap(_metadata, CAP_SYS_ADMIN);
	umount(dir_s3d2);
	clear_cap(_metadata, CAP_SYS_ADMIN);
	delete_dir_and_file(dir_s3d2);
	delete_dir_and_file(dir_s3d1);

	delete_dir_and_file(TMP_DIR);
}

FIXTURE(layout1) {
};

FIXTURE_SETUP(layout1)
{
	disable_caps(_metadata);
	cleanup_layout1(_metadata);

	/* Do not pollute the rest of the system. */
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, unshare(CLONE_NEWNS));
	clear_cap(_metadata, CAP_SYS_ADMIN);
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
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, mount("tmp", dir_s3d2, "tmpfs", 0, "size=4m,mode=700"));
	clear_cap(_metadata, CAP_SYS_ADMIN);
	create_dir_and_file(_metadata, dir_s3d3);
}

FIXTURE_TEARDOWN(layout1)
{
	/*
	 * cleanup_layout1() would be denied here, use TEST(cleanup) instead.
	 */
}

/*
 * This helper enables to use the ASSERT_* macros and print the line number
 * pointing to the test caller.
 */
static int test_open_rel(const int dirfd, const char *const path, const int flags)
{
	int fd;

	/* Works with file and directories. */
	fd = openat(dirfd, path, flags | O_CLOEXEC);
	if (fd < 0)
		return errno;
	if (close(fd) == 0)
		return 0;
	/*
	 * Mixing error codes from close(2) and open(2) should not lead to any
	 * (access type) confusion for this test.
	 */
	return errno;
}

static int test_open(const char *const path, const int flags)
{
	return test_open_rel(AT_FDCWD, path, flags);
}

TEST_F(layout1, no_restriction)
{
	ASSERT_EQ(0, test_open(dir_s1d1, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s1d1, O_RDONLY));
	ASSERT_EQ(0, test_open(file2_s1d1, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s1d2, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s1d2, O_RDONLY));
	ASSERT_EQ(0, test_open(file2_s1d2, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDONLY));

	ASSERT_EQ(0, test_open(dir_s2d1, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s2d1, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s2d2, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s2d2, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s2d3, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s2d3, O_RDONLY));

	ASSERT_EQ(0, test_open(dir_s3d1, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s3d2, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s3d3, O_RDONLY));
}

TEST_F(layout1, inval)
{
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_WRITE_FILE,
		.parent_fd = -1,
	};
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_WRITE_FILE,
	};
	int ruleset_fd;

	path_beneath.parent_fd = open(dir_s1d2, O_PATH | O_DIRECTORY |
			O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);

	ruleset_fd = open(dir_s1d1, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, ruleset_fd);
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	/* Returns EBADF because ruleset_fd contains O_PATH. */
	ASSERT_EQ(EBADF, errno);
	ASSERT_EQ(0, close(ruleset_fd));

	ruleset_fd = open(dir_s1d1, O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, ruleset_fd);
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	/* Returns EBADFD because ruleset_fd is not a valid ruleset. */
	ASSERT_EQ(EBADFD, errno);
	ASSERT_EQ(0, close(ruleset_fd));

	/* Gets a real ruleset. */
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	ASSERT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Tests without O_PATH. */
	path_beneath.parent_fd = open(dir_s1d2, O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	ASSERT_EQ(EBADFD, errno);
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Checks unhandled allowed_access. */
	path_beneath.parent_fd = open(dir_s1d2, O_PATH | O_DIRECTORY |
			O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);

	/* Test with legitimate values. */
	path_beneath.allowed_access |= LANDLOCK_ACCESS_FS_EXECUTE;
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	ASSERT_EQ(EINVAL, errno);
	path_beneath.allowed_access &= ~LANDLOCK_ACCESS_FS_EXECUTE;

	/* Test with unknown (64-bits) value. */
	path_beneath.allowed_access |= (1ULL << 60);
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	ASSERT_EQ(EINVAL, errno);
	path_beneath.allowed_access &= ~(1ULL << 60);

	/* Test with no access. */
	path_beneath.allowed_access = 0;
	ASSERT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	path_beneath.allowed_access &= ~(1ULL << 60);

	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Enforces the ruleset. */
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_enforce_ruleset_current(ruleset_fd, 0));

	ASSERT_EQ(0, close(ruleset_fd));
}

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE)

#define ACCESS_LAST LANDLOCK_ACCESS_FS_MAKE_SYM

#define ACCESS_ALL ( \
	ACCESS_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	ACCESS_LAST)

TEST_F(layout1, file_access_rights)
{
	__u64 access;
	int err;
	struct landlock_path_beneath_attr path_beneath = {};
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = ACCESS_ALL,
	};
	const int ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);

	ASSERT_LE(0, ruleset_fd);

	/* Tests access rights for files. */
	path_beneath.parent_fd = open(file1_s1d2, O_PATH | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	for (access = 1; access <= ACCESS_LAST; access <<= 1) {
		path_beneath.allowed_access = access;
		err = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0);
		if ((access | ACCESS_FILE) == ACCESS_FILE) {
			ASSERT_EQ(0, err);
		} else {
			ASSERT_EQ(-1, err);
			ASSERT_EQ(EINVAL, errno);
		}
	}
	ASSERT_EQ(0, close(path_beneath.parent_fd));
}

static void add_path_beneath(struct __test_metadata *const _metadata,
		const int ruleset_fd, const __u64 allowed_access,
		const char *const path)
{
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = allowed_access,
	};

	path_beneath.parent_fd = open(path, O_PATH | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd) {
		TH_LOG("Failed to open directory \"%s\": %s", path,
				strerror(errno));
	}
	ASSERT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0)) {
		TH_LOG("Failed to update the ruleset with \"%s\": %s", path,
				strerror(errno));
	}
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
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = handled_access_fs,
	};

	ASSERT_NE(NULL, rules) {
		TH_LOG("No rule list");
	}
	ASSERT_NE(NULL, rules[0].path) {
		TH_LOG("Empty rule list");
	}

	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd) {
		TH_LOG("Failed to create a ruleset: %s", strerror(errno));
	}

	for (i = 0; rules[i].path; i++) {
		add_path_beneath(_metadata, ruleset_fd, rules[i].access,
				rules[i].path);
	}
	return ruleset_fd;
}

static void enforce_ruleset(struct __test_metadata *const _metadata,
		const int ruleset_fd)
{
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_enforce_ruleset_current(ruleset_fd, 0)) {
		TH_LOG("Failed to enforce ruleset: %s", strerror(errno));
	}
}

TEST_F(layout1, proc_nsfs)
{
	const struct rule rules[] = {
		{
			.path = "/dev/null",
			.access = LANDLOCK_ACCESS_FS_READ_FILE |
				LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{}
	};
	struct landlock_path_beneath_attr path_beneath;
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access |
			LANDLOCK_ACCESS_FS_READ_DIR, rules);

	ASSERT_LE(0, ruleset_fd);
	ASSERT_EQ(0, test_open("/proc/self/ns/mnt", O_RDONLY));

	enforce_ruleset(_metadata, ruleset_fd);

	ASSERT_EQ(EACCES, test_open("/", O_RDONLY));
	ASSERT_EQ(EACCES, test_open("/dev", O_RDONLY));
	ASSERT_EQ(0, test_open("/dev/null", O_RDONLY));
	ASSERT_EQ(EACCES, test_open("/dev/full", O_RDONLY));

	ASSERT_EQ(EACCES, test_open("/proc", O_RDONLY));
	ASSERT_EQ(EACCES, test_open("/proc/self", O_RDONLY));
	ASSERT_EQ(EACCES, test_open("/proc/self/ns", O_RDONLY));
	/*
	 * Because nsfs is an internal filesystem, /proc/self/ns/mnt is a
	 * disconnected path.  Such path cannot be identified and must then be
	 * allowed.
	 */
	ASSERT_EQ(0, test_open("/proc/self/ns/mnt", O_RDONLY));

	/*
	 * Checks that it is not possible to add nsfs-like filesystem
	 * references to a ruleset.
	 */
	path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_WRITE_FILE,
	path_beneath.parent_fd = open("/proc/self/ns/mnt", O_PATH | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath, 0));
	ASSERT_EQ(EBADFD, errno);
	ASSERT_EQ(0, close(path_beneath.parent_fd));
}

static void drop_privileges(struct __test_metadata *const _metadata)
{
	cap_t caps;
	const cap_value_t cap_val = CAP_SYS_ADMIN;

	caps = cap_get_proc();
	ASSERT_NE(NULL, caps);
	ASSERT_EQ(0, cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_val,
				CAP_CLEAR));
	ASSERT_EQ(0, cap_set_proc(caps));
	ASSERT_EQ(0, cap_free(caps));
}

TEST_F(layout1, unpriv) {
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = ACCESS_RO,
		},
		{}
	};
	int ruleset_fd;

	drop_privileges(_metadata);
	ruleset_fd = create_ruleset(_metadata, ACCESS_RO, rules);
	ASSERT_LE(0, ruleset_fd);
	ASSERT_EQ(-1, landlock_enforce_ruleset_current(ruleset_fd, 0));
	ASSERT_EQ(EPERM, errno);

	/* enforce_ruleset() calls prctl(no_new_privs). */
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));
}

TEST_F(layout1, whitelist)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = ACCESS_RO,
		},
		{
			.path = file1_s2d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE |
				LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);
	char buf;
	int reg_fd;

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Tests on a directory. */
	ASSERT_EQ(EACCES, test_open("/", O_RDONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s1d2, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s1d2, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDONLY));

	/* Tests on a file. */
	ASSERT_EQ(EACCES, test_open(dir_s2d2, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s2d2, O_RDONLY));

	/* Checks effective read and write actions. */
	reg_fd = open(file1_s2d2, O_RDWR | O_CLOEXEC);
	ASSERT_LE(0, reg_fd);
	ASSERT_EQ(1, write(reg_fd, ".", 1));
	ASSERT_LE(0, lseek(reg_fd, 0, SEEK_SET));
	ASSERT_EQ(1, read(reg_fd, &buf, 1));
	ASSERT_EQ('.', buf);
	ASSERT_EQ(0, close(reg_fd));

	/* Just in case, double-checks effective actions. */
	reg_fd = open(file1_s2d2, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, reg_fd);
	ASSERT_EQ(-1, write(reg_fd, &buf, 1));
	ASSERT_EQ(EBADF, errno);
	ASSERT_EQ(0, close(reg_fd));
}

TEST_F(layout1, unhandled_access)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = ACCESS_RO,
		},
		{}
	};
	/* Here, we only handle read accesses, not write accesses. */
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RO, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/*
	 * Because the policy does not handle LANDLOCK_ACCESS_FS_WRITE_FILE,
	 * opening for write-only should be allowed, but not read-write.
	 */
	ASSERT_EQ(0, test_open(file1_s1d1, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_RDWR));

	ASSERT_EQ(0, test_open(file1_s1d2, O_WRONLY));
	ASSERT_EQ(0, test_open(file1_s1d2, O_RDWR));
}

TEST_F(layout1, ruleset_overlap)
{
	const struct rule rules[] = {
		/* These rules should be ORed among them. */
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE |
				LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE |
				LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks s1d1 hierarchy. */
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_RDWR));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY | O_DIRECTORY));

	/* Checks s1d2 hierarchy. */
	ASSERT_EQ(0, test_open(file1_s1d2, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s1d2, O_WRONLY));
	ASSERT_EQ(0, test_open(file1_s1d2, O_RDWR));
	ASSERT_EQ(0, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));

	/* Checks s1d3 hierarchy. */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDONLY));
	ASSERT_EQ(0, test_open(file1_s1d3, O_WRONLY));
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDWR));
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY | O_DIRECTORY));
}

TEST_F(layout1, interleaved_masked_accesses)
{
	/*
	 * Checks overly restrictive rules:
	 * layer 1: allows R  s1d1/s1d2/s1d3/file1
	 * layer 2: allows R  s1d1/s1d2/s1d3
	 *          denies R  s1d1/s1d2
	 * layer 3: allows R  s1d1
	 * layer 4: denies  W s1d1/s1d2
	 * layer 5: allows R  s1d1/s1d2
	 * layer 6: denies R  s1d1/s1d2
	 */
	const struct rule layer1_read[] = {
		/* Allows access to file1_s1d3 with the first layer. */
		{
			.path = file1_s1d3,
			.access = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		{}
	};
	const struct rule layer2_read[] = {
		/* Start by granting access via its parent directory... */
		{
			.path = dir_s1d3,
			.access = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		/* ...but also denies access via its grandparent directory. */
		{
			.path = dir_s1d2,
			.access = 0,
		},
		{}
	};
	const struct rule layer3_read[] = {
		/* Allows access via its great-grandparent directory. */
		{
			.path = dir_s1d1,
			.access = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		{}
	};
	const struct rule layer4_write[] = {
		/*
		 * Try to confuse the deny access by denying write (but not
		 * read) access via its grandparent directory.
		 */
		{
			.path = dir_s1d2,
			.access = 0,
		},
		{}
	};
	const struct rule layer5_read[] = {
		/*
		 * Try to override layer2's deny read access by explicitly
		 * allowing read access via file1_s1d3's grandparent.
		 */
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		{}
	};
	const struct rule layer6_read[] = {
		/*
		 * Finally, denies read access to file1_s1d3 via its
		 * grandparent.
		 */
		{
			.path = dir_s1d2,
			.access = 0,
		},
		{}
	};
	int ruleset_fd;

	ruleset_fd = create_ruleset(_metadata, LANDLOCK_ACCESS_FS_READ_FILE,
			layer1_read);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks that access is granted for file1_s1d3 with layer 1. */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDWR));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_RDONLY));
	ASSERT_EQ(0, test_open(file2_s1d3, O_WRONLY));

	ruleset_fd = create_ruleset(_metadata, LANDLOCK_ACCESS_FS_READ_FILE,
			layer2_read);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks that previous access rights are unchanged with layer 2. */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDWR));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_RDONLY));
	ASSERT_EQ(0, test_open(file2_s1d3, O_WRONLY));

	ruleset_fd = create_ruleset(_metadata, LANDLOCK_ACCESS_FS_READ_FILE,
			layer3_read);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks that previous access rights are unchanged with layer 3. */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDWR));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_RDONLY));
	ASSERT_EQ(0, test_open(file2_s1d3, O_WRONLY));

	/* This time, creates a write-only rule. */
	ruleset_fd = create_ruleset(_metadata, LANDLOCK_ACCESS_FS_WRITE_FILE,
			layer4_write);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/*
	 * Checks that the only change with layer 4 is that write access is
	 * denied.
	 */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_WRONLY));

	ruleset_fd = create_ruleset(_metadata, LANDLOCK_ACCESS_FS_READ_FILE,
			layer5_read);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks that previous access rights are unchanged with layer 5. */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_RDONLY));

	ruleset_fd = create_ruleset(_metadata, LANDLOCK_ACCESS_FS_READ_FILE,
			layer6_read);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks read access is now denied with layer 6. */
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(file2_s1d3, O_RDONLY));
}

TEST_F(layout1, inherit_subset)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE |
				LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);

	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY | O_DIRECTORY));

	/* Write access is forbidden. */
	ASSERT_EQ(EACCES, test_open(file1_s1d2, O_WRONLY));
	/* Readdir access is allowed. */
	ASSERT_EQ(0, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));

	/* Write access is forbidden. */
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_WRONLY));
	/* Readdir access is allowed. */
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY | O_DIRECTORY));

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
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY | O_DIRECTORY));

	/* It is still forbidden to write in file1_s1d2. */
	ASSERT_EQ(EACCES, test_open(file1_s1d2, O_WRONLY));
	/* Readdir access is still allowed. */
	ASSERT_EQ(0, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));

	/* It is still forbidden to write in file1_s1d3. */
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_WRONLY));
	/* Readdir access is still allowed. */
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY | O_DIRECTORY));

	/*
	 * Try to get more privileges by adding new access rights to the parent
	 * directory: dir_s1d1.
	 */
	add_path_beneath(_metadata, ruleset_fd, ACCESS_RW, dir_s1d1);
	enforce_ruleset(_metadata, ruleset_fd);

	/* Same tests and results as above. */
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY | O_DIRECTORY));

	/* It is still forbidden to write in file1_s1d2. */
	ASSERT_EQ(EACCES, test_open(file1_s1d2, O_WRONLY));
	/* Readdir access is still allowed. */
	ASSERT_EQ(0, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));

	/* It is still forbidden to write in file1_s1d3. */
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_WRONLY));
	/* Readdir access is still allowed. */
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY | O_DIRECTORY));

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
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_WRONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY | O_DIRECTORY));

	/* It is still forbidden to write in file1_s1d2. */
	ASSERT_EQ(EACCES, test_open(file1_s1d2, O_WRONLY));
	/* Readdir access is still allowed. */
	ASSERT_EQ(0, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));

	/* It is still forbidden to write in file1_s1d3. */
	ASSERT_EQ(EACCES, test_open(file1_s1d3, O_WRONLY));
	/* Readdir of dir_s1d3 is now forbidden too. */
	ASSERT_EQ(EACCES, test_open(dir_s1d3, O_RDONLY | O_DIRECTORY));
}

TEST_F(layout1, inherit_superset)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d3,
			.access = ACCESS_RO,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);

	/* Readdir access is denied for dir_s1d2. */
	ASSERT_EQ(EACCES, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));
	/* Readdir access is allowed for dir_s1d3. */
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY | O_DIRECTORY));
	/* File access is allowed for file1_s1d3. */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDONLY));

	/* Now dir_s1d2, parent of dir_s1d3, gets a new rule tied to it. */
	add_path_beneath(_metadata, ruleset_fd, LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_READ_DIR, dir_s1d2);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Readdir access is still denied for dir_s1d2. */
	ASSERT_EQ(EACCES, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));
	/* Readdir access is still allowed for dir_s1d3. */
	ASSERT_EQ(0, test_open(dir_s1d3, O_RDONLY | O_DIRECTORY));
	/* File access is still allowed for file1_s1d3. */
	ASSERT_EQ(0, test_open(file1_s1d3, O_RDONLY));
}

TEST_F(layout1, max_layers)
{
	int i, err;
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = ACCESS_RO,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	for (i = 0; i < 64; i++)
		enforce_ruleset(_metadata, ruleset_fd);

	for (i = 0; i < 2; i++) {
		err = landlock_enforce_ruleset_current(ruleset_fd, 0);
		ASSERT_EQ(-1, err);
		ASSERT_EQ(E2BIG, errno);
	}
	EXPECT_EQ(0, close(ruleset_fd));
}

TEST_F(layout1, empty_or_same_ruleset)
{
	struct landlock_ruleset_attr ruleset_attr = {};
	int ruleset_fd;

	/* Tests empty handled_access_fs. */
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);
	ASSERT_LE(-1, ruleset_fd);
	ASSERT_EQ(ENOMSG, errno);

	/* Enforces policy which deny read access to all files. */
	ruleset_attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s1d1, O_RDONLY));

	/* Nests a policy which deny read access to all directories. */
	ruleset_attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_DIR;
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY));

	/* Enforces a second time with the same ruleset. */
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));
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
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, test_open(dir_s1d1, O_RDONLY));

	ASSERT_EQ(EACCES, test_open(dir_s2d1, O_RDONLY));

	ASSERT_EQ(EACCES, test_open(dir_s3d1, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s3d2, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s3d3, O_RDONLY));
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
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, test_open(dir_s1d1, O_RDONLY));

	ASSERT_EQ(EACCES, test_open(dir_s2d1, O_RDONLY));

	ASSERT_EQ(0, test_open(dir_s3d1, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s3d2, O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s3d3, O_RDONLY));
}

/*
 * This test verifies that we can apply a landlock rule on the root directory
 * (which might require special handling).
 */
TEST_F(layout1, rule_over_root_allow_then_deny)
{
	struct rule rules[] = {
		{
			.path = "/",
			.access = ACCESS_RO,
		},
		{}
	};
	int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks allowed access. */
	ASSERT_EQ(0, test_open("/", O_RDONLY));
	ASSERT_EQ(0, test_open(dir_s1d1, O_RDONLY));

	rules[0].access = LANDLOCK_ACCESS_FS_READ_FILE;
	ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks denied access (on a directory). */
	ASSERT_EQ(EACCES, test_open("/", O_RDONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY));
}

TEST_F(layout1, rule_over_root_deny)
{
	const struct rule rules[] = {
		{
			.path = "/",
			.access = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks denied access (on a directory). */
	ASSERT_EQ(EACCES, test_open("/", O_RDONLY));
	ASSERT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY));
}

TEST_F(layout1, rule_inside_mount_ns)
{
	const struct rule rules[] = {
		{
			.path = "s3d3",
			.access = ACCESS_RO,
		},
		{}
	};
	int ruleset_fd;

	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	ASSERT_EQ(0, syscall(SYS_pivot_root, dir_s3d2, dir_s3d3)) {
		TH_LOG("Failed to pivot_root into \"%s\": %s", dir_s3d2,
				strerror(errno));
	};
	ASSERT_EQ(0, chdir("/"));
	clear_cap(_metadata, CAP_SYS_ADMIN);

	ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);
	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, test_open("s3d3", O_RDONLY));
	ASSERT_EQ(EACCES, test_open("/", O_RDONLY));
}

TEST_F(layout1, mount_and_pivot)
{
	const struct rule rules[] = {
		{
			.path = dir_s3d2,
			.access = ACCESS_RO,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	ASSERT_EQ(EPERM, errno);
	ASSERT_EQ(-1, syscall(SYS_pivot_root, dir_s3d2, dir_s3d3));
	ASSERT_EQ(EPERM, errno);
}

TEST_F(layout1, move_mount)
{
	const struct rule rules[] = {
		{
			.path = dir_s3d2,
			.access = ACCESS_RO,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);

	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	ASSERT_EQ(0, syscall(SYS_move_mount, AT_FDCWD, dir_s3d2, AT_FDCWD,
				dir_s1d2, 0)) {
		TH_LOG("Failed to move_mount: %s", strerror(errno));
	}
	ASSERT_EQ(0, syscall(SYS_move_mount, AT_FDCWD, dir_s1d2, AT_FDCWD,
				dir_s3d2, 0));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, syscall(SYS_move_mount, AT_FDCWD, dir_s3d2, AT_FDCWD,
				dir_s1d2, 0));
	ASSERT_EQ(EPERM, errno);
}

TEST_F(layout1, release_inodes)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d1,
			.access = ACCESS_RO,
		},
		{
			.path = dir_s3d2,
			.access = ACCESS_RO,
		},
		{
			.path = dir_s3d3,
			.access = ACCESS_RO,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
	/* Unmount a file hierarchy while it is being used by a ruleset. */
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, umount(dir_s3d2));
	clear_cap(_metadata, CAP_SYS_ADMIN);

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, test_open(file1_s1d1, O_RDONLY));
	ASSERT_EQ(EACCES, test_open(dir_s3d2, O_RDONLY));
	/* This dir_s3d3 would not be allowed and does not exist anyway. */
	ASSERT_EQ(ENOENT, test_open(dir_s3d3, O_RDONLY));
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
		{}
	};
	int dirfd;
	const int ruleset_fd = create_ruleset(_metadata, ACCESS_RW, rules);

	ASSERT_LE(0, ruleset_fd);
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

	set_cap(_metadata, CAP_SYS_CHROOT);
	enforce_ruleset(_metadata, ruleset_fd);

	switch (rel) {
	case REL_OPEN:
		dirfd = open(dir_s1d2, O_DIRECTORY);
		ASSERT_LE(0, dirfd);
		break;
	case REL_CHDIR:
		ASSERT_EQ(0, chdir(dir_s1d2));
		dirfd = AT_FDCWD;
		break;
	case REL_CHROOT_ONLY:
		/* Do chroot into dir_s1d2 (relative to dir_s2d2). */
		ASSERT_EQ(0, chroot("../../s1d1/s1d2")) {
			TH_LOG("Failed to chroot: %s", strerror(errno));
		}
		dirfd = AT_FDCWD;
		break;
	case REL_CHROOT_CHDIR:
		/* Do chroot into dir_s1d2. */
		ASSERT_EQ(0, chroot(".")) {
			TH_LOG("Failed to chroot: %s", strerror(errno));
		}
		dirfd = AT_FDCWD;
		break;
	}

	ASSERT_EQ((rel == REL_CHROOT_CHDIR) ? 0 : EACCES,
			test_open_rel(dirfd, "..", O_RDONLY));
	ASSERT_EQ(0, test_open_rel(dirfd, ".", O_RDONLY));

	if (rel == REL_CHROOT_ONLY) {
		/* The current directory is dir_s2d2. */
		ASSERT_EQ(0, test_open_rel(dirfd, "./s2d3", O_RDONLY));
	} else {
		/* The current directory is dir_s1d2. */
		ASSERT_EQ(0, test_open_rel(dirfd, "./s1d3", O_RDONLY));
	}

	if (rel != REL_CHROOT_CHDIR) {
		ASSERT_EQ(EACCES, test_open_rel(dirfd, "../../s1d1", O_RDONLY));
		ASSERT_EQ(0, test_open_rel(dirfd, "../../s1d1/s1d2", O_RDONLY));
		ASSERT_EQ(0, test_open_rel(dirfd, "../../s1d1/s1d2/s1d3", O_RDONLY));

		ASSERT_EQ(EACCES, test_open_rel(dirfd, "../../s2d1", O_RDONLY));
		ASSERT_EQ(0, test_open_rel(dirfd, "../../s2d1/s2d2", O_RDONLY));
		ASSERT_EQ(0, test_open_rel(dirfd, "../../s2d1/s2d2/s2d3", O_RDONLY));
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

static void copy_binary(struct __test_metadata *const _metadata,
		const char *const dst_path)
{
	int dst_fd, src_fd;
	struct stat statbuf;

	dst_fd = open(dst_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	ASSERT_LE(0, dst_fd) {
		TH_LOG("Failed to open \"%s\": %s", dst_path,
				strerror(errno));
	}
	src_fd = open(BINARY_PATH, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, src_fd) {
		TH_LOG("Failed to open \"" BINARY_PATH "\": %s",
				strerror(errno));
	}
	ASSERT_EQ(0, fstat(src_fd, &statbuf));
	ASSERT_EQ(statbuf.st_size, sendfile(dst_fd, src_fd, 0,
				statbuf.st_size));
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
			TH_LOG("Failed to execute \"%s\": %s", path,
					strerror(errno));
		};
		ASSERT_EQ(EACCES, errno);
		_exit(_metadata->passed ? 2 : 1);
		return;
	}
	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_EQ(1, WIFEXITED(status));
	ASSERT_EQ(ret ? 2 : 0, WEXITSTATUS(status)) {
		TH_LOG("Unexpected return code for \"%s\": %s", path,
				strerror(errno));
	};
}

TEST_F(layout1, execute)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_EXECUTE,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);
	copy_binary(_metadata, file1_s1d1);
	copy_binary(_metadata, file1_s1d2);
	copy_binary(_metadata, file1_s1d3);

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	test_execute(_metadata, file1_s1d1, -1);
	test_execute(_metadata, file1_s1d2, 0);
	test_execute(_metadata, file1_s1d3, 0);
}

TEST_F(layout1, link)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_MAKE_REG,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(0, unlink(file1_s1d1));
	ASSERT_EQ(0, unlink(file1_s1d2));
	ASSERT_EQ(0, unlink(file1_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, link(file2_s1d1, file1_s1d1));
	ASSERT_EQ(EACCES, errno);
	/* Denies linking because of reparenting. */
	ASSERT_EQ(-1, link(file1_s2d1, file1_s1d2));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, link(file2_s1d2, file1_s1d3));
	ASSERT_EQ(EACCES, errno);

	ASSERT_EQ(0, link(file2_s1d2, file1_s1d2)) {
		TH_LOG("Failed to link file to \"%s\": %s", file2_s1d2,
				strerror(errno));
	};
	ASSERT_EQ(0, link(file2_s1d3, file1_s1d3));
}

TEST_F(layout1, rename_file)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d3,
			.access = LANDLOCK_ACCESS_FS_REMOVE_FILE,
		},
		{
			.path = dir_s2d2,
			.access = LANDLOCK_ACCESS_FS_REMOVE_FILE,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(0, unlink(file1_s1d1));
	ASSERT_EQ(0, unlink(file1_s1d2));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Replaces file. */
	ASSERT_EQ(-1, rename(file1_s2d3, file1_s1d3));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(-1, rename(file1_s2d1, file1_s1d3));
	ASSERT_EQ(EACCES, errno);
	/* Same parent. */
	ASSERT_EQ(0, rename(file2_s2d3, file1_s2d3)) {
		TH_LOG("Failed to rename file \"%s\": %s", file2_s2d3,
				strerror(errno));
	};

	/* Renames files. */
	ASSERT_EQ(-1, rename(file1_s2d2, file1_s1d2));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, unlink(file1_s1d3));
	ASSERT_EQ(-1, rename(file1_s2d1, file1_s1d3));
	ASSERT_EQ(EACCES, errno);
	/* Same parent. */
	ASSERT_EQ(0, rename(file2_s1d3, file1_s1d3));
}

TEST_F(layout1, rename_dir)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_REMOVE_DIR,
		},
		{
			.path = dir_s2d1,
			.access = LANDLOCK_ACCESS_FS_REMOVE_DIR,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);

	/* Empties dir_s1d3. */
	ASSERT_EQ(0, unlink(file1_s1d3));
	ASSERT_EQ(0, unlink(file2_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Renames directory. */
	ASSERT_EQ(-1, rename(dir_s2d3, dir_s1d3));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, unlink(file1_s1d2));
	ASSERT_EQ(0, rename(dir_s1d3, file1_s1d2)) {
		TH_LOG("Failed to rename directory \"%s\": %s", dir_s1d3,
				strerror(errno));
	};
	ASSERT_EQ(0, rmdir(file1_s1d2));
}

TEST_F(layout1, rmdir)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_REMOVE_DIR,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(0, unlink(file1_s1d1));
	ASSERT_EQ(0, unlink(file1_s1d2));
	ASSERT_EQ(0, unlink(file1_s1d3));
	ASSERT_EQ(0, unlink(file2_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, rmdir(dir_s1d3));
	/* dir_s1d2 itself cannot be removed. */
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
			.access = LANDLOCK_ACCESS_FS_REMOVE_FILE,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, unlink(file1_s1d1));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, unlink(file1_s1d2)) {
		TH_LOG("Failed to unlink file \"%s\": %s", file1_s1d2,
				strerror(errno));
	};
	ASSERT_EQ(0, unlink(file1_s1d3));
}

static void test_make_file(struct __test_metadata *const _metadata,
		const __u64 access, const mode_t mode, const dev_t dev)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = access,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, access, rules);

	ASSERT_LE(0, ruleset_fd);

	unlink(file1_s1d1);
	unlink(file1_s1d2);
	unlink(file1_s1d3);

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, mknod(file1_s1d1, mode | 0400, dev));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, mknod(file1_s1d2, mode | 0400, dev)) {
		TH_LOG("Failed to make file \"%s\": %s",
				file1_s1d2, strerror(errno));
	};
	ASSERT_EQ(0, mknod(file1_s1d3, mode | 0400, dev));
}

TEST_F(layout1, make_char)
{
	/* Creates a /dev/null device. */
	set_cap(_metadata, CAP_MKNOD);
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_CHAR, S_IFCHR,
			makedev(1, 3));
}

TEST_F(layout1, make_block)
{
	/* Creates a /dev/loop0 device. */
	set_cap(_metadata, CAP_MKNOD);
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_BLOCK, S_IFBLK,
			makedev(7, 0));
}

TEST_F(layout1, make_reg)
{
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_REG, S_IFREG, 0);
	test_make_file(_metadata, LANDLOCK_ACCESS_FS_MAKE_REG, 0, 0);
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
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(0, unlink(file1_s1d1));
	ASSERT_EQ(0, unlink(file1_s1d2));
	ASSERT_EQ(0, unlink(file1_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(-1, symlink("none", file1_s1d1));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, symlink("none", file1_s1d2)) {
		TH_LOG("Failed to make symlink \"%s\": %s",
				file1_s1d2, strerror(errno));
	};
	ASSERT_EQ(0, symlink("none", file1_s1d3));
}

TEST_F(layout1, make_dir)
{
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_MAKE_DIR,
		},
		{}
	};
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(0, unlink(file1_s1d1));
	ASSERT_EQ(0, unlink(file1_s1d2));
	ASSERT_EQ(0, unlink(file1_s1d3));

	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Uses file_* as directory names. */
	ASSERT_EQ(-1, mkdir(file1_s1d1, 0700));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(0, mkdir(file1_s1d2, 0700)) {
		TH_LOG("Failed to make directory \"%s\": %s",
				file1_s1d2, strerror(errno));
	};
	ASSERT_EQ(0, mkdir(file1_s1d3, 0700));
}

static int open_proc_fd(struct __test_metadata *const _metadata, const int fd,
		const int open_flags)
{
	static const char path_template[] = "/proc/self/fd/%d";
	char procfd_path[sizeof(path_template) + 10];
	const int procfd_path_size = snprintf(procfd_path, sizeof(procfd_path),
			path_template, fd);

	ASSERT_LT(procfd_path_size, sizeof(procfd_path));
	return open(procfd_path, open_flags);
}

TEST_F(layout1, proc_unlinked_file)
{
	const struct rule rules[] = {
		{
			.path = file1_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		{}
	};
	int reg_fd, proc_fd;
	const int ruleset_fd = create_ruleset(_metadata,
			LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_WRITE_FILE, rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(EACCES, test_open(file1_s1d2, O_RDWR));
	ASSERT_EQ(0, test_open(file1_s1d2, O_RDONLY));
	reg_fd = open(file1_s1d2, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, reg_fd);
	ASSERT_EQ(0, unlink(file1_s1d2));

	proc_fd = open_proc_fd(_metadata, reg_fd, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, proc_fd);
	EXPECT_EQ(0, close(proc_fd));

	proc_fd = open_proc_fd(_metadata, reg_fd, O_RDWR | O_CLOEXEC);
	ASSERT_EQ(-1, proc_fd) {
		TH_LOG("Successfully opened /proc/self/fd/%d: %s",
				reg_fd, strerror(errno));
	}
	ASSERT_EQ(EACCES, errno);

	EXPECT_EQ(0, close(reg_fd));
}

TEST_F(layout1, proc_pipe)
{
	int proc_fd;
	int pipe_fds[2];
	char buf = '\0';
	const struct rule rules[] = {
		{
			.path = dir_s1d2,
			.access = LANDLOCK_ACCESS_FS_READ_FILE |
				LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{}
	};
	/* Limits read and write access to files tied to the filesystem. */
	const int ruleset_fd = create_ruleset(_metadata, rules[0].access,
			rules);

	ASSERT_LE(0, ruleset_fd);
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks enforcement for normal files. */
	ASSERT_EQ(0, test_open(file1_s1d2, O_RDWR));
	ASSERT_EQ(EACCES, test_open(file1_s1d1, O_RDWR));

	/* Checks access to pipes through FD. */
	ASSERT_EQ(0, pipe(pipe_fds));
	ASSERT_EQ(1, write(pipe_fds[1], ".", 1)) {
		TH_LOG("Failed to write in pipe: %s", strerror(errno));
	}
	ASSERT_EQ(1, read(pipe_fds[0], &buf, 1));
	ASSERT_EQ('.', buf);

	/* Checks write access to pipe through /proc/self/fd . */
	proc_fd = open_proc_fd(_metadata, pipe_fds[1], O_WRONLY | O_CLOEXEC);
	ASSERT_LE(0, proc_fd);
	ASSERT_EQ(1, write(proc_fd, ".", 1)) {
		TH_LOG("Failed to write through /proc/self/fd/%d: %s",
				pipe_fds[1], strerror(errno));
	}
	EXPECT_EQ(0, close(proc_fd));

	/* Checks read access to pipe through /proc/self/fd . */
	proc_fd = open_proc_fd(_metadata, pipe_fds[0], O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, proc_fd);
	buf = '\0';
	ASSERT_EQ(1, read(proc_fd, &buf, 1)) {
		TH_LOG("Failed to read through /proc/self/fd/%d: %s",
				pipe_fds[1], strerror(errno));
	}
	EXPECT_EQ(0, close(proc_fd));

	EXPECT_EQ(0, close(pipe_fds[0]));
	EXPECT_EQ(0, close(pipe_fds[1]));
}

TEST(cleanup)
{
	cleanup_layout1(_metadata);
}

TEST_HARNESS_MAIN
