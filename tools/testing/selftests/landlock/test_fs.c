/*
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * Tests code for Landlock
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <fcntl.h> /* open() */
#include <sys/mount.h>
#include <sys/stat.h> /* mkdir() */
#include <sys/mman.h> /* mmap() */

#include "../seccomp/test_harness.h"
#include "../../../../samples/bpf/bpf_load.h"

#define TMP_PREFIX "tmp_"

#ifndef SECCOMP_ADD_LANDLOCK_RULE
#define SECCOMP_ADD_LANDLOCK_RULE	2
#endif

#ifndef seccomp
static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}
#endif

static unsigned int __step_count = 0;

#define ASSERT_STEP(cond) \
	{ \
		step--; \
		if (!(cond)) \
			_exit(step); \
	}

TEST(seccomp_landlock)
{
	int ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0);
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS");
	}
	ret = seccomp(SECCOMP_ADD_LANDLOCK_RULE, 0, NULL);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EFAULT, errno) {
		TH_LOG("Kernel does not support CONFIG_SECURITY_LANDLOCK");
	}
}

struct layout1 {
	int file_ro;
	int file_rw;
	int file_wo;
};

static void setup_layout1(struct __test_metadata *_metadata,
		struct layout1 *l1)
{
	int fd;
	char buf[] = "fs1";

	l1->file_ro = -1;
	l1->file_rw = -1;
	l1->file_wo = -1;

	fd = open(TMP_PREFIX "file_created",
			O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(sizeof(buf), write(fd, buf, sizeof(buf)));
	ASSERT_EQ(0, close(fd));

	fd = mkdir(TMP_PREFIX "dir_created", S_IRUSR | S_IWUSR);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(0, close(fd));

	l1->file_ro = open(TMP_PREFIX "file_ro",
			O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	ASSERT_LE(0, l1->file_ro);
	ASSERT_EQ(sizeof(buf), write(l1->file_ro, buf, sizeof(buf)));
	ASSERT_EQ(0, close(l1->file_ro));
	l1->file_ro = open(TMP_PREFIX "file_ro",
			O_RDONLY | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	ASSERT_LE(0, l1->file_ro);

	l1->file_rw = open(TMP_PREFIX "file_rw",
			O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	ASSERT_LE(0, l1->file_rw);
	ASSERT_EQ(sizeof(buf), write(l1->file_rw, buf, sizeof(buf)));
	ASSERT_EQ(0, lseek(l1->file_rw, 0, SEEK_SET));

	l1->file_wo = open(TMP_PREFIX "file_wo",
			O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	ASSERT_LE(0, l1->file_wo);
	ASSERT_EQ(sizeof(buf), write(l1->file_wo, buf, sizeof(buf)));
	ASSERT_EQ(0, lseek(l1->file_wo, 0, SEEK_SET));
}

static void cleanup_layout1(void)
{
	unlink(TMP_PREFIX "file_created");
	unlink(TMP_PREFIX "file_ro");
	unlink(TMP_PREFIX "file_rw");
	unlink(TMP_PREFIX "file_wo");
	unlink(TMP_PREFIX "should_not_exist");
	rmdir(TMP_PREFIX "dir_created");
}

FIXTURE(rule_fs1) {
	struct layout1 l1;
	int prog;
};

FIXTURE_SETUP(rule_fs1)
{
	cleanup_layout1();
	setup_layout1(_metadata, &self->l1);

	ASSERT_EQ(0, load_bpf_file("rules/fs1.o")) {
		TH_LOG("%s", bpf_log_buf);
	}
	self->prog = prog_fd[0];
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS");
	}
}

FIXTURE_TEARDOWN(rule_fs1)
{
	EXPECT_EQ(0, close(self->prog));
	/* cleanup_layout1() would be denied here */
}

TEST_F(rule_fs1, load_prog) {}

TEST_F(rule_fs1, read_only_file)
{
	int fd;
	int step = 0;
	char buf_write[] = "should not be written";
	char buf_read[2];

	ASSERT_EQ(-1, write(self->l1.file_ro, buf_write, sizeof(buf_write)));
	ASSERT_EQ(EBADF, errno);

	ASSERT_EQ(-1, read(self->l1.file_wo, buf_read, sizeof(buf_read)));
	ASSERT_EQ(EBADF, errno);

	ASSERT_EQ(0, seccomp(SECCOMP_ADD_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs1: %s", strerror(errno));
	}

	fd = open(".",
			O_TMPFILE | O_EXCL | O_RDWR | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	ASSERT_STEP(fd == -1);
	ASSERT_STEP(errno != EOPNOTSUPP)
	ASSERT_STEP(errno == EPERM);

	fd = open(TMP_PREFIX "file_created",
			O_RDONLY | O_CLOEXEC);
	ASSERT_STEP(fd >= 0);
	ASSERT_STEP(!close(fd));

	fd = open(TMP_PREFIX "file_created",
			O_RDWR | O_CLOEXEC);
	ASSERT_STEP(fd == -1);
	ASSERT_STEP(errno == EPERM);

	fd = open(TMP_PREFIX "file_created",
			O_WRONLY | O_CLOEXEC);
	ASSERT_STEP(fd == -1);
	ASSERT_STEP(errno == EPERM);

	fd = open(TMP_PREFIX "should_not_exist",
			O_CREAT | O_EXCL | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	ASSERT_STEP(fd == -1);
	ASSERT_STEP(errno == EPERM);

	ASSERT_STEP(-1 ==
			write(self->l1.file_ro, buf_write, sizeof(buf_write)));
	ASSERT_STEP(errno == EBADF);
	ASSERT_STEP(sizeof(buf_read) ==
			read(self->l1.file_ro, buf_read, sizeof(buf_read)));

	ASSERT_STEP(-1 ==
			write(self->l1.file_rw, buf_write, sizeof(buf_write)));
	ASSERT_STEP(errno == EPERM);
	ASSERT_STEP(sizeof(buf_read) ==
			read(self->l1.file_rw, buf_read, sizeof(buf_read)));

	ASSERT_STEP(-1 == write(self->l1.file_wo, buf_write, sizeof(buf_write)));
	ASSERT_STEP(errno == EPERM);
	ASSERT_STEP(-1 == read(self->l1.file_wo, buf_read, sizeof(buf_read)));
	ASSERT_STEP(errno == EBADF);

	ASSERT_STEP(-1 == unlink(TMP_PREFIX "file_created"));
	ASSERT_STEP(errno == EPERM);
	ASSERT_STEP(-1 == rmdir(TMP_PREFIX "dir_created"));
	ASSERT_STEP(errno == EPERM);

	ASSERT_STEP(0 == close(self->l1.file_ro));
	ASSERT_STEP(0 == close(self->l1.file_rw));
	ASSERT_STEP(0 == close(self->l1.file_wo));
}

TEST_F(rule_fs1, read_only_mount)
{
	int step = 0;

	ASSERT_EQ(0, mount(".", TMP_PREFIX "dir_created",
				NULL, MS_BIND, NULL));
	ASSERT_EQ(0, umount2(TMP_PREFIX "dir_created", MNT_FORCE));

	ASSERT_EQ(0, seccomp(SECCOMP_ADD_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs1: %s", strerror(errno));
	}

	ASSERT_STEP(-1 == mount(".", TMP_PREFIX "dir_created",
				NULL, MS_BIND, NULL));
	ASSERT_STEP(errno == EPERM);
	ASSERT_STEP(-1 == umount("/"));
	ASSERT_STEP(errno == EPERM);
}

TEST_F(rule_fs1, read_only_mem)
{
	int step = 0;
	void *addr;

	addr = mmap(NULL, 1, PROT_READ | PROT_WRITE,
			MAP_SHARED, self->l1.file_rw, 0);
	ASSERT_NE(NULL, addr);
	ASSERT_EQ(0, munmap(addr, 1));

	ASSERT_EQ(0, seccomp(SECCOMP_ADD_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs1: %s", strerror(errno));
	}

	addr = mmap(NULL, 1, PROT_READ, MAP_SHARED,
			self->l1.file_rw, 0);
	ASSERT_STEP(addr != NULL);
	ASSERT_STEP(-1 == mprotect(addr, 1, PROT_WRITE));
	ASSERT_STEP(errno == EPERM);
	ASSERT_STEP(0 == munmap(addr, 1));

	addr = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED,
			self->l1.file_rw, 0);
	ASSERT_STEP(addr != NULL);
	ASSERT_STEP(errno == EPERM);

	addr = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE,
			self->l1.file_rw, 0);
	ASSERT_STEP(addr != NULL);
	ASSERT_STEP(0 == munmap(addr, 1));
}

FIXTURE(rule_fs2) {
	struct layout1 l1;
	int prog;
};

FIXTURE_SETUP(rule_fs2)
{
	cleanup_layout1();
	setup_layout1(_metadata, &self->l1);

	ASSERT_EQ(0, load_bpf_file("rules/fs2.o")) {
		TH_LOG("%s", bpf_log_buf);
	}
	self->prog = prog_fd[0];
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS");
	}
}

FIXTURE_TEARDOWN(rule_fs2)
{
	EXPECT_EQ(0, close(self->prog));
	cleanup_layout1();
}

static void landlocked_deny_open(struct __test_metadata *_metadata,
		struct layout1 *l1)
{
	int fd;
	void *addr;

	fd = open(".", O_DIRECTORY | O_CLOEXEC);
	ASSERT_EQ(-1, fd);
	ASSERT_EQ(EPERM, errno);

	addr = mmap(NULL, 1, PROT_READ | PROT_WRITE,
			MAP_SHARED, l1->file_rw, 0);
	ASSERT_NE(NULL, addr);
	ASSERT_EQ(0, munmap(addr, 1));
}

TEST_F(rule_fs2, deny_open_for_hierarchy) {
	int fd;
	int status;
	pid_t child;

	fd = open(".", O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));

	ASSERT_EQ(0, seccomp(SECCOMP_ADD_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs2: %s", strerror(errno));
	}

	landlocked_deny_open(_metadata, &self->l1);

	child = fork();
	ASSERT_LE(0, child);
	if (!child) {
		landlocked_deny_open(_metadata, &self->l1);
		_exit(1);
	}
	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	_exit(WEXITSTATUS(status));
}

TEST_HARNESS_MAIN
