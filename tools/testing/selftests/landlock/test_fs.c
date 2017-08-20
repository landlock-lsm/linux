/*
 * Landlock tests - filesystem
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
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

#include "test.h"

#define TMP_PREFIX "tmp_"

struct layout1 {
	int file_ro;
	int file_rw;
	int file_wo;
};

static void setup_layout1(struct __test_metadata *_metadata,
		struct layout1 *l1)
{
	int fd;
	char buf[] = "fs_read_only";

	l1->file_ro = -1;
	l1->file_rw = -1;
	l1->file_wo = -1;

	fd = open(TMP_PREFIX "file_created",
			O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(sizeof(buf), write(fd, buf, sizeof(buf)));
	ASSERT_EQ(0, close(fd));

	fd = mkdir(TMP_PREFIX "dir_created", 0600);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(0, close(fd));

	l1->file_ro = open(TMP_PREFIX "file_ro",
			O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	ASSERT_LE(0, l1->file_ro);
	ASSERT_EQ(sizeof(buf), write(l1->file_ro, buf, sizeof(buf)));
	ASSERT_EQ(0, close(l1->file_ro));
	l1->file_ro = open(TMP_PREFIX "file_ro",
			O_RDONLY | O_CLOEXEC, 0600);
	ASSERT_LE(0, l1->file_ro);

	l1->file_rw = open(TMP_PREFIX "file_rw",
			O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	ASSERT_LE(0, l1->file_rw);
	ASSERT_EQ(sizeof(buf), write(l1->file_rw, buf, sizeof(buf)));
	ASSERT_EQ(0, lseek(l1->file_rw, 0, SEEK_SET));

	l1->file_wo = open(TMP_PREFIX "file_wo",
			O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
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

FIXTURE(fs_read_only) {
	struct layout1 l1;
	int prog;
};

FIXTURE_SETUP(fs_read_only)
{
	cleanup_layout1();
	setup_layout1(_metadata, &self->l1);

	ASSERT_EQ(0, load_bpf_file("rule_fs_read_only.o")) {
		TH_LOG("%s", bpf_log_buf);
	}
	self->prog = prog_fd[0];
}

FIXTURE_TEARDOWN(fs_read_only)
{
	EXPECT_EQ(0, close(self->prog));
	/* cleanup_layout1() would be denied here */
}

TEST_F(fs_read_only, load_prog) {}

TEST_F(fs_read_only, read_only_file)
{
	int fd;
	char buf_write[] = "should not be written";
	char buf_read[2];

	ASSERT_EQ(-1, write(self->l1.file_ro, buf_write, sizeof(buf_write)));
	ASSERT_EQ(EBADF, errno);

	ASSERT_EQ(-1, read(self->l1.file_wo, buf_read, sizeof(buf_read)));
	ASSERT_EQ(EBADF, errno);

	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs_read_only: %s",
				strerror(errno));
	}
	_metadata->no_print = true;

	fd = open(".", O_TMPFILE | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	ASSERT_EQ(fd, -1);
	ASSERT_NE(errno, EOPNOTSUPP)
	ASSERT_EQ(errno, EPERM);

	fd = open(TMP_PREFIX "file_created",
			O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(close(fd), 0);

	fd = open(TMP_PREFIX "file_created",
			O_RDWR | O_CLOEXEC);
	ASSERT_EQ(fd, -1);
	ASSERT_EQ(errno, EPERM);

	fd = open(TMP_PREFIX "file_created",
			O_WRONLY | O_CLOEXEC);
	ASSERT_EQ(fd, -1);
	ASSERT_EQ(errno, EPERM);

	fd = open(TMP_PREFIX "should_not_exist",
			O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	ASSERT_EQ(fd, -1);
	ASSERT_EQ(errno, EPERM);

	ASSERT_EQ(-1,
			write(self->l1.file_ro, buf_write, sizeof(buf_write)));
	ASSERT_EQ(errno, EBADF);
	ASSERT_EQ(sizeof(buf_read),
			read(self->l1.file_ro, buf_read, sizeof(buf_read)));

	ASSERT_EQ(-1,
			write(self->l1.file_rw, buf_write, sizeof(buf_write)));
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(sizeof(buf_read),
			read(self->l1.file_rw, buf_read, sizeof(buf_read)));

	ASSERT_EQ(-1, write(self->l1.file_wo, buf_write, sizeof(buf_write)));
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(-1, read(self->l1.file_wo, buf_read, sizeof(buf_read)));
	ASSERT_EQ(errno, EBADF);

	ASSERT_EQ(-1, unlink(TMP_PREFIX "file_created"));
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(-1, rmdir(TMP_PREFIX "dir_created"));
	ASSERT_EQ(errno, EPERM);

	ASSERT_EQ(0, close(self->l1.file_ro));
	ASSERT_EQ(0, close(self->l1.file_rw));
	ASSERT_EQ(0, close(self->l1.file_wo));
}

TEST_F(fs_read_only, read_only_mount)
{
	ASSERT_EQ(0, mount(".", TMP_PREFIX "dir_created",
				NULL, MS_BIND, NULL));
	ASSERT_EQ(0, umount2(TMP_PREFIX "dir_created", MNT_FORCE));

	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs_read_only: %s",
				strerror(errno));
	}

	ASSERT_EQ(-1, mount(".", TMP_PREFIX "dir_created",
				NULL, MS_BIND, NULL));
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(-1, umount("/"));
	ASSERT_EQ(errno, EPERM);
}

TEST_F(fs_read_only, read_only_mem)
{
	void *addr;

	addr = mmap(NULL, 1, PROT_READ | PROT_WRITE,
			MAP_SHARED, self->l1.file_rw, 0);
	ASSERT_NE(NULL, addr);
	ASSERT_EQ(0, munmap(addr, 1));

	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs_read_only: %s",
				strerror(errno));
	}

	addr = mmap(NULL, 1, PROT_READ, MAP_SHARED,
			self->l1.file_rw, 0);
	ASSERT_NE(addr, NULL);
	ASSERT_EQ(-1, mprotect(addr, 1, PROT_WRITE));
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(0, munmap(addr, 1));

	addr = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED,
			self->l1.file_rw, 0);
	ASSERT_NE(addr, NULL);
	ASSERT_EQ(errno, EPERM);

	addr = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE,
			self->l1.file_rw, 0);
	ASSERT_NE(addr, NULL);
	ASSERT_EQ(0, munmap(addr, 1));
}

FIXTURE(fs_no_open) {
	struct layout1 l1;
	int prog;
};

FIXTURE_SETUP(fs_no_open)
{
	cleanup_layout1();
	setup_layout1(_metadata, &self->l1);

	ASSERT_EQ(0, load_bpf_file("rule_fs_no_open.o")) {
		TH_LOG("%s", bpf_log_buf);
	}
	self->prog = prog_fd[0];
}

FIXTURE_TEARDOWN(fs_no_open)
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

TEST_F(fs_no_open, deny_open_for_hierarchy) {
	int fd;
	int status;
	pid_t child;

	fd = open(".", O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));

	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_RULE, 0, &self->prog)) {
		TH_LOG("Failed to apply rule fs_no_open: %s", strerror(errno));
	}

	landlocked_deny_open(_metadata, &self->l1);

	child = fork();
	ASSERT_LE(0, child);
	if (!child) {
		landlocked_deny_open(_metadata, &self->l1);
		_exit(0);
	}
	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	_exit(WEXITSTATUS(status));
}

TEST_HARNESS_MAIN
