/*
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by the GPLv2 license.
 *
 * Test code for seccomp bpf.
 */

#include <asm/siginfo.h>
#define __have_siginfo_t 1
#define __have_sigval_t 1
#define __have_sigevent_t 1

#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <linux/prctl.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <linux/elf.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/times.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "test_harness.h"

#ifndef PR_SET_PTRACER
# define PR_SET_PTRACER 0x59616d61
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#endif

#ifndef PR_SECCOMP_EXT
#define PR_SECCOMP_EXT 43
#endif

#ifndef SECCOMP_EXT_ACT
#define SECCOMP_EXT_ACT 1
#endif

#ifndef SECCOMP_EXT_ACT_TSYNC
#define SECCOMP_EXT_ACT_TSYNC 1
#endif

#ifndef SECCOMP_MODE_STRICT
#define SECCOMP_MODE_STRICT 1
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_RET_KILL
#define SECCOMP_RET_KILL        0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP        0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO       0x00050000U /* returns an errno */
#define SECCOMP_RET_TRACE       0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_ALLOW       0x7fff0000U /* allow */

/* Masks for the return value sections. */
#define SECCOMP_RET_ACTION      0x7fff0000U
#define SECCOMP_RET_DATA        0x0000ffffU

struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
	__u32 is_valid_syscall; /* SECCOMP_DATA_VALIDSYS_PRESENT */
	__u32 checker_group; /* SECCOMP_DATA_ARGEVAL_PRESENT */
	__u64 arg_matches[6]; /* SECCOMP_DATA_ARGEVAL_PRESENT */
};

#define SECCOMP_DATA_ARGEVAL_PRESENT
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define match_arg(_n) (offsetof(struct seccomp_data, arg_matches[_n]))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]) + sizeof(__u32))
#define match_arg(_n) \
	(offsetof(struct seccomp_data, arg_matches[_n]) + sizeof(__u32))
#else
#error "wut? Unknown __BYTE_ORDER?!"
#endif

#define SIBLING_EXIT_UNKILLED	0xbadbeef
#define SIBLING_EXIT_FAILURE	0xbadface
#define SIBLING_EXIT_NEWPRIVS	0xbadfeed

TEST(mode_strict_support)
{
	long ret;

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, NULL, NULL, NULL);
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support CONFIG_SECCOMP");
	}
	syscall(__NR_exit, 1);
}

TEST_SIGNAL(mode_strict_cannot_call_prctl, SIGKILL)
{
	long ret;

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, NULL, NULL, NULL);
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support CONFIG_SECCOMP");
	}
	syscall(__NR_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
		NULL, NULL, NULL);
	EXPECT_FALSE(true) {
		TH_LOG("Unreachable!");
	}
}

/* Note! This doesn't test no new privs behavior */
TEST(no_new_privs_support)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	EXPECT_EQ(0, ret) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}
}

/* Tests kernel support by checking for a copy_from_user() fault on * NULL. */
TEST(mode_filter_support)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0);
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL, NULL, NULL);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EFAULT, errno) {
		TH_LOG("Kernel does not support CONFIG_SECCOMP_FILTER!");
	}
}

TEST(mode_filter_without_nnp)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_GET_NO_NEW_PRIVS, 0, NULL, 0, 0);
	ASSERT_LE(0, ret) {
		TH_LOG("Expected 0 or unsupported for NO_NEW_PRIVS");
	}
	errno = 0;
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	/* Succeeds with CAP_SYS_ADMIN, fails without */
	/* TODO(wad) check caps not euid */
	if (geteuid()) {
		EXPECT_EQ(-1, ret);
		EXPECT_EQ(EACCES, errno);
	} else {
		EXPECT_EQ(0, ret);
	}
}

#define MAX_INSNS_PER_PATH 32768

TEST(filter_size_limits)
{
	int i;
	int count = BPF_MAXINSNS + 1;
	struct sock_filter allow[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter *filter;
	struct sock_fprog prog = { };
	long ret;

	filter = calloc(count, sizeof(*filter));
	ASSERT_NE(NULL, filter);

	for (i = 0; i < count; i++)
		filter[i] = allow[0];

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	prog.filter = filter;
	prog.len = count;

	/* Too many filter instructions in a single filter. */
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	ASSERT_NE(0, ret) {
		TH_LOG("Installing %d insn filter was allowed", prog.len);
	}

	/* One less is okay, though. */
	prog.len -= 1;
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	ASSERT_EQ(0, ret) {
		TH_LOG("Installing %d insn filter wasn't allowed", prog.len);
	}
}

TEST(filter_chain_limits)
{
	int i;
	int count = BPF_MAXINSNS;
	struct sock_filter allow[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter *filter;
	struct sock_fprog prog = { };
	long ret;

	filter = calloc(count, sizeof(*filter));
	ASSERT_NE(NULL, filter);

	for (i = 0; i < count; i++)
		filter[i] = allow[0];

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	prog.filter = filter;
	prog.len = 1;

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	ASSERT_EQ(0, ret);

	prog.len = count;

	/* Too many total filter instructions. */
	for (i = 0; i < MAX_INSNS_PER_PATH; i++) {
		ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
		if (ret != 0)
			break;
	}
	ASSERT_NE(0, ret) {
		TH_LOG("Allowed %d %d-insn filters (total with penalties:%d)",
		       i, count, i * (count + 4));
	}
}

TEST(mode_filter_cannot_move_to_strict)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, NULL, 0, 0);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
}


TEST(mode_filter_get_seccomp)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
	EXPECT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
	EXPECT_EQ(2, ret);
}


TEST(ALLOW_all)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);
}

TEST(empty_prog)
{
	struct sock_filter filter[] = {
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
}

TEST_SIGNAL(unknown_ret_is_kill_inside, SIGSYS)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, 0x10000000U),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);
	EXPECT_EQ(0, syscall(__NR_getpid)) {
		TH_LOG("getpid() shouldn't ever return");
	}
}

TEST_SIGNAL(KILL_all, SIGSYS)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);
}

TEST_SIGNAL(KILL_one, SIGSYS)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;
	pid_t parent = getppid();

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);

	EXPECT_EQ(parent, syscall(__NR_getppid));
	/* getpid() should never return. */
	EXPECT_EQ(0, syscall(__NR_getpid));
}

TEST_SIGNAL(KILL_one_arg_one, SIGSYS)
{
	void *fatal_address;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_times, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		/* Only both with lower 32-bit for now. */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, syscall_arg(0)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,
			(unsigned long)&fatal_address, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;
	pid_t parent = getppid();
	struct tms timebuf;
	clock_t clock = times(&timebuf);

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);

	EXPECT_EQ(parent, syscall(__NR_getppid));
	EXPECT_LE(clock, syscall(__NR_times, &timebuf));
	/* times() should never return. */
	EXPECT_EQ(0, syscall(__NR_times, &fatal_address));
}

TEST_SIGNAL(KILL_one_arg_six, SIGSYS)
{
#ifndef __NR_mmap2
	int sysno = __NR_mmap;
#else
	int sysno = __NR_mmap2;
#endif
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, sysno, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		/* Only both with lower 32-bit for now. */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, syscall_arg(5)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x0C0FFEE, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;
	pid_t parent = getppid();
	int fd;
	void *map1, *map2;
	int page_size = sysconf(_SC_PAGESIZE);

	ASSERT_LT(0, page_size);

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);

	fd = open("/dev/zero", O_RDONLY);
	ASSERT_NE(-1, fd);

	EXPECT_EQ(parent, syscall(__NR_getppid));
	map1 = (void *)syscall(sysno,
		NULL, page_size, PROT_READ, MAP_PRIVATE, fd, page_size);
	EXPECT_NE(MAP_FAILED, map1);
	/* mmap2() should never return. */
	map2 = (void *)syscall(sysno,
		 NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0x0C0FFEE);
	EXPECT_EQ(MAP_FAILED, map2);

	/* The test failed, so clean up the resources. */
	munmap(map1, page_size);
	munmap(map2, page_size);
	close(fd);
}

/* TODO(wad) add 64-bit versus 32-bit arg tests. */
TEST(arg_out_of_range)
{
	struct sock_filter filter[] = {
#ifdef SECCOMP_DATA_ARGEVAL_PRESENT
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, match_arg(6)),
#else
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, syscall_arg(6)),
#endif
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
}

TEST(ERRNO_valid)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | E2BIG),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;
	pid_t parent = getppid();

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);

	EXPECT_EQ(parent, syscall(__NR_getppid));
	EXPECT_EQ(-1, read(0, NULL, 0));
	EXPECT_EQ(E2BIG, errno);
}

TEST(ERRNO_zero)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;
	pid_t parent = getppid();

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);

	EXPECT_EQ(parent, syscall(__NR_getppid));
	/* "errno" of 0 is ok. */
	EXPECT_EQ(0, read(0, NULL, 0));
}

TEST(ERRNO_capped)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | 4096),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;
	pid_t parent = getppid();

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	ASSERT_EQ(0, ret);

	EXPECT_EQ(parent, syscall(__NR_getppid));
	EXPECT_EQ(-1, read(0, NULL, 0));
	EXPECT_EQ(4095, errno);
}

FIXTURE_DATA(TRAP) {
	struct sock_fprog prog;
};

FIXTURE_SETUP(TRAP)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};

	memset(&self->prog, 0, sizeof(self->prog));
	self->prog.filter = malloc(sizeof(filter));
	ASSERT_NE(NULL, self->prog.filter);
	memcpy(self->prog.filter, filter, sizeof(filter));
	self->prog.len = (unsigned short)ARRAY_SIZE(filter);
}

FIXTURE_TEARDOWN(TRAP)
{
	if (self->prog.filter)
		free(self->prog.filter);
}

TEST_F_SIGNAL(TRAP, dfl, SIGSYS)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog);
	ASSERT_EQ(0, ret);
	syscall(__NR_getpid);
}

/* Ensure that SIGSYS overrides SIG_IGN */
TEST_F_SIGNAL(TRAP, ign, SIGSYS)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	signal(SIGSYS, SIG_IGN);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog);
	ASSERT_EQ(0, ret);
	syscall(__NR_getpid);
}

static struct siginfo TRAP_info;
static volatile int TRAP_nr;
static void TRAP_action(int nr, siginfo_t *info, void *void_context)
{
	memcpy(&TRAP_info, info, sizeof(TRAP_info));
	TRAP_nr = nr;
}

TEST_F(TRAP, handler)
{
	int ret, test;
	struct sigaction act;
	sigset_t mask;

	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &TRAP_action;
	act.sa_flags = SA_SIGINFO;
	ret = sigaction(SIGSYS, &act, NULL);
	ASSERT_EQ(0, ret) {
		TH_LOG("sigaction failed");
	}
	ret = sigprocmask(SIG_UNBLOCK, &mask, NULL);
	ASSERT_EQ(0, ret) {
		TH_LOG("sigprocmask failed");
	}

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog);
	ASSERT_EQ(0, ret);
	TRAP_nr = 0;
	memset(&TRAP_info, 0, sizeof(TRAP_info));
	/* Expect the registers to be rolled back. (nr = error) may vary
	 * based on arch. */
	ret = syscall(__NR_getpid);
	/* Silence gcc warning about volatile. */
	test = TRAP_nr;
	EXPECT_EQ(SIGSYS, test);
	struct local_sigsys {
		void *_call_addr;	/* calling user insn */
		int _syscall;		/* triggering system call number */
		unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
	} *sigsys = (struct local_sigsys *)
#ifdef si_syscall
		&(TRAP_info.si_call_addr);
#else
		&TRAP_info.si_pid;
#endif
	EXPECT_EQ(__NR_getpid, sigsys->_syscall);
	/* Make sure arch is non-zero. */
	EXPECT_NE(0, sigsys->_arch);
	EXPECT_NE(0, (unsigned long)sigsys->_call_addr);
}

FIXTURE_DATA(precedence) {
	struct sock_fprog allow;
	struct sock_fprog trace;
	struct sock_fprog error;
	struct sock_fprog trap;
	struct sock_fprog kill;
};

FIXTURE_SETUP(precedence)
{
	struct sock_filter allow_insns[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter trace_insns[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE),
	};
	struct sock_filter error_insns[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO),
	};
	struct sock_filter trap_insns[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
	};
	struct sock_filter kill_insns[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
	};

	memset(self, 0, sizeof(*self));
#define FILTER_ALLOC(_x) \
	self->_x.filter = malloc(sizeof(_x##_insns)); \
	ASSERT_NE(NULL, self->_x.filter); \
	memcpy(self->_x.filter, &_x##_insns, sizeof(_x##_insns)); \
	self->_x.len = (unsigned short)ARRAY_SIZE(_x##_insns)
	FILTER_ALLOC(allow);
	FILTER_ALLOC(trace);
	FILTER_ALLOC(error);
	FILTER_ALLOC(trap);
	FILTER_ALLOC(kill);
}

FIXTURE_TEARDOWN(precedence)
{
#define FILTER_FREE(_x) if (self->_x.filter) free(self->_x.filter)
	FILTER_FREE(allow);
	FILTER_FREE(trace);
	FILTER_FREE(error);
	FILTER_FREE(trap);
	FILTER_FREE(kill);
}

TEST_F(precedence, allow_ok)
{
	pid_t parent, res = 0;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->error);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trap);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->kill);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	res = syscall(__NR_getppid);
	EXPECT_EQ(parent, res);
}

TEST_F_SIGNAL(precedence, kill_is_highest, SIGSYS)
{
	pid_t parent, res = 0;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->error);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trap);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->kill);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	res = syscall(__NR_getppid);
	EXPECT_EQ(parent, res);
	/* getpid() should never return. */
	res = syscall(__NR_getpid);
	EXPECT_EQ(0, res);
}

TEST_F_SIGNAL(precedence, kill_is_highest_in_any_order, SIGSYS)
{
	pid_t parent;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->kill);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->error);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trap);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	EXPECT_EQ(parent, syscall(__NR_getppid));
	/* getpid() should never return. */
	EXPECT_EQ(0, syscall(__NR_getpid));
}

TEST_F_SIGNAL(precedence, trap_is_second, SIGSYS)
{
	pid_t parent;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->error);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trap);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	EXPECT_EQ(parent, syscall(__NR_getppid));
	/* getpid() should never return. */
	EXPECT_EQ(0, syscall(__NR_getpid));
}

TEST_F_SIGNAL(precedence, trap_is_second_in_any_order, SIGSYS)
{
	pid_t parent;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trap);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->error);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	EXPECT_EQ(parent, syscall(__NR_getppid));
	/* getpid() should never return. */
	EXPECT_EQ(0, syscall(__NR_getpid));
}

TEST_F(precedence, errno_is_third)
{
	pid_t parent;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->error);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	EXPECT_EQ(parent, syscall(__NR_getppid));
	EXPECT_EQ(0, syscall(__NR_getpid));
}

TEST_F(precedence, errno_is_third_in_any_order)
{
	pid_t parent;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->error);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	EXPECT_EQ(parent, syscall(__NR_getppid));
	EXPECT_EQ(0, syscall(__NR_getpid));
}

TEST_F(precedence, trace_is_fourth)
{
	pid_t parent;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	EXPECT_EQ(parent, syscall(__NR_getppid));
	/* No ptracer */
	EXPECT_EQ(-1, syscall(__NR_getpid));
}

TEST_F(precedence, trace_is_fourth_in_any_order)
{
	pid_t parent;
	long ret;

	parent = getppid();
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->trace);
	ASSERT_EQ(0, ret);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->allow);
	ASSERT_EQ(0, ret);
	/* Should work just fine. */
	EXPECT_EQ(parent, syscall(__NR_getppid));
	/* No ptracer */
	EXPECT_EQ(-1, syscall(__NR_getpid));
}

#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP	0x00000080
#endif

/* Catch the Ubuntu 12.04 value error. */
#if PTRACE_EVENT_SECCOMP != 7
#undef PTRACE_EVENT_SECCOMP
#endif

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif

#define IS_SECCOMP_EVENT(status) ((status >> 16) == PTRACE_EVENT_SECCOMP)
bool tracer_running;
void tracer_stop(int sig)
{
	tracer_running = false;
}

typedef void tracer_func_t(struct __test_metadata *_metadata,
			   pid_t tracee, int status, void *args);

void tracer(struct __test_metadata *_metadata, int fd, pid_t tracee,
	    tracer_func_t tracer_func, void *args)
{
	int ret = -1;
	struct sigaction action = {
		.sa_handler = tracer_stop,
	};

	/* Allow external shutdown. */
	tracer_running = true;
	ASSERT_EQ(0, sigaction(SIGUSR1, &action, NULL));

	errno = 0;
	while (ret == -1 && errno != EINVAL)
		ret = ptrace(PTRACE_ATTACH, tracee, NULL, 0);
	ASSERT_EQ(0, ret) {
		kill(tracee, SIGKILL);
	}
	/* Wait for attach stop */
	wait(NULL);

	ret = ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACESECCOMP);
	ASSERT_EQ(0, ret) {
		TH_LOG("Failed to set PTRACE_O_TRACESECCOMP");
		kill(tracee, SIGKILL);
	}
	ptrace(PTRACE_CONT, tracee, NULL, 0);

	/* Unblock the tracee */
	ASSERT_EQ(1, write(fd, "A", 1));
	ASSERT_EQ(0, close(fd));

	/* Run until we're shut down. Must assert to stop execution. */
	while (tracer_running) {
		int status;

		if (wait(&status) != tracee)
			continue;
		if (WIFSIGNALED(status) || WIFEXITED(status))
			/* Child is dead. Time to go. */
			return;

		/* Make sure this is a seccomp event. */
		ASSERT_EQ(true, IS_SECCOMP_EVENT(status));

		tracer_func(_metadata, tracee, status, args);

		ret = ptrace(PTRACE_CONT, tracee, NULL, NULL);
		ASSERT_EQ(0, ret);
	}
	/* Directly report the status of our test harness results. */
	syscall(__NR_exit, _metadata->passed ? EXIT_SUCCESS : EXIT_FAILURE);
}

/* Common tracer setup/teardown functions. */
void cont_handler(int num)
{ }
pid_t setup_trace_fixture(struct __test_metadata *_metadata,
			  tracer_func_t func, void *args)
{
	char sync;
	int pipefd[2];
	pid_t tracer_pid;
	pid_t tracee = getpid();

	/* Setup a pipe for clean synchronization. */
	ASSERT_EQ(0, pipe(pipefd));

	/* Fork a child which we'll promote to tracer */
	tracer_pid = fork();
	ASSERT_LE(0, tracer_pid);
	signal(SIGALRM, cont_handler);
	if (tracer_pid == 0) {
		close(pipefd[0]);
		tracer(_metadata, pipefd[1], tracee, func, args);
		syscall(__NR_exit, 0);
	}
	close(pipefd[1]);
	prctl(PR_SET_PTRACER, tracer_pid, 0, 0, 0);
	read(pipefd[0], &sync, 1);
	close(pipefd[0]);

	return tracer_pid;
}
void teardown_trace_fixture(struct __test_metadata *_metadata,
			    pid_t tracer)
{
	if (tracer) {
		int status;
		/*
		 * Extract the exit code from the other process and
		 * adopt it for ourselves in case its asserts failed.
		 */
		ASSERT_EQ(0, kill(tracer, SIGUSR1));
		ASSERT_EQ(tracer, waitpid(tracer, &status, 0));
		if (WEXITSTATUS(status))
			_metadata->passed = 0;
	}
}

/* "poke" tracer arguments and function. */
struct tracer_args_poke_t {
	unsigned long *poke_addr;
	unsigned long *poke_data;
	unsigned long poke_len;
};

void tracer_poke(struct __test_metadata *_metadata, pid_t tracee, int status,
		 void *args)
{
	int ret;
	unsigned long msg, i;
	struct tracer_args_poke_t *info = (struct tracer_args_poke_t *)args;

	ret = ptrace(PTRACE_GETEVENTMSG, tracee, NULL, &msg);
	EXPECT_EQ(0, ret);
	/* If this fails, don't try to recover. */
	ASSERT_EQ(0x1001, msg) {
		kill(tracee, SIGKILL);
	}
	/*
	 * Poke in the message.
	 * Registers are not touched to try to keep this relatively arch
	 * agnostic.
	 */
	for (i = 0; i < info->poke_len; i++) {
		unsigned long addr = (unsigned long)info->poke_addr +
			i * sizeof(long);

		ret = ptrace(PTRACE_POKEDATA, tracee,
				addr, *(info->poke_data + i));
		EXPECT_EQ(0, ret);
	}
}

FIXTURE_DATA(TRACE_poke_sys_read) {
	struct sock_fprog prog;
	pid_t tracer;
	long poked;
	struct tracer_args_poke_t tracer_args;
	unsigned long flag;
};

FIXTURE_SETUP(TRACE_poke_sys_read)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE | 0x1001),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};

	self->poked = 0;
	memset(&self->prog, 0, sizeof(self->prog));
	self->prog.filter = malloc(sizeof(filter));
	ASSERT_NE(NULL, self->prog.filter);
	memcpy(self->prog.filter, filter, sizeof(filter));
	self->prog.len = (unsigned short)ARRAY_SIZE(filter);

	/* Set up tracer args. */
	self->tracer_args.poke_addr = &self->poked;
	self->flag = 0x2001;
	self->tracer_args.poke_data = &self->flag;
	self->tracer_args.poke_len = 1;

	/* Launch tracer. */
	self->tracer = setup_trace_fixture(_metadata, tracer_poke,
					   &self->tracer_args);
}

FIXTURE_TEARDOWN(TRACE_poke_sys_read)
{
	teardown_trace_fixture(_metadata, self->tracer);
	if (self->prog.filter)
		free(self->prog.filter);
}

TEST_F(TRACE_poke_sys_read, read_has_side_effects)
{
	ssize_t ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog, 0, 0);
	ASSERT_EQ(0, ret);

	EXPECT_EQ(0, self->poked);
	ret = read(-1, NULL, 0);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(0x2001, self->poked);
}

TEST_F(TRACE_poke_sys_read, getpid_runs_normally)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog, 0, 0);
	ASSERT_EQ(0, ret);

	EXPECT_EQ(0, self->poked);
	EXPECT_NE(0, syscall(__NR_getpid));
	EXPECT_EQ(0, self->poked);
}

#if defined(__x86_64__)
# define ARCH_REGS	struct user_regs_struct
# define SYSCALL_NUM	orig_rax
# define SYSCALL_RET	rax
#elif defined(__i386__)
# define ARCH_REGS	struct user_regs_struct
# define SYSCALL_NUM	orig_eax
# define SYSCALL_RET	eax
#elif defined(__arm__)
# define ARCH_REGS	struct pt_regs
# define SYSCALL_NUM	ARM_r7
# define SYSCALL_RET	ARM_r0
#elif defined(__aarch64__)
# define ARCH_REGS	struct user_pt_regs
# define SYSCALL_NUM	regs[8]
# define SYSCALL_RET	regs[0]
#elif defined(__powerpc__)
# define ARCH_REGS	struct pt_regs
# define SYSCALL_NUM	gpr[0]
# define SYSCALL_RET	gpr[3]
#elif defined(__s390__)
# define ARCH_REGS     s390_regs
# define SYSCALL_NUM   gprs[2]
# define SYSCALL_RET   gprs[2]
#else
# error "Do not know how to find your architecture's registers and syscalls"
#endif

/* Use PTRACE_GETREGS and PTRACE_SETREGS when available. This is useful for
 * architectures without HAVE_ARCH_TRACEHOOK (e.g. User-mode Linux).
 */
#if defined(__x86_64__) || defined(__i386__)
#define HAVE_GETREGS
#endif

/* Architecture-specific syscall fetching routine. */
int get_syscall(struct __test_metadata *_metadata, pid_t tracee)
{
	ARCH_REGS regs;
#ifdef HAVE_GETREGS
	EXPECT_EQ(0, ptrace(PTRACE_GETREGS, tracee, 0, &regs)) {
		TH_LOG("PTRACE_GETREGS failed");
		return -1;
	}
#else
	struct iovec iov;

	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	EXPECT_EQ(0, ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &iov)) {
		TH_LOG("PTRACE_GETREGSET failed");
		return -1;
	}
#endif

	return regs.SYSCALL_NUM;
}

/* Architecture-specific syscall changing routine. */
void change_syscall(struct __test_metadata *_metadata,
		    pid_t tracee, int syscall)
{
	int ret;
	ARCH_REGS regs;
#ifdef HAVE_GETREGS
	ret = ptrace(PTRACE_GETREGS, tracee, 0, &regs);
#else
	struct iovec iov;
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	ret = ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &iov);
#endif
	EXPECT_EQ(0, ret);

#if defined(__x86_64__) || defined(__i386__) || defined(__powerpc__) || \
    defined(__s390__)
	{
		regs.SYSCALL_NUM = syscall;
	}

#elif defined(__arm__)
# ifndef PTRACE_SET_SYSCALL
#  define PTRACE_SET_SYSCALL   23
# endif
	{
		ret = ptrace(PTRACE_SET_SYSCALL, tracee, NULL, syscall);
		EXPECT_EQ(0, ret);
	}

#elif defined(__aarch64__)
# ifndef NT_ARM_SYSTEM_CALL
#  define NT_ARM_SYSTEM_CALL 0x404
# endif
	{
		iov.iov_base = &syscall;
		iov.iov_len = sizeof(syscall);
		ret = ptrace(PTRACE_SETREGSET, tracee, NT_ARM_SYSTEM_CALL,
			     &iov);
		EXPECT_EQ(0, ret);
	}

#else
	ASSERT_EQ(1, 0) {
		TH_LOG("How is the syscall changed on this architecture?");
	}
#endif

	/* If syscall is skipped, change return value. */
	if (syscall == -1)
		regs.SYSCALL_RET = 1;

#ifdef HAVE_GETREGS
	ret = ptrace(PTRACE_SETREGS, tracee, 0, &regs);
#else
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	ret = ptrace(PTRACE_SETREGSET, tracee, NT_PRSTATUS, &iov);
#endif
	EXPECT_EQ(0, ret);
}

void tracer_syscall(struct __test_metadata *_metadata, pid_t tracee,
		    int status, void *args)
{
	int ret;
	unsigned long msg;

	/* Make sure we got the right message. */
	ret = ptrace(PTRACE_GETEVENTMSG, tracee, NULL, &msg);
	EXPECT_EQ(0, ret);

	/* Validate and take action on expected syscalls. */
	switch (msg) {
	case 0x1002:
		/* change getpid to getppid. */
		EXPECT_EQ(__NR_getpid, get_syscall(_metadata, tracee));
		change_syscall(_metadata, tracee, __NR_getppid);
		break;
	case 0x1003:
		/* skip gettid. */
		EXPECT_EQ(__NR_gettid, get_syscall(_metadata, tracee));
		change_syscall(_metadata, tracee, -1);
		break;
	case 0x1004:
		/* do nothing (allow getppid) */
		EXPECT_EQ(__NR_getppid, get_syscall(_metadata, tracee));
		break;
	default:
		EXPECT_EQ(0, msg) {
			TH_LOG("Unknown PTRACE_GETEVENTMSG: 0x%lx", msg);
			kill(tracee, SIGKILL);
		}
	}

}

FIXTURE_DATA(TRACE_syscall) {
	struct sock_fprog prog;
	pid_t tracer, mytid, mypid, parent;
};

FIXTURE_SETUP(TRACE_syscall)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE | 0x1002),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_gettid, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE | 0x1003),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getppid, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE | 0x1004),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};

	memset(&self->prog, 0, sizeof(self->prog));
	self->prog.filter = malloc(sizeof(filter));
	ASSERT_NE(NULL, self->prog.filter);
	memcpy(self->prog.filter, filter, sizeof(filter));
	self->prog.len = (unsigned short)ARRAY_SIZE(filter);

	/* Prepare some testable syscall results. */
	self->mytid = syscall(__NR_gettid);
	ASSERT_GT(self->mytid, 0);
	ASSERT_NE(self->mytid, 1) {
		TH_LOG("Running this test as init is not supported. :)");
	}

	self->mypid = getpid();
	ASSERT_GT(self->mypid, 0);
	ASSERT_EQ(self->mytid, self->mypid);

	self->parent = getppid();
	ASSERT_GT(self->parent, 0);
	ASSERT_NE(self->parent, self->mypid);

	/* Launch tracer. */
	self->tracer = setup_trace_fixture(_metadata, tracer_syscall, NULL);
}

FIXTURE_TEARDOWN(TRACE_syscall)
{
	teardown_trace_fixture(_metadata, self->tracer);
	if (self->prog.filter)
		free(self->prog.filter);
}

TEST_F(TRACE_syscall, syscall_allowed)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog, 0, 0);
	ASSERT_EQ(0, ret);

	/* getppid works as expected (no changes). */
	EXPECT_EQ(self->parent, syscall(__NR_getppid));
	EXPECT_NE(self->mypid, syscall(__NR_getppid));
}

TEST_F(TRACE_syscall, syscall_redirected)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog, 0, 0);
	ASSERT_EQ(0, ret);

	/* getpid has been redirected to getppid as expected. */
	EXPECT_EQ(self->parent, syscall(__NR_getpid));
	EXPECT_NE(self->mypid, syscall(__NR_getpid));
}

TEST_F(TRACE_syscall, syscall_dropped)
{
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret);

	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &self->prog, 0, 0);
	ASSERT_EQ(0, ret);

	/* gettid has been skipped and an altered return value stored. */
	EXPECT_EQ(1, syscall(__NR_gettid));
	EXPECT_NE(self->mytid, syscall(__NR_gettid));
}

#ifndef __NR_seccomp
# if defined(__i386__)
#  define __NR_seccomp 354
# elif defined(__x86_64__)
#  define __NR_seccomp 317
# elif defined(__arm__)
#  define __NR_seccomp 383
# elif defined(__aarch64__)
#  define __NR_seccomp 277
# elif defined(__powerpc__)
#  define __NR_seccomp 358
# elif defined(__s390__)
#  define __NR_seccomp 348
# else
#  warning "seccomp syscall number unknown for this architecture"
#  define __NR_seccomp 0xffff
# endif
#endif

#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT 0
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

#ifndef seccomp
int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}
#endif

TEST(seccomp_syscall)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	/* Reject insane operation. */
	ret = seccomp(-1, 0, &prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	EXPECT_EQ(EINVAL, errno) {
		TH_LOG("Did not reject crazy op value!");
	}

	/* Reject strict with flags or pointer. */
	ret = seccomp(SECCOMP_SET_MODE_STRICT, -1, NULL);
	EXPECT_EQ(EINVAL, errno) {
		TH_LOG("Did not reject mode strict with flags!");
	}
	ret = seccomp(SECCOMP_SET_MODE_STRICT, 0, &prog);
	EXPECT_EQ(EINVAL, errno) {
		TH_LOG("Did not reject mode strict with uargs!");
	}

	/* Reject insane args for filter. */
	ret = seccomp(SECCOMP_SET_MODE_FILTER, -1, &prog);
	EXPECT_EQ(EINVAL, errno) {
		TH_LOG("Did not reject crazy filter flags!");
	}
	ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, NULL);
	EXPECT_EQ(EFAULT, errno) {
		TH_LOG("Did not reject NULL filter!");
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
	EXPECT_EQ(0, errno) {
		TH_LOG("Kernel does not support SECCOMP_SET_MODE_FILTER: %s",
			strerror(errno));
	}
}

TEST(seccomp_syscall_mode_lock)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0);
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	EXPECT_EQ(0, ret) {
		TH_LOG("Could not install filter!");
	}

	/* Make sure neither entry point will switch to strict. */
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
	EXPECT_EQ(EINVAL, errno) {
		TH_LOG("Switched to mode strict!");
	}

	ret = seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL);
	EXPECT_EQ(EINVAL, errno) {
		TH_LOG("Switched to mode strict!");
	}
}

TEST(TSYNC_first)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0);
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		      &prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	EXPECT_EQ(0, ret) {
		TH_LOG("Could not install initial filter with TSYNC!");
	}
}

#define TSYNC_SIBLINGS 2
struct tsync_sibling {
	pthread_t tid;
	pid_t system_tid;
	sem_t *started;
	pthread_cond_t *cond;
	pthread_mutex_t *mutex;
	int diverge;
	int num_waits;
	struct sock_fprog *prog;
	struct __test_metadata *metadata;
};

FIXTURE_DATA(TSYNC) {
	struct sock_fprog root_prog, apply_prog;
	struct tsync_sibling sibling[TSYNC_SIBLINGS];
	sem_t started;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	int sibling_count;
};

FIXTURE_SETUP(TSYNC)
{
	struct sock_filter root_filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter apply_filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};

	memset(&self->root_prog, 0, sizeof(self->root_prog));
	memset(&self->apply_prog, 0, sizeof(self->apply_prog));
	memset(&self->sibling, 0, sizeof(self->sibling));
	self->root_prog.filter = malloc(sizeof(root_filter));
	ASSERT_NE(NULL, self->root_prog.filter);
	memcpy(self->root_prog.filter, &root_filter, sizeof(root_filter));
	self->root_prog.len = (unsigned short)ARRAY_SIZE(root_filter);

	self->apply_prog.filter = malloc(sizeof(apply_filter));
	ASSERT_NE(NULL, self->apply_prog.filter);
	memcpy(self->apply_prog.filter, &apply_filter, sizeof(apply_filter));
	self->apply_prog.len = (unsigned short)ARRAY_SIZE(apply_filter);

	self->sibling_count = 0;
	pthread_mutex_init(&self->mutex, NULL);
	pthread_cond_init(&self->cond, NULL);
	sem_init(&self->started, 0, 0);
	self->sibling[0].tid = 0;
	self->sibling[0].cond = &self->cond;
	self->sibling[0].started = &self->started;
	self->sibling[0].mutex = &self->mutex;
	self->sibling[0].diverge = 0;
	self->sibling[0].num_waits = 1;
	self->sibling[0].prog = &self->root_prog;
	self->sibling[0].metadata = _metadata;
	self->sibling[1].tid = 0;
	self->sibling[1].cond = &self->cond;
	self->sibling[1].started = &self->started;
	self->sibling[1].mutex = &self->mutex;
	self->sibling[1].diverge = 0;
	self->sibling[1].prog = &self->root_prog;
	self->sibling[1].num_waits = 1;
	self->sibling[1].metadata = _metadata;
}

FIXTURE_TEARDOWN(TSYNC)
{
	int sib = 0;

	if (self->root_prog.filter)
		free(self->root_prog.filter);
	if (self->apply_prog.filter)
		free(self->apply_prog.filter);

	for ( ; sib < self->sibling_count; ++sib) {
		struct tsync_sibling *s = &self->sibling[sib];
		void *status;

		if (!s->tid)
			continue;
		if (pthread_kill(s->tid, 0)) {
			pthread_cancel(s->tid);
			pthread_join(s->tid, &status);
		}
	}
	pthread_mutex_destroy(&self->mutex);
	pthread_cond_destroy(&self->cond);
	sem_destroy(&self->started);
}

void *tsync_sibling(void *data)
{
	long ret = 0;
	struct tsync_sibling *me = data;

	me->system_tid = syscall(__NR_gettid);

	pthread_mutex_lock(me->mutex);
	if (me->diverge) {
		/* Just re-apply the root prog to fork the tree */
		ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
				me->prog, 0, 0);
	}
	sem_post(me->started);
	/* Return outside of started so parent notices failures. */
	if (ret) {
		pthread_mutex_unlock(me->mutex);
		return (void *)SIBLING_EXIT_FAILURE;
	}
	do {
		pthread_cond_wait(me->cond, me->mutex);
		me->num_waits = me->num_waits - 1;
	} while (me->num_waits);
	pthread_mutex_unlock(me->mutex);

	ret = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (!ret)
		return (void *)SIBLING_EXIT_NEWPRIVS;
	read(0, NULL, 0);
	return (void *)SIBLING_EXIT_UNKILLED;
}

void tsync_start_sibling(struct tsync_sibling *sibling)
{
	pthread_create(&sibling->tid, NULL, tsync_sibling, (void *)sibling);
}

TEST_F(TSYNC, siblings_fail_prctl)
{
	long ret;
	void *status;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_prctl, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | EINVAL),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	/* Check prctl failure detection by requesting sib 0 diverge. */
	ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	ASSERT_EQ(0, ret) {
		TH_LOG("setting filter failed");
	}

	self->sibling[0].diverge = 1;
	tsync_start_sibling(&self->sibling[0]);
	tsync_start_sibling(&self->sibling[1]);

	while (self->sibling_count < TSYNC_SIBLINGS) {
		sem_wait(&self->started);
		self->sibling_count++;
	}

	/* Signal the threads to clean up*/
	pthread_mutex_lock(&self->mutex);
	ASSERT_EQ(0, pthread_cond_broadcast(&self->cond)) {
		TH_LOG("cond broadcast non-zero");
	}
	pthread_mutex_unlock(&self->mutex);

	/* Ensure diverging sibling failed to call prctl. */
	pthread_join(self->sibling[0].tid, &status);
	EXPECT_EQ(SIBLING_EXIT_FAILURE, (long)status);
	pthread_join(self->sibling[1].tid, &status);
	EXPECT_EQ(SIBLING_EXIT_UNKILLED, (long)status);
}

TEST_F(TSYNC, two_siblings_with_ancestor)
{
	long ret;
	void *status;

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, &self->root_prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support SECCOMP_SET_MODE_FILTER!");
	}
	tsync_start_sibling(&self->sibling[0]);
	tsync_start_sibling(&self->sibling[1]);

	while (self->sibling_count < TSYNC_SIBLINGS) {
		sem_wait(&self->started);
		self->sibling_count++;
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		      &self->apply_prog);
	ASSERT_EQ(0, ret) {
		TH_LOG("Could install filter on all threads!");
	}
	/* Tell the siblings to test the policy */
	pthread_mutex_lock(&self->mutex);
	ASSERT_EQ(0, pthread_cond_broadcast(&self->cond)) {
		TH_LOG("cond broadcast non-zero");
	}
	pthread_mutex_unlock(&self->mutex);
	/* Ensure they are both killed and don't exit cleanly. */
	pthread_join(self->sibling[0].tid, &status);
	EXPECT_EQ(0x0, (long)status);
	pthread_join(self->sibling[1].tid, &status);
	EXPECT_EQ(0x0, (long)status);
}

TEST_F(TSYNC, two_sibling_want_nnp)
{
	void *status;

	/* start siblings before any prctl() operations */
	tsync_start_sibling(&self->sibling[0]);
	tsync_start_sibling(&self->sibling[1]);
	while (self->sibling_count < TSYNC_SIBLINGS) {
		sem_wait(&self->started);
		self->sibling_count++;
	}

	/* Tell the siblings to test no policy */
	pthread_mutex_lock(&self->mutex);
	ASSERT_EQ(0, pthread_cond_broadcast(&self->cond)) {
		TH_LOG("cond broadcast non-zero");
	}
	pthread_mutex_unlock(&self->mutex);

	/* Ensure they are both upset about lacking nnp. */
	pthread_join(self->sibling[0].tid, &status);
	EXPECT_EQ(SIBLING_EXIT_NEWPRIVS, (long)status);
	pthread_join(self->sibling[1].tid, &status);
	EXPECT_EQ(SIBLING_EXIT_NEWPRIVS, (long)status);
}

TEST_F(TSYNC, two_siblings_with_no_filter)
{
	long ret;
	void *status;

	/* start siblings before any prctl() operations */
	tsync_start_sibling(&self->sibling[0]);
	tsync_start_sibling(&self->sibling[1]);
	while (self->sibling_count < TSYNC_SIBLINGS) {
		sem_wait(&self->started);
		self->sibling_count++;
	}

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		      &self->apply_prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	ASSERT_EQ(0, ret) {
		TH_LOG("Could install filter on all threads!");
	}

	/* Tell the siblings to test the policy */
	pthread_mutex_lock(&self->mutex);
	ASSERT_EQ(0, pthread_cond_broadcast(&self->cond)) {
		TH_LOG("cond broadcast non-zero");
	}
	pthread_mutex_unlock(&self->mutex);

	/* Ensure they are both killed and don't exit cleanly. */
	pthread_join(self->sibling[0].tid, &status);
	EXPECT_EQ(0x0, (long)status);
	pthread_join(self->sibling[1].tid, &status);
	EXPECT_EQ(0x0, (long)status);
}

TEST_F(TSYNC, two_siblings_with_one_divergence)
{
	long ret;
	void *status;

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, &self->root_prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support SECCOMP_SET_MODE_FILTER!");
	}
	self->sibling[0].diverge = 1;
	tsync_start_sibling(&self->sibling[0]);
	tsync_start_sibling(&self->sibling[1]);

	while (self->sibling_count < TSYNC_SIBLINGS) {
		sem_wait(&self->started);
		self->sibling_count++;
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		      &self->apply_prog);
	ASSERT_EQ(self->sibling[0].system_tid, ret) {
		TH_LOG("Did not fail on diverged sibling.");
	}

	/* Wake the threads */
	pthread_mutex_lock(&self->mutex);
	ASSERT_EQ(0, pthread_cond_broadcast(&self->cond)) {
		TH_LOG("cond broadcast non-zero");
	}
	pthread_mutex_unlock(&self->mutex);

	/* Ensure they are both unkilled. */
	pthread_join(self->sibling[0].tid, &status);
	EXPECT_EQ(SIBLING_EXIT_UNKILLED, (long)status);
	pthread_join(self->sibling[1].tid, &status);
	EXPECT_EQ(SIBLING_EXIT_UNKILLED, (long)status);
}

TEST_F(TSYNC, two_siblings_not_under_filter)
{
	long ret, sib;
	void *status;

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}

	/*
	 * Sibling 0 will have its own seccomp policy
	 * and Sibling 1 will not be under seccomp at
	 * all. Sibling 1 will enter seccomp and 0
	 * will cause failure.
	 */
	self->sibling[0].diverge = 1;
	tsync_start_sibling(&self->sibling[0]);
	tsync_start_sibling(&self->sibling[1]);

	while (self->sibling_count < TSYNC_SIBLINGS) {
		sem_wait(&self->started);
		self->sibling_count++;
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, &self->root_prog);
	ASSERT_NE(ENOSYS, errno) {
		TH_LOG("Kernel does not support seccomp syscall!");
	}
	ASSERT_EQ(0, ret) {
		TH_LOG("Kernel does not support SECCOMP_SET_MODE_FILTER!");
	}

	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		      &self->apply_prog);
	ASSERT_EQ(ret, self->sibling[0].system_tid) {
		TH_LOG("Did not fail on diverged sibling.");
	}
	sib = 1;
	if (ret == self->sibling[0].system_tid)
		sib = 0;

	pthread_mutex_lock(&self->mutex);

	/* Increment the other siblings num_waits so we can clean up
	 * the one we just saw.
	 */
	self->sibling[!sib].num_waits += 1;

	/* Signal the thread to clean up*/
	ASSERT_EQ(0, pthread_cond_broadcast(&self->cond)) {
		TH_LOG("cond broadcast non-zero");
	}
	pthread_mutex_unlock(&self->mutex);
	pthread_join(self->sibling[sib].tid, &status);
	EXPECT_EQ(SIBLING_EXIT_UNKILLED, (long)status);
	/* Poll for actual task death. pthread_join doesn't guarantee it. */
	while (!kill(self->sibling[sib].system_tid, 0))
		sleep(0.1);
	/* Switch to the remaining sibling */
	sib = !sib;

	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		      &self->apply_prog);
	ASSERT_EQ(0, ret) {
		TH_LOG("Expected the remaining sibling to sync");
	};

	pthread_mutex_lock(&self->mutex);

	/* If remaining sibling didn't have a chance to wake up during
	 * the first broadcast, manually reduce the num_waits now.
	 */
	if (self->sibling[sib].num_waits > 1)
		self->sibling[sib].num_waits = 1;
	ASSERT_EQ(0, pthread_cond_broadcast(&self->cond)) {
		TH_LOG("cond broadcast non-zero");
	}
	pthread_mutex_unlock(&self->mutex);
	pthread_join(self->sibling[sib].tid, &status);
	EXPECT_EQ(0, (long)status);
	/* Poll for actual task death. pthread_join doesn't guarantee it. */
	while (!kill(self->sibling[sib].system_tid, 0))
		sleep(0.1);

	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
		      &self->apply_prog);
	ASSERT_EQ(0, ret);  /* just us chickens */
}

/* Make sure restarted syscalls are seen directly as "restart_syscall". */
TEST(syscall_restart)
{
	long ret;
	unsigned long msg;
	pid_t child_pid;
	int pipefd[2];
	int status;
	siginfo_t info = { };
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			 offsetof(struct seccomp_data, nr)),

#ifdef __NR_sigreturn
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_sigreturn, 6, 0),
#endif
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 5, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit, 4, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_rt_sigreturn, 3, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_nanosleep, 4, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_restart_syscall, 4, 0),

		/* Allow __NR_write for easy logging. */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		/* The nanosleep jump target. */
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE|0x100),
		/* The restart_syscall jump target. */
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE|0x200),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
#if defined(__arm__)
	struct utsname utsbuf;
#endif

	ASSERT_EQ(0, pipe(pipefd));

	child_pid = fork();
	ASSERT_LE(0, child_pid);
	if (child_pid == 0) {
		/* Child uses EXPECT not ASSERT to deliver status correctly. */
		char buf = ' ';
		struct timespec timeout = { };

		/* Attach parent as tracer and stop. */
		EXPECT_EQ(0, ptrace(PTRACE_TRACEME));
		EXPECT_EQ(0, raise(SIGSTOP));

		EXPECT_EQ(0, close(pipefd[1]));

		EXPECT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
		}

		ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
		EXPECT_EQ(0, ret) {
			TH_LOG("Failed to install filter!");
		}

		EXPECT_EQ(1, read(pipefd[0], &buf, 1)) {
			TH_LOG("Failed to read() sync from parent");
		}
		EXPECT_EQ('.', buf) {
			TH_LOG("Failed to get sync data from read()");
		}

		/* Start nanosleep to be interrupted. */
		timeout.tv_sec = 1;
		errno = 0;
		EXPECT_EQ(0, nanosleep(&timeout, NULL)) {
			TH_LOG("Call to nanosleep() failed (errno %d)", errno);
		}

		/* Read final sync from parent. */
		EXPECT_EQ(1, read(pipefd[0], &buf, 1)) {
			TH_LOG("Failed final read() from parent");
		}
		EXPECT_EQ('!', buf) {
			TH_LOG("Failed to get final data from read()");
		}

		/* Directly report the status of our test harness results. */
		syscall(__NR_exit, _metadata->passed ? EXIT_SUCCESS
						     : EXIT_FAILURE);
	}
	EXPECT_EQ(0, close(pipefd[0]));

	/* Attach to child, setup options, and release. */
	ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
	ASSERT_EQ(true, WIFSTOPPED(status));
	ASSERT_EQ(0, ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
			    PTRACE_O_TRACESECCOMP));
	ASSERT_EQ(0, ptrace(PTRACE_CONT, child_pid, NULL, 0));
	ASSERT_EQ(1, write(pipefd[1], ".", 1));

	/* Wait for nanosleep() to start. */
	ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
	ASSERT_EQ(true, WIFSTOPPED(status));
	ASSERT_EQ(SIGTRAP, WSTOPSIG(status));
	ASSERT_EQ(PTRACE_EVENT_SECCOMP, (status >> 16));
	ASSERT_EQ(0, ptrace(PTRACE_GETEVENTMSG, child_pid, NULL, &msg));
	ASSERT_EQ(0x100, msg);
	EXPECT_EQ(__NR_nanosleep, get_syscall(_metadata, child_pid));

	/* Might as well check siginfo for sanity while we're here. */
	ASSERT_EQ(0, ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &info));
	ASSERT_EQ(SIGTRAP, info.si_signo);
	ASSERT_EQ(SIGTRAP | (PTRACE_EVENT_SECCOMP << 8), info.si_code);
	EXPECT_EQ(0, info.si_errno);
	EXPECT_EQ(getuid(), info.si_uid);
	/* Verify signal delivery came from child (seccomp-triggered). */
	EXPECT_EQ(child_pid, info.si_pid);

	/* Interrupt nanosleep with SIGSTOP (which we'll need to handle). */
	ASSERT_EQ(0, kill(child_pid, SIGSTOP));
	ASSERT_EQ(0, ptrace(PTRACE_CONT, child_pid, NULL, 0));
	ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
	ASSERT_EQ(true, WIFSTOPPED(status));
	ASSERT_EQ(SIGSTOP, WSTOPSIG(status));
	/* Verify signal delivery came from parent now. */
	ASSERT_EQ(0, ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &info));
	EXPECT_EQ(getpid(), info.si_pid);

	/* Restart nanosleep with SIGCONT, which triggers restart_syscall. */
	ASSERT_EQ(0, kill(child_pid, SIGCONT));
	ASSERT_EQ(0, ptrace(PTRACE_CONT, child_pid, NULL, 0));
	ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
	ASSERT_EQ(true, WIFSTOPPED(status));
	ASSERT_EQ(SIGCONT, WSTOPSIG(status));
	ASSERT_EQ(0, ptrace(PTRACE_CONT, child_pid, NULL, 0));

	/* Wait for restart_syscall() to start. */
	ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
	ASSERT_EQ(true, WIFSTOPPED(status));
	ASSERT_EQ(SIGTRAP, WSTOPSIG(status));
	ASSERT_EQ(PTRACE_EVENT_SECCOMP, (status >> 16));
	ASSERT_EQ(0, ptrace(PTRACE_GETEVENTMSG, child_pid, NULL, &msg));

	ASSERT_EQ(0x200, msg);
	ret = get_syscall(_metadata, child_pid);
#if defined(__arm__)
	/*
	 * FIXME:
	 * - native ARM registers do NOT expose true syscall.
	 * - compat ARM registers on ARM64 DO expose true syscall.
	 */
	ASSERT_EQ(0, uname(&utsbuf));
	if (strncmp(utsbuf.machine, "arm", 3) == 0) {
		EXPECT_EQ(__NR_nanosleep, ret);
	} else
#endif
	{
		EXPECT_EQ(__NR_restart_syscall, ret);
	}

	/* Write again to end test. */
	ASSERT_EQ(0, ptrace(PTRACE_CONT, child_pid, NULL, 0));
	ASSERT_EQ(1, write(pipefd[1], "!", 1));
	EXPECT_EQ(0, close(pipefd[1]));

	ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
	if (WIFSIGNALED(status) || WEXITSTATUS(status))
		_metadata->passed = 0;
}

#ifdef SECCOMP_DATA_ARGEVAL_PRESENT
TEST(field_is_valid_syscall)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
				offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
				offsetof(struct seccomp_data, is_valid_syscall)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 1, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | EINVAL),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}
	EXPECT_EQ(0, seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)) {
		TH_LOG("Failed to install filter!");
	}

	EXPECT_EQ(-1, syscall(__NR_getpid));
	EXPECT_EQ(EINVAL, errno);
}

#define PATH_DEV_NULL "/dev/null"
#define PATH_DEV_ZERO "/dev/zero"

/* The sandbox0 allow opening only @allowed_path */
void apply_sandbox0(struct __test_metadata *_metadata, const char *allowed_path)
{
	struct sock_filter filter0[] = {
		/* Only care about open(2) */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
				offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open, 0, 1),
		/* Check the objects of group 5 matching the first argument */
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ARGEVAL | 1 << 8 | 5),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog0 = {
		.len = (unsigned short)ARRAY_SIZE(filter0),
		.filter = filter0,
	};
	struct sock_filter filter1[] = {
		/* Does not need to check for arch nor syscall number because
		 * of the @checker_group check
		 */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
				offsetof(struct seccomp_data, checker_group)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 5, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		/* Kill if not a valid syscall (unknown open‽) */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
				offsetof(struct seccomp_data, is_valid_syscall)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 1, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		/* Denied access if the first argument was not validated by the
		 * checker.
		 */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, match_arg(0)),
		/* Match the first two checkers, if any */
		BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 3, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		/* Use an impossible errno value to ensure it comes from our
		 * filter (should be EACCES most of the time).
		 */
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | E2BIG),
	};
	struct sock_fprog prog1 = {
		.len = (unsigned short)ARRAY_SIZE(filter1),
		.filter = filter1,
	};
	struct seccomp_object_path path0 = SECCOMP_MAKE_PATH_DENTRY(allowed_path);
	struct seccomp_checker checker0[] = {
		SECCOMP_MAKE_OBJ_PATH(FS_LITERAL, &path0),
	};
	/* Group 5 */
	struct seccomp_checker_group checker_group0 = {
		.version = 1,
		.id = 5,
		.len = ARRAY_SIZE(checker0),
		.checkers = &checker0,
	};

	/* Set up the test sandbox */
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS!");
	}
	/* Load the path checkers */
	EXPECT_EQ(0, seccomp(SECCOMP_ADD_CHECKER_GROUP, 0, &checker_group0)) {
		TH_LOG("Failed to add checker group!");
	}
	/* Load filters in reverse order */
	EXPECT_EQ(0, seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog1)) {
		TH_LOG("Failed to install filter!");
	}
	EXPECT_EQ(0, seccomp(SECCOMP_SET_MODE_FILTER,
				SECCOMP_FILTER_FLAG_TSYNC, &prog0)) {
		TH_LOG("Failed to install filter!");
	}
}

TEST(argeval_open_whitelist)
{
	int fd;

	/* Validate the first test file */
	fd = open(PATH_DEV_ZERO, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open " PATH_DEV_ZERO);
	}
	close(fd);

	/* Validate the second test file */
	fd = open(PATH_DEV_NULL, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open " PATH_DEV_NULL);
	}
	close(fd);

	apply_sandbox0(_metadata, PATH_DEV_ZERO);

	/* Allowed file */
	fd = open(PATH_DEV_ZERO, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open " PATH_DEV_ZERO);
	}
	close(fd);

	/* Denied file (by the filter) */
	fd = open(PATH_DEV_NULL, O_RDONLY);
	EXPECT_EQ(-1, fd) {
		TH_LOG("Could open " PATH_DEV_NULL);
	}
	EXPECT_EQ(E2BIG, errno);
	close(fd);
}

FIXTURE_DATA(TRACE_poke_arg_path) {
	struct sock_fprog prog;
	pid_t tracer;
	struct tracer_args_poke_t tracer_args;
	char *path_orig;
	char *path_hijack;
};

FIXTURE_SETUP(TRACE_poke_arg_path)
{
	unsigned long orig_delta, orig_size, hijack_delta, hijack_size;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE | 0x1001),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};

	memset(&self->prog, 0, sizeof(self->prog));
	self->prog.filter = malloc(sizeof(filter));
	ASSERT_NE(NULL, self->prog.filter);
	memcpy(self->prog.filter, filter, sizeof(filter));
	self->prog.len = (unsigned short)ARRAY_SIZE(filter);

	/* @path_orig must be writable */
	orig_delta = sizeof(PATH_DEV_ZERO) % sizeof(long);
	orig_size = sizeof(PATH_DEV_ZERO) - orig_delta +
		(orig_delta ? sizeof(long) : 0);
	self->path_orig = malloc(orig_size);
	ASSERT_NE(NULL, self->path_orig);
	memset(self->path_orig, 0, orig_size);
	memcpy(self->path_orig, PATH_DEV_ZERO, sizeof(PATH_DEV_ZERO));
	self->tracer_args.poke_addr = (unsigned long *)self->path_orig;

	hijack_delta = sizeof(PATH_DEV_NULL) % sizeof(long);
	hijack_size = sizeof(PATH_DEV_NULL) - hijack_delta +
		(hijack_delta ? sizeof(long) : 0);
	/* @path_hijack must be able to override @path_orig */
	ASSERT_GE(orig_size, hijack_size);
	self->path_hijack = malloc(hijack_size);
	ASSERT_NE(NULL, self->path_hijack);
	memset(self->path_hijack, 0, hijack_size);
	memcpy(self->path_hijack, PATH_DEV_NULL, sizeof(PATH_DEV_NULL));
	self->tracer_args.poke_data = (unsigned long *)self->path_hijack;
	self->tracer_args.poke_len = hijack_size;

	/* Launch tracer */
	self->tracer = setup_trace_fixture(_metadata, tracer_poke,
					   &self->tracer_args);
}

FIXTURE_TEARDOWN(TRACE_poke_arg_path)
{
	teardown_trace_fixture(_metadata, self->tracer);
	if (self->prog.filter)
		free(self->prog.filter);
	if (self->path_orig)
		free(self->path_orig);
}

/* Any tracer process can bypass a seccomp filter, so we can't protect against
 * this threat and should deny any ptrace call from a seccomped process to be
 * able to properly sandbox it.
 *
 * However, a seccomped process can fork and ask its child to change a shared
 * memory used to hold the syscall arguments. This can be used to trigger
 * TOCTOU race conditions between the filter evaluation and the effective
 * syscall operations. For test purpose, it is simpler to ask a dedicated
 * tracer process to do the same action after the filter evaluation to acheive
 * the same result. The kernel must detect and block this race condition.
 */
TEST_F(TRACE_poke_arg_path, argeval_toctou_argument)
{
	int fd;
	char buf;
	ssize_t len;

	/* Validate the first test file */
	fd = open(self->path_orig, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open %s", self->path_orig);
	}
	len = read(fd, &buf, sizeof(buf));
	EXPECT_EQ(1, len) {
		TH_LOG("Failed to read from %s", self->path_orig);
	}
	EXPECT_EQ(0, buf) {
		TH_LOG("Got unexpected value from %s", self->path_orig);
	}
	close(fd);

	/* Validate the second test file */
	fd = open(self->path_hijack, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open %s", self->path_hijack);
	}
	len = read(fd, &buf, sizeof(buf));
	EXPECT_EQ(0, len) {
		TH_LOG("Able to read from %s", self->path_orig);
	}
	close(fd);

	apply_sandbox0(_metadata, PATH_DEV_ZERO);

	/* Allowed file: /dev/zero */
	fd = open(self->path_orig, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open %s", self->path_orig);
	}
	len = read(fd, &buf, sizeof(buf));
	EXPECT_EQ(1, len) {
		TH_LOG("Failed to read from %s", self->path_orig);
	}
	EXPECT_EQ(0, buf) {
		TH_LOG("Got unexpected value from %s", self->path_orig);
	}
	close(fd);

	/* Denied file: /dev/null */
	fd = open(self->path_hijack, O_RDONLY);
	EXPECT_EQ(-1, fd) {
		TH_LOG("Could open %s", self->path_hijack);
	}
	close(fd);

	/* Setup the hijack for every open: replace /dev/zero with /dev/null */
	EXPECT_EQ(0, seccomp(SECCOMP_SET_MODE_FILTER,
				SECCOMP_FILTER_FLAG_TSYNC, &self->prog)) {
		TH_LOG("Failed to install filter!");
	}

	/* Should read /dev/zero even if it is hijacked with /dev/null after
	 * the filter
	 */
	fd = open(self->path_orig, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open %s", self->path_orig);
	}
	len = read(fd, &buf, sizeof(buf));
	EXPECT_EQ(1, len) {
		TH_LOG("Failed to read from %s", self->path_orig);
	}
	EXPECT_EQ(0, buf) {
		TH_LOG("Got unexpected value from %s", self->path_orig);
	}
	close(fd);

	/* Now path_orig is definitely hijacked, so it must be denied */
	fd = open(self->path_orig, O_RDONLY);
	EXPECT_EQ(-1, fd) {
		TH_LOG("Could open %s", self->path_orig);
	}
	EXPECT_EQ(E2BIG, errno);
	close(fd);
}

char *new_file(struct __test_metadata *_metadata, const char *name, char buf)
{
	int ret, fd, path_len;
	char *path;
	const char tmpl[] = "/tmp/seccomp-test_%s.XXXXXX";

	path_len = sizeof(tmpl) - 2 + strlen(name);
	path = malloc(path_len);
	ASSERT_NE(path, NULL);
	ret = snprintf(path, path_len, tmpl, name);
	ASSERT_EQ(ret, path_len - 1);
	fd = mkostemp(path, O_CLOEXEC);
	ASSERT_NE(fd, -1);
	ret = write(fd, &buf, sizeof(buf));
	ASSERT_EQ(ret, sizeof(buf));
	close(fd);
	return path;
}

struct tracer_args_files {
	char *path_orig, *path_hijack, *path_swap;
};

/* Move a file after the filter evaluation but before the effective syscall. */
void tracer_swap_file(struct __test_metadata *_metadata, pid_t tracee,
		int status, void *args)
{
	int ret;
	unsigned long msg;
	struct tracer_args_files *info = (struct tracer_args_files *)args;

	ret = ptrace(PTRACE_GETEVENTMSG, tracee, NULL, &msg);
	EXPECT_EQ(0, ret);
	/* If this fails, don't try to recover. */
	ASSERT_EQ(0x1002, msg) {
		kill(tracee, SIGKILL);
	}
	/* Let's start the bonneteau! */
	ret = rename(info->path_orig, info->path_swap);
	EXPECT_EQ(0, ret);
	ret = rename(info->path_hijack, info->path_orig);
	EXPECT_EQ(0, ret);
	ret = rename(info->path_swap, info->path_hijack);
	EXPECT_EQ(0, ret);
}

FIXTURE_DATA(TRACE_swap_file) {
	struct sock_fprog prog;
	pid_t tracer;
	struct tracer_args_files tracer_args;
	char *path_orig, *path_hijack, *path_swap;
};

FIXTURE_SETUP(TRACE_swap_file)
{
	int fd;
	unsigned long orig_delta, orig_size, hijack_delta, hijack_size;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE | 0x1002),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};

	memset(&self->prog, 0, sizeof(self->prog));
	self->prog.filter = malloc(sizeof(filter));
	ASSERT_NE(NULL, self->prog.filter);
	memcpy(self->prog.filter, filter, sizeof(filter));
	self->prog.len = (unsigned short)ARRAY_SIZE(filter);

	/* Create all the files */
	self->path_orig = new_file(_metadata, "orig", 'O');
	self->tracer_args.path_orig = self->path_orig;
	self->path_hijack = new_file(_metadata, "hijack", 'H');
	self->tracer_args.path_hijack = self->path_hijack;
	self->path_swap = new_file(_metadata, "swap", 'S');
	self->tracer_args.path_swap = self->path_swap;

	/* Remove the temporary swap file */
	unlink(self->path_swap);

	/* Launch tracer */
	self->tracer = setup_trace_fixture(_metadata, tracer_swap_file,
					   &self->tracer_args);
}

FIXTURE_TEARDOWN(TRACE_swap_file)
{
	teardown_trace_fixture(_metadata, self->tracer);
	if (self->prog.filter)
		free(self->prog.filter);
	if (self->path_orig) {
		unlink(self->path_orig);
		free(self->path_orig);
	}
	if (self->path_hijack) {
		unlink(self->path_hijack);
		free(self->path_hijack);
	}
	if (self->path_swap) {
		unlink(self->path_swap);
		free(self->path_swap);
	}
}

TEST_F(TRACE_swap_file, argeval_toctou_filesystem)
{
	int fd;
	char buf;
	ssize_t len;

	/* Validate the first test file */
	fd = open(self->path_orig, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open %s", self->path_orig);
	}
	len = read(fd, &buf, sizeof(buf));
	EXPECT_EQ(1, len) {
		TH_LOG("Failed to read from %s", self->path_orig);
	}
	EXPECT_EQ('O', buf) {
		TH_LOG("Got unexpected value from %s", self->path_orig);
	}
	close(fd);

	/* Validate the second test file */
	fd = open(self->path_hijack, O_RDONLY);
	EXPECT_NE(-1, fd) {
		TH_LOG("Failed to open %s", self->path_hijack);
	}
	len = read(fd, &buf, sizeof(buf));
	EXPECT_EQ(1, len) {
		TH_LOG("Failed to read from %s", self->path_hijack);
	}
	EXPECT_EQ('H', buf) {
		TH_LOG("Got unexpected value from %s", self->path_hijack);
	}
	close(fd);

	apply_sandbox0(_metadata, self->path_orig);

	/* Setup the hijack for every open */
	EXPECT_EQ(0, seccomp(SECCOMP_SET_MODE_FILTER,
				SECCOMP_FILTER_FLAG_TSYNC, &self->prog)) {
		TH_LOG("Failed to install filter!");
	}

	/* Hijacked file */
	fd = open(self->path_orig, O_RDONLY);
	EXPECT_EQ(-1, fd) {
		TH_LOG("Could open %s", self->path_hijack);
	}
	EXPECT_EQ(EPERM, errno);
	close(fd);

	/* Denied file */
	fd = open(self->path_orig, O_RDONLY);
	EXPECT_EQ(-1, fd) {
		TH_LOG("Could open %s", self->path_hijack);
	}
	EXPECT_EQ(E2BIG, errno);
	close(fd);
}

/*
 * TODO: tests to add
 * - symlink following
 * - dentry/inode/device/mount checkers
 * - PATH_BENEATH
 * - object creation with nonexistent file
 * - validate that ptrace's SETREGS is still working on a process using seccomp-objects
 * - TOCTOU with a hard link (should pass)
 * - limits
 */

#endif /* SECCOMP_DATA_ARGEVAL_PRESENT */

/*
 * TODO:
 * - add microbenchmarks
 * - expand NNP testing
 * - better arch-specific TRACE and TRAP handlers.
 * - endianness checking when appropriate
 * - 64-bit arg prodding
 * - arch value testing (x86 modes especially)
 * - ...
 */

TEST_HARNESS_MAIN
