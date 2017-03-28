/*
 * Landlock tests - ptrace
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#define _GNU_SOURCE
#include <signal.h> /* raise */
#include <sys/ptrace.h>
#include <sys/types.h> /* waitpid */
#include <sys/wait.h> /* waitpid */
#include <unistd.h> /* fork, pipe */

#include "test.h"

static void apply_null_sandbox(struct __test_metadata *_metadata)
{
	const struct bpf_insn prog_accept[] = {
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	const union bpf_prog_subtype subtype = {
		.landlock_rule = {
			.version = 1,
			.event = LANDLOCK_SUBTYPE_EVENT_FS,
		}
	};
	int prog;
	char log[256] = "";

	prog = bpf_load_program(BPF_PROG_TYPE_LANDLOCK,
			(const struct bpf_insn *)&prog_accept,
			sizeof(prog_accept) / sizeof(struct bpf_insn), "GPL",
			0, log, sizeof(log), &subtype);
	ASSERT_NE(-1, prog) {
		TH_LOG("Failed to load minimal rule: %s\n%s",
				strerror(errno), log);
	}
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, 0, 0)) {
		TH_LOG("Kernel does not support PR_SET_NO_NEW_PRIVS");
	}
	ASSERT_EQ(0, seccomp(SECCOMP_APPEND_LANDLOCK_RULE, 0, &prog)) {
		TH_LOG("Failed to apply minimal rule: %s", strerror(errno));
	}
	EXPECT_EQ(0, close(prog));
}

/* PTRACE_TRACEME and PTRACE_ATTACH without Landlock rules effect */
static void check_ptrace(struct __test_metadata *_metadata,
		int sandbox_both, int sandbox_parent, int sandbox_child,
		int expect_ptrace)
{
	pid_t child;
	int status;
	int pipefd[2];

	ASSERT_EQ(0, pipe(pipefd));
	if (sandbox_both)
		apply_null_sandbox(_metadata);

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		char buf;

		EXPECT_EQ(0, close(pipefd[1]));
		if (sandbox_child)
			apply_null_sandbox(_metadata);

		/* test traceme */
		ASSERT_EQ(expect_ptrace, ptrace(PTRACE_TRACEME));
		if (expect_ptrace) {
			ASSERT_EQ(EPERM, errno);
		} else {
			ASSERT_EQ(0, raise(SIGSTOP));
		}

		/* sync */
		ASSERT_EQ(1, read(pipefd[0], &buf, 1)) {
			TH_LOG("Failed to read() sync from parent");
		}
		ASSERT_EQ('.', buf);
		_exit(_metadata->passed ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	EXPECT_EQ(0, close(pipefd[0]));
	if (sandbox_parent)
		apply_null_sandbox(_metadata);

	/* test traceme */
	if (!expect_ptrace) {
		ASSERT_EQ(child, waitpid(child, &status, 0));
		ASSERT_EQ(1, WIFSTOPPED(status));
		ASSERT_EQ(0, ptrace(PTRACE_DETACH, child, NULL, 0));
	}
	/* test attach */
	ASSERT_EQ(expect_ptrace, ptrace(PTRACE_ATTACH, child, NULL, 0));
	if (expect_ptrace) {
		ASSERT_EQ(EPERM, errno);
	} else {
		ASSERT_EQ(child, waitpid(child, &status, 0));
		ASSERT_EQ(1, WIFSTOPPED(status));
		ASSERT_EQ(0, ptrace(PTRACE_CONT, child, NULL, 0));
	}

	/* sync */
	ASSERT_EQ(1, write(pipefd[1], ".", 1)) {
		TH_LOG("Failed to write() sync to child");
	}
	ASSERT_EQ(child, waitpid(child, &status, 0));
	if (WIFSIGNALED(status) || WEXITSTATUS(status))
		_metadata->passed = 0;
}

TEST(ptrace_allow_without_sandbox)
{
	/* no sandbox */
	check_ptrace(_metadata, 0, 0, 0, 0);
}

TEST(ptrace_allow_with_one_sandbox)
{
	/* child sandbox */
	check_ptrace(_metadata, 0, 0, 1, 0);
}

TEST(ptrace_allow_with_nested_sandbox)
{
	/* inherited and child sandbox */
	check_ptrace(_metadata, 1, 0, 1, 0);
}

TEST(ptrace_deny_with_parent_sandbox)
{
	/* parent sandbox */
	check_ptrace(_metadata, 0, 1, 0, -1);
}

TEST(ptrace_deny_with_nested_and_parent_sandbox)
{
	/* inherited and parent sandbox */
	check_ptrace(_metadata, 1, 1, 0, -1);
}

TEST(ptrace_deny_with_forked_sandbox)
{
	/* inherited, parent and child sandbox */
	check_ptrace(_metadata, 1, 1, 1, -1);
}

TEST(ptrace_deny_with_sibling_sandbox)
{
	/* parent and child sandbox */
	check_ptrace(_metadata, 0, 1, 1, -1);
}

TEST_HARNESS_MAIN
