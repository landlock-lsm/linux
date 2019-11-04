// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - ptrace
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019 ANSSI
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test.h"

#define LOG_SIZE 512

static void create_domain(struct __test_metadata *_metadata,
		bool scoped_ptrace, bool inherited_only)
{
	const struct bpf_insn prog_void[] = {
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn prog_check[] = {
		BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_1),
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
			offsetof(struct landlock_context_ptrace, tracer)),
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
			offsetof(struct landlock_context_ptrace, tracee)),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_task_landlock_ptrace_ancestor),
		/*
		 * If @tracee is an ancestor or at the same level of @tracer,
		 * then allow ptrace (warning: do not use BPF_JGE 0).
		 */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, inherited_only ? 0 : 1, 2),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_DENY),
		BPF_EXIT_INSN(),
		BPF_MOV32_IMM(BPF_REG_0, LANDLOCK_RET_ALLOW),
		BPF_EXIT_INSN(),
	};
	int prog;
	char log[LOG_SIZE] = "";

	if (scoped_ptrace)
		prog = ll_bpf_load_program(prog_check, sizeof(prog_check),
				log, sizeof(log), BPF_LANDLOCK_PTRACE);
	else
		prog = ll_bpf_load_program(prog_void, sizeof(prog_void),
				log, sizeof(log), BPF_LANDLOCK_PTRACE);
	ASSERT_NE(-1, prog) {
		TH_LOG("Failed to load the %s program: %s\n%s",
				scoped_ptrace ? "check" : "void",
				strerror(errno), log);
	}
	ASSERT_EQ(0, seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &prog)) {
		TH_LOG("Failed to create a Landlock domain: %s",
				strerror(errno));
	}
	EXPECT_EQ(0, close(prog));
}

/* test PTRACE_TRACEME and PTRACE_ATTACH for parent and child */
static void _check_ptrace(struct __test_metadata *_metadata,
		bool scoped_ptrace, bool domain_both,
		bool domain_parent, bool domain_child)
{
	pid_t child, parent;
	int status;
	int pipe_child[2], pipe_parent[2];
	char buf_parent;
	const bool inherited_only = domain_both && !domain_parent &&
		!domain_child;

	parent = getpid();

	ASSERT_EQ(0, pipe(pipe_child));
	ASSERT_EQ(0, pipe(pipe_parent));
	if (domain_both)
		create_domain(_metadata, scoped_ptrace, inherited_only);

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		char buf_child;

		EXPECT_EQ(0, close(pipe_parent[1]));
		EXPECT_EQ(0, close(pipe_child[0]));
		if (domain_child)
			create_domain(_metadata, scoped_ptrace, inherited_only);

		/* sync #1 */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1)) {
			TH_LOG("Failed to read() sync #1 from parent");
		}
		ASSERT_EQ('.', buf_child);

		/* test the parent protection */
		ASSERT_EQ((domain_child && scoped_ptrace) ? -1 : 0,
				ptrace(PTRACE_ATTACH, parent, NULL, 0));
		if (domain_child && scoped_ptrace) {
			ASSERT_EQ(EPERM, errno);
		} else {
			ASSERT_EQ(parent, waitpid(parent, &status, 0));
			ASSERT_EQ(1, WIFSTOPPED(status));
			ASSERT_EQ(0, ptrace(PTRACE_DETACH, parent, NULL, 0));
		}

		/* sync #2 */
		ASSERT_EQ(1, write(pipe_child[1], ".", 1)) {
			TH_LOG("Failed to write() sync #2 to parent");
		}

		/* test traceme */
		ASSERT_EQ((domain_parent && scoped_ptrace) ? -1 : 0,
				ptrace(PTRACE_TRACEME));
		if (domain_parent && scoped_ptrace) {
			ASSERT_EQ(EPERM, errno);
		} else {
			ASSERT_EQ(0, raise(SIGSTOP));
		}

		/* sync #3 */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1)) {
			TH_LOG("Failed to read() sync #3 from parent");
		}
		ASSERT_EQ('.', buf_child);
		_exit(_metadata->passed ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	EXPECT_EQ(0, close(pipe_child[1]));
	EXPECT_EQ(0, close(pipe_parent[0]));
	if (domain_parent)
		create_domain(_metadata, scoped_ptrace, inherited_only);

	/* sync #1 */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1)) {
		TH_LOG("Failed to write() sync #1 to child");
	}

	/* test the parent protection */
	/* sync #2 */
	ASSERT_EQ(1, read(pipe_child[0], &buf_parent, 1)) {
		TH_LOG("Failed to read() sync #2 from child");
	}
	ASSERT_EQ('.', buf_parent);

	/* test traceme */
	if (!(domain_parent && scoped_ptrace)) {
		ASSERT_EQ(child, waitpid(child, &status, 0));
		ASSERT_EQ(1, WIFSTOPPED(status));
		ASSERT_EQ(0, ptrace(PTRACE_DETACH, child, NULL, 0));
	}
	/* test attach */
	ASSERT_EQ((domain_parent && scoped_ptrace) ? -1 : 0,
			ptrace(PTRACE_ATTACH, child, NULL, 0));
	if (domain_parent && scoped_ptrace) {
		ASSERT_EQ(EPERM, errno);
	} else {
		ASSERT_EQ(child, waitpid(child, &status, 0));
		ASSERT_EQ(1, WIFSTOPPED(status));
		ASSERT_EQ(0, ptrace(PTRACE_DETACH, child, NULL, 0));
	}

	/* sync #3 */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1)) {
		TH_LOG("Failed to write() sync #3 to child");
	}
	ASSERT_EQ(child, waitpid(child, &status, 0));
	if (WIFSIGNALED(status) || WEXITSTATUS(status))
		_metadata->passed = 0;
}

/* keep the *_scoped order to check program inheritance */
#define CHECK_PTRACE(name, domain_both, domain_parent, domain_child) \
	TEST(name ## _unscoped) { \
		_check_ptrace(_metadata, false, domain_both, domain_parent, \
				domain_child); \
	} \
	TEST(name ## _scoped) { \
		_check_ptrace(_metadata, false, domain_both, domain_parent, \
				domain_child); \
		_check_ptrace(_metadata, true, domain_both, domain_parent, \
				domain_child); \
	}

/*
 * Test multiple tracing combinations between a parent process P1 and a child
 * process P2.
 *
 * Yama's scoped ptrace is presumed disabled.  If enabled, this additional
 * restriction is enforced before any Landlock check, which means that all P2
 * requests to trace P1 would be denied.
 */

/*
 *        No domain
 *
 *   P1-.               P1 -> P2 : allow
 *       \              P2 -> P1 : allow
 *        'P2
 */
CHECK_PTRACE(allow_without_domain, false, false, false);

/*
 *        Child domain
 *
 *   P1--.              P1 -> P2 : allow
 *        \             P2 -> P1 : deny
 *        .'-----.
 *        |  P2  |
 *        '------'
 */
CHECK_PTRACE(allow_with_one_domain, false, false, true);

/*
 *        Parent domain
 * .------.
 * |  P1  --.           P1 -> P2 : deny
 * '------'  \          P2 -> P1 : allow
 *            '
 *            P2
 */
CHECK_PTRACE(deny_with_parent_domain, false, true, false);

/*
 *        Parent + child domain (siblings)
 * .------.
 * |  P1  ---.          P1 -> P2 : deny
 * '------'   \         P2 -> P1 : deny
 *         .---'--.
 *         |  P2  |
 *         '------'
 */
CHECK_PTRACE(deny_with_sibling_domain, false, true, true);

/*
 *         Same domain (inherited)
 * .-------------.
 * | P1----.     |      P1 -> P2 : allow
 * |        \    |      P2 -> P1 : allow
 * |         '   |
 * |         P2  |
 * '-------------'
 */
CHECK_PTRACE(allow_sibling_domain, true, false, false);

/*
 *         Inherited + child domain
 * .-----------------.
 * |  P1----.        |  P1 -> P2 : allow
 * |         \       |  P2 -> P1 : deny
 * |        .-'----. |
 * |        |  P2  | |
 * |        '------' |
 * '-----------------'
 */
CHECK_PTRACE(allow_with_nested_domain, true, false, true);

/*
 *         Inherited + parent domain
 * .-----------------.
 * |.------.         |  P1 -> P2 : deny
 * ||  P1  ----.     |  P2 -> P1 : allow
 * |'------'    \    |
 * |             '   |
 * |             P2  |
 * '-----------------'
 */
CHECK_PTRACE(deny_with_nested_and_parent_domain, true, true, false);

/*
 *         Inherited + parent and child domain (siblings)
 * .-----------------.
 * | .------.        |  P1 -> P2 : deny
 * | |  P1  .        |  P2 -> P1 : deny
 * | '------'\       |
 * |          \      |
 * |        .--'---. |
 * |        |  P2  | |
 * |        '------' |
 * '-----------------'
 */
CHECK_PTRACE(deny_with_forked_domain, true, true, true);

TEST_HARNESS_MAIN
