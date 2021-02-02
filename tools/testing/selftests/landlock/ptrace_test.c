// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Ptrace
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019-2020 ANSSI
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

static void create_domain(struct __test_metadata *const _metadata)
{
	int ruleset_fd;
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	struct landlock_path_beneath_attr path_beneath_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);
	EXPECT_LE(0, ruleset_fd) {
		TH_LOG("Failed to create a ruleset: %s", strerror(errno));
	}
	path_beneath_attr.parent_fd = open("/tmp", O_PATH | O_NOFOLLOW |
			O_DIRECTORY | O_CLOEXEC);
	EXPECT_LE(0, path_beneath_attr.parent_fd);
	EXPECT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				&path_beneath_attr, 0));
	EXPECT_EQ(0, close(path_beneath_attr.parent_fd));

	EXPECT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	EXPECT_EQ(0, landlock_restrict_self(ruleset_fd, 0));
	EXPECT_EQ(0, close(ruleset_fd));
}

FIXTURE(hierarchy) { };

FIXTURE_VARIANT(hierarchy) {
	const bool domain_both;
	const bool domain_parent;
	const bool domain_child;
};

/*
 * Test multiple tracing combinations between a parent process P1 and a child
 * process P2.
 *
 * Yama's scoped ptrace is presumed disabled.  If enabled, this optional
 * restriction is enforced in addition to any Landlock check, which means that
 * all P2 requests to trace P1 would be denied.
 */

/*
 *        No domain
 *
 *   P1-.               P1 -> P2 : allow
 *       \              P2 -> P1 : allow
 *        'P2
 */
FIXTURE_VARIANT_ADD(hierarchy, allow_without_domain) {
	.domain_both = false,
	.domain_parent = false,
	.domain_child = false,
};

/*
 *        Child domain
 *
 *   P1--.              P1 -> P2 : allow
 *        \             P2 -> P1 : deny
 *        .'-----.
 *        |  P2  |
 *        '------'
 */
FIXTURE_VARIANT_ADD(hierarchy, allow_with_one_domain) {
	.domain_both = false,
	.domain_parent = false,
	.domain_child = true,
};

/*
 *        Parent domain
 * .------.
 * |  P1  --.           P1 -> P2 : deny
 * '------'  \          P2 -> P1 : allow
 *            '
 *            P2
 */
FIXTURE_VARIANT_ADD(hierarchy, deny_with_parent_domain) {
	.domain_both = false,
	.domain_parent = true,
	.domain_child = false,
};

/*
 *        Parent + child domain (siblings)
 * .------.
 * |  P1  ---.          P1 -> P2 : deny
 * '------'   \         P2 -> P1 : deny
 *         .---'--.
 *         |  P2  |
 *         '------'
 */
FIXTURE_VARIANT_ADD(hierarchy, deny_with_sibling_domain) {
	.domain_both = false,
	.domain_parent = true,
	.domain_child = true,
};

/*
 *         Same domain (inherited)
 * .-------------.
 * | P1----.     |      P1 -> P2 : allow
 * |        \    |      P2 -> P1 : allow
 * |         '   |
 * |         P2  |
 * '-------------'
 */
FIXTURE_VARIANT_ADD(hierarchy, allow_sibling_domain) {
	.domain_both = true,
	.domain_parent = false,
	.domain_child = false,
};

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
FIXTURE_VARIANT_ADD(hierarchy, allow_with_nested_domain) {
	.domain_both = true,
	.domain_parent = false,
	.domain_child = true,
};

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
FIXTURE_VARIANT_ADD(hierarchy, deny_with_nested_and_parent_domain) {
	.domain_both = true,
	.domain_parent = true,
	.domain_child = false,
};

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
FIXTURE_VARIANT_ADD(hierarchy, deny_with_forked_domain) {
	.domain_both = true,
	.domain_parent = true,
	.domain_child = true,
};

FIXTURE_SETUP(hierarchy)
{ }

FIXTURE_TEARDOWN(hierarchy)
{ }

/* Test PTRACE_TRACEME and PTRACE_ATTACH for parent and child. */
TEST_F(hierarchy, trace)
{
	pid_t child, parent;
	int status;
	int pipe_child[2], pipe_parent[2];
	char buf_parent;
	long ret;

	disable_caps(_metadata);

	parent = getpid();
	ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));
	if (variant->domain_both) {
		create_domain(_metadata);
		if (!_metadata->passed)
			/* Aborts before forking. */
			return;
	}

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		char buf_child;

		ASSERT_EQ(0, close(pipe_parent[1]));
		ASSERT_EQ(0, close(pipe_child[0]));
		if (variant->domain_child)
			create_domain(_metadata);

		/* Waits for the parent to be in a domain, if any. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1));

		/* Tests PTRACE_ATTACH on the parent. */
		ret = ptrace(PTRACE_ATTACH, parent, NULL, 0);
		if (variant->domain_child) {
			EXPECT_EQ(-1, ret);
			EXPECT_EQ(EPERM, errno);
		} else {
			EXPECT_EQ(0, ret);
		}
		if (ret == 0) {
			ASSERT_EQ(parent, waitpid(parent, &status, 0));
			ASSERT_EQ(1, WIFSTOPPED(status));
			ASSERT_EQ(0, ptrace(PTRACE_DETACH, parent, NULL, 0));
		}

		/* Tests child PTRACE_TRACEME. */
		ret = ptrace(PTRACE_TRACEME);
		if (variant->domain_parent) {
			EXPECT_EQ(-1, ret);
			EXPECT_EQ(EPERM, errno);
		} else {
			EXPECT_EQ(0, ret);
		}

		/*
		 * Signals that the PTRACE_ATTACH test is done and the
		 * PTRACE_TRACEME test is ongoing.
		 */
		ASSERT_EQ(1, write(pipe_child[1], ".", 1));

		if (!variant->domain_parent) {
			ASSERT_EQ(0, raise(SIGSTOP));
		}

		/* Waits for the parent PTRACE_ATTACH test. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1));
		_exit(_metadata->passed ? EXIT_SUCCESS : EXIT_FAILURE);
		return;
	}

	ASSERT_EQ(0, close(pipe_child[1]));
	ASSERT_EQ(0, close(pipe_parent[0]));
	if (variant->domain_parent)
		create_domain(_metadata);

	/* Signals that the parent is in a domain, if any. */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

	/*
	 * Waits for the child to test PTRACE_ATTACH on the parent and start
	 * testing PTRACE_TRACEME.
	 */
	ASSERT_EQ(1, read(pipe_child[0], &buf_parent, 1));

	/* Tests child PTRACE_TRACEME. */
	if (!variant->domain_parent) {
		ASSERT_EQ(child, waitpid(child, &status, 0));
		ASSERT_EQ(1, WIFSTOPPED(status));
		ASSERT_EQ(0, ptrace(PTRACE_DETACH, child, NULL, 0));
	} else {
		/* The child should not be traced by the parent. */
		EXPECT_EQ(-1, ptrace(PTRACE_DETACH, child, NULL, 0));
		EXPECT_EQ(ESRCH, errno);
	}

	/* Tests PTRACE_ATTACH on the child. */
	ret = ptrace(PTRACE_ATTACH, child, NULL, 0);
	if (variant->domain_parent) {
		EXPECT_EQ(-1, ret);
		EXPECT_EQ(EPERM, errno);
	} else {
		EXPECT_EQ(0, ret);
	}
	if (ret == 0) {
		ASSERT_EQ(child, waitpid(child, &status, 0));
		ASSERT_EQ(1, WIFSTOPPED(status));
		ASSERT_EQ(0, ptrace(PTRACE_DETACH, child, NULL, 0));
	}

	/* Signals that the parent PTRACE_ATTACH test is done. */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));
	ASSERT_EQ(child, waitpid(child, &status, 0));
	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
			WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->passed = 0;
}

TEST_HARNESS_MAIN
