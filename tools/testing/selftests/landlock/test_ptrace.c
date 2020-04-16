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
	struct landlock_attr_features attr_features;
	struct landlock_attr_enforce attr_enforce;
	struct landlock_attr_ruleset attr_ruleset = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	struct landlock_attr_path_beneath path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
	};

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
	ASSERT_LE(0, ruleset_fd) {
		TH_LOG("Failed to create a ruleset: %s", strerror(errno));
	}
	path_beneath.ruleset_fd = ruleset_fd;
	path_beneath.parent_fd = open("/tmp", O_PATH | O_NOFOLLOW | O_DIRECTORY
			| O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(0, landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
			sizeof(path_beneath), &path_beneath));
	ASSERT_EQ(0, errno);
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, errno);

	attr_enforce.ruleset_fd = ruleset_fd;
	ASSERT_EQ(0, landlock(LANDLOCK_CMD_ENFORCE_RULESET,
			LANDLOCK_OPT_ENFORCE_RULESET, sizeof(attr_enforce),
			&attr_enforce));
	ASSERT_EQ(0, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

/* test PTRACE_TRACEME and PTRACE_ATTACH for parent and child */
static void check_ptrace(struct __test_metadata *const _metadata,
		const bool domain_both, const bool domain_parent,
		const bool domain_child)
{
	pid_t child, parent;
	int status;
	int pipe_child[2], pipe_parent[2];
	char buf_parent;

	parent = getpid();
	ASSERT_EQ(0, pipe(pipe_child));
	ASSERT_EQ(0, pipe(pipe_parent));
	if (domain_both)
		create_domain(_metadata);

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		char buf_child;

		EXPECT_EQ(0, close(pipe_parent[1]));
		EXPECT_EQ(0, close(pipe_child[0]));
		if (domain_child)
			create_domain(_metadata);

		/* sync #1 */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1)) {
			TH_LOG("Failed to read() sync #1 from parent");
		}
		ASSERT_EQ('.', buf_child);

		/* Tests the parent protection. */
		ASSERT_EQ(domain_child ? -1 : 0,
				ptrace(PTRACE_ATTACH, parent, NULL, 0));
		if (domain_child) {
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

		/* Tests traceme. */
		ASSERT_EQ(domain_parent ? -1 : 0, ptrace(PTRACE_TRACEME));
		if (domain_parent) {
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
		create_domain(_metadata);

	/* sync #1 */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1)) {
		TH_LOG("Failed to write() sync #1 to child");
	}

	/* Tests the parent protection. */
	/* sync #2 */
	ASSERT_EQ(1, read(pipe_child[0], &buf_parent, 1)) {
		TH_LOG("Failed to read() sync #2 from child");
	}
	ASSERT_EQ('.', buf_parent);

	/* Tests traceme. */
	if (!domain_parent) {
		ASSERT_EQ(child, waitpid(child, &status, 0));
		ASSERT_EQ(1, WIFSTOPPED(status));
		ASSERT_EQ(0, ptrace(PTRACE_DETACH, child, NULL, 0));
	}
	/* Tests attach. */
	ASSERT_EQ(domain_parent ? -1 : 0,
			ptrace(PTRACE_ATTACH, child, NULL, 0));
	if (domain_parent) {
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
TEST(allow_without_domain) {
	check_ptrace(_metadata, false, false, false);
}

/*
 *        Child domain
 *
 *   P1--.              P1 -> P2 : allow
 *        \             P2 -> P1 : deny
 *        .'-----.
 *        |  P2  |
 *        '------'
 */
TEST(allow_with_one_domain) {
	check_ptrace(_metadata, false, false, true);
}

/*
 *        Parent domain
 * .------.
 * |  P1  --.           P1 -> P2 : deny
 * '------'  \          P2 -> P1 : allow
 *            '
 *            P2
 */
TEST(deny_with_parent_domain) {
	check_ptrace(_metadata, false, true, false);
}

/*
 *        Parent + child domain (siblings)
 * .------.
 * |  P1  ---.          P1 -> P2 : deny
 * '------'   \         P2 -> P1 : deny
 *         .---'--.
 *         |  P2  |
 *         '------'
 */
TEST(deny_with_sibling_domain) {
	check_ptrace(_metadata, false, true, true);
}

/*
 *         Same domain (inherited)
 * .-------------.
 * | P1----.     |      P1 -> P2 : allow
 * |        \    |      P2 -> P1 : allow
 * |         '   |
 * |         P2  |
 * '-------------'
 */
TEST(allow_sibling_domain) {
	check_ptrace(_metadata, true, false, false);
}

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
TEST(allow_with_nested_domain) {
	check_ptrace(_metadata, true, false, true);
}

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
TEST(deny_with_nested_and_parent_domain) {
	check_ptrace(_metadata, true, true, false);
}

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
TEST(deny_with_forked_domain) {
	check_ptrace(_metadata, true, true, true);
}

TEST_HARNESS_MAIN
