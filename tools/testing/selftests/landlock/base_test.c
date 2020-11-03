// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Common user space base
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019-2020 ANSSI
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <string.h>
#include <sys/prctl.h>

#include "common.h"

#ifndef O_PATH
#define O_PATH		010000000
#endif

TEST(inconsistent_attr) {
	const long page_size = sysconf(_SC_PAGESIZE);
	char *const buf = malloc(page_size + 1);
	struct landlock_ruleset_attr *const ruleset_attr = (void *)buf;

	ASSERT_NE(NULL, buf);

	/* Checks copy_from_user(). */
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, 0, 0));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, 1, 0));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, 1, 0));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EFAULT, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL,
				sizeof(struct landlock_ruleset_attr), 0));
	ASSERT_EQ(EFAULT, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size + 1, 0));
	ASSERT_EQ(E2BIG, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr,
				sizeof(struct landlock_ruleset_attr), 0));
	ASSERT_EQ(ENOMSG, errno);
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size, 0));
	ASSERT_EQ(ENOMSG, errno);

	/* Checks non-zero value. */
	buf[page_size - 2] = '.';
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size, 0));
	ASSERT_EQ(E2BIG, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size + 1, 0));
	ASSERT_EQ(E2BIG, errno);

	free(buf);
}

TEST(empty_path_beneath_attr) {
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
	};
	const int ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);

	ASSERT_LE(0, ruleset_fd);

	/* Similar to struct landlock_path_beneath_attr.parent_fd = 0 */
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				NULL, 0));
	ASSERT_EQ(EFAULT, errno);
	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(inval_fd_enforce) {
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

	ASSERT_EQ(-1, landlock_enforce_ruleset_current(-1, 0));
	ASSERT_EQ(EBADF, errno);
}

TEST(unpriv_enforce_without_no_new_privs) {
	int err;

	disable_caps(_metadata);
	err = landlock_enforce_ruleset_current(-1, 0);
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(err, -1);
}

TEST(ruleset_fd)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd;
	char buf;

	disable_caps(_metadata);
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
			sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(-1, write(ruleset_fd, ".", 1));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, read(ruleset_fd, &buf, 1));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

TEST_HARNESS_MAIN
