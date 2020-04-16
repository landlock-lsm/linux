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
#include <sys/prctl.h>

#include "common.h"

#ifndef O_PATH
#define O_PATH		010000000
#endif

TEST(features)
{
	struct landlock_attr_features attr_features = {
		.options_get_features = ~0ULL,
		.options_create_ruleset = ~0ULL,
		.options_add_rule = ~0ULL,
		.options_enforce_ruleset = ~0ULL,
		.access_fs = ~0ULL,
		.size_attr_ruleset = ~0ULL,
		.size_attr_path_beneath = ~0ULL,
		.size_attr_enforce = ~0ULL,
	};

	ASSERT_EQ(0, landlock(LANDLOCK_CMD_GET_FEATURES,
				LANDLOCK_OPT_GET_FEATURES,
				sizeof(attr_features), &attr_features));
	ASSERT_EQ(((LANDLOCK_OPT_GET_FEATURES << 1) - 1),
			attr_features.options_get_features);
	ASSERT_EQ(((LANDLOCK_OPT_CREATE_RULESET << 1) - 1),
			attr_features.options_create_ruleset);
	ASSERT_EQ(((LANDLOCK_OPT_ADD_RULE_PATH_BENEATH << 1) - 1),
			attr_features.options_add_rule);
	ASSERT_EQ(((LANDLOCK_OPT_ENFORCE_RULESET << 1) - 1),
			attr_features.options_enforce_ruleset);
	ASSERT_EQ(((LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1),
			attr_features.access_fs);
	ASSERT_EQ(sizeof(struct landlock_attr_ruleset),
		attr_features.size_attr_ruleset);
	ASSERT_EQ(sizeof(struct landlock_attr_path_beneath),
		attr_features.size_attr_path_beneath);
	ASSERT_EQ(sizeof(struct landlock_attr_enforce),
		attr_features.size_attr_enforce);
}

TEST(inconsistent_attr) {
	const long page_size = sysconf(_SC_PAGESIZE);
	char *buf = malloc(page_size + 1);

	/* Checks copy_from_user(). */
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, 0, buf));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, 1, NULL));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET,
			sizeof(struct landlock_attr_enforce), NULL));
	ASSERT_EQ(EFAULT, errno);

	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, page_size + 1, buf));
	ASSERT_EQ(E2BIG, errno);

	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, page_size, buf));
	ASSERT_EQ(ENOMSG, errno);

	/* Checks non-zero value. */
	buf[page_size - 2] = '.';
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, page_size, buf));
	ASSERT_EQ(E2BIG, errno);
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, page_size + 1, buf));
	ASSERT_EQ(E2BIG, errno);

	/* Checks copy_to_user(). */
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_GET_FEATURES,
			LANDLOCK_OPT_GET_FEATURES, 0, NULL));
	ASSERT_EQ(ENODATA, errno);
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_GET_FEATURES,
			LANDLOCK_OPT_GET_FEATURES, 0, buf));
	ASSERT_EQ(ENODATA, errno);
	ASSERT_EQ(0, landlock(LANDLOCK_CMD_GET_FEATURES,
				LANDLOCK_OPT_GET_FEATURES, 1, buf));
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_GET_FEATURES,
			LANDLOCK_OPT_GET_FEATURES, page_size + 1, buf));
	ASSERT_EQ(E2BIG, errno);
	ASSERT_EQ('.', buf[page_size - 2]);
	ASSERT_EQ(0, landlock(LANDLOCK_CMD_GET_FEATURES,
			LANDLOCK_OPT_GET_FEATURES, page_size, buf));
	ASSERT_EQ('\0', buf[page_size - 2]);

	free(buf);
}

TEST(empty_attr_ruleset) {
	/* Similar to struct landlock_attr_create.handled_access_fs = 0 */
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, 0, NULL));
	ASSERT_EQ(EINVAL, errno);
}

TEST(empty_attr_path_beneath) {
	/* Similar to struct landlock_attr_path_beneath.*_fd = 0 */
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_ADD_RULE,
			LANDLOCK_OPT_ADD_RULE_PATH_BENEATH, 0, NULL));
	ASSERT_EQ(EINVAL, errno);
}

TEST(empty_attr_enforce) {
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

	/* Similar to struct landlock_attr_enforce.ruleset_fd = 0 */
	ASSERT_EQ(-1, landlock(LANDLOCK_CMD_ENFORCE_RULESET,
			LANDLOCK_OPT_ENFORCE_RULESET, 0, NULL));
	ASSERT_EQ(EINVAL, errno);
}

TEST(ruleset_fd)
{
	struct landlock_attr_ruleset attr_ruleset = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd;
	char buf;

	ruleset_fd = landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, sizeof(attr_ruleset),
			&attr_ruleset);
	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(-1, write(ruleset_fd, ".", 1));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, read(ruleset_fd, &buf, 1));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

TEST_HARNESS_MAIN
