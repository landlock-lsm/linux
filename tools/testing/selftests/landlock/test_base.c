// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - common resources
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019-2020 ANSSI
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/prctl.h>

#include "test.h"

#define FDINFO_TEMPLATE "/proc/self/fdinfo/%d"
#define FDINFO_SIZE 128

#ifndef O_PATH
#define O_PATH		010000000
#endif

TEST_F(ruleset_rw, fdinfo)
{
	int fdinfo_fd, fdinfo_path_size, fdinfo_buf_size;
	char fdinfo_path[sizeof(FDINFO_TEMPLATE) + 2];
	char fdinfo_buf[FDINFO_SIZE];

	fdinfo_path_size = snprintf(fdinfo_path, sizeof(fdinfo_path),
			FDINFO_TEMPLATE, self->ruleset_fd);
	ASSERT_LE(fdinfo_path_size, sizeof(fdinfo_path));

	fdinfo_fd = open(fdinfo_path, O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fdinfo_fd, 0);

	fdinfo_buf_size = read(fdinfo_fd, fdinfo_buf, sizeof(fdinfo_buf));
	ASSERT_LE(fdinfo_buf_size, sizeof(fdinfo_buf) - 1);

	/*
	 * fdinfo_buf: pos:        0
	 * flags:  02000002
	 * mnt_id: 13
	 * handled_access_fs:     804000
	 */
	EXPECT_EQ(0, close(fdinfo_fd));
}

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
	};

	ASSERT_EQ(0, landlock(LANDLOCK_CMD_GET_FEATURES,
				LANDLOCK_OPT_CREATE_RULESET,
				sizeof(attr_features), &attr_features));
	ASSERT_EQ(((LANDLOCK_OPT_GET_FEATURES << 1) - 1),
			attr_features.options_get_features);
	ASSERT_EQ(((LANDLOCK_OPT_CREATE_RULESET << 1) - 1),
			attr_features.options_create_ruleset);
	ASSERT_EQ(((LANDLOCK_OPT_ADD_RULE_PATH_BENEATH << 1) - 1),
			attr_features.options_add_rule);
	ASSERT_EQ(((LANDLOCK_OPT_ENFORCE_RULESET << 1) - 1),
			attr_features.options_enforce_ruleset);
	ASSERT_EQ(((LANDLOCK_ACCESS_FS_MAP << 1) - 1),
			attr_features.access_fs);
	ASSERT_EQ(sizeof(struct landlock_attr_ruleset),
		attr_features.size_attr_ruleset);
	ASSERT_EQ(sizeof(struct landlock_attr_path_beneath),
		attr_features.size_attr_path_beneath);
}

TEST_HARNESS_MAIN
