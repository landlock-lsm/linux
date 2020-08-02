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

TEST(features)
{
	struct landlock_attr_features attr_features;

	/* Tests that all fields are properly initialized. */
	memset(&attr_features, 0xff, sizeof(attr_features));
	ASSERT_EQ(0, landlock_get_features(&attr_features, sizeof(attr_features)));
	ASSERT_EQ(0, attr_features.options_get_features);
	ASSERT_EQ(0, attr_features.options_create_ruleset);
	ASSERT_EQ(0, attr_features.options_add_rule);
	ASSERT_EQ(0, attr_features.options_enforce_ruleset);
	ASSERT_EQ(sizeof(struct landlock_attr_features),
		attr_features.size_attr_features);
	ASSERT_EQ(sizeof(struct landlock_attr_ruleset),
		attr_features.size_attr_ruleset);
	ASSERT_EQ(sizeof(struct landlock_attr_path_beneath),
		attr_features.size_attr_path_beneath);
	ASSERT_EQ(((LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1),
			attr_features.access_fs);
	ASSERT_EQ(LANDLOCK_RULE_PATH_BENEATH, attr_features.last_rule_type);
	ASSERT_EQ(LANDLOCK_TARGET_CURRENT_THREAD, attr_features.last_target_type);
}

TEST(inconsistent_attr) {
	const long page_size = sysconf(_SC_PAGESIZE);
	char *const buf = malloc(page_size + 1);
	struct landlock_attr_ruleset *const ruleset = (void *)buf;
	struct landlock_attr_features *const features = (void *)buf;

	ASSERT_NE(NULL, buf);

	/* Checks copy_from_user(). */
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset, 0));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, 1));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, sizeof(struct landlock_attr_ruleset)));
	ASSERT_EQ(EFAULT, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset, page_size + 1));
	ASSERT_EQ(E2BIG, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset, page_size));
	ASSERT_EQ(ENOMSG, errno);

	/* Checks non-zero value. */
	buf[page_size - 2] = '.';
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset, page_size));
	ASSERT_EQ(E2BIG, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset, page_size + 1));
	ASSERT_EQ(E2BIG, errno);

	/* Checks copy_to_user(). */
	ASSERT_EQ(-1, landlock_get_features(NULL, 0));
	ASSERT_EQ(ENODATA, errno);
	ASSERT_EQ(-1, landlock_get_features(features, 0));
	ASSERT_EQ(ENODATA, errno);

	ASSERT_EQ(0, landlock_get_features(features, 1));

	ASSERT_EQ(-1, landlock_get_features(features, page_size + 1));
	ASSERT_EQ(E2BIG, errno);

	ASSERT_EQ('.', buf[page_size - 2]);
	ASSERT_EQ(0, landlock_get_features(features, page_size));
	ASSERT_EQ('\0', buf[page_size - 2]);

	free(buf);
}

TEST(empty_attr_ruleset) {
	/* Similar to struct landlock_attr_ruleset.handled_access_fs = 0 */
	ASSERT_EQ(-1, landlock_create_ruleset(NULL, 0));
	ASSERT_EQ(EINVAL, errno);
}

TEST(empty_attr_path_beneath) {
	const struct landlock_attr_ruleset ruleset = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
	};
	const int ruleset_fd = landlock_create_ruleset(&ruleset, sizeof(ruleset));

	ASSERT_LE(0, ruleset_fd);

	/* Similar to struct landlock_attr_path_beneath.parent_fd = 0 */
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, NULL, 0));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(inval_fd_enforce) {
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

	ASSERT_EQ(-1, landlock_enforce_ruleset(-1));
	ASSERT_EQ(EBADF, errno);
}

TEST(unpriv_enforce_without_no_new_privs) {
	int err;

	disable_caps(_metadata);
	err = landlock_enforce_ruleset(-1);
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(err, -1);
}

TEST(ruleset_fd)
{
	struct landlock_attr_ruleset attr_ruleset = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd;
	char buf;

	disable_caps(_metadata);
	ruleset_fd = landlock_create_ruleset(&attr_ruleset,
			sizeof(attr_ruleset));
	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(-1, write(ruleset_fd, ".", 1));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, read(ruleset_fd, &buf, 1));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

TEST_HARNESS_MAIN
