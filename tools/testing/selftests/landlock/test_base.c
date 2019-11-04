// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - base
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 */

#define _GNU_SOURCE
#include <errno.h>

#include "test.h"

TEST(seccomp_landlock)
{
	int ret;

	ret = seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, NULL);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EFAULT, errno) {
		TH_LOG("Kernel does not support CONFIG_SECURITY_LANDLOCK");
	}
}

TEST_HARNESS_MAIN
