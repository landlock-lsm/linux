/*
 * Landlock tests - base
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
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
