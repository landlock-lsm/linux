/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Landlock test helpers
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019-2020 ANSSI
 */

#include <errno.h>
#include <linux/landlock.h>
#include <sys/syscall.h>

#include "../kselftest_harness.h"

#ifndef landlock
static inline int landlock(const unsigned int command,
		const unsigned int options,
		const size_t attr_size, void *const attr_ptr)
{
	errno = 0;
	return syscall(__NR_landlock, command, options, attr_size, attr_ptr, 0,
			NULL);
}
#endif

FIXTURE(ruleset_rw) {
	struct landlock_attr_ruleset attr_ruleset;
	int ruleset_fd;
};

FIXTURE_SETUP(ruleset_rw) {
	self->attr_ruleset.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_WRITE_FILE;
	self->ruleset_fd = landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET,
			sizeof(self->attr_ruleset), &self->attr_ruleset);
	ASSERT_LE(0, self->ruleset_fd);
}

FIXTURE_TEARDOWN(ruleset_rw) {
	ASSERT_EQ(0, close(self->ruleset_fd));
}
