/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Landlock test helpers
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019-2020 ANSSI
 */

#include <errno.h>
#include <linux/landlock.h>
#include <sys/capability.h>
#include <sys/syscall.h>

#include "../kselftest_harness.h"

#ifndef landlock
static inline int landlock(const unsigned int command,
		const unsigned int options,
		void *const attr_ptr, const size_t attr_size)
{
	errno = 0;
	return syscall(__NR_landlock, command, options, attr_ptr, attr_size,
			NULL, 0);
}
#endif

static void disable_caps(struct __test_metadata *const _metadata)
{
	cap_t cap_p;
	/* Only these two capabilities are useful for the tests. */
	const cap_value_t caps[] = {
		CAP_MKNOD,
		CAP_SYS_ADMIN,
		CAP_SYS_CHROOT,
	};

	cap_p = cap_get_proc();
	ASSERT_NE(NULL, cap_p) {
		TH_LOG("Failed to cap_get_proc: %s", strerror(errno));
	}
	ASSERT_NE(-1, cap_clear(cap_p)) {
		TH_LOG("Failed to cap_clear: %s", strerror(errno));
	}
	ASSERT_NE(-1, cap_set_flag(cap_p, CAP_PERMITTED,
				sizeof(caps) / sizeof(caps[0]),
				caps, CAP_SET)) {
		TH_LOG("Failed to cap_set_flag: %s", strerror(errno));
	}
	ASSERT_NE(-1, cap_set_proc(cap_p)) {
		TH_LOG("Failed to cap_set_proc: %s", strerror(errno));
	}
	ASSERT_NE(-1, cap_free(cap_p)) {
		TH_LOG("Failed to cap_free: %s", strerror(errno));
	}
}

static void effective_cap(struct __test_metadata *const _metadata,
		const cap_value_t caps, const cap_flag_value_t value)
{
	cap_t cap_p;

	cap_p = cap_get_proc();
	ASSERT_NE(NULL, cap_p) {
		TH_LOG("Failed to cap_get_proc: %s", strerror(errno));
	}
	ASSERT_NE(-1, cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &caps, value)) {
		TH_LOG("Failed to cap_set_flag: %s", strerror(errno));
	}
	ASSERT_NE(-1, cap_set_proc(cap_p)) {
		TH_LOG("Failed to cap_set_proc: %s", strerror(errno));
	}
	ASSERT_NE(-1, cap_free(cap_p)) {
		TH_LOG("Failed to cap_free: %s", strerror(errno));
	}
}

/* We can't put such helpers in a library because of kselftest_harness.h . */
__attribute__((__unused__))
static void set_cap(struct __test_metadata *const _metadata,
		const cap_value_t caps)
{
	effective_cap(_metadata, caps, CAP_SET);
}

__attribute__((__unused__))
static void clear_cap(struct __test_metadata *const _metadata,
		const cap_value_t caps)
{
	effective_cap(_metadata, caps, CAP_CLEAR);
}

FIXTURE(ruleset_rw) {
	struct landlock_attr_ruleset attr_ruleset;
	int ruleset_fd;
};

FIXTURE_SETUP(ruleset_rw) {
	self->attr_ruleset.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_WRITE_FILE;
	self->ruleset_fd = landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET,
			&self->attr_ruleset, sizeof(self->attr_ruleset));
	ASSERT_LE(0, self->ruleset_fd);
}

FIXTURE_TEARDOWN(ruleset_rw) {
	ASSERT_EQ(0, close(self->ruleset_fd));
}
