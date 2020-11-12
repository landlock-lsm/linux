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

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
		const struct landlock_ruleset_attr *const attr,
		const size_t size, const __u32 flags)
{
	errno = 0;
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
		const enum landlock_rule_type rule_type,
		const void *const rule_attr, const __u32 flags)
{
	errno = 0;
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
			rule_attr, flags);
}
#endif

#ifndef landlock_enforce_ruleset_current
static inline int landlock_enforce_ruleset_current(const int ruleset_fd,
		const __u32 flags)
{
	errno = 0;
	return syscall(__NR_landlock_enforce_ruleset_current, ruleset_fd,
			flags);
}
#endif

static void disable_caps(struct __test_metadata *const _metadata)
{
	cap_t cap_p;
	/* Only these three capabilities are useful for the tests. */
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
	ASSERT_NE(-1, cap_set_flag(cap_p, CAP_PERMITTED, ARRAY_SIZE(caps),
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

/* We cannot put such helpers in a library because of kselftest_harness.h . */
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
