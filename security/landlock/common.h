/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - private headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h>
#include <linux/filter.h>

enum landlock_hook_type {
	LANDLOCK_HOOK_PTRACE = 1,
};

static inline enum landlock_hook_type get_hook_type(const struct bpf_prog *prog)
{
	switch (prog->expected_attach_type) {
	case BPF_LANDLOCK_PTRACE:
		return LANDLOCK_HOOK_PTRACE;
	default:
		WARN_ON(1);
		return BPF_LANDLOCK_PTRACE;
	}
}

#endif /* _SECURITY_LANDLOCK_COMMON_H */
