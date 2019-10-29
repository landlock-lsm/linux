/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - eBPF program evaluation headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_BPF_RUN_H
#define _SECURITY_LANDLOCK_BPF_RUN_H

#include "common.h"
#include "hooks_ptrace.h"

struct landlock_hook_ctx {
	enum landlock_hook_type type;
	union {
		struct landlock_hook_ctx_ptrace *ctx_ptrace;
	};
};

bool landlock_access_denied(struct landlock_domain *domain,
		struct landlock_hook_ctx *hook_ctx);

#endif /* _SECURITY_LANDLOCK_BPF_RUN_H */
