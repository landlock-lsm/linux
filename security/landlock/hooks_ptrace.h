/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - ptrace hooks headers
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_HOOKS_PTRACE_H
#define _SECURITY_LANDLOCK_HOOKS_PTRACE_H

struct landlock_hook_ctx_ptrace;

const struct landlock_context_ptrace *landlock_get_ctx_ptrace(
		const struct landlock_hook_ctx_ptrace *hook_ctx);

__init void landlock_add_hooks_ptrace(void);

#endif /* _SECURITY_LANDLOCK_HOOKS_PTRACE_H */
