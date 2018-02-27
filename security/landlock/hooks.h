/*
 * Landlock LSM - hooks helpers
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <linux/sched.h> /* struct task_struct */
#include <linux/seccomp.h>

#include "hooks_fs.h"

struct landlock_hook_ctx {
	union {
		struct landlock_hook_ctx_fs_walk *fs_walk;
		struct landlock_hook_ctx_fs_pick *fs_pick;
		struct landlock_hook_ctx_fs_get *fs_get;
	};
};

static inline bool landlocked(const struct task_struct *task)
{
#ifdef CONFIG_SECCOMP_FILTER
	return !!(task->seccomp.landlock_prog_set);
#else
	return false;
#endif /* CONFIG_SECCOMP_FILTER */
}

int landlock_decide(enum landlock_hook_type, struct landlock_hook_ctx *, u64);
