/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - hooks helpers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <asm/current.h>
#include <linux/sched.h> /* struct task_struct */
#include <linux/seccomp.h>

#include "hooks_fs.h"

struct landlock_hook_ctx {
	union {
		struct landlock_hook_ctx_fs_walk *fs_walk;
		struct landlock_hook_ctx_fs_pick *fs_pick;
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
