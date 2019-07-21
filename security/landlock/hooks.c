// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - hook helpers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <asm/current.h>
#include <linux/bpf.h> /* enum bpf_prog_aux */
#include <linux/errno.h>
#include <linux/filter.h> /* BPF_PROG_RUN() */
#include <linux/rculist.h> /* list_add_tail_rcu */
#include <uapi/linux/landlock.h> /* struct landlock_context */

#include "common.h" /* struct landlock_rule, get_hook_index() */
#include "hooks.h" /* landlock_hook_ctx */

#include "hooks_fs.h"

/* return a Landlock program context (e.g. hook_ctx->fs_walk.prog_ctx) */
static const void *get_ctx(enum landlock_hook_type hook_type,
		struct landlock_hook_ctx *hook_ctx)
{
	switch (hook_type) {
	case LANDLOCK_HOOK_FS_WALK:
		return landlock_get_ctx_fs_walk(hook_ctx->fs_walk);
	case LANDLOCK_HOOK_FS_PICK:
		return landlock_get_ctx_fs_pick(hook_ctx->fs_pick);
	}
	WARN_ON(1);
	return NULL;
}

/**
 * landlock_access_deny - run Landlock programs tied to a hook
 *
 * @hook_idx: hook index in the programs array
 * @ctx: non-NULL valid eBPF context
 * @prog_set: Landlock program set pointer
 * @triggers: a bitmask to check if a program should be run
 *
 * Return true if at least one program return deny.
 */
static bool landlock_access_deny(enum landlock_hook_type hook_type,
		struct landlock_hook_ctx *hook_ctx,
		struct landlock_prog_set *prog_set, u64 triggers)
{
	struct landlock_prog_list *prog_list, *prev_list = NULL;
	u32 hook_idx = get_hook_index(hook_type);

	if (!prog_set)
		return false;

	for (prog_list = prog_set->programs[hook_idx];
			prog_list; prog_list = prog_list->prev) {
		u32 ret;
		const void *prog_ctx;

		/* check if @prog expect at least one of this triggers */
		if (triggers && !(triggers & prog_list->prog->aux->
					expected_attach_triggers))
			continue;
		prog_ctx = get_ctx(hook_type, hook_ctx);
		if (!prog_ctx || WARN_ON(IS_ERR(prog_ctx)))
			return true;
		rcu_read_lock();
		ret = BPF_PROG_RUN(prog_list->prog, prog_ctx);
		rcu_read_unlock();
		/* deny access if a program returns a value different than 0 */
		if (ret)
			return true;
		if (prev_list && prog_list->prev && prog_list->prev->prog->
				expected_attach_type ==
				prev_list->prog->expected_attach_type)
			WARN_ON(prog_list->prev != prev_list);
		prev_list = prog_list;
	}
	return false;
}

int landlock_decide(enum landlock_hook_type hook_type,
		struct landlock_hook_ctx *hook_ctx, u64 triggers)
{
	bool deny = false;

#ifdef CONFIG_SECCOMP_FILTER
	deny = landlock_access_deny(hook_type, hook_ctx,
			current->seccomp.landlock_prog_set, triggers);
#endif /* CONFIG_SECCOMP_FILTER */

	/* should we use -EPERM or -EACCES? */
	return deny ? -EACCES : 0;
}
