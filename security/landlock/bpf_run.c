// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - eBPF program evaluation
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <asm/current.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/preempt.h>
#include <linux/rculist.h>
#include <uapi/linux/landlock.h>

#include "bpf_run.h"
#include "common.h"
#include "hooks_ptrace.h"

static const void *get_prog_ctx(struct landlock_hook_ctx *hook_ctx)
{
	switch (hook_ctx->type) {
	case LANDLOCK_HOOK_PTRACE:
		return landlock_get_ctx_ptrace(hook_ctx->ctx_ptrace);
	}
	WARN_ON(1);
	return NULL;
}

/**
 * landlock_access_denied - run Landlock programs tied to a hook
 *
 * @domain: Landlock domain pointer
 * @hook_ctx: non-NULL valid eBPF context pointer
 *
 * Return true if at least one program return deny, false otherwise.
 */
bool landlock_access_denied(struct landlock_domain *domain,
		struct landlock_hook_ctx *hook_ctx)
{
	struct landlock_prog_list *prog_list;
	const size_t hook = get_hook_index(hook_ctx->type);

	if (!domain)
		return false;

	for (prog_list = domain->programs[hook]; prog_list;
			prog_list = prog_list->prev) {
		u32 ret;
		const void *prog_ctx;

		prog_ctx = get_prog_ctx(hook_ctx);
		if (!prog_ctx || WARN_ON(IS_ERR(prog_ctx)))
			return true;
		preempt_disable();
		rcu_read_lock();
		ret = BPF_PROG_RUN(prog_list->prog, prog_ctx);
		rcu_read_unlock();
		preempt_enable();
		if (ret & LANDLOCK_RET_DENY)
			return true;
	}
	return false;
}
