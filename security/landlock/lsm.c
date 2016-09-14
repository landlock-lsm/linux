/*
 * Landlock LSM
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <linux/bpf-cgroup.h> /* cgroup_bpf_enabled */
#include <linux/bpf.h> /* enum bpf_reg_type, struct landlock_data */
#include <linux/cred.h>
#include <linux/err.h> /* MAX_ERRNO */
#include <linux/filter.h> /* struct bpf_prog, BPF_PROG_RUN() */
#include <linux/kernel.h> /* FIELD_SIZEOF() */
#include <linux/landlock.h>
#include <linux/lsm_hooks.h>
#include <linux/preempt.h> /* in_interrupt() */
#include <linux/seccomp.h> /* struct seccomp_* */
#include <linux/types.h> /* uintptr_t */

#ifdef CONFIG_CGROUP_BPF
#include <linux/cgroup-defs.h> /* struct cgroup */
#endif /* CONFIG_CGROUP_BPF */

#include "checker_fs.h"
#include "common.h"

#define LANDLOCK_MAP0(m, ...)
#define LANDLOCK_MAP1(m, d, t, a) m(d, t, a)
#define LANDLOCK_MAP2(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP1(m, __VA_ARGS__)
#define LANDLOCK_MAP3(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP2(m, __VA_ARGS__)
#define LANDLOCK_MAP4(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP3(m, __VA_ARGS__)
#define LANDLOCK_MAP5(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP4(m, __VA_ARGS__)
#define LANDLOCK_MAP6(m, d, t, a, ...) m(d, t, a), LANDLOCK_MAP5(m, __VA_ARGS__)
#define LANDLOCK_MAP(n, ...) LANDLOCK_MAP##n(__VA_ARGS__)

#define LANDLOCK_ARG_D(d, t, a) d
#define LANDLOCK_ARG_TA(d, t, a) t a
#define LANDLOCK_ARG_A(d, t, a) ((u64)(uintptr_t)a)

#define LANDLOCK_HOOKx(X, NAME, CNAME, ...)				\
	static inline int landlock_hook_##NAME(				\
		LANDLOCK_MAP(X, LANDLOCK_ARG_TA, __VA_ARGS__))		\
	{								\
		__u64 args[6] = {					\
			LANDLOCK_MAP(X, LANDLOCK_ARG_A, __VA_ARGS__)	\
		};							\
		return landlock_run_prog(LANDLOCK_HOOK_##CNAME, args);	\
	}								\
	static inline bool __is_valid_access_hook_##CNAME(		\
			int off, int size, enum bpf_access_type type,	\
			enum bpf_reg_type *reg_type,			\
			union bpf_prog_subtype *prog_subtype)		\
	{								\
		enum bpf_reg_type arg_types[6] = {			\
			LANDLOCK_MAP(X, LANDLOCK_ARG_D, __VA_ARGS__)	\
		};							\
		return __is_valid_access(off, size, type, reg_type,	\
				arg_types, prog_subtype);		\
	}								\

#define LANDLOCK_HOOK1(NAME, ...) LANDLOCK_HOOKx(1, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK2(NAME, ...) LANDLOCK_HOOKx(2, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK3(NAME, ...) LANDLOCK_HOOKx(3, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK4(NAME, ...) LANDLOCK_HOOKx(4, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK5(NAME, ...) LANDLOCK_HOOKx(5, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK6(NAME, ...) LANDLOCK_HOOKx(6, NAME, __VA_ARGS__)

#define LANDLOCK_HOOK_INIT(NAME) LSM_HOOK_INIT(NAME, landlock_hook_##NAME)

/**
 * landlock_run_prog_for_syscall - run Landlock program for a syscall
 *
 * @hook_idx: hook index in the rules array
 * @ctx: non-NULL eBPF context; the "origin" field will be updated
 * @hooks: Landlock hooks pointer
 */
static u32 landlock_run_prog_for_syscall(u32 hook_idx,
		struct landlock_data *ctx, struct landlock_hooks *hooks)
{
	struct landlock_rule *rule;
	u32 cur_ret = 0, ret = 0;

	if (!hooks)
		return 0;

	for (rule = hooks->rules[hook_idx]; rule && !ret; rule = rule->prev) {
		if (!(rule->prog->subtype.landlock_hook.origin & ctx->origin))
			continue;
		cur_ret = BPF_PROG_RUN(rule->prog, (void *)ctx);
		if (cur_ret > MAX_ERRNO)
			ret = MAX_ERRNO;
		else
			ret = cur_ret;
	}
	return ret;
}

static int landlock_run_prog(enum landlock_hook_id hook_id, __u64 args[6])
{
	u32 cur_ret = 0, ret = 0;
#ifdef CONFIG_SECCOMP_FILTER
	struct landlock_seccomp_ret *lr;
#endif /* CONFIG_SECCOMP_FILTER */
#ifdef CONFIG_CGROUP_BPF
	struct cgroup *cgrp;
#endif /* CONFIG_CGROUP_BPF */
	struct landlock_rule *rule;
	u32 hook_idx = get_index(hook_id);
	u16 current_call;

	struct landlock_data ctx = {
		.hook = hook_id,
		.cookie = 0,
		.args[0] = args[0],
		.args[1] = args[1],
		.args[2] = args[2],
		.args[3] = args[3],
		.args[4] = args[4],
		.args[5] = args[5],
	};

	/* TODO: use lockless_dereference()? */

	/*
	 * Run the seccomp-based triggers before the cgroup-based triggers to
	 * prioritize fine-grained policies (i.e. per thread), and return early.
	 */

	if (unlikely(in_interrupt())) {
		current_call = LANDLOCK_FLAG_ORIGIN_INTERRUPT;
#ifdef CONFIG_SECCOMP_FILTER
		/* bypass landlock_ret evaluation */
		goto seccomp_int;
#endif /* CONFIG_SECCOMP_FILTER */
	} else {
		current_call = LANDLOCK_FLAG_ORIGIN_SYSCALL;
	}

#ifdef CONFIG_SECCOMP_FILTER
	/* seccomp triggers and landlock_ret cleanup */
	ctx.origin = LANDLOCK_FLAG_ORIGIN_SECCOMP;
	for (lr = current->seccomp.landlock_ret; lr; lr = lr->prev) {
		if (!lr->triggered)
			continue;
		lr->triggered = false;
		/* clean up all seccomp results */
		if (ret)
			continue;
		ctx.cookie = lr->cookie;
		for (rule = current->seccomp.landlock_hooks->rules[hook_idx];
				rule && !ret; rule = rule->prev) {
			struct seccomp_filter *filter;

			if (!(rule->prog->subtype.landlock_hook.origin &
						ctx.origin))
				continue;
			for (filter = rule->thread_filter; filter;
					filter = filter->thread_prev) {
				if (rule->thread_filter != lr->filter)
					continue;
				cur_ret = BPF_PROG_RUN(rule->prog, (void *)&ctx);
				if (cur_ret > MAX_ERRNO)
					ret = MAX_ERRNO;
				else
					ret = cur_ret;
				/* walk to the next program */
				break;
			}
		}
	}
	if (ret)
		return -ret;
	ctx.cookie = 0;

seccomp_int:
	/* syscall trigger */
	ctx.origin = current_call;
	ret = landlock_run_prog_for_syscall(hook_idx, &ctx,
			current->seccomp.landlock_hooks);
	if (ret)
		return -ret;
#endif /* CONFIG_SECCOMP_FILTER */

#ifdef CONFIG_CGROUP_BPF
	/* syscall trigger */
	if (cgroup_bpf_enabled) {
		ctx.origin = current_call;
		/* get the default cgroup associated with the current thread */
		cgrp = task_css_set(current)->dfl_cgrp;
		ret = landlock_run_prog_for_syscall(hook_idx, &ctx,
				cgrp->bpf.effective[BPF_CGROUP_LANDLOCK].hooks);
	}
#endif /* CONFIG_CGROUP_BPF */

	return -ret;
}

static const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id, union bpf_prog_subtype *prog_subtype)
{
	bool access_update = !!(prog_subtype->landlock_hook.access &
			LANDLOCK_FLAG_ACCESS_UPDATE);
	bool access_debug = !!(prog_subtype->landlock_hook.access &
			LANDLOCK_FLAG_ACCESS_DEBUG);

	switch (func_id) {
	case BPF_FUNC_landlock_cmp_fs_prop_with_struct_file:
		return &bpf_landlock_cmp_fs_prop_with_struct_file_proto;
	case BPF_FUNC_landlock_cmp_fs_beneath_with_struct_file:
		return &bpf_landlock_cmp_fs_beneath_with_struct_file_proto;

	/* access_update */
	case BPF_FUNC_map_lookup_elem:
		if (access_update)
			return &bpf_map_lookup_elem_proto;
		return NULL;
	case BPF_FUNC_map_update_elem:
		if (access_update)
			return &bpf_map_update_elem_proto;
		return NULL;
	case BPF_FUNC_map_delete_elem:
		if (access_update)
			return &bpf_map_delete_elem_proto;
		return NULL;
	case BPF_FUNC_tail_call:
		if (access_update)
			return &bpf_tail_call_proto;
		return NULL;

	/* access_debug */
	case BPF_FUNC_trace_printk:
		if (access_debug)
			return bpf_get_trace_printk_proto();
		return NULL;
	case BPF_FUNC_get_prandom_u32:
		if (access_debug)
			return &bpf_get_prandom_u32_proto;
		return NULL;
	case BPF_FUNC_get_current_pid_tgid:
		if (access_debug)
			return &bpf_get_current_pid_tgid_proto;
		return NULL;
	case BPF_FUNC_get_current_uid_gid:
		if (access_debug)
			return &bpf_get_current_uid_gid_proto;
		return NULL;
	case BPF_FUNC_get_current_comm:
		if (access_debug)
			return &bpf_get_current_comm_proto;
		return NULL;

	default:
		return NULL;
	}
}

static bool __is_valid_access(int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type,
		enum bpf_reg_type arg_types[6],
		union bpf_prog_subtype *prog_subtype)
{
	int arg_nb, expected_size;

	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct landlock_data))
		return false;

	/* check size */
	switch (off) {
	case offsetof(struct landlock_data, origin):
	case offsetof(struct landlock_data, cookie):
		expected_size = sizeof(__u16);
		break;
	case offsetof(struct landlock_data, hook):
		expected_size = sizeof(__u32);
		break;
	case offsetof(struct landlock_data, args[0]) ...
			offsetof(struct landlock_data, args[5]):
	case offsetof(struct landlock_data, opt_skb):
		expected_size = sizeof(__u64);
		break;
	default:
		return false;
	}
	if (expected_size != size)
		return false;

	/* check pointer access and set pointer type */
	switch (off) {
	case offsetof(struct landlock_data, args[0]) ...
			offsetof(struct landlock_data, args[5]):
		arg_nb = (off - offsetof(struct landlock_data, args[0]))
			/ FIELD_SIZEOF(struct landlock_data, args[0]);
		*reg_type = arg_types[arg_nb];
		if (*reg_type == NOT_INIT)
			return false;
		break;
	case offsetof(struct landlock_data, opt_skb):
		if (!(prog_subtype->landlock_hook.access &
				(LANDLOCK_FLAG_ACCESS_SKB_READ |
				 LANDLOCK_FLAG_ACCESS_SKB_WRITE)))
			return false;
		*reg_type = PTR_TO_STRUCT_SKB;
		break;
	}

	return true;
}

LANDLOCK_HOOK2(file_open, FILE_OPEN,
	PTR_TO_STRUCT_FILE, struct file *, file,
	NOT_INIT, const struct cred *, cred
)

LANDLOCK_HOOK2(file_permission, FILE_PERMISSION,
	PTR_TO_STRUCT_FILE, struct file *, file,
	UNKNOWN_VALUE, int, mask
)

LANDLOCK_HOOK4(mmap_file, MMAP_FILE,
	PTR_TO_STRUCT_FILE, struct file *, file,
	UNKNOWN_VALUE, unsigned long, reqprot,
	UNKNOWN_VALUE, unsigned long, prot,
	UNKNOWN_VALUE, unsigned long, flags
)

static struct security_hook_list landlock_hooks[] = {
	LANDLOCK_HOOK_INIT(file_open),
	LANDLOCK_HOOK_INIT(file_permission),
	LANDLOCK_HOOK_INIT(mmap_file),
};

#ifdef CONFIG_SECCOMP_FILTER
#ifdef CONFIG_CGROUP_BPF
#define LANDLOCK_MANAGERS "seccomp and cgroups"
#else /* CONFIG_CGROUP_BPF */
#define LANDLOCK_MANAGERS "seccomp"
#endif /* CONFIG_CGROUP_BPF */
#elif define(CONFIG_CGROUP_BPF)
#define LANDLOCK_MANAGERS "cgroups"
#else
#error "Need CONFIG_SECCOMP_FILTER or CONFIG_CGROUP_BPF"
#endif /* CONFIG_SECCOMP_FILTER */

void __init landlock_add_hooks(void)
{
	pr_info("landlock: Becoming ready to sandbox with " LANDLOCK_MANAGERS "\n");
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks));
}

#define LANDLOCK_CASE_ACCESS_HOOK(CNAME)			\
	case LANDLOCK_HOOK_##CNAME:				\
		return __is_valid_access_hook_##CNAME(		\
				off, size, type, reg_type, prog_subtype);

static inline bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, enum bpf_reg_type *reg_type,
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_hook_id hook_id = prog_subtype->landlock_hook.id;

	switch (hook_id) {
	LANDLOCK_CASE_ACCESS_HOOK(FILE_OPEN)
	LANDLOCK_CASE_ACCESS_HOOK(FILE_PERMISSION)
	LANDLOCK_CASE_ACCESS_HOOK(MMAP_FILE)
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
}

static inline bool bpf_landlock_is_valid_subtype(
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_hook_id hook_id = prog_subtype->landlock_hook.id;

	switch (hook_id) {
	case LANDLOCK_HOOK_FILE_OPEN:
	case LANDLOCK_HOOK_FILE_PERMISSION:
	case LANDLOCK_HOOK_MMAP_FILE:
		break;
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
	if (!prog_subtype->landlock_hook.id ||
			prog_subtype->landlock_hook.id > _LANDLOCK_HOOK_LAST)
		return false;
	if (!prog_subtype->landlock_hook.origin ||
			(prog_subtype->landlock_hook.origin &
			 ~_LANDLOCK_FLAG_ORIGIN_MASK))
		return false;
#ifndef CONFIG_SECCOMP_FILTER
	if (prog_subtype->landlock_hook.origin & LANDLOCK_FLAG_ORIGIN_SECCOMP)
		return false;
#endif /* !CONFIG_SECCOMP_FILTER */
	if (prog_subtype->landlock_hook.access & ~_LANDLOCK_FLAG_ACCESS_MASK)
		return false;

	/* check access flags */
	if (prog_subtype->landlock_hook.access & LANDLOCK_FLAG_ACCESS_UPDATE &&
			!capable(CAP_SYS_ADMIN))
		return false;
	if (prog_subtype->landlock_hook.access & LANDLOCK_FLAG_ACCESS_DEBUG &&
			!capable(CAP_SYS_ADMIN))
		return false;
	/*
	 * Capability checks must be enforced for every landlocked process.
	 * To support user namespaces/capabilities, we must then check the
	 * namespaces of a task before putting it in a landlocked cgroup.
	 * This could be implemented in the future.
	 */
	if (prog_subtype->landlock_hook.access & LANDLOCK_FLAG_ACCESS_SKB_READ &&
			!capable(CAP_NET_ADMIN))
		return false;
	/*
	 * It is interesting to differentiate read and write access to be able
	 * to securely delegate some work to unprivileged (and potentially
	 * compromised/untrusted) processes. This different type of access can
	 * be checked for function calls or context accesses.
	 */
	if (prog_subtype->landlock_hook.access & LANDLOCK_FLAG_ACCESS_SKB_WRITE &&
			!capable(CAP_NET_ADMIN))
		return false;

	return true;
}

static const struct bpf_verifier_ops bpf_landlock_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
	.is_valid_subtype = bpf_landlock_is_valid_subtype,
};

static struct bpf_prog_type_list bpf_landlock_type __read_mostly = {
	.ops	= &bpf_landlock_ops,
	.type	= BPF_PROG_TYPE_LANDLOCK,
};

static int __init register_landlock_filter_ops(void)
{
	bpf_register_prog_type(&bpf_landlock_type);
	return 0;
}

late_initcall(register_landlock_filter_ops);
