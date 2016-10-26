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
#include <linux/seccomp.h> /* struct seccomp_* */
#include <linux/types.h> /* uintptr_t */

/* hook arguments */
#include <linux/dcache.h> /* struct dentry */
#include <linux/fs.h> /* struct inode */
#include <linux/path.h> /* struct path */

#ifdef CONFIG_CGROUP_BPF
#include <linux/cgroup-defs.h> /* struct cgroup */
#endif /* CONFIG_CGROUP_BPF */

#include "checker_fs.h"
#include "common.h"

#define MAP0(s, m, ...)
#define MAP1(s, m, d, t, a) m(d, t, a)
#define MAP2(s, m, d, t, a, ...) m(d, t, a) s() MAP1(s, m, __VA_ARGS__)
#define MAP3(s, m, d, t, a, ...) m(d, t, a) s() MAP2(s, m, __VA_ARGS__)
#define MAP4(s, m, d, t, a, ...) m(d, t, a) s() MAP3(s, m, __VA_ARGS__)
#define MAP5(s, m, d, t, a, ...) m(d, t, a) s() MAP4(s, m, __VA_ARGS__)
#define MAP6(s, m, d, t, a, ...) m(d, t, a) s() MAP5(s, m, __VA_ARGS__)

/* separators */
#define SEP_COMMA() ,
#define SEP_NONE()

/* arguments */
#define ARG_MAP(n, ...) MAP##n(SEP_COMMA, __VA_ARGS__)
#define ARG_REGTYPE(d, t, a) d##_REGTYPE
#define ARG_TA(d, t, a) t a
#define ARG_GET(d, t, a) ((u64) d##_GET(a))

/* declarations */
#define DEC_MAP(n, ...) MAP##n(SEP_NONE, DEC, __VA_ARGS__)
#define DEC(d, t, a) d##_DEC(a)

#define LANDLOCK_HOOKx(X, NAME, CNAME, ...)				\
	static inline int landlock_hook_##NAME(				\
		ARG_MAP(X, ARG_TA, __VA_ARGS__))			\
	{								\
		DEC_MAP(X, __VA_ARGS__)					\
		__u64 args[6] = {					\
			ARG_MAP(X, ARG_GET, __VA_ARGS__)		\
		};							\
		return landlock_enforce(LANDLOCK_HOOK_##CNAME, args);	\
	}								\
	static inline bool __is_valid_access_hook_##CNAME(		\
			int off, int size, enum bpf_access_type type,	\
			enum bpf_reg_type *reg_type,			\
			union bpf_prog_subtype *prog_subtype)		\
	{								\
		enum bpf_reg_type arg_types[6] = {			\
			ARG_MAP(X, ARG_REGTYPE, __VA_ARGS__)		\
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

/* LANDLOCK_WRAPARG_NONE */
#define LANDLOCK_WRAPARG_NONE_REGTYPE	NOT_INIT
#define LANDLOCK_WRAPARG_NONE_DEC(arg)
#define LANDLOCK_WRAPARG_NONE_GET(arg)	0

/* LANDLOCK_WRAPARG_RAW */
#define LANDLOCK_WRAPARG_RAW_REGTYPE	UNKNOWN_VALUE
#define LANDLOCK_WRAPARG_RAW_DEC(arg)
#define LANDLOCK_WRAPARG_RAW_GET(arg)	arg

/* LANDLOCK_WRAPARG_FILE */
#define LANDLOCK_WRAPARG_FILE_REGTYPE	CONST_PTR_TO_LANDLOCK_ARG_FS
#define LANDLOCK_WRAPARG_FILE_DEC(arg)			\
	const struct landlock_arg_fs wrap_##arg =	\
	{ .type = LANDLOCK_ARGTYPE_FILE, .file = arg };
#define LANDLOCK_WRAPARG_FILE_GET(arg)	(uintptr_t)&wrap_##arg

/* LANDLOCK_WRAPARG_INODE */
#define LANDLOCK_WRAPARG_INODE_REGTYPE	CONST_PTR_TO_LANDLOCK_ARG_FS
#define LANDLOCK_WRAPARG_INODE_DEC(arg)			\
	const struct landlock_arg_fs wrap_##arg =	\
	{ .type = LANDLOCK_ARGTYPE_INODE, .inode = arg };
#define LANDLOCK_WRAPARG_INODE_GET(arg)	(uintptr_t)&wrap_##arg

/* LANDLOCK_WRAPARG_PATH */
#define LANDLOCK_WRAPARG_PATH_REGTYPE	CONST_PTR_TO_LANDLOCK_ARG_FS
#define LANDLOCK_WRAPARG_PATH_DEC(arg)			\
	const struct landlock_arg_fs wrap_##arg =	\
	{ .type = LANDLOCK_ARGTYPE_PATH, .path = arg };
#define LANDLOCK_WRAPARG_PATH_GET(arg)	(uintptr_t)&wrap_##arg

/**
 * landlock_run_prog - run Landlock program for a syscall
 *
 * @hook_idx: hook index in the rules array
 * @ctx: non-NULL eBPF context
 * @hooks: Landlock hooks pointer
 */
static u32 landlock_run_prog(u32 hook_idx, const struct landlock_data *ctx,
		struct landlock_hooks *hooks)
{
	struct landlock_node *node;
	u32 ret = 0;

	if (!hooks)
		return 0;

	for (node = hooks->nodes[hook_idx]; node; node = node->prev) {
		struct landlock_rule *rule;

		for (rule = node->rule; rule; rule = rule->prev) {
			if (WARN_ON(!rule->prog))
				continue;
			rcu_read_lock();
			ret = BPF_PROG_RUN(rule->prog, (void *)ctx);
			rcu_read_unlock();
			if (ret) {
				if (ret > MAX_ERRNO)
					ret = MAX_ERRNO;
				goto out;
			}
		}
	}

out:
	return ret;
}

static int landlock_enforce(enum landlock_hook hook, __u64 args[6])
{
	u32 ret = 0;
#ifdef CONFIG_CGROUP_BPF
	struct cgroup *cgrp;
#endif /* CONFIG_CGROUP_BPF */
	u32 hook_idx = get_index(hook);

	struct landlock_data ctx = {
		.hook = hook,
		.args[0] = args[0],
		.args[1] = args[1],
		.args[2] = args[2],
		.args[3] = args[3],
		.args[4] = args[4],
		.args[5] = args[5],
	};

#ifdef CONFIG_SECCOMP_FILTER
	ret = landlock_run_prog(hook_idx, &ctx,
			current->seccomp.landlock_hooks);
	if (ret)
		goto out;
#endif /* CONFIG_SECCOMP_FILTER */

#ifdef CONFIG_CGROUP_BPF
	if (cgroup_bpf_enabled) {
		/* get the default cgroup associated with the current thread */
		cgrp = task_css_set(current)->dfl_cgrp;
		ret = landlock_run_prog(hook_idx, &ctx,
				cgrp->bpf.effective[BPF_CGROUP_LANDLOCK].hooks);
	}
#endif /* CONFIG_CGROUP_BPF */

out:
	return -ret;
}

static const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id, union bpf_prog_subtype *prog_subtype)
{
	bool access_update = !!(prog_subtype->landlock_rule.access &
			LANDLOCK_SUBTYPE_ACCESS_UPDATE);
	bool access_debug = !!(prog_subtype->landlock_rule.access &
			LANDLOCK_SUBTYPE_ACCESS_DEBUG);

	switch (func_id) {
	case BPF_FUNC_landlock_get_fs_mode:
		return &bpf_landlock_get_fs_mode_proto;
	case BPF_FUNC_landlock_cmp_fs_beneath:
		return &bpf_landlock_cmp_fs_beneath_proto;

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
	case offsetof(struct landlock_data, hook):
		expected_size = sizeof(__u32);
		break;
	case offsetof(struct landlock_data, args[0]) ...
			offsetof(struct landlock_data, args[5]):
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
	}

	return true;
}

LANDLOCK_HOOK2(file_open, FILE_OPEN,
	LANDLOCK_WRAPARG_FILE, struct file *, file,
	LANDLOCK_WRAPARG_NONE, const struct cred *, cred
)

LANDLOCK_HOOK2(file_permission, FILE_PERMISSION,
	LANDLOCK_WRAPARG_FILE, struct file *, file,
	LANDLOCK_WRAPARG_RAW, int, mask
)

LANDLOCK_HOOK4(mmap_file, MMAP_FILE,
	LANDLOCK_WRAPARG_FILE, struct file *, file,
	LANDLOCK_WRAPARG_RAW, unsigned long, reqprot,
	LANDLOCK_WRAPARG_RAW, unsigned long, prot,
	LANDLOCK_WRAPARG_RAW, unsigned long, flags
)

/* a directory inode contains only one dentry */
LANDLOCK_HOOK3(inode_create, INODE_CREATE,
	LANDLOCK_WRAPARG_INODE, struct inode *, dir,
	LANDLOCK_WRAPARG_NONE, struct dentry *, dentry,
	LANDLOCK_WRAPARG_RAW, umode_t, mode
)

LANDLOCK_HOOK3(inode_link, INODE_LINK,
	LANDLOCK_WRAPARG_NONE, struct dentry *, old_dentry,
	LANDLOCK_WRAPARG_INODE, struct inode *, dir,
	LANDLOCK_WRAPARG_NONE, struct dentry *, new_dentry
)

LANDLOCK_HOOK2(inode_unlink, INODE_UNLINK,
	LANDLOCK_WRAPARG_INODE, struct inode *, dir,
	LANDLOCK_WRAPARG_NONE, struct dentry *, dentry
)

LANDLOCK_HOOK2(inode_permission, INODE_PERMISSION,
	LANDLOCK_WRAPARG_INODE, struct inode *, inode,
	LANDLOCK_WRAPARG_RAW, int, mask
)

LANDLOCK_HOOK1(inode_getattr, INODE_GETATTR,
	LANDLOCK_WRAPARG_PATH, const struct path *, path
)

static struct security_hook_list landlock_hooks[] = {
	LANDLOCK_HOOK_INIT(file_open),
	LANDLOCK_HOOK_INIT(file_permission),
	LANDLOCK_HOOK_INIT(mmap_file),
	LANDLOCK_HOOK_INIT(inode_create),
	LANDLOCK_HOOK_INIT(inode_link),
	LANDLOCK_HOOK_INIT(inode_unlink),
	LANDLOCK_HOOK_INIT(inode_permission),
	LANDLOCK_HOOK_INIT(inode_getattr),
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
	enum landlock_hook hook = prog_subtype->landlock_rule.hook;

	switch (hook) {
	LANDLOCK_CASE_ACCESS_HOOK(FILE_OPEN)
	LANDLOCK_CASE_ACCESS_HOOK(FILE_PERMISSION)
	LANDLOCK_CASE_ACCESS_HOOK(MMAP_FILE)
	LANDLOCK_CASE_ACCESS_HOOK(INODE_CREATE)
	LANDLOCK_CASE_ACCESS_HOOK(INODE_LINK)
	LANDLOCK_CASE_ACCESS_HOOK(INODE_UNLINK)
	LANDLOCK_CASE_ACCESS_HOOK(INODE_PERMISSION)
	LANDLOCK_CASE_ACCESS_HOOK(INODE_GETATTR)
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
}

static inline bool bpf_landlock_is_valid_subtype(
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_hook hook = prog_subtype->landlock_rule.hook;

	switch (hook) {
	case LANDLOCK_HOOK_FILE_OPEN:
	case LANDLOCK_HOOK_FILE_PERMISSION:
	case LANDLOCK_HOOK_MMAP_FILE:
	case LANDLOCK_HOOK_INODE_CREATE:
	case LANDLOCK_HOOK_INODE_LINK:
	case LANDLOCK_HOOK_INODE_UNLINK:
	case LANDLOCK_HOOK_INODE_PERMISSION:
	case LANDLOCK_HOOK_INODE_GETATTR:
		break;
	case LANDLOCK_HOOK_UNSPEC:
	default:
		return false;
	}
	if (!prog_subtype->landlock_rule.hook ||
			prog_subtype->landlock_rule.hook > _LANDLOCK_HOOK_LAST)
		return false;
	if (prog_subtype->landlock_rule.access & ~_LANDLOCK_SUBTYPE_ACCESS_MASK)
		return false;
	if (prog_subtype->landlock_rule.option & ~_LANDLOCK_SUBTYPE_OPTION_MASK)
		return false;

	/* check access flags */
	if (prog_subtype->landlock_rule.access & LANDLOCK_SUBTYPE_ACCESS_UPDATE &&
			!capable(CAP_SYS_ADMIN))
		return false;
	if (prog_subtype->landlock_rule.access & LANDLOCK_SUBTYPE_ACCESS_DEBUG &&
			!capable(CAP_SYS_ADMIN))
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
