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
#include <linux/bpf.h> /* enum bpf_reg_type, struct landlock_data */
#include <linux/cred.h>
#include <linux/filter.h> /* struct bpf_prog, BPF_PROG_RUN() */
#include <linux/kernel.h> /* FIELD_SIZEOF() */
#include <linux/lsm_hooks.h>
#include <linux/seccomp.h> /* struct seccomp_* */

#include "checker_fs.h"

#ifdef CONFIG_CGROUPS
#include "checker_cgroup.h"
#endif /* CONFIG_CGROUPS */

#define LANDLOCK_HOOK_INIT(NAME) LSM_HOOK_INIT(NAME, landlock_hook_##NAME)

#define LANDLOCK_HOOKx(X, NAME, CNAME, ...)				\
	static inline int landlock_hook_##NAME(				\
		LANDLOCK_MAP(X, LANDLOCK_ARG_TA, __VA_ARGS__))		\
	{								\
		__u64 args[6] = {					\
			LANDLOCK_MAP(X, LANDLOCK_ARG_A, __VA_ARGS__)	\
		};							\
		return landlock_run_prog(args);				\
	}								\
	static inline bool bpf_landlock_##NAME##_is_valid_access(	\
			int off, int size, enum bpf_access_type type,	\
			enum bpf_reg_type *reg_type)			\
	{								\
		enum bpf_reg_type arg_types[6] = {			\
			LANDLOCK_MAP(X, LANDLOCK_ARG_D, __VA_ARGS__)	\
		};							\
		return __is_valid_access(off, size, type, reg_type, arg_types); \
	}								\
	static const struct bpf_verifier_ops bpf_landlock_##NAME##_ops = { \
		.get_func_proto	= bpf_landlock_func_proto,		\
		.is_valid_access = bpf_landlock_##NAME##_is_valid_access, \
		.convert_ctx_access = landlock_convert_ctx_access,	\
	};								\
	static struct bpf_prog_type_list bpf_landlock_##NAME##_type __read_mostly = { \
		.ops	= &bpf_landlock_##NAME##_ops,			\
		.type	= BPF_PROG_TYPE_LANDLOCK_##CNAME,		\
	};								\
	static int __init register_landlock_##NAME##_filter_ops(void)	\
	{								\
		bpf_register_prog_type(&bpf_landlock_##NAME##_type);	\
		return 0;						\
	}								\
	late_initcall(register_landlock_##NAME##_filter_ops);

#define LANDLOCK_HOOK1(NAME, ...) LANDLOCK_HOOKx(1, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK2(NAME, ...) LANDLOCK_HOOKx(2, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK3(NAME, ...) LANDLOCK_HOOKx(3, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK4(NAME, ...) LANDLOCK_HOOKx(4, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK5(NAME, ...) LANDLOCK_HOOKx(5, NAME, __VA_ARGS__)
#define LANDLOCK_HOOK6(NAME, ...) LANDLOCK_HOOKx(6, NAME, __VA_ARGS__)

#define LANDLOCK_MAP0(m,...)
#define LANDLOCK_MAP1(m,d,t,a) m(d,t,a)
#define LANDLOCK_MAP2(m,d,t,a,...) m(d,t,a), LANDLOCK_MAP1(m,__VA_ARGS__)
#define LANDLOCK_MAP3(m,d,t,a,...) m(d,t,a), LANDLOCK_MAP2(m,__VA_ARGS__)
#define LANDLOCK_MAP4(m,d,t,a,...) m(d,t,a), LANDLOCK_MAP3(m,__VA_ARGS__)
#define LANDLOCK_MAP5(m,d,t,a,...) m(d,t,a), LANDLOCK_MAP4(m,__VA_ARGS__)
#define LANDLOCK_MAP6(m,d,t,a,...) m(d,t,a), LANDLOCK_MAP5(m,__VA_ARGS__)
#define LANDLOCK_MAP(n,...) LANDLOCK_MAP##n(__VA_ARGS__)

#define LANDLOCK_ARG_D(d,t,a) d
#define LANDLOCK_ARG_TA(d,t,a) t a
#define LANDLOCK_ARG_A(d,t,a) (u64)a


static int landlock_run_prog(__u64 args[6])
{
	u32 cur_ret = 0, ret = 0;
	struct seccomp_landlock_ret *landlock_ret;
	struct seccomp_landlock_prog *prog;

	/* the hook ID is faked by landlock_convert_ctx_access() */
	struct landlock_data ctx = {
		.args[0] = args[0],
		.args[1] = args[1],
		.args[2] = args[2],
		.args[3] = args[3],
		.args[4] = args[4],
		.args[5] = args[5],
	};

	/* TODO: use lockless_dereference()? */
	/* run all the triggered Landlock programs */
	for (landlock_ret = current->seccomp.landlock_ret;
			landlock_ret; landlock_ret = landlock_ret->prev) {
		if (landlock_ret->triggered) {
			ctx.cookie = landlock_ret->cookie;
			for (prog = current->seccomp.landlock_prog;
					prog; prog = prog->prev) {
				if (prog->filter == landlock_ret->filter) {
					cur_ret = BPF_PROG_RUN(prog->prog, (void *)&ctx);
					break;
				}
			}
			if (!ret) {
				/* check errno to not mess with kernel code */
				if (cur_ret > _ERRNO_LAST)
					ret = EPERM;
				else
					ret = cur_ret;
			}
		}
	}
	return -ret;
}

static const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_landlock_cmp_fs_prop_with_struct_file:
		return &bpf_landlock_cmp_fs_prop_with_struct_file_proto;
	case BPF_FUNC_landlock_cmp_fs_beneath_with_struct_file:
		return &bpf_landlock_cmp_fs_beneath_with_struct_file_proto;
	case BPF_FUNC_landlock_cmp_cgroup_beneath:
#ifdef CONFIG_CGROUPS
		return &bpf_landlock_cmp_cgroup_beneath_proto;
#endif	/* CONFIG_CGROUPS */
	default:
		return NULL;
	}
}

static u32 landlock_convert_ctx_access(enum bpf_access_type type, int dst_reg,
				      int src_reg, int ctx_off,
				      struct bpf_insn *insn_buf,
				      struct bpf_prog *prog)
{
	struct bpf_insn *insn = insn_buf;

	/* only handle 32-bit values */
	switch (ctx_off) {
	case offsetof(struct landlock_data, hook):
		*insn++ = BPF_MOV32_IMM(dst_reg, prog->type);
		break;
	default:
		return 1;
	}

	return insn - insn_buf;
}

static bool __is_valid_access(int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, enum bpf_reg_type arg_types[6])
{
	int arg_nb, expected_size;

	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct landlock_data))
		return false;

	switch (off) {
	case offsetof(struct landlock_data, cookie):
		expected_size = sizeof(__u16);
		break;
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

	/* check pointer type */
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
	PTR_TO_STRUCT_FILE, struct file *, file,
	PTR_TO_STRUCT_CRED, const struct cred *, cred
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

void __init landlock_add_hooks(void)
{
	pr_info("landlock: Becoming ready for sandboxing\n");
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks));
}
