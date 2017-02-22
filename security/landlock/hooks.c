/*
 * Landlock LSM - hooks
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/current.h>
#include <asm/processor.h> /* task_pt_regs() */
#include <asm/syscall.h> /* syscall_get_nr(), syscall_get_arch() */
#include <linux/bpf.h> /* enum bpf_access_type, struct landlock_context */
#include <linux/err.h> /* EPERM */
#include <linux/filter.h> /* struct bpf_prog, BPF_PROG_RUN() */
#include <linux/kernel.h> /* ARRAY_SIZE */
#include <linux/landlock.h> /* struct landlock_node */
#include <linux/lsm_hooks.h>
#include <linux/seccomp.h> /* struct seccomp_* */
#include <linux/stddef.h> /* offsetof */
#include <linux/types.h> /* uintptr_t */

/* permissions translation */
#include <linux/fs.h> /* MAY_* */
#include <linux/mman.h> /* PROT_* */

/* hook arguments */
#include <linux/cred.h>
#include <linux/dcache.h> /* struct dentry */
#include <linux/fs.h> /* struct inode, struct iattr */
#include <linux/mm_types.h> /* struct vm_area_struct */
#include <linux/mount.h> /* struct vfsmount */
#include <linux/path.h> /* struct path */
#include <linux/sched.h> /* struct task_struct */
#include <linux/time.h> /* struct timespec */


#include "common.h" /* get_index() */

#define CTX_ARG_NB 2

/* separators */
#define SEP_COMMA() ,
#define SEP_SPACE()
#define SEP_AND() &&

#define MAP2x1(s, m, x1, x2, ...) m(x1, x2)
#define MAP2x2(s, m, x1, x2, ...) m(x1, x2) s() MAP2x1(s, m, __VA_ARGS__)
#define MAP2x3(s, m, x1, x2, ...) m(x1, x2) s() MAP2x2(s, m, __VA_ARGS__)
#define MAP2x4(s, m, x1, x2, ...) m(x1, x2) s() MAP2x3(s, m, __VA_ARGS__)
#define MAP2x5(s, m, x1, x2, ...) m(x1, x2) s() MAP2x4(s, m, __VA_ARGS__)
#define MAP2x6(s, m, x1, x2, ...) m(x1, x2) s() MAP2x5(s, m, __VA_ARGS__)
#define MAP2x(n, ...) MAP2x##n(__VA_ARGS__)

#define MAP1x1(s, m, x1, ...) m(x1)
#define MAP1x2(s, m, x1, ...) m(x1) s() MAP1x1(s, m, __VA_ARGS__)
#define MAP1x(n, ...) MAP1x##n(__VA_ARGS__)

#define SKIP2x1(x1, x2, ...) __VA_ARGS__
#define SKIP2x2(x1, x2, ...) SKIP2x1(__VA_ARGS__)
#define SKIP2x3(x1, x2, ...) SKIP2x2(__VA_ARGS__)
#define SKIP2x4(x1, x2, ...) SKIP2x3(__VA_ARGS__)
#define SKIP2x5(x1, x2, ...) SKIP2x4(__VA_ARGS__)
#define SKIP2x6(x1, x2, ...) SKIP2x5(__VA_ARGS__)
#define SKIP2x(n, ...) SKIP2x##n(__VA_ARGS__)

/* LSM hook argument helpers */
#define MAP_HOOK_COMMA(n, ...) MAP2x(n, SEP_COMMA, __VA_ARGS__)

#define GET_HOOK_TA(t, a) t a

/* Landlock event argument helpers  */
#define MAP_EVENT_COMMA(h, n, m, ...) MAP2x(n, SEP_COMMA, m, SKIP2x(h, __VA_ARGS__))
#define MAP_EVENT_SPACE(h, n, m, ...) MAP2x(n, SEP_SPACE, m, SKIP2x(h, __VA_ARGS__))
#define MAP_EVENT_AND(h, n, m, ...) MAP2x(n, SEP_AND, m, SKIP2x(h, __VA_ARGS__))

#define GET_CMD(h, n, ...) SKIP2x(n, SKIP2x(h, __VA_ARGS__))

#define EXPAND_TYPE(d) d##_TYPE
#define EXPAND_BPF(d) d##_BPF
#define EXPAND_C(d) d##_C

#define GET_TYPE_BPF(t) EXPAND_BPF(t)
#define GET_TYPE_C(t) EXPAND_C(t) *

#define GET_EVENT_C(d, a) GET_TYPE_C(EXPAND_TYPE(d))
#define GET_EVENT_U64(d, a) ((u64)(d##_VAL(a)))
#define GET_EVENT_DEC(d, a) d##_DEC(a)
#define GET_EVENT_OK(d, a) d##_OK(a)


/**
 * HOOK_ACCESS
 *
 * @EVENT: Landlock event name
 * @NA: number of event arguments
 *
 * The __consistent_##EVENT() extern functions and __wrapcheck_* types are
 * useful to catch inconsistencies in LSM hook definitions thanks to the
 * compiler type checking.
 */
#define HOOK_ACCESS(EVENT, NA, ...) \
	static inline bool __is_valid_access_event_##EVENT(		\
			int off, int size, enum bpf_access_type type,	\
			enum bpf_reg_type *reg_type,			\
			union bpf_prog_subtype *prog_subtype)		\
	{								\
		enum bpf_reg_type _ctx_types[CTX_ARG_NB] = {		\
			MAP1x(NA, SEP_COMMA, GET_TYPE_BPF, __VA_ARGS__)	\
		};							\
		return __is_valid_access(off, size, type, reg_type,	\
				_ctx_types, prog_subtype);		\
	}								\
	extern void __consistent_##EVENT(				\
			MAP1x(NA, SEP_COMMA, GET_TYPE_C, __VA_ARGS__));

/**
 * HOOK_NEW
 *
 * @INST: event instance for this hook
 * @EVENT: Landlock event name
 * @NE: number of event arguments
 * @HOOK: LSM hook name
 * @NH: number of hook arguments
 */
#define HOOK_NEW(INST, EVENT, NE, HOOK, NH, ...)			\
	static int landlock_hook_##EVENT##_##HOOK##_##INST(		\
			MAP_HOOK_COMMA(NH, GET_HOOK_TA, __VA_ARGS__))	\
	{								\
		if (!landlock_used())					\
			return 0;					\
		if (!(MAP_EVENT_AND(NH, NE, GET_EVENT_OK,		\
						__VA_ARGS__)))		\
			return 0;					\
		{							\
		MAP_EVENT_SPACE(NH, NE, GET_EVENT_DEC, __VA_ARGS__)	\
		__u64 _ctx_values[CTX_ARG_NB] = {			\
			MAP_EVENT_COMMA(NH, NE, GET_EVENT_U64,		\
					__VA_ARGS__)			\
		};							\
		u32 _cmd = GET_CMD(NH, NE, __VA_ARGS__);		\
		return landlock_decide(LANDLOCK_SUBTYPE_EVENT_##EVENT,	\
				_ctx_values, _cmd, #HOOK);		\
		}							\
	}								\
	extern void __consistent_##EVENT(MAP_EVENT_COMMA(		\
				NH, NE, GET_EVENT_C, __VA_ARGS__));

#define HOOK_NEW_FS(...) HOOK_NEW(1, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS2(...) HOOK_NEW(2, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS3(...) HOOK_NEW(3, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS4(...) HOOK_NEW(4, FS, 2, __VA_ARGS__, 0)
#define HOOK_NEW_FS_CMD(...) HOOK_NEW(1, FS, 2, __VA_ARGS__)
#define HOOK_INIT_FS(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_1)
#define HOOK_INIT_FS2(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_2)
#define HOOK_INIT_FS3(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_3)
#define HOOK_INIT_FS4(HOOK) LSM_HOOK_INIT(HOOK, landlock_hook_FS_##HOOK##_4)

/*
 * The WRAP_TYPE_* definitions group the bpf_reg_type enum value and the C
 * type. This C type may remains unused except to catch inconsistencies in LSM
 * hook definitions thanks to the compiler type checking.
 */

/* WRAP_TYPE_NONE */
#define WRAP_TYPE_NONE_BPF	NOT_INIT
#define WRAP_TYPE_NONE_C	struct __wrapcheck_none
WRAP_TYPE_NONE_C;

/* WRAP_TYPE_RAW */
#define WRAP_TYPE_RAW_BPF	UNKNOWN_VALUE
#define WRAP_TYPE_RAW_C		struct __wrapcheck_raw
WRAP_TYPE_RAW_C;

/* WRAP_TYPE_FS */
#define WRAP_TYPE_FS_BPF	CONST_PTR_TO_HANDLE_FS
#define WRAP_TYPE_FS_C		const struct bpf_handle_fs

/*
 * The WRAP_ARG_* definitions group the LSM hook argument type (C and BPF), the
 * wrapping struct declaration (if any) and the value to copy to the BPF
 * context. This definitions may be used thanks to the EXPAND_* helpers.
 *
 * *_OK: Can we handle the argument?
 */

/* WRAP_ARG_NONE */
#define WRAP_ARG_NONE_TYPE	WRAP_TYPE_NONE
#define WRAP_ARG_NONE_DEC(arg)
#define WRAP_ARG_NONE_VAL(arg)	0
#define WRAP_ARG_NONE_OK(arg)	(!WARN_ON(true))

/* WRAP_ARG_RAW */
#define WRAP_ARG_RAW_TYPE	WRAP_TYPE_RAW
#define WRAP_ARG_RAW_DEC(arg)
#define WRAP_ARG_RAW_VAL(arg)	arg
#define WRAP_ARG_RAW_OK(arg)	(true)

/* WRAP_ARG_FILE */
#define WRAP_ARG_FILE_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_FILE_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_FILE, .file = arg };
#define WRAP_ARG_FILE_VAL(arg)	(uintptr_t)&wrap_##arg
#define WRAP_ARG_FILE_OK(arg)	(arg)

/* WRAP_ARG_VMAF */
#define WRAP_ARG_VMAF_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_VMAF_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_FILE, .file = arg->vm_file };
#define WRAP_ARG_VMAF_VAL(arg)	(uintptr_t)&wrap_##arg
#define WRAP_ARG_VMAF_OK(arg)	(arg && arg->vm_file)

/* WRAP_ARG_INODE */
#define WRAP_ARG_INODE_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_INODE_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_INODE, .inode = arg };
#define WRAP_ARG_INODE_VAL(arg)	(uintptr_t)&wrap_##arg
#define WRAP_ARG_INODE_OK(arg)	(arg)

/* WRAP_ARG_PATH */
#define WRAP_ARG_PATH_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_PATH_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_PATH, .path = arg };
#define WRAP_ARG_PATH_VAL(arg)	(uintptr_t)&wrap_##arg
#define WRAP_ARG_PATH_OK(arg)	(arg)

/* WRAP_ARG_DENTRY */
#define WRAP_ARG_DENTRY_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_DENTRY_DEC(arg)				\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_DENTRY, .dentry = arg };
#define WRAP_ARG_DENTRY_VAL(arg)	(uintptr_t)&wrap_##arg
#define WRAP_ARG_DENTRY_OK(arg)	(arg)

/* WRAP_ARG_SB */
#define WRAP_ARG_SB_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_SB_DEC(arg)					\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_DENTRY, .dentry = arg->s_root };
#define WRAP_ARG_SB_VAL(arg)	(uintptr_t)&wrap_##arg
#define WRAP_ARG_SB_OK(arg)	(arg && arg->s_root)

/* WRAP_ARG_MNTROOT */
#define WRAP_ARG_MNTROOT_TYPE	WRAP_TYPE_FS
#define WRAP_ARG_MNTROOT_DEC(arg)				\
	EXPAND_C(WRAP_TYPE_FS) wrap_##arg =			\
	{ .type = BPF_HANDLE_FS_TYPE_DENTRY, .dentry = arg->mnt_root };
#define WRAP_ARG_MNTROOT_VAL(arg)	(uintptr_t)&wrap_##arg
#define WRAP_ARG_MNTROOT_OK(arg)	(arg && arg->mnt_root)


static inline u64 fs_may_to_access(int fs_may)
{
	u64 ret = 0;

	if (fs_may & MAY_EXEC)
		ret |= LANDLOCK_ACTION_FS_EXEC;
	if (fs_may & MAY_READ)
		ret |= LANDLOCK_ACTION_FS_READ;
	if (fs_may & MAY_WRITE)
		ret |= LANDLOCK_ACTION_FS_WRITE;
	if (fs_may & MAY_APPEND)
		ret |= LANDLOCK_ACTION_FS_WRITE;
	if (fs_may & MAY_OPEN)
		ret |= LANDLOCK_ACTION_FS_GET;
	/* ignore MAY_CHDIR and MAY_ACCESS */

	return ret;
}

static u64 mem_prot_to_access(unsigned long prot, bool private)
{
	u64 ret = 0;

	/* private mapping do not write to files */
	if (!private && (prot & PROT_WRITE))
		ret |= LANDLOCK_ACTION_FS_WRITE;
	if (prot & PROT_READ)
		ret |= LANDLOCK_ACTION_FS_READ;
	if (prot & PROT_EXEC)
		ret |= LANDLOCK_ACTION_FS_EXEC;

	return ret;
}

static inline bool landlock_used(void)
{
#ifdef CONFIG_SECCOMP_FILTER
	return !!(current->seccomp.landlock_events);
#else
	return false;
#endif /* CONFIG_SECCOMP_FILTER */
}

/**
 * landlock_run_prog - run Landlock program for a syscall
 *
 * @event_idx: event index in the rules array
 * @ctx: non-NULL eBPF context
 * @events: Landlock events pointer
 */
static int landlock_run_prog(u32 event_idx, const struct landlock_context *ctx,
		struct landlock_events *events)
{
	struct landlock_node *node;

	if (!events)
		return 0;

	for (node = events->nodes[event_idx]; node; node = node->prev) {
		struct landlock_rule *rule;

		for (rule = node->rule; rule; rule = rule->prev) {
			u32 ret;

			if (WARN_ON(!rule->prog))
				continue;
			rcu_read_lock();
			ret = BPF_PROG_RUN(rule->prog, (void *)ctx);
			rcu_read_unlock();
			if (ret)
				return -EPERM;
		}
	}
	return 0;
}

static int landlock_decide(enum landlock_subtype_event event,
		__u64 ctx_values[CTX_ARG_NB], u32 cmd, const char *hook)
{
	int ret = 0;
	u32 event_idx = get_index(event);

	struct landlock_context ctx = {
		.status = 0,
		.arch = syscall_get_arch(),
		.syscall_nr = syscall_get_nr(current, task_pt_regs(current)),
		.syscall_cmd = cmd,
		.event = event,
		.arg1 = ctx_values[0],
		.arg2 = ctx_values[1],
	};

#ifdef CONFIG_SECCOMP_FILTER
	ret = landlock_run_prog(event_idx, &ctx,
			current->seccomp.landlock_events);
#endif /* CONFIG_SECCOMP_FILTER */

	return ret;
}

static bool __is_valid_access(int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type,
		enum bpf_reg_type ctx_types[CTX_ARG_NB],
		union bpf_prog_subtype *prog_subtype)
{
	int max_size;

	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct landlock_context))
		return false;
	if (size <= 0 || size > sizeof(__u64))
		return false;

	/* set max size */
	switch (off) {
	case offsetof(struct landlock_context, arch):
	case offsetof(struct landlock_context, syscall_nr):
	case offsetof(struct landlock_context, syscall_cmd):
	case offsetof(struct landlock_context, event):
		max_size = sizeof(__u32);
		break;
	case offsetof(struct landlock_context, status):
	case offsetof(struct landlock_context, arg1):
	case offsetof(struct landlock_context, arg2):
		max_size = sizeof(__u64);
		break;
	default:
		return false;
	}

	/* set register type */
	switch (off) {
	case offsetof(struct landlock_context, arg1):
		*reg_type = ctx_types[0];
		break;
	case offsetof(struct landlock_context, arg2):
		*reg_type = ctx_types[1];
		break;
	default:
		*reg_type = UNKNOWN_VALUE;
	}

	/* check memory range access */
	switch (*reg_type) {
	case NOT_INIT:
		return false;
	case UNKNOWN_VALUE:
	case CONST_IMM:
		/* allow partial raw value */
		if (size > max_size)
			return false;
		break;
	default:
		/* deny partial pointer */
		if (size != max_size)
			return false;
	}

	return true;
}


/* hook definitions */

HOOK_ACCESS(FS, 2, WRAP_TYPE_FS, WRAP_TYPE_RAW);

/* binder_* hooks */

HOOK_NEW_FS(binder_transfer_file, 3,
	struct task_struct *, from,
	struct task_struct *, to,
	struct file *, file,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

/* sb_* hooks */

HOOK_NEW_FS(sb_statfs, 1,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

/*
 * Being able to mount on a path means being able to override the underlying
 * filesystem view of this path, hence the need for a write access right.
 */
HOOK_NEW_FS(sb_mount, 5,
	const char *, dev_name,
	const struct path *, path,
	const char *, type,
	unsigned long, flags,
	void *, data,
	WRAP_ARG_PATH, path,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(sb_remount, 2,
	struct super_block *, sb,
	void *, data,
	WRAP_ARG_SB, sb,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(sb_umount, 2,
	struct vfsmount *, mnt,
	int, flags,
	WRAP_ARG_MNTROOT, mnt,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

/*
 * The old_path is similar to a destination mount point.
 */
HOOK_NEW_FS(sb_pivotroot, 2,
	const struct path *, old_path,
	const struct path *, new_path,
	WRAP_ARG_PATH, old_path,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

/* inode_* hooks */

/* a directory inode contains only one dentry */
HOOK_NEW_FS(inode_create, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_create, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_link, 3,
	struct dentry *, old_dentry,
	struct inode *, dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, old_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS2(inode_link, 3,
	struct dentry *, old_dentry,
	struct inode *, dir,
	struct dentry *, new_dentry,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS3(inode_link, 3,
	struct dentry *, old_dentry,
	struct inode *, dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, new_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_unlink, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_unlink, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_REMOVE
);

HOOK_NEW_FS(inode_symlink, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	const char *, old_name,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_symlink, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	const char *, old_name,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_mkdir, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_mkdir, 3,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_rmdir, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_rmdir, 2,
	struct inode *, dir,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_REMOVE
);

HOOK_NEW_FS(inode_mknod, 4,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	dev_t, dev,
	WRAP_ARG_INODE, dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_mknod, 4,
	struct inode *, dir,
	struct dentry *, dentry,
	umode_t, mode,
	dev_t, dev,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_INODE, old_dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS2(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, old_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_REMOVE
);

HOOK_NEW_FS3(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_INODE, new_dir,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS4(inode_rename, 4,
	struct inode *, old_dir,
	struct dentry *, old_dentry,
	struct inode *, new_dir,
	struct dentry *, new_dentry,
	WRAP_ARG_DENTRY, new_dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_NEW
);

HOOK_NEW_FS(inode_readlink, 1,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

// XXX: handle inode?
HOOK_NEW_FS(inode_follow_link, 3,
	struct dentry *, dentry,
	struct inode *, inode,
	bool, rcu,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_permission, 2,
	struct inode *, inode,
	int, mask,
	WRAP_ARG_INODE, inode,
	WRAP_ARG_RAW, fs_may_to_access(mask)
);

HOOK_NEW_FS(inode_setattr, 2,
	struct dentry *, dentry,
	struct iattr *, attr,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(inode_getattr, 1,
	const struct path *, path,
	WRAP_ARG_PATH, path,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_setxattr, 5,
	struct dentry *, dentry,
	const char *, name,
	const void *, value,
	size_t, size,
	int, flags,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(inode_getxattr, 2,
	struct dentry *, dentry,
	const char *, name,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_listxattr, 1,
	struct dentry *, dentry,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_removexattr, 2,
	struct dentry *, dentry,
	const char *, name,
	WRAP_ARG_DENTRY, dentry,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

HOOK_NEW_FS(inode_getsecurity, 4,
	struct inode *, inode,
	const char *, name,
	void **, buffer,
	bool, alloc,
	WRAP_ARG_INODE, inode,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_READ
);

HOOK_NEW_FS(inode_setsecurity, 5,
	struct inode *, inode,
	const char *, name,
	const void *, value,
	size_t, size,
	int, flag,
	WRAP_ARG_INODE, inode,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_WRITE
);

/* file_* hooks */

HOOK_NEW_FS(file_permission, 2,
	struct file *, file,
	int, mask,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, fs_may_to_access(mask)
);

/*
 * An ioctl command can be a read or a write. This can be checked with _IOC*()
 * for some commands but a Landlock rule should check the ioctl command to
 * whitelist them.
 */
HOOK_NEW_FS_CMD(file_ioctl, 3,
	struct file *, file,
	unsigned int, cmd,
	unsigned long, arg,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_IOCTL,
	cmd
);

HOOK_NEW_FS_CMD(file_lock, 2,
	struct file *, file,
	unsigned int, cmd,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_LOCK,
	cmd
);

HOOK_NEW_FS_CMD(file_fcntl, 3,
	struct file *, file,
	unsigned int, cmd,
	unsigned long, arg,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_FCNTL,
	cmd
);

HOOK_NEW_FS(mmap_file, 4,
	struct file *, file,
	unsigned long, reqprot,
	unsigned long, prot,
	unsigned long, flags,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, mem_prot_to_access(prot, flags & MAP_PRIVATE)
);

HOOK_NEW_FS(file_mprotect, 3,
	struct vm_area_struct *, vma,
	unsigned long, reqprot,
	unsigned long, prot,
	WRAP_ARG_VMAF, vma,
	WRAP_ARG_RAW, mem_prot_to_access(prot, !(vma->vm_flags & VM_SHARED))
);

HOOK_NEW_FS(file_receive, 1,
	struct file *, file,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_GET
);

HOOK_NEW_FS(file_open, 2,
	struct file *, file,
	const struct cred *, cred,
	WRAP_ARG_FILE, file,
	WRAP_ARG_RAW, LANDLOCK_ACTION_FS_GET
);

static struct security_hook_list landlock_hooks[] = {
	HOOK_INIT_FS(binder_transfer_file),

	HOOK_INIT_FS(sb_statfs),
	HOOK_INIT_FS(sb_mount),
	HOOK_INIT_FS(sb_remount),
	HOOK_INIT_FS(sb_umount),
	HOOK_INIT_FS(sb_pivotroot),

	HOOK_INIT_FS(inode_create),
	HOOK_INIT_FS2(inode_create),
	HOOK_INIT_FS(inode_link),
	HOOK_INIT_FS2(inode_link),
	HOOK_INIT_FS3(inode_link),
	HOOK_INIT_FS(inode_unlink),
	HOOK_INIT_FS2(inode_unlink),
	HOOK_INIT_FS(inode_symlink),
	HOOK_INIT_FS2(inode_symlink),
	HOOK_INIT_FS(inode_mkdir),
	HOOK_INIT_FS2(inode_mkdir),
	HOOK_INIT_FS(inode_rmdir),
	HOOK_INIT_FS2(inode_rmdir),
	HOOK_INIT_FS(inode_mknod),
	HOOK_INIT_FS2(inode_mknod),
	HOOK_INIT_FS(inode_rename),
	HOOK_INIT_FS2(inode_rename),
	HOOK_INIT_FS3(inode_rename),
	HOOK_INIT_FS4(inode_rename),
	HOOK_INIT_FS(inode_readlink),
	HOOK_INIT_FS(inode_follow_link),
	HOOK_INIT_FS(inode_permission),
	HOOK_INIT_FS(inode_setattr),
	HOOK_INIT_FS(inode_getattr),
	HOOK_INIT_FS(inode_setxattr),
	HOOK_INIT_FS(inode_getxattr),
	HOOK_INIT_FS(inode_listxattr),
	HOOK_INIT_FS(inode_removexattr),
	HOOK_INIT_FS(inode_getsecurity),
	HOOK_INIT_FS(inode_setsecurity),

	HOOK_INIT_FS(file_permission),
	HOOK_INIT_FS(file_ioctl),
	HOOK_INIT_FS(file_lock),
	HOOK_INIT_FS(file_fcntl),
	HOOK_INIT_FS(mmap_file),
	HOOK_INIT_FS(file_mprotect),
	HOOK_INIT_FS(file_receive),
	HOOK_INIT_FS(file_open),
};

static inline bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, enum bpf_reg_type *reg_type,
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_subtype_event event = prog_subtype->landlock_rule.event;

	switch (event) {
	case LANDLOCK_SUBTYPE_EVENT_FS:
		return __is_valid_access_event_FS(off, size, type, reg_type,
				prog_subtype);
	case LANDLOCK_SUBTYPE_EVENT_UNSPEC:
	default:
		return false;
	}
}

static inline bool bpf_landlock_is_valid_subtype(
		union bpf_prog_subtype *prog_subtype)
{
	enum landlock_subtype_event event = prog_subtype->landlock_rule.event;

	switch (event) {
	case LANDLOCK_SUBTYPE_EVENT_FS:
		break;
	case LANDLOCK_SUBTYPE_EVENT_UNSPEC:
	default:
		return false;
	}
	if (!prog_subtype->landlock_rule.version ||
			prog_subtype->landlock_rule.version > LANDLOCK_VERSION)
		return false;
	if (!prog_subtype->landlock_rule.event ||
			prog_subtype->landlock_rule.event > _LANDLOCK_SUBTYPE_EVENT_LAST)
		return false;
	if (prog_subtype->landlock_rule.ability & ~_LANDLOCK_SUBTYPE_ABILITY_MASK)
		return false;
	if (prog_subtype->landlock_rule.option & ~_LANDLOCK_SUBTYPE_OPTION_MASK)
		return false;

	/* check ability flags */
	if (prog_subtype->landlock_rule.ability & LANDLOCK_SUBTYPE_ABILITY_WRITE &&
			!capable(CAP_SYS_ADMIN))
		return false;
	if (prog_subtype->landlock_rule.ability & LANDLOCK_SUBTYPE_ABILITY_DEBUG &&
			!capable(CAP_SYS_ADMIN))
		return false;

	return true;
}

static inline const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id, union bpf_prog_subtype *prog_subtype)
{
	bool event_fs = (prog_subtype->landlock_rule.event ==
			LANDLOCK_SUBTYPE_EVENT_FS);
	bool ability_write = !!(prog_subtype->landlock_rule.ability &
			LANDLOCK_SUBTYPE_ABILITY_WRITE);
	bool ability_debug = !!(prog_subtype->landlock_rule.ability &
			LANDLOCK_SUBTYPE_ABILITY_DEBUG);

	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;

	/* event_fs */
	case BPF_FUNC_handle_fs_get_mode:
		if (event_fs)
			return &bpf_handle_fs_get_mode_proto;
		return NULL;

	/* ability_write */
	case BPF_FUNC_map_delete_elem:
		if (ability_write)
			return &bpf_map_delete_elem_proto;
		return NULL;
	case BPF_FUNC_map_update_elem:
		if (ability_write)
			return &bpf_map_update_elem_proto;
		return NULL;

	/* ability_debug */
	case BPF_FUNC_get_current_comm:
		if (ability_debug)
			return &bpf_get_current_comm_proto;
		return NULL;
	case BPF_FUNC_get_current_pid_tgid:
		if (ability_debug)
			return &bpf_get_current_pid_tgid_proto;
		return NULL;
	case BPF_FUNC_get_current_uid_gid:
		if (ability_debug)
			return &bpf_get_current_uid_gid_proto;
		return NULL;
	case BPF_FUNC_trace_printk:
		if (ability_debug)
			return bpf_get_trace_printk_proto();
		return NULL;

	default:
		return NULL;
	}
}

static const struct bpf_verifier_ops bpf_landlock_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
	.is_valid_subtype = bpf_landlock_is_valid_subtype,
};

static struct bpf_prog_type_list bpf_landlock_type __ro_after_init = {
	.ops = &bpf_landlock_ops,
	.type = BPF_PROG_TYPE_LANDLOCK,
};

void __init landlock_add_hooks(void)
{
	pr_info("landlock: Version %u, ready to sandbox with %s\n",
			LANDLOCK_VERSION,
			"seccomp");
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks));
	bpf_register_prog_type(&bpf_landlock_type);
}
