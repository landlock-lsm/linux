#ifndef _LINUX_SECCOMP_H
#define _LINUX_SECCOMP_H

#include <uapi/linux/seccomp.h>

#define SECCOMP_FILTER_FLAG_MASK	(SECCOMP_FILTER_FLAG_TSYNC)

#ifdef CONFIG_SECCOMP

#include <linux/thread_info.h>
#include <asm/seccomp.h>
#include <linux/path.h>

struct seccomp_filter;
struct seccomp_filter_checker_group;
struct seccomp_argeval_checked;
struct seccomp_argeval_cache;
struct seccomp_argeval_syscall;

/**
 * struct seccomp - the state of a seccomp'ed process
 *
 * @mode:  indicates one of the valid values above for controlled
 *         system calls available to a process.
 * @filter: must always point to a valid seccomp-filter or NULL as it is
 *          accessed without locking during system call entry.
 *
 * @checker_group: an append-only list of argument checkers usable by filters
 *                 created after the last update.
 *
 *          @filter must only be accessed from the context of current as there
 *          is no read locking.
 */
struct seccomp {
	int mode;
	struct seccomp_filter *filter;

#ifdef CONFIG_SECURITY_SECCOMP
	/* @checker_group is only used for filter creation and unique per thread */
	struct seccomp_filter_checker_group *checker_group;

	/* syscall-lifetime data */
	struct seccomp_argeval_checked *arg_checked;
	struct seccomp_argeval_cache *arg_cache;
	struct seccomp_argeval_syscall *orig_syscall;
#endif
};

#ifdef CONFIG_HAVE_ARCH_SECCOMP_FILTER
extern int __secure_computing(void);
static inline int secure_computing(void)
{
	if (unlikely(test_thread_flag(TIF_SECCOMP)))
		return  __secure_computing();
	return 0;
}

#define SECCOMP_PHASE1_OK	0
#define SECCOMP_PHASE1_SKIP	1

extern u32 seccomp_phase1(struct seccomp_data *sd);
int seccomp_phase2(u32 phase1_result);
#else
extern void secure_computing_strict(int this_syscall);
#endif

extern long prctl_get_seccomp(void);
extern long prctl_set_seccomp(unsigned long, char __user *);

static inline int seccomp_mode(struct seccomp *s)
{
	return s->mode;
}

#else /* CONFIG_SECCOMP */

#include <linux/errno.h>

struct seccomp { };
struct seccomp_filter { };

#ifdef CONFIG_HAVE_ARCH_SECCOMP_FILTER
static inline int secure_computing(void) { return 0; }
#else
static inline void secure_computing_strict(int this_syscall) { return; }
#endif

static inline long prctl_get_seccomp(void)
{
	return -EINVAL;
}

static inline long prctl_set_seccomp(unsigned long arg2, char __user *arg3)
{
	return -EINVAL;
}

static inline int seccomp_mode(struct seccomp *s)
{
	return SECCOMP_MODE_DISABLED;
}
#endif /* CONFIG_SECCOMP */

#ifdef CONFIG_SECCOMP_FILTER
extern void put_seccomp(struct task_struct *tsk);
extern void get_seccomp_filter(struct task_struct *tsk);

#ifdef CONFIG_SECURITY_SECCOMP
extern void flush_seccomp_cache(struct task_struct *tsk);

struct seccomp_filter_object_path {
	u32 flags;
	struct path path;
};

struct seccomp_filter_checker {
	/* e.g. SECCOMP_ARGCHECK_FS_LITERAL */
	u32 check;
	/* e.g. SECCOMP_ARGTYPE_PATH */
	u32 type;
	union {
		struct seccomp_filter_object_path object_path;
	};
};

/** seccomp_argrule_t - Argument rule matcher
 * e.g. seccomp_argrule_path_literal()
 * This prototype get the whole syscall argument picture to be able to get the
 * sementic from multiple arguments (e.g. pointer plus size of the pointed
 * data, which can indicated by @argrule).
 *
 * Return which arguments match @argdesc.
 *
 * @argdesc: Pointer to the argument type description.
 * @args: Pointer to an array of the (max) six arguments. Can use them thanks
 *	to @argdesc.
 * @to_check: Which arguments are asked to check; should at least have one to
 *	make sense.
 * @argrule: The rule to check on @args.
 */
typedef u8 seccomp_argrule_t(const u8(*argdesc)[6],
			     const u64(*args)[6], u8 to_check,
			     const struct seccomp_filter_checker *checker);

/* seccomp LSM */

seccomp_argrule_t *get_argrule_checker(u32 check);
struct syscall_argdesc *syscall_nr_to_argdesc(int nr);

/**
 * struct seccomp_argeval_cache_fs
 *
 * @hash_len: refer to the hashlen field from struct qstr.
 */
struct seccomp_argeval_cache_fs {
	struct path *path;
	u64 hash_len;
};

struct seccomp_argeval_history {
	/* @checker point to current.seccomp->checker_group->checkers[] */
	struct seccomp_filter_checker *checker;
	u8 asked;
	u8 result;
	struct seccomp_argeval_history *next;
};

/**
 * struct seccomp_argeval_cache_entry
 *
 * To be consistent with the filters checks, we only check the original
 * arguments but not those put by a tracer process, if any.
 *
 * Because the cache is uptr-oriented, it is possible to have the same dentry
 * in multiple cache entries (but with different uptr).
 */
struct seccomp_argeval_cache_entry {
	const void __user *uptr;
	u8 args;
	union {
		struct seccomp_argeval_cache_fs fs;
	};
	struct seccomp_argeval_cache_entry *next;
};

struct seccomp_argeval_cache {
	/* e.g. SECCOMP_ARGTYPE_PATH */
	u32 type;
	struct seccomp_argeval_cache_entry *entry;
	struct seccomp_argeval_cache *next;
};

/* Use get_argrule_checker() */
struct seccomp_argeval_checked {
	u32 check;
	struct seccomp_argeval_history *history;
	struct seccomp_argeval_checked *next;
};

void put_seccomp_filter_checker(struct seccomp_filter_checker *);

u8 seccomp_argrule_path(const u8(*)[6], const u64(*)[6], u8,
			const struct seccomp_filter_checker *);

long seccomp_set_argcheck_fs(const struct seccomp_checker *,
			     struct seccomp_filter_checker *);

/* Need to save syscall properties to be able to properly recheck the filters
 * even if the syscall and its arguments has been tampered by a tracer process.
 */
struct seccomp_argeval_syscall {
	int nr;
	u64 args[6];
};

#endif /* CONFIG_SECURITY_SECCOMP */

#else  /* CONFIG_SECCOMP_FILTER */
static inline void put_seccomp(struct task_struct *tsk)
{
	return;
}

static inline void get_seccomp_filter(struct task_struct *tsk)
{
	return;
}

#endif /* CONFIG_SECCOMP_FILTER */

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_CHECKPOINT_RESTORE)
extern long seccomp_get_filter(struct task_struct *task,
			       unsigned long filter_off, void __user *data);
#else
static inline long seccomp_get_filter(struct task_struct *task,
				      unsigned long n, void __user *data)
{
	return -EINVAL;
}
#endif /* CONFIG_SECCOMP_FILTER && CONFIG_CHECKPOINT_RESTORE */
#endif /* _LINUX_SECCOMP_H */
