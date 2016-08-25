#ifndef _LINUX_SECCOMP_H
#define _LINUX_SECCOMP_H

#include <uapi/linux/seccomp.h>

#define SECCOMP_FILTER_FLAG_MASK	(SECCOMP_FILTER_FLAG_TSYNC)

#ifdef CONFIG_SECCOMP

#include <linux/thread_info.h>
#include <asm/seccomp.h>

#ifdef CONFIG_SECURITY_LANDLOCK
#include <linux/bpf.h>	/* struct bpf_prog */
#endif /* CONFIG_SECURITY_LANDLOCK */

struct seccomp_filter;

#ifdef CONFIG_SECURITY_LANDLOCK
struct seccomp_landlock_ret {
	struct seccomp_landlock_ret *prev;
	/* @filter points to a @landlock_filter list */
	struct seccomp_filter *filter;
	u16 cookie;
	bool triggered;
};

struct seccomp_landlock_prog {
	atomic_t usage;
	struct seccomp_landlock_prog *prev;
	/*
	 * List of filters (through filter->landlock_prev) allowed to trigger
	 * this Landlock program.
	 */
	struct seccomp_filter *filter;
	struct bpf_prog *prog;
};
#endif /* CONFIG_SECURITY_LANDLOCK */

/**
 * struct seccomp - the state of a seccomp'ed process
 *
 * @mode:  indicates one of the valid values above for controlled
 *         system calls available to a process.
 * @filter: must always point to a valid seccomp-filter or NULL as it is
 *          accessed without locking during system call entry.
 * @landlock_filter: list of filters allowed to trigger an associated
 *                    Landlock hook via a RET_LANDLOCK.
 * @landlock_ret: stored values from a RET_LANDLOCK.
 * @landlock_prog: list of Landlock programs.
 *
 *          @filter must only be accessed from the context of current as there
 *          is no read locking.
 */
struct seccomp {
	int mode;
	struct seccomp_filter *filter;

#ifdef CONFIG_SECURITY_LANDLOCK
	struct seccomp_filter *landlock_filter;
	struct seccomp_landlock_ret *landlock_ret;
	struct seccomp_landlock_prog *landlock_prog;
#endif /* CONFIG_SECURITY_LANDLOCK */
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
#ifdef CONFIG_SECURITY_LANDLOCK
extern void put_landlock_ret(struct seccomp_landlock_ret *landlock_ret);
extern struct seccomp_landlock_ret *dup_landlock_ret(
		struct seccomp_landlock_ret *ret_orig);
#endif /* CONFIG_SECURITY_LANDLOCK */

#else  /* CONFIG_SECCOMP_FILTER */
static inline void put_seccomp(struct task_struct *tsk)
{
	return;
}

static inline void get_seccomp_filter(struct task_struct *tsk)
{
	return;
}

#ifdef CONFIG_SECURITY_LANDLOCK
static inline void put_landlock_ret(struct seccomp_landlock_ret *landlock_ret) {}
static inline struct seccomp_landlock_ret *dup_landlock_ret(
		struct seccomp_landlock_ret *ret_orig) {}
#endif /* CONFIG_SECURITY_LANDLOCK */

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
