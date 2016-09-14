#ifndef _LINUX_SECCOMP_H
#define _LINUX_SECCOMP_H

#include <uapi/linux/seccomp.h>

#define SECCOMP_FILTER_FLAG_MASK	(SECCOMP_FILTER_FLAG_TSYNC)

#ifdef CONFIG_SECCOMP

#include <linux/thread_info.h>
#include <asm/seccomp.h>

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_SECURITY_LANDLOCK)
#include <linux/landlock.h>
#endif /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */

/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @usage: reference count to manage the object lifetime.
 *         get/put helpers should be used when accessing an instance
 *         outside of a lifetime-guarded section.  In general, this
 *         is only needed for handling filters shared across tasks.
 * @prev: points to a previously installed, or inherited, filter
 * @prog: the BPF program to evaluate
 * @thread_prev: points to filters installed by the same thread
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @usage).
 */
struct seccomp_filter {
	atomic_t usage;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_SECURITY_LANDLOCK)
	struct seccomp_filter *thread_prev;
#endif /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */
};

/**
 * struct seccomp - the state of a seccomp'ed process
 *
 * @mode:  indicates one of the valid values above for controlled
 *         system calls available to a process.
 * @filter: must always point to a valid seccomp-filter or NULL as it is
 *          accessed without locking during system call entry.
 * @thread_filter: list of filters allowed to trigger an associated Landlock
 *                 hook via a RET_LANDLOCK; must walk through thread_prev.
 * @landlock_ret: one unique private list per thread storing the RET_LANDLOCK
 *                values of all filters.
 * @landlock_hooks: contains an array of Landlock programs.
 *
 *          @filter must only be accessed from the context of current as there
 *          is no read locking.
 */
struct seccomp {
	int mode;
	struct seccomp_filter *filter;

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_SECURITY_LANDLOCK)
	struct seccomp_filter *thread_filter;
	struct landlock_seccomp_ret *landlock_ret;
	struct landlock_hooks *landlock_hooks;
#endif /* CONFIG_SECCOMP_FILTER && CONFIG_SECURITY_LANDLOCK */
};

#ifdef CONFIG_HAVE_ARCH_SECCOMP_FILTER
extern int __secure_computing(const struct seccomp_data *sd);
static inline int secure_computing(const struct seccomp_data *sd)
{
	if (unlikely(test_thread_flag(TIF_SECCOMP)))
		return  __secure_computing(sd);
	return 0;
}
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
static inline int secure_computing(struct seccomp_data *sd) { return 0; }
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
extern void put_seccomp_filter(struct seccomp_filter *filter);
extern void get_seccomp_filter(struct task_struct *tsk);

#else  /* CONFIG_SECCOMP_FILTER */
static inline void put_seccomp(struct task_struct *tsk)
{
	return;
}

static void put_seccomp_filter(struct seccomp_filter *filter)
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
