/*
 * linux/kernel/seccomp.c
 *
 * Copyright 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 *
 * Copyright (C) 2012 Google, Inc.
 * Will Drewry <wad@chromium.org>
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This defines a simple but solid secure-computing facility.
 *
 * Mode 1 uses a fixed list of allowed system calls.
 * Mode 2 allows user-defined system call filters in the form
 *        of Berkeley Packet Filters/Linux Socket Filters.
 */

#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <linux/bitops.h>	/* BIT_ULL() */
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/namei.h>	/* user_lpath*() path_put() */
#include <linux/path.h>

#ifdef CONFIG_HAVE_ARCH_SECCOMP_FILTER
#include <asm/syscall.h>
#endif

#ifdef CONFIG_SECCOMP_FILTER
#include <linux/filter.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/tracehook.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>	/* for arch_syscall_match_sym_name() overload */

#ifdef CONFIG_SECURITY_SECCOMP
#include <linux/kernel.h>	/* FIELD_SIZEOF() */

#ifdef CONFIG_COMPAT
/* struct seccomp_checker_group */
struct compat_seccomp_checker_group {
	__u8 version;
	__u8 id;
	unsigned int len;
	compat_uptr_t checkers;	/* const struct seccomp_checker (*)[] */
};

/* struct seccomp_checker */
struct compat_seccomp_checker {
	__u32 check;
	__u32 type;
	unsigned int len;
	compat_uptr_t checker;	/* const struct seccomp_object_path * */
};

extern struct syscall_argdesc (*compat_seccomp_syscalls_argdesc)[];
#endif /* CONFIG_COMPAT */

extern struct syscall_argdesc (*seccomp_syscalls_argdesc)[];
#endif /* CONFIG_SECURITY_SECCOMP */

/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @usage: reference count to manage the object lifetime.
 *         get/put helpers should be used when accessing an instance
 *         outside of a lifetime-guarded section.  In general, this
 *         is only needed for handling filters shared across tasks.
 * @prev: points to a previously installed, or inherited, filter
 * @len: the number of instructions in the program
 * @insnsi: the BPF program instructions to evaluate
 *
 * @checker_group: the list of argument checkers usable by a filter
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
#ifdef CONFIG_SECURITY_SECCOMP
	struct seccomp_filter_checker_group *checker_group;
#endif
};

/* Argument group attached to seccomp filters
 *
 * @usage keep track of the references
 * @prev link to the previous checker_group
 * @id is given by userland to easely check a filter statically and not
 *     leak data from the kernel
 * @checkers_len is the number of @checkers elements
 * @checkers contains the checkers
 *
 * seccomp_filter_checker_group checkers are organized in a tree linked via the
 * @prev pointer. For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter->checker_group, the most recently added argument
 * group. All filters created by a process share the argument groups created by
 * this process until the filter creation but they can not be changed. However,
 * multiple argument groups may share a @prev node, which results in a
 * unidirectional tree existing in memory. They are not inherited through
 * fork().
 */
#ifdef CONFIG_SECURITY_SECCOMP
struct seccomp_filter_checker_group {
	atomic_t usage;
	struct seccomp_filter_checker_group *prev;
	u8 id;
	unsigned int checkers_len;
	struct seccomp_filter_checker checkers[];
};
#endif /* CONFIG_SECURITY_SECCOMP */

/* Limit any path through the tree to 256KB worth of instructions. */
#define MAX_INSNS_PER_PATH ((1 << 18) / sizeof(struct sock_filter))

static void clean_seccomp_data(struct seccomp_data *sd)
{
	sd->is_valid_syscall = 0;
	sd->checker_group = 0;
	sd->arg_matches[0] = 0ULL;
	sd->arg_matches[1] = 0ULL;
	sd->arg_matches[2] = 0ULL;
	sd->arg_matches[3] = 0ULL;
	sd->arg_matches[4] = 0ULL;
	sd->arg_matches[5] = 0ULL;
}

/*
 * Endianness is explicitly ignored and left for BPF program authors to manage
 * as per the specific architecture.
 */
static void populate_seccomp_data(struct seccomp_data *sd)
{
	struct task_struct *task = current;
	struct pt_regs *regs = task_pt_regs(task);
	unsigned long args[6];

	sd->nr = syscall_get_nr(task, regs);
	sd->arch = syscall_get_arch();
	syscall_get_arguments(task, regs, 0, 6, args);
	sd->args[0] = args[0];
	sd->args[1] = args[1];
	sd->args[2] = args[2];
	sd->args[3] = args[3];
	sd->args[4] = args[4];
	sd->args[5] = args[5];
	sd->instruction_pointer = KSTK_EIP(task);
	clean_seccomp_data(sd);
}

/**
 *	seccomp_check_filter - verify seccomp filter code
 *	@filter: filter to verify
 *	@flen: length of filter
 *
 * Takes a previously checked filter (by bpf_check_classic) and
 * redirects all filter code that loads struct sk_buff data
 * and related data through seccomp_bpf_load.  It also
 * enforces length and alignment checking of those loads.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
static int seccomp_check_filter(struct sock_filter *filter, unsigned int flen)
{
	int pc;
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;
		u32 k = ftest->k;

		switch (code) {
		case BPF_LD | BPF_W | BPF_ABS:
			ftest->code = BPF_LDX | BPF_W | BPF_ABS;
			/* 32-bit aligned and not out of bounds. */
			if (k >= sizeof(struct seccomp_data) || k & 3)
				return -EINVAL;
			continue;
		case BPF_LD | BPF_W | BPF_LEN:
			ftest->code = BPF_LD | BPF_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		case BPF_LDX | BPF_W | BPF_LEN:
			ftest->code = BPF_LDX | BPF_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		/* Explicitly include allowed calls. */
		case BPF_RET | BPF_K:
		case BPF_RET | BPF_A:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_NEG:
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
		case BPF_MISC | BPF_TAX:
		case BPF_MISC | BPF_TXA:
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
		case BPF_ST:
		case BPF_STX:
		case BPF_JMP | BPF_JA:
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
			continue;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

#ifdef CONFIG_SECURITY_SECCOMP
seccomp_argrule_t *get_argrule_checker(u32 check)
{
	switch (check) {
	case SECCOMP_CHECK_FS_LITERAL:
	case SECCOMP_CHECK_FS_BENEATH:
		return seccomp_argrule_path;
	}
	return NULL;
}

struct syscall_argdesc *syscall_nr_to_argdesc(int nr)
{
	unsigned int nr_syscalls;
	struct syscall_argdesc (*seccomp_sa)[];

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		nr_syscalls = IA32_NR_syscalls;
		seccomp_sa = compat_seccomp_syscalls_argdesc;
	} else /* falls below */
#endif	/* CONFIG_COMPAT */
	{
		nr_syscalls = NR_syscalls;
		seccomp_sa = seccomp_syscalls_argdesc;
	}

	if (nr >= nr_syscalls || nr < 0)
		return NULL;
	if (unlikely(!seccomp_sa)) {
		WARN_ON(1);
		return NULL;
	}

	return &(*seccomp_sa)[nr];
}

/* Return a new empty history entry for the check type or NULL if ENOMEM */
static struct seccomp_argeval_history *new_argeval_history(u32 check)
{
	struct seccomp_argeval_checked **arg_checked;
	struct seccomp_argeval_history **history;
	bool found = false;

	/* Find the check type */
	arg_checked = &current->seccomp.arg_checked;
	while (*arg_checked) {
		if ((*arg_checked)->check == check) {
			found = true;
			break;
		}
		arg_checked = &(*arg_checked)->next;
	}
	if (!found) {
		*arg_checked = kmalloc(sizeof(**arg_checked), GFP_KERNEL);
		if (!*arg_checked)
			return NULL;
		(*arg_checked)->check = check;
		(*arg_checked)->history = NULL;
		(*arg_checked)->next = NULL;
	}

	/* Append to history */
	history = &(*arg_checked)->history;
	while (*history)
		history = &(*history)->next;
	*history = kzalloc(sizeof(**history), GFP_KERNEL);

	return *history;
}

/* Return the argument group address that match the group ID, or NULL
 * otherwise.
 */
static struct seccomp_filter_checker_group *seccomp_update_argrule_data(
		struct seccomp_filter *filter,
		struct seccomp_data *sd, u16 ret_data)
{
	int i, j;
	u8 match;
	struct seccomp_filter_checker_group *walker, *checker_group = NULL;
	const struct syscall_argdesc *argdesc;
	struct seccomp_filter_checker *checker;
	seccomp_argrule_t *engine;
	struct seccomp_argeval_history *history;

	const u8 group_id = ret_data & SECCOMP_RET_CHECKER_GROUP;
	const u8 to_check = (ret_data & SECCOMP_RET_ARG_MATCHES) >> 8;

	clean_seccomp_data(sd);

	/* Find the matching group in those accessible to this filter */
	for (walker = filter->checker_group; walker; walker = walker->prev) {
		if (walker->id == group_id) {
			checker_group = walker;
			break;
		}
	}
	if (!checker_group)
		return NULL;
	sd->checker_group = checker_group->id;

	argdesc = syscall_nr_to_argdesc(sd->nr);
	if (!argdesc)
		return checker_group;
	sd->is_valid_syscall = 1;

	for (i = 0; i < checker_group->checkers_len; i++) {
		checker = &checker_group->checkers[i];
		engine = get_argrule_checker(checker->check);
		if (engine) {
			match = (*engine)(&argdesc->args, &sd->args, to_check, checker);

			/* Append the results to be able to replay the checks */
			history = new_argeval_history(checker->check);
			if (!history) {
				/* XXX: return -ENOMEM somehow? */
				break;
			}
			history->checker = checker;
			history->asked = to_check;
			history->result = match;

			/* Store the matches after the history record */
			for (j = 0; j < 6; j++) {
				sd->arg_matches[j] |=
				    ((BIT_ULL(j) & match) >> j) << i;
			}
		}
	}
	return checker_group;
}

static void free_seccomp_argeval_cache_entry(u32 type,
					     struct seccomp_argeval_cache_entry
					     *entry)
{
	while (entry) {
		struct seccomp_argeval_cache_entry *freeme = entry;

		switch (type) {
		case SECCOMP_OBJTYPE_PATH:
			if (entry->fs.path) {
				/* Pointer checks done in path_put() */
				path_put(entry->fs.path);
				kfree(entry->fs.path);
			}
			break;
		default:
			WARN_ON(1);
		}
		entry = entry->next;
		kfree(freeme);
	}
}

static void free_seccomp_argeval_cache(struct seccomp_argeval_cache *arg_cache)
{
	while (arg_cache) {
		struct seccomp_argeval_cache *freeme = arg_cache;

		free_seccomp_argeval_cache_entry(arg_cache->type, arg_cache->entry);
		arg_cache = arg_cache->next;
		kfree(freeme);
	}
}

void flush_seccomp_cache(struct task_struct *tsk)
{
	free_seccomp_argeval_cache(tsk->seccomp.arg_cache);
	tsk->seccomp.arg_cache = NULL;
}

static void free_seccomp_argeval_history(struct seccomp_argeval_history *history)
{
	struct seccomp_argeval_history *walker = history;

	while (walker) {
		struct seccomp_argeval_history *freeme = walker;

		/* Must not free history->checker owned by
		 * current.seccomp->checker_group->checkers[]
		 */
		walker = walker->next;
		kfree(freeme);
	}
}

static void free_seccomp_argeval_checked(struct seccomp_argeval_checked *checked)
{
	struct seccomp_argeval_checked *walker = checked;

	while (walker) {
		struct seccomp_argeval_checked *freeme = walker;

		free_seccomp_argeval_history(walker->history);
		walker = walker->next;
		kfree(freeme);
	}
}

static inline void free_seccomp_argeval_syscall(struct seccomp_argeval_syscall *orig_syscall)
{
	kfree(orig_syscall);
}
#endif /* CONFIG_SECURITY_SECCOMP */

static void put_seccomp_filter(struct task_struct *tsk);

/**
 * seccomp_run_filters - evaluates all seccomp filters against @syscall
 * @syscall: number of the current system call
 *
 * Returns valid seccomp BPF response codes.
 */
static u32 seccomp_run_filters(struct seccomp_data *sd)
{
#ifdef CONFIG_SECURITY_SECCOMP
	struct seccomp_filter_checker_group *walker, *arg_match = NULL;
#endif
	struct seccomp_data sd_local;
	u32 ret = SECCOMP_RET_ALLOW;
	/* Make sure cross-thread synced filter points somewhere sane. */
	struct seccomp_filter *f =
			lockless_dereference(current->seccomp.filter);

	/* Ensure unexpected behavior doesn't result in failing open. */
	if (unlikely(WARN_ON(f == NULL)))
		return SECCOMP_RET_KILL;

	if (!sd) {
		populate_seccomp_data(&sd_local);
		sd = &sd_local;
	}
#ifdef CONFIG_SECURITY_SECCOMP
	/* Backup the current syscall and its arguments (used by the filters),
	 * to not be misled in the LSM checks by a potential ptrace setregs
	 * command.
	 */
	if (!current->seccomp.orig_syscall) {
		current->seccomp.orig_syscall =
		    kmalloc(sizeof(*current->seccomp.orig_syscall), GFP_KERNEL);
		if (!current->seccomp.orig_syscall)
			return SECCOMP_RET_KILL;
	}
	current->seccomp.orig_syscall->nr = sd->nr;
	current->seccomp.orig_syscall->args[0] = sd->args[0];
	current->seccomp.orig_syscall->args[1] = sd->args[1];
	current->seccomp.orig_syscall->args[2] = sd->args[2];
	current->seccomp.orig_syscall->args[3] = sd->args[3];
	current->seccomp.orig_syscall->args[4] = sd->args[4];
	current->seccomp.orig_syscall->args[5] = sd->args[5];

	/* Cleanup old (syscall-lifetime) history and cache */
	free_seccomp_argeval_checked(current->seccomp.arg_checked);
	current->seccomp.arg_checked = NULL;
	flush_seccomp_cache(current);
#endif

	/*
	 * All filters in the list are evaluated and the lowest BPF return
	 * value always takes priority (ignoring the DATA).
	 */
	for (; f; f = f->prev) {
		u32 cur_ret;

#ifdef CONFIG_SECURITY_SECCOMP
		if (arg_match) {
			bool found = false;

			/* Find if the argument group is accessible from this filter */
			for (walker = f->checker_group; walker; walker = walker->prev) {
				if (walker == arg_match) {
					found = true;
					break;
				}
			}
			if (!found)
				clean_seccomp_data(sd);
		}
#endif /* CONFIG_SECURITY_SECCOMP */
		cur_ret = BPF_PROG_RUN(f->prog, (void *)sd);

#ifdef CONFIG_SECURITY_SECCOMP
		/* Intermediate return values */
		if ((cur_ret & SECCOMP_RET_INTER) == SECCOMP_RET_ARGEVAL) {
			/* XXX: sd modification /!\ */
			arg_match = seccomp_update_argrule_data(f, sd,
					(cur_ret & SECCOMP_RET_DATA));
		} else if (arg_match) {
			clean_seccomp_data(sd);
			arg_match = NULL;
		}
#endif /* CONFIG_SECURITY_SECCOMP */

		if ((cur_ret & SECCOMP_RET_INTER) < (ret & SECCOMP_RET_ACTION))
			ret = cur_ret;
	}
#ifdef CONFIG_SECURITY_SECCOMP
	if (arg_match && sd != &sd_local)
		clean_seccomp_data(sd);
#endif /* CONFIG_SECURITY_SECCOMP */
	return ret;
}
#endif /* CONFIG_SECCOMP_FILTER */

static inline bool seccomp_may_assign_mode(unsigned long seccomp_mode)
{
	assert_spin_locked(&current->sighand->siglock);

	if (current->seccomp.mode && current->seccomp.mode != seccomp_mode)
		return false;

	return true;
}

static inline void seccomp_assign_mode(struct task_struct *task,
				       unsigned long seccomp_mode)
{
	assert_spin_locked(&task->sighand->siglock);

	task->seccomp.mode = seccomp_mode;
	/*
	 * Make sure TIF_SECCOMP cannot be set before the mode (and
	 * filter) is set.
	 */
	smp_mb__before_atomic();
	set_tsk_thread_flag(task, TIF_SECCOMP);
}

#ifdef CONFIG_SECCOMP_FILTER
/* Returns 1 if the parent is an ancestor of the child. */
static int is_ancestor(struct seccomp_filter *parent,
		       struct seccomp_filter *child)
{
	/* NULL is the root ancestor. */
	if (parent == NULL)
		return 1;
	for (; child; child = child->prev)
		if (child == parent)
			return 1;
	return 0;
}

/**
 * seccomp_can_sync_threads: checks if all threads can be synchronized
 *
 * Expects sighand and cred_guard_mutex locks to be held.
 *
 * Returns 0 on success, -ve on error, or the pid of a thread which was
 * either not in the correct seccomp mode or it did not have an ancestral
 * seccomp filter.
 */
static inline pid_t seccomp_can_sync_threads(void)
{
	struct task_struct *thread, *caller;

	BUG_ON(!mutex_is_locked(&current->signal->cred_guard_mutex));
	assert_spin_locked(&current->sighand->siglock);

	/* Validate all threads being eligible for synchronization. */
	caller = current;
	for_each_thread(caller, thread) {
		pid_t failed;

		/* Skip current, since it is initiating the sync. */
		if (thread == caller)
			continue;

		if (thread->seccomp.mode == SECCOMP_MODE_DISABLED ||
		    (thread->seccomp.mode == SECCOMP_MODE_FILTER &&
		     is_ancestor(thread->seccomp.filter,
				 caller->seccomp.filter)))
			continue;

		/* Return the first thread that cannot be synchronized. */
		failed = task_pid_vnr(thread);
		/* If the pid cannot be resolved, then return -ESRCH */
		if (unlikely(WARN_ON(failed == 0)))
			failed = -ESRCH;
		return failed;
	}

	return 0;
}

/**
 * seccomp_sync_threads: sets all threads to use current's filter
 *
 * Expects sighand and cred_guard_mutex locks to be held, and for
 * seccomp_can_sync_threads() to have returned success already
 * without dropping the locks.
 *
 */
static inline void seccomp_sync_threads(void)
{
	struct task_struct *thread, *caller;

	BUG_ON(!mutex_is_locked(&current->signal->cred_guard_mutex));
	assert_spin_locked(&current->sighand->siglock);

	/* Synchronize all threads. */
	caller = current;
	for_each_thread(caller, thread) {
		/* Skip current, since it needs no changes. */
		if (thread == caller)
			continue;

		/* Get a task reference for the new leaf node. */
		get_seccomp_filter(caller);
		/*
		 * Drop the task reference to the shared ancestor since
		 * current's path will hold a reference.  (This also
		 * allows a put before the assignment.)
		 */
		put_seccomp_filter(thread);
		smp_store_release(&thread->seccomp.filter,
				  caller->seccomp.filter);

		/*
		 * Don't let an unprivileged task work around
		 * the no_new_privs restriction by creating
		 * a thread that sets it up, enters seccomp,
		 * then dies.
		 */
		if (task_no_new_privs(caller))
			task_set_no_new_privs(thread);

		/*
		 * Opt the other thread into seccomp if needed.
		 * As threads are considered to be trust-realm
		 * equivalent (see ptrace_may_access), it is safe to
		 * allow one thread to transition the other.
		 */
		if (thread->seccomp.mode == SECCOMP_MODE_DISABLED)
			seccomp_assign_mode(thread, SECCOMP_MODE_FILTER);
	}
}

/**
 * seccomp_prepare_filter: Prepares a seccomp filter for use.
 * @fprog: BPF program to install
 *
 * Returns filter on success or an ERR_PTR on failure.
 */
static struct seccomp_filter *seccomp_prepare_filter(struct sock_fprog *fprog)
{
	struct seccomp_filter *sfilter;
	int ret;
	const bool save_orig = config_enabled(CONFIG_CHECKPOINT_RESTORE);

	if (fprog->len == 0 || fprog->len > BPF_MAXINSNS)
		return ERR_PTR(-EINVAL);

	BUG_ON(INT_MAX / fprog->len < sizeof(struct sock_filter));

	/*
	 * Installing a seccomp filter requires that the task has
	 * CAP_SYS_ADMIN in its namespace or be running with no_new_privs.
	 * This avoids scenarios where unprivileged tasks can affect the
	 * behavior of privileged children.
	 */
	if (!task_no_new_privs(current) &&
	    security_capable_noaudit(current_cred(), current_user_ns(),
				     CAP_SYS_ADMIN) != 0)
		return ERR_PTR(-EACCES);

	/* Allocate a new seccomp_filter */
	sfilter = kzalloc(sizeof(*sfilter), GFP_KERNEL | __GFP_NOWARN);
	if (!sfilter)
		return ERR_PTR(-ENOMEM);

	ret = bpf_prog_create_from_user(&sfilter->prog, fprog,
					seccomp_check_filter, save_orig);
	if (ret < 0) {
		kfree(sfilter);
		return ERR_PTR(ret);
	}

#ifdef CONFIG_SECURITY_SECCOMP
	sfilter->checker_group =
		lockless_dereference(current->seccomp.checker_group);
	if (sfilter->checker_group)
		atomic_inc(&sfilter->checker_group->usage);
#endif /* CONFIG_SECURITY_SECCOMP */

	atomic_set(&sfilter->usage, 1);

	return sfilter;
}

/**
 * seccomp_prepare_user_filter - prepares a user-supplied sock_fprog
 * @user_filter: pointer to the user data containing a sock_fprog.
 *
 * Returns 0 on success and non-zero otherwise.
 */
static struct seccomp_filter *
seccomp_prepare_user_filter(const char __user *user_filter)
{
	struct sock_fprog fprog;
	struct seccomp_filter *filter = ERR_PTR(-EFAULT);

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		struct compat_sock_fprog fprog32;
		if (copy_from_user(&fprog32, user_filter, sizeof(fprog32)))
			goto out;
		fprog.len = fprog32.len;
		fprog.filter = compat_ptr(fprog32.filter);
	} else /* falls through to the if below. */
#endif
	if (copy_from_user(&fprog, user_filter, sizeof(fprog)))
		goto out;
	filter = seccomp_prepare_filter(&fprog);
out:
	return filter;
}

/**
 * seccomp_attach_filter: validate and attach filter
 * @flags:  flags to change filter behavior
 * @filter: seccomp filter to add to the current process
 *
 * Caller must be holding current->sighand->siglock lock.
 *
 * Returns 0 on success, -ve on error.
 */
static long seccomp_attach_filter(unsigned int flags,
				  struct seccomp_filter *filter)
{
	unsigned long total_insns;
	struct seccomp_filter *walker;

	assert_spin_locked(&current->sighand->siglock);

	/* Validate resulting filter length. */
	total_insns = filter->prog->len;
	for (walker = current->seccomp.filter; walker; walker = walker->prev)
		total_insns += walker->prog->len + 4;  /* 4 instr penalty */
	if (total_insns > MAX_INSNS_PER_PATH)
		return -ENOMEM;

	/* If thread sync has been requested, check that it is possible. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC) {
		int ret;

		ret = seccomp_can_sync_threads();
		if (ret)
			return ret;
	}

	/*
	 * If there is an existing filter, make it the prev and don't drop its
	 * task reference.
	 */
	filter->prev = current->seccomp.filter;
	current->seccomp.filter = filter;

	/* Now that the new filter is in place, synchronize to all threads. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		seccomp_sync_threads();

	return 0;
}

/* get_seccomp_filter - increments the reference count of the filter on @tsk */
void get_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = tsk->seccomp.filter;
	if (!orig)
		return;
	/* Reference count is bounded by the number of total processes. */
	atomic_inc(&orig->usage);
}

#ifdef CONFIG_SECURITY_SECCOMP
/* Do not free @checker */
static void put_seccomp_obj(struct seccomp_filter_checker *checker)
{
	switch (checker->type) {
	case SECCOMP_OBJTYPE_PATH:
		/* Pointer checks done in path_put() */
		path_put(&checker->object_path.path);
		break;
	default:
		WARN_ON(1);
	}
}

/* Free @checker_group */
static void put_seccomp_checker_group(struct seccomp_filter_checker_group *checker_group)
{
	int i;
	struct seccomp_filter_checker_group *orig = checker_group;

	/* Clean up single-reference branches iteratively. */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct seccomp_filter_checker_group *freeme = orig;

		for (i = 0; i < freeme->checkers_len; i++)
			put_seccomp_obj(&freeme->checkers[i]);
		orig = orig->prev;
		kfree(freeme);
	}
}
#endif /* CONFIG_SECURITY_SECCOMP */

static inline void seccomp_filter_free(struct seccomp_filter *filter)
{
	if (filter) {
#ifdef CONFIG_SECURITY_SECCOMP
		put_seccomp_checker_group(filter->checker_group);
#endif /* CONFIG_SECURITY_SECCOMP */
		bpf_prog_destroy(filter->prog);
		kfree(filter);
	}
}

/* put_seccomp_filter - decrements the ref count of tsk->seccomp.filter */
static void put_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = tsk->seccomp.filter;
	/* Clean up single-reference branches iteratively. */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct seccomp_filter *freeme = orig;
		orig = orig->prev;
		seccomp_filter_free(freeme);
	}
}

void put_seccomp(struct task_struct *tsk)
{
	put_seccomp_filter(tsk);
#ifdef CONFIG_SECURITY_SECCOMP
	/* Free in that order because of referenced checkers */
	free_seccomp_argeval_checked(tsk->seccomp.arg_checked);
	free_seccomp_argeval_cache(tsk->seccomp.arg_cache);
	free_seccomp_argeval_syscall(tsk->seccomp.orig_syscall);
	put_seccomp_checker_group(tsk->seccomp.checker_group);
#endif
}

/**
 * seccomp_send_sigsys - signals the task to allow in-process syscall emulation
 * @syscall: syscall number to send to userland
 * @reason: filter-supplied reason code to send to userland (via si_errno)
 *
 * Forces a SIGSYS with a code of SYS_SECCOMP and related sigsys info.
 */
static void seccomp_send_sigsys(int syscall, int reason)
{
	struct siginfo info;
	memset(&info, 0, sizeof(info));
	info.si_signo = SIGSYS;
	info.si_code = SYS_SECCOMP;
	info.si_call_addr = (void __user *)KSTK_EIP(current);
	info.si_errno = reason;
	info.si_arch = syscall_get_arch();
	info.si_syscall = syscall;
	force_sig_info(SIGSYS, &info, current);
}
#endif	/* CONFIG_SECCOMP_FILTER */

/*
 * Secure computing mode 1 allows only read/write/exit/sigreturn.
 * To be fully secure this must be combined with rlimit
 * to limit the stack allocations too.
 */
static int mode1_syscalls[] = {
	__NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
	0, /* null terminated */
};

#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
	__NR_seccomp_read_32, __NR_seccomp_write_32, __NR_seccomp_exit_32, __NR_seccomp_sigreturn_32,
	0, /* null terminated */
};
#endif

static void __secure_computing_strict(int this_syscall)
{
	int *syscall_whitelist = mode1_syscalls;
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		syscall_whitelist = mode1_syscalls_32;
#endif
	do {
		if (*syscall_whitelist == this_syscall)
			return;
	} while (*++syscall_whitelist);

#ifdef SECCOMP_DEBUG
	dump_stack();
#endif
	audit_seccomp(this_syscall, SIGKILL, SECCOMP_RET_KILL);
	do_exit(SIGKILL);
}

#ifndef CONFIG_HAVE_ARCH_SECCOMP_FILTER
void secure_computing_strict(int this_syscall)
{
	int mode = current->seccomp.mode;

	if (config_enabled(CONFIG_CHECKPOINT_RESTORE) &&
	    unlikely(current->ptrace & PT_SUSPEND_SECCOMP))
		return;

	if (mode == SECCOMP_MODE_DISABLED)
		return;
	else if (mode == SECCOMP_MODE_STRICT)
		__secure_computing_strict(this_syscall);
	else
		BUG();
}
#else
int __secure_computing(void)
{
	u32 phase1_result = seccomp_phase1(NULL);

	if (likely(phase1_result == SECCOMP_PHASE1_OK))
		return 0;
	else if (likely(phase1_result == SECCOMP_PHASE1_SKIP))
		return -1;
	else
		return seccomp_phase2(phase1_result);
}

#ifdef CONFIG_SECCOMP_FILTER
static u32 __seccomp_phase1_filter(int this_syscall, struct seccomp_data *sd)
{
	u32 filter_ret, action;
	int data, ret;

	/*
	 * Make sure that any changes to mode from another thread have
	 * been seen after TIF_SECCOMP was seen.
	 */
	rmb();

	/* Enable caching */
	audit_seccomp_entry();

	filter_ret = seccomp_run_filters(sd);
	data = filter_ret & SECCOMP_RET_DATA;
	action = filter_ret & SECCOMP_RET_ACTION;

	switch (action) {
	case SECCOMP_RET_ERRNO:
		/* Set low-order bits as an errno, capped at MAX_ERRNO. */
		if (data > MAX_ERRNO)
			data = MAX_ERRNO;
		syscall_set_return_value(current, task_pt_regs(current),
					 -data, 0);
		goto skip;

	case SECCOMP_RET_TRAP:
		/* Show the handler the original registers. */
		syscall_rollback(current, task_pt_regs(current));
		/* Let the filter pass back 16 bits of data. */
		seccomp_send_sigsys(this_syscall, data);
		goto skip;

	case SECCOMP_RET_TRACE:
		ret = filter_ret;  /* Save the rest for phase 2. */
		goto audit_exit;

	case SECCOMP_RET_ARGEVAL:
		/* Handled in seccomp_run_filters() */
		BUG();
	case SECCOMP_RET_ALLOW:
		ret = SECCOMP_PHASE1_OK;
		goto audit_exit;

	case SECCOMP_RET_KILL:
	default:
		audit_seccomp(this_syscall, SIGSYS, action);
		do_exit(SIGSYS);
	}

	unreachable();

audit_exit:
	audit_seccomp_exit(0);
	return ret;

skip:
	audit_seccomp_exit(1);
	audit_seccomp(this_syscall, 0, action);
	return SECCOMP_PHASE1_SKIP;
}
#endif

/**
 * seccomp_phase1() - run fast path seccomp checks on the current syscall
 * @arg sd: The seccomp_data or NULL
 *
 * This only reads pt_regs via the syscall_xyz helpers.  The only change
 * it will make to pt_regs is via syscall_set_return_value, and it will
 * only do that if it returns SECCOMP_PHASE1_SKIP.
 *
 * If sd is provided, it will not read pt_regs at all.
 *
 * It may also call do_exit or force a signal; these actions must be
 * safe.
 *
 * If it returns SECCOMP_PHASE1_OK, the syscall passes checks and should
 * be processed normally.
 *
 * If it returns SECCOMP_PHASE1_SKIP, then the syscall should not be
 * invoked.  In this case, seccomp_phase1 will have set the return value
 * using syscall_set_return_value.
 *
 * If it returns anything else, then the return value should be passed
 * to seccomp_phase2 from a context in which ptrace hooks are safe.
 */
u32 seccomp_phase1(struct seccomp_data *sd)
{
	int mode = current->seccomp.mode;
	int this_syscall = sd ? sd->nr :
		syscall_get_nr(current, task_pt_regs(current));

	if (config_enabled(CONFIG_CHECKPOINT_RESTORE) &&
	    unlikely(current->ptrace & PT_SUSPEND_SECCOMP))
		return SECCOMP_PHASE1_OK;

	switch (mode) {
	case SECCOMP_MODE_STRICT:
		__secure_computing_strict(this_syscall);  /* may call do_exit */
		return SECCOMP_PHASE1_OK;
#ifdef CONFIG_SECCOMP_FILTER
	case SECCOMP_MODE_FILTER:
		return __seccomp_phase1_filter(this_syscall, sd);
#endif
	default:
		BUG();
	}
}

/**
 * seccomp_phase2() - finish slow path seccomp work for the current syscall
 * @phase1_result: The return value from seccomp_phase1()
 *
 * This must be called from a context in which ptrace hooks can be used.
 *
 * Returns 0 if the syscall should be processed or -1 to skip the syscall.
 */
int seccomp_phase2(u32 phase1_result)
{
	struct pt_regs *regs = task_pt_regs(current);
	u32 action = phase1_result & SECCOMP_RET_ACTION;
	int data = phase1_result & SECCOMP_RET_DATA;

	BUG_ON(action != SECCOMP_RET_TRACE);

	audit_seccomp(syscall_get_nr(current, regs), 0, action);

	/* Skip these calls if there is no tracer. */
	if (!ptrace_event_enabled(current, PTRACE_EVENT_SECCOMP)) {
		syscall_set_return_value(current, regs,
					 -ENOSYS, 0);
		return -1;
	}

	/* Allow the BPF to provide the event message */
	ptrace_event(PTRACE_EVENT_SECCOMP, data);
	/*
	 * The delivery of a fatal signal during event
	 * notification may silently skip tracer notification.
	 * Terminating the task now avoids executing a system
	 * call that may not be intended.
	 */
	if (fatal_signal_pending(current))
		do_exit(SIGSYS);
	if (syscall_get_nr(current, regs) < 0)
		return -1;  /* Explicit request to skip. */

	return 0;
}
#endif /* CONFIG_HAVE_ARCH_SECCOMP_FILTER */

long prctl_get_seccomp(void)
{
	return current->seccomp.mode;
}

/**
 * seccomp_set_mode_strict: internal function for setting strict seccomp
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
static long seccomp_set_mode_strict(void)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_STRICT;
	long ret = -EINVAL;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

#ifdef TIF_NOTSC
	disable_TSC();
#endif
	seccomp_assign_mode(current, seccomp_mode);
	ret = 0;

out:
	spin_unlock_irq(&current->sighand->siglock);

	return ret;
}

#ifdef CONFIG_SECCOMP_FILTER
/**
 * seccomp_set_mode_filter: internal function for setting seccomp filter
 * @flags:  flags to change filter behavior
 * @filter: struct sock_fprog containing filter
 *
 * This function may be called repeatedly to install additional filters.
 * Every filter successfully installed will be evaluated (in reverse order)
 * for each system call the task makes.
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
static long seccomp_set_mode_filter(unsigned int flags,
				    const char __user *filter)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_FILTER;
	struct seccomp_filter *prepared = NULL;
	long ret = -EINVAL;

	/* Validate flags. */
	if (flags & ~SECCOMP_FILTER_FLAG_MASK)
		return -EINVAL;

	/* Prepare the new filter before holding any locks. */
	prepared = seccomp_prepare_user_filter(filter);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);

	/*
	 * Make sure we cannot change seccomp or nnp state via TSYNC
	 * while another thread is in the middle of calling exec.
	 */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC &&
	    mutex_lock_killable(&current->signal->cred_guard_mutex))
		goto out_free;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

	ret = seccomp_attach_filter(flags, prepared);
	if (ret)
		goto out;
	/* Do not free the successfully attached filter. */
	prepared = NULL;

	seccomp_assign_mode(current, seccomp_mode);
out:
	spin_unlock_irq(&current->sighand->siglock);
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		mutex_unlock(&current->signal->cred_guard_mutex);
out_free:
	seccomp_filter_free(prepared);
	return ret;
}
#else
static inline long seccomp_set_mode_filter(unsigned int flags,
					   const char __user *filter)
{
	return -EINVAL;
}
#endif

#ifdef CONFIG_SECURITY_SECCOMP

/* Limit checkers number to 64 to be able to show matches with a bitmask. */
#define SECCOMP_CHECKERS_MAX \
	(FIELD_SIZEOF(struct seccomp_data, arg_matches[0]) * BITS_PER_BYTE)

/* Limit arg group list and their checkers to 256KB. */
#define SECCOMP_GROUP_CHECKERS_MAX_SIZE (1 << 18)

static long seccomp_add_checker_group(unsigned int flags, const char __user *group)
{
	struct seccomp_checker_group kgroup;
	struct seccomp_checker (*kcheckers)[], *user_checker;
	struct seccomp_filter_checker_group *filter_group, *walker;
	struct seccomp_filter_checker *kernel_obj;
	unsigned int i;
	unsigned long group_size, kcheckers_size, full_group_size;
	long result;

	/* FIXME: Deny unsecure path evaluation (i.e. without audit_names) for
	 * the entire task life.
	 */
	if (!current->audit_context)
		return -EPERM;
	if (!task_no_new_privs(current) &&
	    security_capable_noaudit(current_cred(),
				     current_user_ns(), CAP_SYS_ADMIN) != 0)
		return -EACCES;
	if (flags != 0 || !group)
		return -EINVAL;

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		struct compat_seccomp_checker_group kgroup32;

		if (copy_from_user(&kgroup32, group, sizeof(kgroup32)))
			return -EFAULT;
		kgroup.version = kgroup32.version;
		kgroup.id = kgroup32.id;
		kgroup.len = kgroup32.len;
		kgroup.checkers = compat_ptr(kgroup32.checkers);
	} else			/* Falls through to the if below */
#endif /* CONFIG_COMPAT */
	if (copy_from_user(&kgroup, group, sizeof(kgroup)))
		return -EFAULT;

	if (kgroup.version != 1)
		return -EINVAL;
	/* The group ID 0 means no evaluated checkers */
	if (kgroup.id == 0)
		return -EINVAL;
	if (kgroup.len == 0)
		return -EINVAL;
	if (kgroup.len > SECCOMP_CHECKERS_MAX)
		return -E2BIG;

	/* Validate resulting checker_group ID and length. */
	group_size = sizeof(*filter_group) +
		kgroup.len * sizeof(filter_group->checkers[0]);
	full_group_size = group_size;
	for (walker = current->seccomp.checker_group;
			walker; walker = walker->prev) {
		if (walker->id == kgroup.id)
			return -EINVAL;
		/* TODO: add penalty? */
		full_group_size += sizeof(*walker) +
			walker->checkers_len * sizeof(walker->checkers[0]);
	}
	if (full_group_size > SECCOMP_GROUP_CHECKERS_MAX_SIZE)
		return -ENOMEM;

	kcheckers_size = kgroup.len * sizeof((*kcheckers)[0]);
	kcheckers = kmalloc(kcheckers_size, GFP_KERNEL);
	if (!kcheckers)
		return -ENOMEM;

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		unsigned int i, kcheckers32_size;
		struct compat_seccomp_checker (*kcheckers32)[];

		kcheckers32_size = kgroup.len * sizeof((*kcheckers32)[0]);
		kcheckers32 = kmalloc(kcheckers32_size, GFP_KERNEL);
		if (!kcheckers32) {
			result = -ENOMEM;
			goto free_kcheckers;
		}
		if (copy_from_user(kcheckers32, kgroup.checkers, kcheckers32_size)) {
			kfree(kcheckers32);
			result = -EFAULT;
			goto free_kcheckers;
		}
		for (i = 0; i < kgroup.len; i++) {
			(*kcheckers)[i].check = (*kcheckers32)[i].check;
			(*kcheckers)[i].type = (*kcheckers32)[i].type;
			(*kcheckers)[i].len = (*kcheckers32)[i].len;
			(*kcheckers)[i].object_path = compat_ptr((*kcheckers32)[i].checker);
		}
		kfree(kcheckers32);
	} else			/* Falls through to the if below */
#endif /* CONFIG_COMPAT */
	if (copy_from_user(kcheckers, kgroup.checkers, kcheckers_size)) {
		result = -EFAULT;
		goto free_kcheckers;
	}

	/* filter_group->checkers must be zeroed to correctly be freed on error */
	filter_group = kzalloc(group_size, GFP_KERNEL);
	if (!filter_group) {
		result = -ENOMEM;
		goto free_kcheckers;
	}
	filter_group->prev = NULL;
	filter_group->id = kgroup.id;
	filter_group->checkers_len = kgroup.len;
	for (i = 0; i < filter_group->checkers_len; i++) {
		user_checker = &(*kcheckers)[i];
		kernel_obj = &filter_group->checkers[i];
		switch (user_checker->check) {
		case SECCOMP_CHECK_FS_LITERAL:
		case SECCOMP_CHECK_FS_BENEATH:
			kernel_obj->check = user_checker->check;
			result =
			    seccomp_set_argcheck_fs(user_checker, kernel_obj);
			if (result)
				goto free_group;
			break;
		default:
			result = -EINVAL;
			goto free_group;
		}
	}

	atomic_set(&filter_group->usage, 1);
	filter_group->prev = current->seccomp.checker_group;
	/* No need to update filter_group->prev->usage because it get one
	 * reference from this filter but lose one from
	 * current->seccomp.checker_group.
	 */
	current->seccomp.checker_group = filter_group;
	/* XXX: Return the number of groups? */
	result = 0;
	goto free_kcheckers;

free_group:
	for (i = 0; i < filter_group->checkers_len; i++) {
		kernel_obj = &filter_group->checkers[i];
		if (kernel_obj->type)
			put_seccomp_obj(kernel_obj);
	}
	kfree(filter_group);

free_kcheckers:
	kfree(kcheckers);
	return result;
}
#endif /* CONFIG_SECURITY_SECCOMP */

/* Common entry point for both prctl and syscall. */
static long do_seccomp(unsigned int op, unsigned int flags,
		       const char __user *uargs)
{
	switch (op) {
	case SECCOMP_SET_MODE_STRICT:
		if (flags != 0 || uargs != NULL)
			return -EINVAL;
		return seccomp_set_mode_strict();
	case SECCOMP_SET_MODE_FILTER:
		return seccomp_set_mode_filter(flags, uargs);
#ifdef CONFIG_SECURITY_SECCOMP
	case SECCOMP_ADD_CHECKER_GROUP:
		return seccomp_add_checker_group(flags, uargs);
#endif /* CONFIG_SECURITY_SECCOMP */
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
			 const char __user *, uargs)
{
	return do_seccomp(op, flags, uargs);
}

/**
 * prctl_set_seccomp: configures current->seccomp.mode
 * @seccomp_mode: requested mode to use
 * @filter: optional struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * Returns 0 on success or -EINVAL on failure.
 */
long prctl_set_seccomp(unsigned long seccomp_mode, char __user *filter)
{
	unsigned int op;
	char __user *uargs;

	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		op = SECCOMP_SET_MODE_STRICT;
		/*
		 * Setting strict mode through prctl always ignored filter,
		 * so make sure it is always NULL here to pass the internal
		 * check in do_seccomp().
		 */
		uargs = NULL;
		break;
	case SECCOMP_MODE_FILTER:
		op = SECCOMP_SET_MODE_FILTER;
		uargs = filter;
		break;
	default:
		return -EINVAL;
	}

	/* prctl interface doesn't have flags, so they are always zero. */
	return do_seccomp(op, 0, uargs);
}

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_CHECKPOINT_RESTORE)
long seccomp_get_filter(struct task_struct *task, unsigned long filter_off,
			void __user *data)
{
	struct seccomp_filter *filter;
	struct sock_fprog_kern *fprog;
	long ret;
	unsigned long count = 0;

	if (!capable(CAP_SYS_ADMIN) ||
	    current->seccomp.mode != SECCOMP_MODE_DISABLED) {
		return -EACCES;
	}

	spin_lock_irq(&task->sighand->siglock);
	if (task->seccomp.mode != SECCOMP_MODE_FILTER) {
		ret = -EINVAL;
		goto out;
	}

	filter = task->seccomp.filter;
	while (filter) {
		filter = filter->prev;
		count++;
	}

	if (filter_off >= count) {
		ret = -ENOENT;
		goto out;
	}
	count -= filter_off;

	filter = task->seccomp.filter;
	while (filter && count > 1) {
		filter = filter->prev;
		count--;
	}

	if (WARN_ON(count != 1 || !filter)) {
		/* The filter tree shouldn't shrink while we're using it. */
		ret = -ENOENT;
		goto out;
	}

	fprog = filter->prog->orig_prog;
	if (!fprog) {
		/* This must be a new non-cBPF filter, since we save
		 * every cBPF filter's orig_prog above when
		 * CONFIG_CHECKPOINT_RESTORE is enabled.
		 */
		ret = -EMEDIUMTYPE;
		goto out;
	}

	ret = fprog->len;
	if (!data)
		goto out;

	get_seccomp_filter(task);
	spin_unlock_irq(&task->sighand->siglock);

	if (copy_to_user(data, fprog->filter, bpf_classic_proglen(fprog)))
		ret = -EFAULT;

	put_seccomp_filter(task);
	return ret;

out:
	spin_unlock_irq(&task->sighand->siglock);
	return ret;
}
#endif
