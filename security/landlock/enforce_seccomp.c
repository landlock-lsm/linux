/*
 * Landlock LSM - enforcing with seccomp
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_SECCOMP_FILTER

#include <linux/bpf.h> /* bpf_prog_put() */
#include <linux/capability.h>
#include <linux/err.h> /* PTR_ERR() */
#include <linux/errno.h>
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/landlock.h>
#include <linux/refcount.h>
#include <linux/sched.h> /* current */
#include <linux/uaccess.h> /* get_user() */

#include "enforce.h"
#include "task.h"

/* headers in include/linux/landlock.h */

/**
 * landlock_seccomp_prepend_prog - attach a Landlock program to the current
 *                                 process
 *
 * current->seccomp.landlock_state->prog_set is lazily allocated. When a
 * process fork, only a pointer is copied.  When a new program is added by a
 * process, if there is other references to this process' prog_set, then a new
 * allocation is made to contain an array pointing to Landlock program lists.
 * This design enable low-performance impact and is memory efficient while
 * keeping the property of prepend-only programs.
 *
 * For now, installing a Landlock prog requires that the requesting task has
 * the global CAP_SYS_ADMIN. We cannot force the use of no_new_privs to not
 * exclude containers where a process may legitimately acquire more privileges
 * thanks to an SUID binary.
 *
 * @flags: not used for now, but could be used for TSYNC
 * @user_bpf_fd: file descriptor pointing to a loaded Landlock prog
 */
int landlock_seccomp_prepend_prog(unsigned int flags,
		const int __user *user_bpf_fd)
{
	struct landlock_prog_set *new_prog_set;
	struct bpf_prog *prog;
	int bpf_fd, err;

	/* planned to be replaced with a no_new_privs check to allow
	 * unprivileged tasks */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/* enable to check if Landlock is supported with early EFAULT */
	if (!user_bpf_fd)
		return -EFAULT;
	if (flags)
		return -EINVAL;
	err = get_user(bpf_fd, user_bpf_fd);
	if (err)
		return err;

	/* allocate current->security here to not have to handle this in
	 * hook_nameidata_free_security() */
	if (!current->security) {
		current->security = landlock_new_task_security(GFP_KERNEL);
		if (!current->security)
			return -ENOMEM;
	}
	prog = bpf_prog_get(bpf_fd);
	if (IS_ERR(prog)) {
		err = PTR_ERR(prog);
		goto free_task;
	}

	/*
	 * We don't need to lock anything for the current process hierarchy,
	 * everything is guarded by the atomic counters.
	 */
	new_prog_set = landlock_prepend_prog(
			current->seccomp.landlock_prog_set, prog);
	bpf_prog_put(prog);
	/* @prog is managed/freed by landlock_prepend_prog() */
	if (IS_ERR(new_prog_set)) {
		err = PTR_ERR(new_prog_set);
		goto free_task;
	}
	current->seccomp.landlock_prog_set = new_prog_set;
	return 0;

free_task:
	landlock_free_task_security(current->security);
	current->security = NULL;
	return err;
}

void put_seccomp_landlock(struct task_struct *tsk)
{
	landlock_put_prog_set(tsk->seccomp.landlock_prog_set);
}

void get_seccomp_landlock(struct task_struct *tsk)
{
	landlock_get_prog_set(tsk->seccomp.landlock_prog_set);
}

#endif /* CONFIG_SECCOMP_FILTER */
