// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - seccomp syscall
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifdef CONFIG_SECCOMP_FILTER

#include <asm/current.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/uaccess.h>

#include "common.h"
#include "domain_manage.h"

/**
 * landlock_seccomp_prepend_prog - attach a Landlock program to the current
 *                                 task
 *
 * current->cred->security[landlock]->domain is lazily allocated. When a new
 * credential is created, only a pointer is copied.  When a new Landlock
 * program is added by a task, if there is other references to this task's
 * domain, then a new allocation is made to contain an array pointing to
 * Landlock program lists.  This design enable low-performance impact and is
 * memory efficient while keeping the property of prepend-only programs.
 *
 * For now, installing a Landlock program requires that the requesting task has
 * the global CAP_SYS_ADMIN. We cannot force the use of no_new_privs to not
 * exclude containers where a process may legitimately acquire more privileges
 * thanks to an SUID binary.
 *
 * @flags: not used, must be 0
 * @user_bpf_fd: file descriptor pointing to a loaded Landlock prog
 */
int landlock_seccomp_prepend_prog(unsigned int flags,
		const int __user *user_bpf_fd)
{
	struct landlock_domain *new_dom;
	struct cred *new_cred;
	struct landlock_cred_security *new_llcred;
	struct bpf_prog *prog;
	int bpf_fd, err;

	/*
	 * It is planned to replaced the CAP_SYS_ADMIN check with a
	 * no_new_privs check to allow unprivileged tasks to sandbox
	 * themselves.  However, they may not be allowed to directly create an
	 * eBPF program, but could received it from a privileged service.
	 */
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
	prog = bpf_prog_get(bpf_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	new_cred = prepare_creds();
	if (!new_cred) {
		bpf_prog_put(prog);
		return -ENOMEM;
	}
	new_llcred = landlock_cred(new_cred);
	/* the new creds are an atomic copy of the current creds */
	new_dom = landlock_prepend_prog(new_llcred->domain, prog);
	bpf_prog_put(prog);
	if (IS_ERR(new_dom)) {
		abort_creds(new_cred);
		return PTR_ERR(new_dom);
	}
	/* replace the old (prepared) domain */
	landlock_put_domain(new_llcred->domain);
	new_llcred->domain = new_dom;
	return commit_creds(new_cred);
}

#endif /* CONFIG_SECCOMP_FILTER */
