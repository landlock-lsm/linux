/*
 * Seccomp Linux Security Module
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/syscall.h>	/* sys_call_table */
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/slab.h>	/* kcalloc() */
#include <linux/syscalls.h>	/* syscall_argdesc */

#include "checker_fs.h"
#include "lsm.h"

/* TODO: Remove the need for CONFIG_SYSFS dependency */

struct syscall_argdesc (*seccomp_syscalls_argdesc)[] = NULL;
#ifdef CONFIG_COMPAT
struct syscall_argdesc (*compat_seccomp_syscalls_argdesc)[] = NULL;
#endif	/* CONFIG_COMPAT */

#define SECCOMP_HOOK(CHECK, NAME, ...)				\
	static inline int seccomp_hook_##NAME(__VA_ARGS__)	\
	{ 							\
		return seccomp_check_##CHECK(CHECK);		\
	}

#define SECCOMP_HOOK_INIT(NAME) LSM_HOOK_INIT(NAME, seccomp_hook_##NAME)

/* TODO: file_set_fowner, file_alloc_security? */

SECCOMP_HOOK(file, binder_transfer_file, struct task_struct *from, struct task_struct *to, struct file *file)
SECCOMP_HOOK(file, file_permission, struct file *file, int mask)
SECCOMP_HOOK(file, file_ioctl, struct file *file, unsigned int cmd, unsigned long arg)
SECCOMP_HOOK(file, mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
SECCOMP_HOOK(file, file_lock, struct file *file, unsigned int cmd)
SECCOMP_HOOK(file, file_fcntl, struct file *file, unsigned int cmd, unsigned long arg)
SECCOMP_HOOK(file, file_receive, struct file *file)
SECCOMP_HOOK(file, file_open, struct file *file, const struct cred *cred)
SECCOMP_HOOK(file, kernel_fw_from_file, struct file *file, char *buf, size_t size)
SECCOMP_HOOK(file, kernel_module_from_file, struct file *file)

/* TODO: Add hooks with:
 * - struct dentry *
 * - struct path *
 * - struct inode *
 * ...
 */


static struct security_hook_list seccomp_hooks[] = {
	SECCOMP_HOOK_INIT(binder_transfer_file),
	SECCOMP_HOOK_INIT(file_permission),
	SECCOMP_HOOK_INIT(file_ioctl),
	SECCOMP_HOOK_INIT(mmap_file),
	SECCOMP_HOOK_INIT(file_lock),
	SECCOMP_HOOK_INIT(file_fcntl),
	SECCOMP_HOOK_INIT(file_receive),
	SECCOMP_HOOK_INIT(file_open),
	SECCOMP_HOOK_INIT(kernel_fw_from_file),
	SECCOMP_HOOK_INIT(kernel_module_from_file),
};


static const struct syscall_argdesc *__init
find_syscall_argdesc(const struct syscall_argdesc *start,
		const struct syscall_argdesc *stop, const void *addr)
{
	if (unlikely(!addr || !start || !stop)) {
		WARN_ON(1);
		return NULL;
	}

	for (; start < stop; start++) {
		if (start->addr == addr)
			return start;
	}
	return NULL;
}

static inline void __init init_argdesc(void)
{
	const struct syscall_argdesc *argdesc;
	const void *addr;
	int i;

	seccomp_syscalls_argdesc = kcalloc(NR_syscalls,
			sizeof((*seccomp_syscalls_argdesc)[0]), GFP_KERNEL);
	if (unlikely(!seccomp_syscalls_argdesc)) {
		WARN_ON(1);
		return;
	}
	for (i = 0; i < NR_syscalls; i++) {
		addr = sys_call_table[i];
		argdesc = find_syscall_argdesc(__start_syscalls_argdesc,
				__stop_syscalls_argdesc, addr);
		if (!argdesc)
			continue;

		(*seccomp_syscalls_argdesc)[i] = *argdesc;
	}

#ifdef CONFIG_COMPAT
	compat_seccomp_syscalls_argdesc = kcalloc(IA32_NR_syscalls,
			sizeof((*compat_seccomp_syscalls_argdesc)[0]),
			GFP_KERNEL);
	if (unlikely(!compat_seccomp_syscalls_argdesc)) {
		WARN_ON(1);
		return;
	}
	for (i = 0; i < IA32_NR_syscalls; i++) {
		addr = ia32_sys_call_table[i];
		argdesc = find_syscall_argdesc(__start_compat_syscalls_argdesc,
				__stop_compat_syscalls_argdesc, addr);
		if (!argdesc)
			continue;

		(*compat_seccomp_syscalls_argdesc)[i] = *argdesc;
	}
#endif	/* CONFIG_COMPAT */
}

void __init seccomp_init(void)
{
	pr_info("seccomp: Becoming ready for sandboxing\n");
	init_argdesc();
	security_add_hooks(seccomp_hooks, ARRAY_SIZE(seccomp_hooks));
}
