/*
 * Landlock LSM - Public headers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H
#ifdef CONFIG_SECURITY_LANDLOCK

#include <linux/bpf.h>	/* _LANDLOCK_HOOK_LAST */
#include <linux/types.h> /* atomic_t */

#ifdef CONFIG_SECCOMP_FILTER
#include <linux/seccomp.h> /* struct seccomp_filter */
#endif /* CONFIG_SECCOMP_FILTER */

#ifdef CONFIG_CGROUP_BPF
#include <linux/cgroup-defs.h> /* struct cgroup */
#endif /* CONFIG_CGROUP_BPF */

#ifdef CONFIG_SECCOMP_FILTER
struct landlock_seccomp_ret {
	struct landlock_seccomp_ret *prev;
	struct seccomp_filter *filter;
	u16 cookie;
	bool triggered;
};
#endif /* CONFIG_SECCOMP_FILTER */

struct landlock_rule {
	atomic_t usage;
	struct landlock_rule *prev;
	/*
	 * List of filters (through filter->thread_prev) allowed to trigger
	 * this Landlock program.
	 */
	struct bpf_prog *prog;
#ifdef CONFIG_SECCOMP_FILTER
	struct seccomp_filter *thread_filter;
#endif /* CONFIG_SECCOMP_FILTER */
};

/**
 * struct landlock_hooks - Landlock hook programs enforced on a thread
 *
 * This is used for low performance impact when forking a process. Instead of
 * copying the full array and incrementing the usage field of each entries,
 * only create a pointer to struct landlock_hooks and increment the usage
 * field.
 *
 * A new struct landlock_hooks must be created thanks to a call to
 * new_landlock_hooks().
 *
 * @usage: reference count to manage the object lifetime. When a thread need to
 *         add Landlock programs and if @usage is greater than 1, then the
 *         thread must duplicate struct landlock_hooks to not change the
 *         children' rules as well.
 */
struct landlock_hooks {
	atomic_t usage;
	struct landlock_rule *rules[_LANDLOCK_HOOK_LAST];
};


struct landlock_hooks *new_landlock_hooks(void);
void get_landlock_hooks(struct landlock_hooks *hooks);
void put_landlock_hooks(struct landlock_hooks *hooks);

#ifdef CONFIG_SECCOMP_FILTER
void put_landlock_ret(struct landlock_seccomp_ret *landlock_ret);
int landlock_seccomp_set_hook(unsigned int flags,
		const char __user *user_bpf_fd);
#endif /* CONFIG_SECCOMP_FILTER */

#ifdef CONFIG_CGROUP_BPF
struct landlock_hooks *landlock_cgroup_set_hook(struct cgroup *cgrp,
		struct bpf_prog *prog);
#endif /* CONFIG_CGROUP_BPF */

#endif /* CONFIG_SECURITY_LANDLOCK */
#endif /* _LINUX_LANDLOCK_H */
