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

struct landlock_rule;

/**
 * struct landlock_node - node in the rule hierarchy
 *
 * This is created when a task insert its first rule in the Landlock rule
 * hierarchy. The set of Landlock rules referenced by this node is then
 * enforced for all the task that inherit this node. However, if a task is
 * cloned before inserting new rules, it doesn't get a dedicated node and its
 * children will not inherit this new rules.
 *
 * @usage: reference count to manage the node lifetime.
 * @rule: list of Landlock rules managed by this node.
 * @prev: reference the parent node.
 * @owner: reference the address of the node in the struct landlock_hooks. This
 *         is needed to know if we need to append a rule to the current node or
 *         create a new node.
 */
struct landlock_node {
	atomic_t usage;
	struct landlock_rule *rule;
	struct landlock_node *prev;
	struct landlock_node **owner;
};

struct landlock_rule {
	atomic_t usage;
	struct landlock_rule *prev;
	struct bpf_prog *prog;
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
 *         children' rules as well. FIXME
 * @nodes: array of non-NULL struct landlock_node pointers.
 */
struct landlock_hooks {
	atomic_t usage;
	struct landlock_node *nodes[_LANDLOCK_HOOK_LAST];
};

void put_landlock_hooks(struct landlock_hooks *hooks);
void get_landlock_hooks(struct landlock_hooks *hooks);

#ifdef CONFIG_SECCOMP_FILTER
int landlock_seccomp_append_prog(unsigned int flags,
		const char __user *user_bpf_fd);
#endif /* CONFIG_SECCOMP_FILTER */

#ifdef CONFIG_CGROUP_BPF
struct landlock_hooks *landlock_cgroup_append_prog(struct cgroup *cgrp,
		struct bpf_prog *prog);
void landlock_insert_node(struct landlock_hooks *dst,
		enum landlock_hook hook, struct landlock_hooks *src);
#endif /* CONFIG_CGROUP_BPF */

#endif /* CONFIG_SECURITY_LANDLOCK */
#endif /* _LINUX_LANDLOCK_H */
