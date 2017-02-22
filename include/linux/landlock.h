/*
 * Landlock LSM - Public headers
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H
#ifdef CONFIG_SECURITY_LANDLOCK

#include <linux/bpf.h>	/* _LANDLOCK_SUBTYPE_EVENT_LAST */
#include <linux/types.h> /* atomic_t */

/*
 * This is not intended for the UAPI headers. Each userland software should use
 * a static minimal version for the required features as explained in the
 * documentation.
 */
#define LANDLOCK_VERSION 1

struct landlock_rule {
	atomic_t usage;
	struct landlock_rule *prev;
	struct bpf_prog *prog;
};

/**
 * struct landlock_node - node in the rule hierarchy
 *
 * This is created when a task inserts its first rule in the Landlock rule
 * hierarchy. The set of Landlock rules referenced by this node is then
 * enforced for all the tasks that inherit this node. However, if a task is
 * cloned before inserting any rule, it doesn't get a dedicated node and its
 * children will not inherit any rules from this task.
 *
 * @usage: reference count to manage the node lifetime
 * @rule: list of Landlock rules managed by this node
 * @prev: reference the parent node
 * @owner: reference the address of the node in the &struct landlock_events.
 *         This is needed to know if we need to append a rule to the current
 *         node or create a new node.
 */
struct landlock_node {
	atomic_t usage;
	struct landlock_rule *rule;
	struct landlock_node *prev;
	struct landlock_node **owner;
};

/**
 * struct landlock_events - Landlock event rules enforced on a thread
 *
 * This is used for low performance impact when forking a process. Instead of
 * copying the full array and incrementing the usage of each entries, only
 * create a pointer to &struct landlock_events and increments its usage.
 *
 * @usage: reference count to manage the object lifetime. When a thread need to
 *         add Landlock rules and if @usage is greater than 1, then the thread
 *         must duplicate &struct landlock_events to not change the children's
 *         rules as well.
 * @nodes: array of non-NULL &struct landlock_node pointers
 */
struct landlock_events {
	atomic_t usage;
	struct landlock_node *nodes[_LANDLOCK_SUBTYPE_EVENT_LAST];
};

void put_landlock_events(struct landlock_events *events);

#ifdef CONFIG_SECCOMP_FILTER
int landlock_seccomp_append_prog(unsigned int flags,
		const char __user *user_bpf_fd);
#endif /* CONFIG_SECCOMP_FILTER */

#endif /* CONFIG_SECURITY_LANDLOCK */
#endif /* _LINUX_LANDLOCK_H */
