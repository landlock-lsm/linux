/*
 * Landlock LSM - public kernel headers
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
 * struct landlock_events - Landlock event rules enforced on a thread
 *
 * This is used for low performance impact when forking a process. Instead of
 * copying the full array and incrementing the usage of each entries, only
 * create a pointer to &struct landlock_events and increments its usage. When
 * appending a new rule, if &struct landlock_events is shared with other tasks,
 * then duplicate it and append the rule to this new &struct landlock_events.
 *
 * @usage: reference count to manage the object lifetime. When a thread need to
 *         add Landlock rules and if @usage is greater than 1, then the thread
 *         must duplicate &struct landlock_events to not change the children's
 *         rules as well.
 * @rules: array of non-NULL &struct landlock_rule pointers
 */
struct landlock_events {
	atomic_t usage;
	struct landlock_rule *rules[_LANDLOCK_SUBTYPE_EVENT_LAST];
};

void put_landlock_events(struct landlock_events *events);

#ifdef CONFIG_SECCOMP_FILTER
int landlock_seccomp_append_prog(unsigned int flags,
		const char __user *user_bpf_fd);
#endif /* CONFIG_SECCOMP_FILTER */

#endif /* CONFIG_SECURITY_LANDLOCK */
#endif /* _LINUX_LANDLOCK_H */
