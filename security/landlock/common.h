/*
 * Landlock LSM - private headers
 *
 * Copyright © 2016-2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h> /* enum landlock_subtype_event */
#include <linux/refcount.h> /* refcount_t */

/*
 * This is not intended for the UAPI headers. Each userland software should use
 * a static minimal ABI for the required features as explained in the
 * documentation.
 */
#define LANDLOCK_ABI 1

#define LANDLOCK_NAME "landlock"

// TODO: change name to not collide with UAPI
struct landlock_rule {
	refcount_t usage;
	struct landlock_rule *prev;
	struct bpf_prog *prog;
};

/**
 * struct landlock_events - Landlock event rules enforced on a thread
 *
 * This is used for low performance impact when forking a process. Instead of
 * copying the full array and incrementing the usage of each entries, only
 * create a pointer to &struct landlock_events and increments its usage. When
 * prepending a new rule, if &struct landlock_events is shared with other
 * tasks, then duplicate it and prepend the rule to this new &struct
 * landlock_events.
 *
 * @usage: reference count to manage the object lifetime. When a thread need to
 *         add Landlock rules and if @usage is greater than 1, then the thread
 *         must duplicate &struct landlock_events to not change the children's
 *         rules as well.
 * @rules: array of non-NULL &struct landlock_rule pointers
 */
struct landlock_events {
	refcount_t usage;
	struct landlock_rule *rules[_LANDLOCK_SUBTYPE_EVENT_LAST];
};

/**
 * get_index - get an index for the rules of struct landlock_events
 *
 * @event: a Landlock event type
 */
static inline int get_index(enum landlock_subtype_event event)
{
	/* event ID > 0 for loaded programs */
	return event - 1;
}

#endif /* _SECURITY_LANDLOCK_COMMON_H */
