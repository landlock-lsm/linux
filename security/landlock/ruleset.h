/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Ruleset management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_RULESET_H
#define _SECURITY_LANDLOCK_RULESET_H

#include <linux/compiler.h>
#include <linux/mutex.h>
#include <linux/poison.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <uapi/linux/landlock.h>

#include "object.h"

#define _LANDLOCK_ACCESS_FS_LAST	LANDLOCK_ACCESS_FS_MAP
#define _LANDLOCK_ACCESS_FS_MASK	((_LANDLOCK_ACCESS_FS_LAST << 1) - 1)

struct landlock_ref {
	/*
	 * @object: Identify a kernel object (e.g. an inode).  This is used as
	 * a key for a ruleset tree (cf. struct landlock_ruleset_elem).  This
	 * pointer is set once and never modified.  It may point to a deleted
	 * object and should then be dereferenced with great care, thanks to a
	 * call to landlock_rule_is_disabled(@rule) from inside an RCU-read
	 * block, cf. landlock_put_rule().
	 */
	struct landlock_object __rcu *object;
	/*
	 * @rule: Ties a rule to an object. Set once with an allocated rule,
	 * but can be NULLed if the rule is disabled.
	 */
	struct landlock_rule __rcu *rule;
};

/*
 * Red-black tree element used in a landlock_ruleset.
 */
struct landlock_ruleset_elem {
	struct landlock_ref ref;
	struct rb_node node;
	struct rcu_head rcu_free;
};

/*
 * Enable hierarchy identification even when a parent domain vanishes.  This is
 * needed for the ptrace protection.
 */
struct landlock_hierarchy {
	struct landlock_hierarchy *parent;
	refcount_t usage;
};

/*
 * Kernel representation of a ruleset.  This data structure must contains
 * unique entries, be updatable, and quick to match an object.
 */
struct landlock_ruleset {
	/*
	 * @fs_access_mask: Contains the subset of filesystem actions which are
	 * restricted by a ruleset.  This is used when merging rulesets and for
	 * userspace backward compatibility (i.e. future-proof).  Set once and
	 * never changed for the lifetime of the ruleset.
	 */
	u32 fs_access_mask;
	struct landlock_hierarchy *hierarchy;
	refcount_t usage;
	union {
		struct rcu_head	rcu_free;
		struct work_struct work_put;
	};
	struct mutex lock;
	atomic_t nb_rules;
	/*
	 * @root: Red-black tree containing landlock_ruleset_elem nodes.
	 */
	struct rb_root root;
};

struct landlock_ruleset *landlock_create_ruleset(u64 fs_access_mask);

void landlock_get_ruleset(struct landlock_ruleset *ruleset);
void landlock_put_ruleset(struct landlock_ruleset *ruleset);
void landlock_put_ruleset_enqueue(struct landlock_ruleset *ruleset);

int landlock_insert_ruleset_rule(struct landlock_ruleset *ruleset,
		struct landlock_object *object, struct landlock_access *access,
		struct landlock_rule *rule);

struct landlock_ruleset *landlock_merge_ruleset(
		struct landlock_ruleset *domain,
		struct landlock_ruleset *ruleset);

const struct landlock_access *landlock_find_access(
		const struct landlock_ruleset *ruleset,
		const struct landlock_object *object);

#endif /* _SECURITY_LANDLOCK_RULESET_H */
