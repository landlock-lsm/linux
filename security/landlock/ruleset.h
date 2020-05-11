/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Ruleset management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_RULESET_H
#define _SECURITY_LANDLOCK_RULESET_H

#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <uapi/linux/landlock.h>

#include "object.h"

#define _LANDLOCK_ACCESS_FS_LAST	LANDLOCK_ACCESS_FS_MAKE_SYM
#define _LANDLOCK_ACCESS_FS_MASK	((_LANDLOCK_ACCESS_FS_LAST << 1) - 1)

/**
 * struct landlock_rule - Access rights tied to an object
 *
 * When enforcing a ruleset (i.e. merging a ruleset into the current domain),
 * the layer level of a new rule is the incremented top layer level (cf.
 * &struct landlock_ruleset).  If there is no rule (from this domain) tied to
 * the same object, then the depth of the new rule is 1. However, if there is
 * already a rule tied to the same object and if this rule's layer level is the
 * previous top layer level, then the depth and the layer level are both
 * incremented and the rule is updated with the new access rights (boolean
 * AND).
 */
struct landlock_rule {
	/**
	 * @node: Node in the red-black tree.
	 */
	struct rb_node node;
	/**
	 * @object: Pointer to identify a kernel object (e.g. an inode).  This
	 * is used as a key for this ruleset element.  This pointer is set once
	 * and never modified.  It always point to an allocated object because
	 * each rule increment the refcount of there object.
	 */
	struct landlock_object *object;
	/**
	 * @access: Bitfield of allowed actions on the kernel object.  They are
	 * relative to the object type (e.g. %LANDLOCK_ACTION_FS_READ).  This
	 * may be the result of the merged access rights (boolean AND) from
	 * multiple layers referring to the same object.
	 */
	u32 access;
	/**
	 * @layers: Bitfield to identify the layers which resulted to @access
	 * from different consecutive intersections.
	 */
	u64 layers;
};

/**
 * struct landlock_hierarchy - Node in a ruleset hierarchy
 */
struct landlock_hierarchy {
	/**
	 * @parent: Pointer to the parent node, or NULL if it is a root Lanlock
	 * domain.
	 */
	struct landlock_hierarchy *parent;
	/**
	 * @usage: Number of potential children domains plus their parent
	 * domain.
	 */
	refcount_t usage;
};

/**
 * struct landlock_ruleset - Landlock ruleset
 *
 * This data structure must contains unique entries, be updatable, and quick to
 * match an object.
 */
struct landlock_ruleset {
	/**
	 * @root: Root of a red-black tree containing &struct landlock_rule
	 * nodes.
	 */
	struct rb_root root;
	/**
	 * @hierarchy: Enables hierarchy identification even when a parent
	 * domain vanishes.  This is needed for the ptrace protection.
	 */
	struct landlock_hierarchy *hierarchy;
	union {
		/**
		 * @work_free: Enables to free a ruleset within a lockless
		 * section.  This is only used by
		 * landlock_put_ruleset_deferred() when @usage reaches zero.
		 * The fields @usage, @lock, @nb_layers, @nb_rules and
		 * @fs_access_mask are then unused.
		 */
		struct work_struct work_free;
		struct {
			/**
			 * @usage: Number of processes (i.e. domains) or file
			 * descriptors referencing this ruleset.
			 */
			refcount_t usage;
			/**
			 * @lock: Guards against concurrent modifications of
			 * @root, if @usage is greater than zero.
			 */
			struct mutex lock;
			/**
			 * @nb_rules: Number of non-overlapping (i.e. not for
			 * the same object) rules in this ruleset.
			 */
			u32 nb_rules;
			/**
			 * @nb_layers: Number of layers which are used in this
			 * ruleset.  This enables to check that all the layers
			 * allow an access request.  A value of 0 identify a
			 * non-merged ruleset (i.e. not a domain).
			 */
			u32 nb_layers;
			/**
			 * @fs_access_mask: Contains the subset of filesystem
			 * actions which are restricted by a ruleset.  This is
			 * used when merging rulesets and for userspace
			 * backward compatibility (i.e. future-proof).  Set
			 * once and never changed for the lifetime of the
			 * ruleset.
			 */
			u32 fs_access_mask;
		};
	};
};

struct landlock_ruleset *landlock_create_ruleset(const u32 fs_access_mask);

void landlock_put_ruleset(struct landlock_ruleset *const ruleset);
void landlock_put_ruleset_deferred(struct landlock_ruleset *const ruleset);

int landlock_insert_rule(struct landlock_ruleset *const ruleset,
		struct landlock_rule *const rule, const bool is_merge);

struct landlock_ruleset *landlock_merge_ruleset(
		struct landlock_ruleset *const parent,
		struct landlock_ruleset *const ruleset);

const struct landlock_rule *landlock_find_rule(
		const struct landlock_ruleset *const ruleset,
		const struct landlock_object *const object);

static inline void landlock_get_ruleset(struct landlock_ruleset *const ruleset)
{
	if (ruleset)
		refcount_inc(&ruleset->usage);
}

#endif /* _SECURITY_LANDLOCK_RULESET_H */
