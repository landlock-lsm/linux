/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Object and rule management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_OBJECT_H
#define _SECURITY_LANDLOCK_OBJECT_H

#include <linux/compiler_types.h>
#include <linux/list.h>
#include <linux/poison.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>

struct landlock_access {
	/*
	 * @self: Bitfield of allowed actions on the kernel object.  They are
	 * relative to the object type (e.g. LANDLOCK_ACTION_FS_READ).
	 */
	u32 self;
	/*
	 * @beneath: Same as @self, but for the child objects (e.g. a file in a
	 * directory).
	 */
	u32 beneath;
};

struct landlock_rule {
	struct landlock_access access;
	/*
	 * @list: Linked list with other rules tied to the same object, which
	 * enable to manage their lifetimes.  This is also used to identify if
	 * a rule is still valid, thanks to landlock_rule_is_disabled(), which
	 * is important in the matching process because the original object
	 * address might have been recycled.
	 */
	struct list_head list;
	union {
		/*
		 * @usage: Number of rulesets pointing to this rule.  This
		 * field is never used by RCU readers.
		 */
		refcount_t usage;
		struct rcu_head rcu_free;
	};
};

enum landlock_object_type {
	LANDLOCK_OBJECT_INODE = 1,
};

struct landlock_object {
	/*
	 * @usage: Main usage counter, used to tie an object to it's underlying
	 * object (i.e. create a lifetime) and potentially add new rules.
	 */
	refcount_t usage;
	/*
	 * @cleaners: Usage counter used to free a rule from @rules (thanks to
	 * put_rule()).  Enables to get a reference to this object until it
	 * really become freed.  Cf. put_object().
	 */
	refcount_t cleaners;
	union {
		/*
		 * The use of this struct is controlled by @usage and
		 * @cleaners, which makes it safe to union it with @rcu_free.
		 */
		struct {
			/*
			 * @underlying_object: Used when cleaning up an object
			 * and to mark an object as tied to its underlying
			 * kernel structure.  It must then be atomically read
			 * using READ_ONCE().
			 *
			 * The one who clear @underlying_object must:
			 * 1. clear the object self-reference and
			 * 2. decrement @usage (and potentially free the
			 *    object).
			 *
			 * Cf. clean_object().
			 */
			void *underlying_object;
			/*
			 * @type: Only used when cleaning up an object.
			 */
			enum landlock_object_type type;
			spinlock_t lock;
			/*
			 * @rules: List of struct landlock_rule linked with
			 * their "list" field.  This list is only accessed when
			 * updating the list (to be able to clean up later)
			 * while holding @lock.
			 */
			struct list_head rules;
		};
		struct rcu_head rcu_free;
	};
};

void landlock_put_rule(struct landlock_object *object,
		struct landlock_rule *rule);

void landlock_release_object(struct landlock_object __rcu *rcu_object);

struct landlock_object *landlock_create_object(
		const enum landlock_object_type type, void *underlying_object);

struct landlock_object *landlock_get_object(struct landlock_object *object)
	__acquires(object->usage);

void landlock_put_object(struct landlock_object *object)
	__releases(object->usage);

void landlock_drop_object(struct landlock_object *object);

static inline bool landlock_rule_is_disabled(
		struct landlock_rule *rule)
{
	/*
	 * Disabling (i.e. unlinking) a landlock_rule is a one-way operation.
	 * It is not possible to re-enable such a rule, then there is no need
	 * for smp_load_acquire().
	 *
	 * LIST_POISON2 is set by list_del() and list_del_rcu().
	 */
	return !rule || READ_ONCE(rule->list.prev) == LIST_POISON2;
}

#endif /* _SECURITY_LANDLOCK_OBJECT_H */
