// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Object and rule management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 *
 * Principles and constraints of the object and rule management:
 * - Do not leak memory.
 * - Try as much as possible to free a memory allocation as soon as it is
 *   unused.
 * - Do not use global lock.
 * - Do not charge processes other than the one requesting a Landlock
 *   operation.
 */

#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/compiler_types.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "object.h"

struct landlock_object *landlock_create_object(
		const enum landlock_object_type type, void *underlying_object)
{
	struct landlock_object *object;

	if (WARN_ON_ONCE(!underlying_object))
		return NULL;
	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return NULL;
	refcount_set(&object->usage, 1);
	refcount_set(&object->cleaners, 1);
	spin_lock_init(&object->lock);
	INIT_LIST_HEAD(&object->rules);
	object->type = type;
	WRITE_ONCE(object->underlying_object, underlying_object);
	return object;
}

struct landlock_object *landlock_get_object(struct landlock_object *object)
	__acquires(object->usage)
{
	__acquire(object->usage);
	/*
	 * If @object->usage equal 0, then it will be ignored by writers, and
	 * underlying_object->object may be replaced, but this is not an issue
	 * for release_object().
	 */
	if (object && refcount_inc_not_zero(&object->usage)) {
		/*
		 * It should not be possible to get a reference to an object if
		 * its underlying object is being terminated (e.g. with
		 * landlock_release_object()), because an object is only
		 * modifiable through such underlying object.  This is not the
		 * case with landlock_get_object_cleaner().
		 */
		WARN_ON_ONCE(!READ_ONCE(object->underlying_object));
		return object;
	}
	return NULL;
}

static struct landlock_object *get_object_cleaner(
		struct landlock_object *object)
	__acquires(object->cleaners)
{
	__acquire(object->cleaners);
	if (object && refcount_inc_not_zero(&object->cleaners))
		return object;
	return NULL;
}

/*
 * There is two cases when an object should be free and the reference to the
 * underlying object should be put:
 * - when the last rule tied to this object is removed, which is handled by
 *   landlock_put_rule() and then release_object();
 * - when the object is being terminated (e.g. no more reference to an inode),
 *   which is handled by landlock_put_object().
 */
static void put_object_free(struct landlock_object *object)
	__releases(object->cleaners)
{
	__release(object->cleaners);
	if (!refcount_dec_and_test(&object->cleaners))
		return;
	WARN_ON_ONCE(refcount_read(&object->usage));
	/*
	 * Ensures a safe use of @object in the RCU block from
	 * landlock_put_rule().
	 */
	kfree_rcu(object, rcu_free);
}

/*
 * Destroys a newly created and useless object.
 */
void landlock_drop_object(struct landlock_object *object)
{
	if (WARN_ON_ONCE(!refcount_dec_and_test(&object->usage)))
		return;
	__acquire(object->cleaners);
	put_object_free(object);
}

/*
 * Puts the underlying object (e.g. inode) if it is the first request to
 * release @object, without calling landlock_put_object().
 *
 * Return true if this call effectively marks @object as released, false
 * otherwise.
 */
static bool release_object(struct landlock_object *object)
	__releases(&object->lock)
{
	void *underlying_object;

	lockdep_assert_held(&object->lock);

	underlying_object = xchg(&object->underlying_object, NULL);
	spin_unlock(&object->lock);
	might_sleep();
	if (!underlying_object)
		return false;

	switch (object->type) {
	case LANDLOCK_OBJECT_INODE:
		break;
	default:
		WARN_ON_ONCE(1);
	}
	return true;
}

static void put_object_cleaner(struct landlock_object *object)
	__releases(object->cleaners)
{
	/* Let's try an early lockless check. */
	if (list_empty(&object->rules) &&
			READ_ONCE(object->underlying_object)) {
		/*
		 * Puts @object if there is no rule tied to it and the
		 * remaining user is the underlying object.  This check is
		 * atomic because @object->rules and @object->underlying_object
		 * are protected by @object->lock.
		 */
		spin_lock(&object->lock);
		if (list_empty(&object->rules) &&
				READ_ONCE(object->underlying_object) &&
				refcount_dec_if_one(&object->usage)) {
			/*
			 * Releases @object, in place of
			 * landlock_release_object().
			 *
			 * @object is already empty, implying that all its
			 * previous rules are already disabled.
			 *
			 * Unbalance the @object->cleaners counter to reflect
			 * the underlying object release.
			 */
			if (!WARN_ON_ONCE(!release_object(object))) {
				__acquire(object->cleaners);
				put_object_free(object);
			}
		} else {
			spin_unlock(&object->lock);
		}
	}
	put_object_free(object);
}

/*
 * Putting an object is easy when the object is being terminated, but it is
 * much more tricky when the reason is that there is no more rule tied to this
 * object.  Indeed, new rules could be added at the same time.
 */
void landlock_put_object(struct landlock_object *object)
	__releases(object->usage)
{
	struct landlock_object *object_cleaner;

	__release(object->usage);
	might_sleep();
	if (!object)
		return;
	/*
	 * Guards against concurrent termination to be able to terminate
	 * @object if it is empty and not referenced by another rule-appender
	 * other than the underlying object.
	 */
	object_cleaner = get_object_cleaner(object);
	if (WARN_ON_ONCE(!object_cleaner)) {
		__release(object->cleaners);
		return;
	}
	/*
	 * Decrements @object->usage and if it reach zero, also decrement
	 * @object->cleaners.  If both reach zero, then release and free
	 * @object.
	 */
	if (refcount_dec_and_test(&object->usage)) {
		struct landlock_rule *rule_walker, *rule_walker2;

		spin_lock(&object->lock);
		/*
		 * Disables all the rules tied to @object when it is forbidden
		 * to add new rule but still allowed to remove them with
		 * landlock_put_rule().  This is crucial to be able to safely
		 * free a rule according to landlock_rule_is_disabled().
		 */
		list_for_each_entry_safe(rule_walker, rule_walker2,
				&object->rules, list)
			list_del_rcu(&rule_walker->list);

		/*
		 * Releases @object if it is not already released (e.g. with
		 * landlock_release_object()).
		 */
		release_object(object);
		/*
		 * Unbalances the @object->cleaners counter to reflect the
		 * underlying object release.
		 */
		__acquire(object->cleaners);
		put_object_free(object);
	}
	put_object_cleaner(object_cleaner);
}

void landlock_put_rule(struct landlock_object *object,
		struct landlock_rule *rule)
{
	if (!rule)
		return;
	WARN_ON_ONCE(!object);
	/*
	 * Guards against a concurrent @object self-destruction with
	 * landlock_put_object() or put_object_cleaner().
	 */
	rcu_read_lock();
	if (landlock_rule_is_disabled(rule)) {
		rcu_read_unlock();
		if (refcount_dec_and_test(&rule->usage))
			kfree_rcu(rule, rcu_free);
		return;
	}
	if (refcount_dec_and_test(&rule->usage)) {
		struct landlock_object *safe_object;

		/*
		 * Now, @rule may still be enabled, or in the process of being
		 * untied to @object by put_object_cleaner().  However, we know
		 * that @object will not be freed until rcu_read_unlock() and
		 * until @object->cleaners reach zero.  Furthermore, we may not
		 * be the only one willing to free a @rule linked with @object.
		 * If we succeed to hold @object with get_object_cleaner(), we
		 * know that until put_object_cleaner(), we can safely use
		 * @object to remove @rule.
		 */
		safe_object = get_object_cleaner(object);
		rcu_read_unlock();
		if (!safe_object) {
			__release(safe_object->cleaners);
			/*
			 * We can safely free @rule because it is already
			 * removed from @object's list.
			 */
			WARN_ON_ONCE(!landlock_rule_is_disabled(rule));
			kfree_rcu(rule, rcu_free);
		} else {
			spin_lock(&safe_object->lock);
			if (!landlock_rule_is_disabled(rule))
				list_del(&rule->list);
			spin_unlock(&safe_object->lock);
			kfree_rcu(rule, rcu_free);
			put_object_cleaner(safe_object);
		}
	} else {
		rcu_read_unlock();
	}
	/*
	 * put_object_cleaner() might sleep, but it is only reachable if
	 * !landlock_rule_is_disabled().  Therefore, clean_ref() can not sleep.
	 */
	might_sleep();
}

void landlock_release_object(struct landlock_object __rcu *rcu_object)
{
	struct landlock_object *object;

	if (!rcu_object)
		return;
	rcu_read_lock();
	object = get_object_cleaner(rcu_dereference(rcu_object));
	rcu_read_unlock();
	if (unlikely(!object)) {
		__release(object->cleaners);
		return;
	}
	/*
	 * Makes sure that the underlying object never point to a freed object
	 * by firstly releasing the object (i.e. NULL the reference to it) to
	 * be sure no one could get a new reference to it while it is being
	 * terminated.  Secondly, put the object globally (e.g. for the
	 * super-block).
	 *
	 * This can run concurrently with put_object_cleaner(), which may try
	 * to release @object as well.
	 */
	spin_lock(&object->lock);
	if (release_object(object)) {
		/*
		 * Unbalances the object to reflect the underlying object
		 * release.
		 */
		__acquire(object->usage);
		landlock_put_object(object);
	}
	/*
	 * If a concurrent thread is adding a new rule, the object will be free
	 * at the end of this rule addition, otherwise it will be free with the
	 * following put_object_cleaner() or a remaining one.
	 */
	put_object_cleaner(object);
}
