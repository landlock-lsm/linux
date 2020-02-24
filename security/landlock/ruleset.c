// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Ruleset management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <linux/bug.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "object.h"
#include "ruleset.h"

static struct landlock_ruleset *create_ruleset(void)
{
	struct landlock_ruleset *ruleset;

	ruleset = kzalloc(sizeof(*ruleset), GFP_KERNEL);
	if (!ruleset)
		return ERR_PTR(-ENOMEM);
	refcount_set(&ruleset->usage, 1);
	mutex_init(&ruleset->lock);
	atomic_set(&ruleset->nb_rules, 0);
	ruleset->root = RB_ROOT;
	return ruleset;
}

struct landlock_ruleset *landlock_create_ruleset(u64 fs_access_mask)
{
	struct landlock_ruleset *ruleset;

	/* Safely handles 32-bits conversion. */
	BUILD_BUG_ON(!__same_type(fs_access_mask, _LANDLOCK_ACCESS_FS_LAST));

	/* Checks content. */
	if ((fs_access_mask | _LANDLOCK_ACCESS_FS_MASK) !=
			_LANDLOCK_ACCESS_FS_MASK)
		return ERR_PTR(-EINVAL);
	/* Informs about useless ruleset. */
	if (!fs_access_mask)
		return ERR_PTR(-ENOMSG);
	ruleset = create_ruleset();
	if (!IS_ERR(ruleset))
		ruleset->fs_access_mask = fs_access_mask;
	return ruleset;
}

/*
 * The underlying kernel object must be held by the caller.
 */
static struct landlock_ruleset_elem *create_ruleset_elem(
		struct landlock_object *object)
{
	struct landlock_ruleset_elem *ruleset_elem;

	ruleset_elem = kzalloc(sizeof(*ruleset_elem), GFP_KERNEL);
	if (!ruleset_elem)
		return ERR_PTR(-ENOMEM);
	RB_CLEAR_NODE(&ruleset_elem->node);
	RCU_INIT_POINTER(ruleset_elem->ref.object, object);
	return ruleset_elem;
}

static struct landlock_rule *create_rule(struct landlock_object *object,
		struct landlock_access *access)
{
	struct landlock_rule *new_rule;

	if (WARN_ON_ONCE(!object))
		return ERR_PTR(-EFAULT);
	if (WARN_ON_ONCE(!access))
		return ERR_PTR(-EFAULT);
	new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule)
		return ERR_PTR(-ENOMEM);
	refcount_set(&new_rule->usage, 1);
	INIT_LIST_HEAD(&new_rule->list);
	new_rule->access = *access;

	spin_lock(&object->lock);
	list_add_tail(&new_rule->list, &object->rules);
	spin_unlock(&object->lock);
	return new_rule;
}

/*
 * An inserted rule can not be removed, only disabled (cf. struct
 * landlock_ruleset_elem).
 *
 * The underlying kernel object must be held by the caller.
 *
 * @rule: Allocated struct owned by this function. The caller must hold the
 * underlying kernel object (e.g., with a FD).
 */
int landlock_insert_ruleset_rule(struct landlock_ruleset *ruleset,
		struct landlock_object *object, struct landlock_access *access,
		struct landlock_rule *rule)
{
	struct rb_node **new;
	struct rb_node *parent = NULL;
	struct landlock_ruleset_elem *ruleset_elem;
	struct landlock_rule *new_rule;

	might_sleep();
	/* Accesses may be set when creating a new rule. */
	if (rule) {
		if (WARN_ON_ONCE(access))
			return -EINVAL;
	} else {
		if (WARN_ON_ONCE(!access))
			return -EFAULT;
	}

	lockdep_assert_held(&ruleset->lock);
	new = &(ruleset->root.rb_node);
	while (*new) {
		struct landlock_ruleset_elem *this = rb_entry(*new,
				struct landlock_ruleset_elem, node);
		uintptr_t this_object;
		struct landlock_rule *this_rule;
		struct landlock_access new_access;

		this_object = (uintptr_t)rcu_access_pointer(this->ref.object);
		if (this_object != (uintptr_t)object) {
			parent = *new;
			if (this_object < (uintptr_t)object)
				new = &((*new)->rb_right);
			else
				new = &((*new)->rb_left);
			continue;
		}

		/* Do not increment ruleset->nb_rules. */
		this_rule = rcu_dereference_protected(this->ref.rule,
				lockdep_is_held(&ruleset->lock));
		/*
		 * Checks if it is a new object with the same address as a
		 * previously disabled one.  There is no possible race
		 * condition because an object can not be disabled/deleted
		 * while being inserted in this tree.
		 */
		if (landlock_rule_is_disabled(this_rule)) {
			if (rule) {
				refcount_inc(&rule->usage);
				new_rule = rule;
			} else {
				/* Replace the previous rule with a new one. */
				new_rule = create_rule(object, access);
				if (IS_ERR(new_rule))
					return PTR_ERR(new_rule);
			}
			rcu_assign_pointer(this->ref.rule, new_rule);
			landlock_put_rule(object, this_rule);
			return 0;
		}

		/* this_rule is potentially enabled. */
		if (refcount_read(&this_rule->usage) == 1) {
			if (rule) {
				/* merge rule: intersection of access rights */
				this_rule->access.self &= rule->access.self;
				this_rule->access.beneath &=
					rule->access.beneath;
			} else {
				/* extend rule: union of access rights */
				this_rule->access.self |= access->self;
				this_rule->access.beneath |= access->beneath;
			}
			return 0;
		}

		/*
		 * If this_rule is shared with another ruleset, then create a
		 * new object rule.
		 */
		if (rule) {
			/* Merging a rule means an intersection of access. */
			new_access.self = this_rule->access.self &
				rule->access.self;
			new_access.beneath = this_rule->access.beneath &
				rule->access.beneath;
		} else {
			/* Extending a rule means a union of access. */
			new_access.self = this_rule->access.self |
				access->self;
			new_access.beneath = this_rule->access.self |
				access->beneath;
		}
		new_rule = create_rule(object, &new_access);
		if (IS_ERR(new_rule))
			return PTR_ERR(new_rule);
		rcu_assign_pointer(this->ref.rule, new_rule);
		landlock_put_rule(object, this_rule);
		return 0;
	}

	/* There is no match for @object. */
	ruleset_elem = create_ruleset_elem(object);
	if (IS_ERR(ruleset_elem))
		return PTR_ERR(ruleset_elem);
	if (rule) {
		refcount_inc(&rule->usage);
		new_rule = rule;
	} else {
		new_rule = create_rule(object, access);
		if (IS_ERR(new_rule)) {
			kfree(ruleset_elem);
			return PTR_ERR(new_rule);
		}
	}
	RCU_INIT_POINTER(ruleset_elem->ref.rule, new_rule);
	/*
	 * Because of the missing RCU context annotation in struct rb_node,
	 * Sparse emits a warning when encountering rb_link_node_rcu(), but
	 * this function call is still safe.
	 */
	rb_link_node_rcu(&ruleset_elem->node, parent, new);
	rb_insert_color(&ruleset_elem->node, &ruleset->root);
	atomic_inc(&ruleset->nb_rules);
	return 0;
}

static int merge_ruleset(struct landlock_ruleset *dst,
		struct landlock_ruleset *src)
{
	struct rb_node *node;
	int err = 0;

	might_sleep();
	if (!src)
		return 0;
	if (WARN_ON_ONCE(!dst))
		return -EFAULT;
	if (WARN_ON_ONCE(!dst->hierarchy))
		return -EINVAL;

	mutex_lock(&dst->lock);
	mutex_lock_nested(&src->lock, 1);
	dst->fs_access_mask |= src->fs_access_mask;
	for (node = rb_first(&src->root); node; node = rb_next(node)) {
		struct landlock_ruleset_elem *elem = rb_entry(node,
				struct landlock_ruleset_elem, node);
		struct landlock_object *object =
			rcu_dereference_protected(elem->ref.object,
					lockdep_is_held(&src->lock));
		struct landlock_rule *rule =
			rcu_dereference_protected(elem->ref.rule,
					lockdep_is_held(&src->lock));

		err = landlock_insert_ruleset_rule(dst, object, NULL, rule);
		if (err)
			goto out_unlock;
	}

out_unlock:
	mutex_unlock(&src->lock);
	mutex_unlock(&dst->lock);
	return err;
}

void landlock_get_ruleset(struct landlock_ruleset *ruleset)
{
	if (!ruleset)
		return;
	refcount_inc(&ruleset->usage);
}

static void put_hierarchy(struct landlock_hierarchy *hierarchy)
{
	if (hierarchy && refcount_dec_and_test(&hierarchy->usage))
		kfree(hierarchy);
}

static void put_ruleset(struct landlock_ruleset *ruleset)
{
	struct rb_node *orig;

	might_sleep();
	for (orig = rb_first(&ruleset->root); orig; orig = rb_next(orig)) {
		struct landlock_ruleset_elem *freeme;
		struct landlock_object *object;
		struct landlock_rule *rule;

		freeme = rb_entry(orig, struct landlock_ruleset_elem, node);
		object = rcu_dereference_protected(freeme->ref.object,
				refcount_read(&ruleset->usage) == 0);
		rule = rcu_dereference_protected(freeme->ref.rule,
				refcount_read(&ruleset->usage) == 0);
		landlock_put_rule(object, rule);
		kfree_rcu(freeme, rcu_free);
	}
	put_hierarchy(ruleset->hierarchy);
	kfree_rcu(ruleset, rcu_free);
}

void landlock_put_ruleset(struct landlock_ruleset *ruleset)
{
	might_sleep();
	if (ruleset && refcount_dec_and_test(&ruleset->usage))
		put_ruleset(ruleset);
}

static void put_ruleset_work(struct work_struct *work)
{
	struct landlock_ruleset *ruleset;

	ruleset = container_of(work, struct landlock_ruleset, work_put);
	/*
	 * Clean up rcu_free because of previous use through union work_put.
	 * ruleset->rcu_free.func is already NULLed by __rcu_reclaim().
	 */
	ruleset->rcu_free.next = NULL;
	put_ruleset(ruleset);
}

void landlock_put_ruleset_enqueue(struct landlock_ruleset *ruleset)
{
	if (ruleset && refcount_dec_and_test(&ruleset->usage)) {
		INIT_WORK(&ruleset->work_put, put_ruleset_work);
		schedule_work(&ruleset->work_put);
	}
}

static bool clean_ref(struct landlock_ref *ref)
{
	struct landlock_rule *rule;

	rule = rcu_dereference(ref->rule);
	if (!rule)
		return false;
	if (!landlock_rule_is_disabled(rule))
		return false;
	rcu_assign_pointer(ref->rule, NULL);
	/*
	 * landlock_put_rule() will not sleep because we already checked
	 * !landlock_rule_is_disabled(rule).
	 */
	landlock_put_rule(rcu_dereference(ref->object), rule);
	return true;
}

static void clean_ruleset(struct landlock_ruleset *ruleset)
{
	struct rb_node *node;

	if (!ruleset)
		return;
	/* We must lock the ruleset to not have a wrong nb_rules counter. */
	mutex_lock(&ruleset->lock);
	rcu_read_lock();
	for (node = rb_first(&ruleset->root); node; node = rb_next(node)) {
		struct landlock_ruleset_elem *elem = rb_entry(node,
				struct landlock_ruleset_elem, node);

		if (clean_ref(&elem->ref)) {
			rb_erase(&elem->node, &ruleset->root);
			kfree_rcu(elem, rcu_free);
			atomic_dec(&ruleset->nb_rules);
		}
	}
	rcu_read_unlock();
	mutex_unlock(&ruleset->lock);
}

/*
 * Creates a new ruleset, merged of @parent and @ruleset, or return @parent if
 * @ruleset is empty.  If @parent is empty, return a duplicate of @ruleset.
 *
 * @parent: Must not be modified (i.e. locked or read-only).
 */
struct landlock_ruleset *landlock_merge_ruleset(
		struct landlock_ruleset *parent,
		struct landlock_ruleset *ruleset)
{
	struct landlock_ruleset *new_dom;
	int err;

	might_sleep();
	/* Opportunistically put disabled rules. */
	clean_ruleset(ruleset);

	if (parent && WARN_ON_ONCE(!parent->hierarchy))
		return ERR_PTR(-EINVAL);
	if (!ruleset || atomic_read(&ruleset->nb_rules) == 0 ||
			parent == ruleset) {
		landlock_get_ruleset(parent);
		return parent;
	}

	new_dom = create_ruleset();
	if (IS_ERR(new_dom))
		return new_dom;
	new_dom->hierarchy = kzalloc(sizeof(*new_dom->hierarchy), GFP_KERNEL);
	if (!new_dom->hierarchy) {
		landlock_put_ruleset(new_dom);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&new_dom->hierarchy->usage, 1);

	if (parent) {
		new_dom->hierarchy->parent = parent->hierarchy;
		refcount_inc(&parent->hierarchy->usage);
		err = merge_ruleset(new_dom, parent);
		if (err) {
			landlock_put_ruleset(new_dom);
			return ERR_PTR(err);
		}
	}
	err = merge_ruleset(new_dom, ruleset);
	if (err) {
		landlock_put_ruleset(new_dom);
		return ERR_PTR(err);
	}
	return new_dom;
}

/*
 * The return pointer must only be used in a RCU-read block.
 */
const struct landlock_access *landlock_find_access(
		const struct landlock_ruleset *ruleset,
		const struct landlock_object *object)
{
	struct rb_node *node;

	WARN_ON_ONCE(!rcu_read_lock_held());
	if (!object)
		return NULL;
	node = ruleset->root.rb_node;
	while (node) {
		struct landlock_ruleset_elem *this = rb_entry(node,
				struct landlock_ruleset_elem, node);
		uintptr_t this_object =
			(uintptr_t)rcu_access_pointer(this->ref.object);

		if (this_object == (uintptr_t)object) {
			struct landlock_rule *rule;

			rule = rcu_dereference(this->ref.rule);
			if (!landlock_rule_is_disabled(rule))
				return &rule->access;
			return NULL;
		}
		if (this_object < (uintptr_t)object)
			node = node->rb_right;
		else
			node = node->rb_left;
	}
	return NULL;
}
