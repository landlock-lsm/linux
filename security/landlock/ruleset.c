// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Ruleset management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/compiler_types.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/rbtree.h>
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
	/*
	 * root = RB_ROOT
	 * hierarchy = NULL
	 * nb_rules = 0
	 * nb_layers = 0
	 * fs_access_mask = 0
	 */
	return ruleset;
}

struct landlock_ruleset *landlock_create_ruleset(const u32 fs_access_mask)
{
	struct landlock_ruleset *ruleset;

	/* Informs about useless ruleset. */
	if (!fs_access_mask)
		return ERR_PTR(-ENOMSG);
	ruleset = create_ruleset();
	if (!IS_ERR(ruleset))
		ruleset->fs_access_mask = fs_access_mask;
	return ruleset;
}

static struct landlock_rule *duplicate_rule(struct landlock_rule *const src)
{
	struct landlock_rule *new_rule;

	new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule)
		return ERR_PTR(-ENOMEM);
	RB_CLEAR_NODE(&new_rule->node);
	landlock_get_object(src->object);
	new_rule->object = src->object;
	new_rule->access = src->access;
	new_rule->layers = src->layers;
	return new_rule;
}

static void put_rule(struct landlock_rule *const rule)
{
	might_sleep();
	if (!rule)
		return;
	landlock_put_object(rule->object);
	kfree(rule);
}

/*
 * Assumptions:
 * - An inserted rule can not be removed.
 * - The underlying kernel object must be held by the caller.
 *
 * @rule: Read-only payload to be inserted (not own by this function).
 * @is_merge: If true, intersects access rights and updates the rule's layers
 * (e.g. merge two rulesets), else do a union of access rights and keep the
 * rule's layers (e.g. extend a ruleset)
 */
int landlock_insert_rule(struct landlock_ruleset *const ruleset,
		struct landlock_rule *const rule, const bool is_merge)
{
	struct rb_node **walker_node;
	struct rb_node *parent_node = NULL;
	struct landlock_rule *new_rule;

	might_sleep();
	lockdep_assert_held(&ruleset->lock);
	walker_node = &(ruleset->root.rb_node);
	while (*walker_node) {
		struct landlock_rule *const this = rb_entry(*walker_node,
				struct landlock_rule, node);

		if (this->object != rule->object) {
			parent_node = *walker_node;
			if (this->object < rule->object)
				walker_node = &((*walker_node)->rb_right);
			else
				walker_node = &((*walker_node)->rb_left);
			continue;
		}

		/* If there is a matching rule, updates it. */
		if (is_merge) {
			/* Intersects access rights. */
			this->access &= rule->access;

			/* Updates the rule layers with the next one. */
			this->layers |= BIT_ULL(ruleset->nb_layers);
		} else {
			/* Extends access rights. */
			this->access |= rule->access;
		}
		return 0;
	}

	/* There is no match for @rule->object. */
	if (ruleset->nb_rules == U32_MAX)
		return -E2BIG;
	new_rule = duplicate_rule(rule);
	if (IS_ERR(new_rule))
		return PTR_ERR(new_rule);
	if (is_merge)
		/* Sets the rule layer to the next one. */
		new_rule->layers = BIT_ULL(ruleset->nb_layers);
	rb_link_node(&new_rule->node, parent_node, walker_node);
	rb_insert_color(&new_rule->node, &ruleset->root);
	ruleset->nb_rules++;
	return 0;
}

static inline void get_hierarchy(struct landlock_hierarchy *const hierarchy)
{
	if (hierarchy)
		refcount_inc(&hierarchy->usage);
}

static void put_hierarchy(struct landlock_hierarchy *hierarchy)
{
	while (hierarchy && refcount_dec_and_test(&hierarchy->usage)) {
		const struct landlock_hierarchy *const freeme = hierarchy;

		hierarchy = hierarchy->parent;
		kfree(freeme);
	}
}

static int merge_ruleset(struct landlock_ruleset *const dst,
		struct landlock_ruleset *const src)
{
	struct landlock_rule *walker_rule, *next_rule;
	int err = 0;

	might_sleep();
	if (!src)
		return 0;
	/* Only merge into a domain. */
	if (WARN_ON_ONCE(!dst || !dst->hierarchy))
		return -EFAULT;

	mutex_lock(&dst->lock);
	mutex_lock_nested(&src->lock, 1);
	/*
	 * Makes a new layer, but only increments the number of layers after
	 * the rules are inserted.
	 */
	if (dst->nb_layers == sizeof(walker_rule->layers) * BITS_PER_BYTE) {
		err = -E2BIG;
		goto out_unlock;
	}
	dst->fs_access_mask |= src->fs_access_mask;

	/* Merges the @src tree. */
	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
			&src->root, node) {
		err = landlock_insert_rule(dst, walker_rule, true);
		if (err)
			goto out_unlock;
	}
	dst->nb_layers++;

out_unlock:
	mutex_unlock(&src->lock);
	mutex_unlock(&dst->lock);
	return err;
}

static struct landlock_ruleset *inherit_ruleset(
		struct landlock_ruleset *const parent)
{
	struct landlock_rule *walker_rule, *next_rule;
	struct landlock_ruleset *new_ruleset;
	int err = 0;

	might_sleep();
	new_ruleset = create_ruleset();
	if (IS_ERR(new_ruleset))
		return new_ruleset;

	new_ruleset->hierarchy = kzalloc(sizeof(*new_ruleset->hierarchy),
			GFP_KERNEL);
	if (!new_ruleset->hierarchy) {
		err = -ENOMEM;
		goto out_put_ruleset;
	}
	refcount_set(&new_ruleset->hierarchy->usage, 1);
	if (!parent)
		return new_ruleset;

	mutex_lock(&new_ruleset->lock);
	mutex_lock_nested(&parent->lock, 1);
	new_ruleset->nb_layers = parent->nb_layers;
	new_ruleset->fs_access_mask = parent->fs_access_mask;
	WARN_ON_ONCE(!parent->hierarchy);
	get_hierarchy(parent->hierarchy);
	new_ruleset->hierarchy->parent = parent->hierarchy;

	/* Copies the @parent tree. */
	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
			&parent->root, node) {
		err = landlock_insert_rule(new_ruleset, walker_rule, false);
		if (err)
			goto out_unlock;
	}
	mutex_unlock(&parent->lock);
	mutex_unlock(&new_ruleset->lock);
	return new_ruleset;

out_unlock:
	mutex_unlock(&parent->lock);
	mutex_unlock(&new_ruleset->lock);

out_put_ruleset:
	landlock_put_ruleset(new_ruleset);
	return ERR_PTR(err);
}

static void free_ruleset(struct landlock_ruleset *const ruleset)
{
	struct landlock_rule *freeme, *next;

	might_sleep();
	rbtree_postorder_for_each_entry_safe(freeme, next, &ruleset->root,
			node)
		put_rule(freeme);
	put_hierarchy(ruleset->hierarchy);
	kfree(ruleset);
}

void landlock_put_ruleset(struct landlock_ruleset *const ruleset)
{
	might_sleep();
	if (ruleset && refcount_dec_and_test(&ruleset->usage))
		free_ruleset(ruleset);
}

static void free_ruleset_work(struct work_struct *const work)
{
	struct landlock_ruleset *ruleset;

	ruleset = container_of(work, struct landlock_ruleset, work_free);
	free_ruleset(ruleset);
}

void landlock_put_ruleset_deferred(struct landlock_ruleset *const ruleset)
{
	if (ruleset && refcount_dec_and_test(&ruleset->usage)) {
		INIT_WORK(&ruleset->work_free, free_ruleset_work);
		schedule_work(&ruleset->work_free);
	}
}

/*
 * Creates a new transition domain, intersection of @parent and @ruleset, or
 * return @parent if @ruleset is empty.  If @parent is empty, returns a
 * duplicate of @ruleset.
 */
struct landlock_ruleset *landlock_merge_ruleset(
		struct landlock_ruleset *const parent,
		struct landlock_ruleset *const ruleset)
{
	struct landlock_ruleset *new_dom;
	int err;

	might_sleep();
	/*
	 * Rulesets without rule must be rejected at the syscall step to inform
	 * user space.  Merging duplicates a ruleset, so a new ruleset can't be
	 * the same as the parent, but they can have similar content.
	 */
	if (WARN_ON_ONCE(!ruleset || ruleset->nb_rules == 0 ||
				parent == ruleset)) {
		landlock_get_ruleset(parent);
		return parent;
	}

	new_dom = inherit_ruleset(parent);
	if (IS_ERR(new_dom))
		return new_dom;

	err = merge_ruleset(new_dom, ruleset);
	if (err) {
		landlock_put_ruleset(new_dom);
		return ERR_PTR(err);
	}
	return new_dom;
}

/*
 * The returned access has the same lifetime as @ruleset.
 */
const struct landlock_rule *landlock_find_rule(
		const struct landlock_ruleset *const ruleset,
		const struct landlock_object *const object)
{
	const struct rb_node *node;

	if (!object)
		return NULL;
	node = ruleset->root.rb_node;
	while (node) {
		struct landlock_rule *this = rb_entry(node,
				struct landlock_rule, node);

		if (this->object == object)
			return this;
		if (this->object < object)
			node = node->rb_right;
		else
			node = node->rb_left;
	}
	return NULL;
}
