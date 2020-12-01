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
#include <linux/lockdep.h>
#include <linux/overflow.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "object.h"
#include "ruleset.h"

static struct landlock_ruleset *create_ruleset(void)
{
	struct landlock_ruleset *new_ruleset;

	new_ruleset = kzalloc(sizeof(*new_ruleset), GFP_KERNEL_ACCOUNT);
	if (!new_ruleset)
		return ERR_PTR(-ENOMEM);
	refcount_set(&new_ruleset->usage, 1);
	mutex_init(&new_ruleset->lock);
	new_ruleset->root = RB_ROOT;
	/*
	 * hierarchy = NULL
	 * nb_rules = 0
	 * nb_layers = 0
	 * fs_access_mask = 0
	 */
	return new_ruleset;
}

struct landlock_ruleset *landlock_create_ruleset(const u32 fs_access_mask)
{
	struct landlock_ruleset *new_ruleset;

	/* Informs about useless ruleset. */
	if (!fs_access_mask)
		return ERR_PTR(-ENOMSG);
	new_ruleset = create_ruleset();
	if (!IS_ERR(new_ruleset))
		new_ruleset->fs_access_mask = fs_access_mask;
	return new_ruleset;
}

static struct landlock_rule *create_rule(
		struct landlock_object *const object,
		const struct landlock_layer (*const layers)[],
		const u32 nb_layers,
		const struct landlock_layer *const new_layer)
{
	struct landlock_rule *new_rule;
	u32 new_nb_layers = nb_layers;

	if (new_layer)
		new_nb_layers++;
	if (WARN_ON_ONCE(new_nb_layers > LANDLOCK_MAX_NB_LAYERS))
		return ERR_PTR(-E2BIG);
	new_rule = kzalloc(struct_size(new_rule, layers, new_nb_layers),
			GFP_KERNEL_ACCOUNT);
	if (!new_rule)
		return ERR_PTR(-ENOMEM);
	RB_CLEAR_NODE(&new_rule->node);
	landlock_get_object(object);
	new_rule->object = object;
	new_rule->nb_layers = new_nb_layers;
	if (new_layer)
		/* Push a copy of @new_layer on the layer stack. */
		new_rule->layers[0] = *new_layer;
	/* Copies the original layer stack. */
	memcpy(&new_rule->layers[new_layer ? 1 : 0], layers,
			flex_array_size(new_rule, layers, nb_layers));
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

/**
 * insert_rule - Create and insert a rule in a ruleset
 *
 * @ruleset: The ruleset to be updated.
 * @object: The object to build the new rule with.  The underlying kernel
 *          object must be held by the caller.
 * @layers: One or multiple layers to be copied into the new rule.
 * @nb_layers: The number of @layers entries.

 * When user space requests to add a new rule to a ruleset, @layers only
 * contains one entry and this entry is not assigned to any level.  In this
 * case, the new rule will extend @ruleset, similarly to a boolean OR between
 * access rights.
 *
 * When merging a ruleset in a domain, or copying a domain, @layers will be
 * added to @ruleset as new constraints, similarly to a boolean AND between
 * access rights.
 */
static int insert_rule(struct landlock_ruleset *const ruleset,
		struct landlock_object *const object,
		const struct landlock_layer (*const layers)[],
		size_t nb_layers)
{
	struct rb_node **walker_node;
	struct rb_node *parent_node = NULL;
	struct landlock_rule *new_rule;

	might_sleep();
	lockdep_assert_held(&ruleset->lock);
	if (WARN_ON_ONCE(!object || !layers))
		return -ENOENT;
	walker_node = &(ruleset->root.rb_node);
	while (*walker_node) {
		struct landlock_rule *const this = rb_entry(*walker_node,
				struct landlock_rule, node);

		if (this->object != object) {
			parent_node = *walker_node;
			if (this->object < object)
				walker_node = &((*walker_node)->rb_right);
			else
				walker_node = &((*walker_node)->rb_left);
			continue;
		}

		/* Only a single-level layer should match an existing rule. */
		if (WARN_ON_ONCE(nb_layers != 1))
			return -EINVAL;

		/* If there is a matching rule, updates it. */
		if ((*layers)[0].level == 0) {
			/*
			 * Extends access rights when the request comes from
			 * landlock_add_rule(2), i.e. @ruleset is not a domain.
			 */
			if (WARN_ON_ONCE(this->nb_layers != 1))
				return -EINVAL;
			if (WARN_ON_ONCE(this->layers[0].level != 0))
				return -EINVAL;
			this->layers[0].access |= (*layers)[0].access;
			return 0;
		}

		if (WARN_ON_ONCE(this->layers[0].level == 0))
			return -EINVAL;

		/*
		 * Intersects access rights when it is a merge between a
		 * ruleset and a domain.
		 */
		new_rule = create_rule(object, &this->layers, this->nb_layers,
				&(*layers)[0]);
		if (IS_ERR(new_rule))
			return PTR_ERR(new_rule);
		rb_replace_node(&this->node, &new_rule->node, &ruleset->root);
		put_rule(this);
		return 0;
	}

	/* There is no match for @object. */
	if (ruleset->nb_rules == U32_MAX)
		return -E2BIG;
	new_rule = create_rule(object, layers, nb_layers, NULL);
	if (IS_ERR(new_rule))
		return PTR_ERR(new_rule);
	rb_link_node(&new_rule->node, parent_node, walker_node);
	rb_insert_color(&new_rule->node, &ruleset->root);
	ruleset->nb_rules++;
	return 0;
}

int landlock_insert_rule(struct landlock_ruleset *const ruleset,
		struct landlock_object *const object, const u32 access)
{
	struct landlock_layer layers[] = {{
		.access = access,
		/* When @level is zero, insert_rule() extends @ruleset. */
		.level = 0,
	}};

	return insert_rule(ruleset, object, &layers, ARRAY_SIZE(layers));
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
		return -EINVAL;

	/*
	 * The ruleset being modified (@dst) is locked first, then the ruleset
	 * being copied (@src).
	 */
	mutex_lock(&dst->lock);
	mutex_lock_nested(&src->lock, SINGLE_DEPTH_NESTING);
	/*
	 * Makes a new layer, but only increments the number of layers after
	 * the rules are inserted.
	 */
	if (dst->nb_layers == LANDLOCK_MAX_NB_LAYERS) {
		err = -E2BIG;
		goto out_unlock;
	}
	dst->fs_access_mask |= src->fs_access_mask;

	/* Merges the @src tree. */
	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
			&src->root, node) {
		struct landlock_layer layers[] = {{
			.level = dst->nb_layers + 1,
		}};

		if (WARN_ON_ONCE(walker_rule->nb_layers != 1)) {
			err = -EINVAL;
			goto out_unlock;
		}
		if (WARN_ON_ONCE(walker_rule->layers[0].level != 0)) {
			err = -EINVAL;
			goto out_unlock;
		}
		layers[0].access = walker_rule->layers[0].access;
		err = insert_rule(dst, walker_rule->object, &layers,
				ARRAY_SIZE(layers));
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
			GFP_KERNEL_ACCOUNT);
	if (!new_ruleset->hierarchy) {
		err = -ENOMEM;
		goto out_put_ruleset;
	}
	refcount_set(&new_ruleset->hierarchy->usage, 1);
	if (!parent)
		return new_ruleset;

	mutex_lock(&new_ruleset->lock);
	mutex_lock_nested(&parent->lock, SINGLE_DEPTH_NESTING);

	/* Copies the @parent tree. */
	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
			&parent->root, node) {
		err = insert_rule(new_ruleset, walker_rule->object,
				&walker_rule->layers, walker_rule->nb_layers);
		if (err)
			goto out_unlock;
	}
	new_ruleset->nb_layers = parent->nb_layers;
	new_ruleset->fs_access_mask = parent->fs_access_mask;
	if (WARN_ON_ONCE(!parent->hierarchy)) {
		err = -EINVAL;
		goto out_unlock;
	}
	get_hierarchy(parent->hierarchy);
	new_ruleset->hierarchy->parent = parent->hierarchy;

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

/**
 * landlock_merge_ruleset - Merge a ruleset with a domain
 *
 * @parent: Parent domain.
 * @ruleset: New ruleset to be merged.
 *
 * Returns the intersection of @parent and @ruleset, or returns @parent if
 * @ruleset is empty, or returns a duplicate of @ruleset if @parent is empty.
 */
struct landlock_ruleset *landlock_merge_ruleset(
		struct landlock_ruleset *const parent,
		struct landlock_ruleset *const ruleset)
{
	struct landlock_ruleset *new_dom;
	int err;

	might_sleep();
	/*
	 * Merging duplicates a ruleset, so a new ruleset cannot be
	 * the same as the parent, but they can have similar content.
	 */
	if (WARN_ON_ONCE(!ruleset || parent == ruleset)) {
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
