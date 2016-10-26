/*
 * Landlock LSM - seccomp and cgroups managers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/page.h> /* PAGE_SIZE */
#include <linux/atomic.h> /* atomic_*(), smp_store_release() */
#include <linux/bpf.h> /* bpf_prog_put() */
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/kernel.h> /* round_up() */
#include <linux/landlock.h>
#include <linux/slab.h> /* alloc(), kfree() */
#include <linux/types.h> /* atomic_t */

#include "common.h"

static void put_landlock_rule(struct landlock_rule *rule)
{
	struct landlock_rule *orig = rule;

	/* clean up single-reference branches iteratively */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct landlock_rule *freeme = orig;

		bpf_prog_put(orig->prog);
		orig = orig->prev;
		kfree(freeme);
	}
}

static void put_landlock_node(struct landlock_node *node)
{
	struct landlock_node *orig = node;

	/* clean up single-reference branches iteratively */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct landlock_node *freeme = orig;

		put_landlock_rule(orig->rule);
		orig = orig->prev;
		kfree(freeme);
	}
}

void put_landlock_hooks(struct landlock_hooks *hooks)
{
	if (hooks && atomic_dec_and_test(&hooks->usage)) {
		size_t i;

		/* XXX: Do we need to use lockless_dereference() here? */
		for (i = 0; i < ARRAY_SIZE(hooks->nodes); i++) {
			if (!hooks->nodes[i])
				continue;
			/* Are we the owner of this node? */
			if (hooks->nodes[i]->owner == &hooks->nodes[i])
				hooks->nodes[i]->owner = NULL;
			put_landlock_node(hooks->nodes[i]);
		}
		kfree(hooks);
	}
}

static struct landlock_hooks *new_raw_landlock_hooks(void)
{
	struct landlock_hooks *ret;

	/* array filled with NULL values */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);
	atomic_set(&ret->usage, 1);
	return ret;
}

static struct landlock_hooks *new_filled_landlock_hooks(void)
{
	size_t i;
	struct landlock_hooks *ret;

	ret = new_raw_landlock_hooks();
	if (IS_ERR(ret))
		return ret;
	/*
	 * We need to initially allocate every nodes to be able to update the
	 * rules they are pointing to, across every (future) children of the
	 * current task.
	 */
	for (i = 0; i < ARRAY_SIZE(ret->nodes); i++) {
		struct landlock_node *node;

		node = kzalloc(sizeof(*node), GFP_KERNEL);
		if (!node)
			goto put_hooks;
		atomic_set(&node->usage, 1);
		/* We are the owner of this node. */
		node->owner = &ret->nodes[i];
		ret->nodes[i] = node;
	}
	return ret;

put_hooks:
	put_landlock_hooks(ret);
	return ERR_PTR(-ENOMEM);
}

static void add_landlock_rule(struct landlock_hooks *hooks,
		struct landlock_rule *rule)
{
	/* subtype.landlock_rule.hook > 0 for loaded programs */
	u32 hook_idx = get_index(rule->prog->subtype.landlock_rule.hook);

	rule->prev = hooks->nodes[hook_idx]->rule;
	WARN_ON(atomic_read(&rule->usage));
	atomic_set(&rule->usage, 1);
	/* do not increment the previous rule usage */
	smp_store_release(&hooks->nodes[hook_idx]->rule, rule);
}

/* Limit Landlock hooks to 256KB. */
#define LANDLOCK_HOOKS_MAX_PAGES (1 << 6)

/**
 * landlock_append_prog - attach a Landlock program to @current_hooks
 *
 * @current_hooks: landlock_hooks pointer, must be locked (if needed) to
 *                 prevent a concurrent put/free. This pointer must not be
 *                 freed after the call.
 * @prog: non-NULL Landlock program to append to @current_hooks. @prog will be
 *        owned by landlock_append_prog() and freed if an error happened.
 *
 * Return @current_hooks or a new pointer when OK. Return a pointer error
 * otherwise.
 */
static struct landlock_hooks *landlock_append_prog(
		struct landlock_hooks *current_hooks, struct bpf_prog *prog)
{
	struct landlock_hooks *new_hooks = current_hooks;
	unsigned long pages;
	struct landlock_rule *rule;
	u32 hook_idx;

	if (prog->type != BPF_PROG_TYPE_LANDLOCK) {
		new_hooks = ERR_PTR(-EINVAL);
		goto put_prog;
	}

	/* validate memory size allocation */
	pages = prog->pages;
	if (current_hooks) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(current_hooks->nodes); i++) {
			struct landlock_node *walker_n;

			for (walker_n = current_hooks->nodes[i];
					walker_n;
					walker_n = walker_n->prev) {
				struct landlock_rule *walker_r;

				for (walker_r = walker_n->rule;
						walker_r;
						walker_r = walker_r->prev)
					pages += walker_r->prog->pages;
			}
		}
		/* count a struct landlock_hooks if we need to allocate one */
		if (atomic_read(&current_hooks->usage) != 1)
			pages += round_up(sizeof(*current_hooks), PAGE_SIZE) /
				PAGE_SIZE;
	}
	if (pages > LANDLOCK_HOOKS_MAX_PAGES) {
		new_hooks = ERR_PTR(-E2BIG);
		goto put_prog;
	}

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		new_hooks = ERR_PTR(-ENOMEM);
		goto put_prog;
	}
	rule->prog = prog;

	/* subtype.landlock_rule.hook > 0 for loaded programs */
	hook_idx = get_index(rule->prog->subtype.landlock_rule.hook);

	if (!current_hooks) {
		/* add a new landlock_hooks, if needed */
		new_hooks = new_filled_landlock_hooks();
		if (IS_ERR(new_hooks))
			goto put_rule;
		add_landlock_rule(new_hooks, rule);
	} else {
		if (new_hooks->nodes[hook_idx]->owner == &new_hooks->nodes[hook_idx]) {
			/* We are the owner, we can then update the node. */
			add_landlock_rule(new_hooks, rule);
		} else if (atomic_read(&current_hooks->usage) == 1) {
			WARN_ON(new_hooks->nodes[hook_idx]->owner);
			/*
			 * We can become the new owner if no other task use it.
			 * This avoid an unnecessary allocation.
			 */
			new_hooks->nodes[hook_idx]->owner =
				&new_hooks->nodes[hook_idx];
			add_landlock_rule(new_hooks, rule);
		} else {
			/*
			 * We are not the owner, we need to fork current_hooks
			 * and then add a new node.
			 */
			struct landlock_node *node;
			size_t i;

			node = kmalloc(sizeof(*node), GFP_KERNEL);
			if (!node) {
				new_hooks = ERR_PTR(-ENOMEM);
				goto put_rule;
			}
			atomic_set(&node->usage, 1);
			/* set the previous node after the new_hooks allocation */
			node->prev = NULL;
			/* do not increment the previous node usage */
			node->owner = &new_hooks->nodes[hook_idx];
			/* rule->prev is already NULL */
			atomic_set(&rule->usage, 1);
			node->rule = rule;

			new_hooks = new_raw_landlock_hooks();
			if (IS_ERR(new_hooks)) {
				/* put the rule as well */
				put_landlock_node(node);
				return ERR_PTR(-ENOMEM);
			}
			for (i = 0; i < ARRAY_SIZE(new_hooks->nodes); i++) {
				new_hooks->nodes[i] = lockless_dereference(current_hooks->nodes[i]);
				if (i == hook_idx)
					node->prev = new_hooks->nodes[i];
				if (!WARN_ON(!new_hooks->nodes[i]))
					atomic_inc(&new_hooks->nodes[i]->usage);
			}
			new_hooks->nodes[hook_idx] = node;

			/*
			 * @current_hooks will not be freed here because it's usage
			 * field is > 1. It is only prevented to be freed by another
			 * subject thanks to the caller of landlock_append_prog() which
			 * should be locked if needed.
			 */
			put_landlock_hooks(current_hooks);
		}
	}
	return new_hooks;

put_prog:
	bpf_prog_put(prog);
	return new_hooks;

put_rule:
	put_landlock_rule(rule);
	return new_hooks;
}
