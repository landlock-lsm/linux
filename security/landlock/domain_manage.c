// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - domain management
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "common.h"
#include "domain_manage.h"

void landlock_get_domain(struct landlock_domain *domain)
{
	if (!domain)
		return;
	refcount_inc(&domain->usage);
}

static void put_prog_list(struct landlock_prog_list *prog_list)
{
	struct landlock_prog_list *orig = prog_list;

	/* clean up single-reference branches iteratively */
	while (orig && refcount_dec_and_test(&orig->usage)) {
		struct landlock_prog_list *freeme = orig;

		if (orig->prog)
			bpf_prog_put(orig->prog);
		orig = orig->prev;
		kfree(freeme);
	}
}

void landlock_put_domain(struct landlock_domain *domain)
{
	if (domain && refcount_dec_and_test(&domain->usage)) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(domain->programs); i++)
			put_prog_list(domain->programs[i]);
		kfree(domain);
	}
}

static struct landlock_prog_list *create_prog_list(struct bpf_prog *prog)
{
	struct landlock_prog_list *new_list;

	if (WARN_ON(IS_ERR_OR_NULL(prog)))
		return ERR_PTR(-EFAULT);
	if (prog->type != BPF_PROG_TYPE_LANDLOCK_HOOK)
		return ERR_PTR(-EINVAL);
	prog = bpf_prog_inc(prog);
	if (IS_ERR(prog))
		return ERR_CAST(prog);
	new_list = kzalloc(sizeof(*new_list), GFP_KERNEL);
	if (!new_list) {
		bpf_prog_put(prog);
		return ERR_PTR(-ENOMEM);
	}
	new_list->prog = prog;
	refcount_set(&new_list->usage, 1);
	return new_list;
}

static struct landlock_domain *create_domain(struct bpf_prog *prog)
{
	struct landlock_domain *new_dom;
	struct landlock_prog_list *new_list;
	size_t hook;

	/* programs[] filled with NULL values */
	new_dom = kzalloc(sizeof(*new_dom), GFP_KERNEL);
	if (!new_dom)
		return ERR_PTR(-ENOMEM);
	refcount_set(&new_dom->usage, 1);
	new_list = create_prog_list(prog);
	if (IS_ERR(new_list)) {
		kfree(new_dom);
		return ERR_CAST(new_list);
	}
	hook = get_hook_index(get_hook_type(prog));
	new_dom->programs[hook] = new_list;
	return new_dom;
}

/**
 * landlock_prepend_prog - extend a Landlock domain with an eBPF program
 *
 * Prepend @prog to @domain if @prog is not already in @domain.
 *
 * @domain: domain to copy and extend with @prog. This domain must not be
 *          modified by another function than this one to guarantee domain
 *          immutability.
 * @prog: non-NULL Landlock program to prepend to a copy of @domain.  @prog
 *        will be owned by landlock_prepend_prog(). You can then call
 *        bpf_prog_put(@prog) after.
 *
 * Return a copy of @domain (with @prog prepended) when OK. Return a pointer
 * error otherwise.
 */
struct landlock_domain *landlock_prepend_prog(struct landlock_domain *domain,
		struct bpf_prog *prog)
{
	struct landlock_prog_list *walker;
	struct landlock_domain *new_dom;
	size_t i, hook;

	if (WARN_ON(!prog))
		return ERR_PTR(-EFAULT);
	if (prog->type != BPF_PROG_TYPE_LANDLOCK_HOOK)
		return ERR_PTR(-EINVAL);

	if (!domain)
		return create_domain(prog);

	hook = get_hook_index(get_hook_type(prog));
	/* check for similar program */
	for (walker = domain->programs[hook]; walker;
			walker = walker->prev) {
		/* don't allow duplicate programs */
		if (prog == walker->prog)
			return ERR_PTR(-EEXIST);
	}

	new_dom = create_domain(prog);
	if (IS_ERR(new_dom))
		return new_dom;

	/* copy @domain (which is guarantee to be immutable) */
	for (i = 0; i < ARRAY_SIZE(new_dom->programs); i++) {
		struct landlock_prog_list *current_list;
		struct landlock_prog_list **new_list;

		current_list = domain->programs[i];
		if (!current_list)
			continue;
		refcount_inc(&current_list->usage);
		new_list = &new_dom->programs[i];
		if (*new_list)
			new_list = &(*new_list)->prev;
		/* do not increment usage */
		*new_list = current_list;
	}
	return new_dom;
}
