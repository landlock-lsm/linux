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

void landlock_get_domain(struct landlock_domain *dom)
{
	if (!dom)
		return;
	refcount_inc(&dom->usage);
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

static struct landlock_prog_list *new_prog_list(struct bpf_prog *prog)
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

/* @prog can legitimately be NULL */
static struct landlock_domain *new_landlock_domain(struct bpf_prog *prog)
{
	struct landlock_domain *new_domain;
	struct landlock_prog_list *new_list;
	size_t hook;

	/* programs[] filled with NULL values */
	new_domain = kzalloc(sizeof(*new_domain), GFP_KERNEL);
	if (!new_domain)
		return ERR_PTR(-ENOMEM);
	refcount_set(&new_domain->usage, 1);
	if (!prog)
		return new_domain;
	new_list = new_prog_list(prog);
	if (IS_ERR(new_list)) {
		kfree(new_domain);
		return ERR_CAST(new_list);
	}
	hook = get_hook_index(get_hook_type(prog));
	new_domain->programs[hook] = new_list;
	return new_domain;
}

/**
 * landlock_prepend_prog - attach a Landlock program to @current_domain
 *
 * Prepend @prog to @current_domain if @prog is not already in @current_domain.
 *
 * @current_domain: landlock_domain pointer which is garantee to not be
 *                  modified elsewhere. This pointer should not be used nor
 *                  put/freed after the call.
 * @prog: non-NULL Landlock program to prepend to @current_domain. @prog will
 *        be owned by landlock_prepend_prog(). You can then call
 *        bpf_prog_put(@prog) after.
 *
 * Return @current_domain or a new pointer when OK. Return a pointer error
 * otherwise.
 */
struct landlock_domain *landlock_prepend_prog(
		struct landlock_domain *current_domain,
		struct bpf_prog *prog)
{
	struct landlock_domain *oneref_domain;
	struct landlock_prog_list *new_list, *walker;
	size_t hook;

	if (WARN_ON(!prog))
		return ERR_PTR(-EFAULT);
	if (prog->type != BPF_PROG_TYPE_LANDLOCK_HOOK)
		return ERR_PTR(-EINVAL);

	/*
	 * Each domain contains an array of prog_list pointers.  If a domain is
	 * used by more than one credential, then this domain is first
	 * duplicated and then @prog is prepended to this new domain.  We then
	 * have the garantee that a domain is immutable when shared, and it can
	 * only be modified if it is referenced only once (by the modifier).
	 */
	if (!current_domain)
		return new_landlock_domain(prog);

	hook = get_hook_index(get_hook_type(prog));
	/* check for similar program */
	for (walker = current_domain->programs[hook]; walker;
			walker = walker->prev) {
		/* don't allow duplicate programs */
		if (prog == walker->prog)
			return ERR_PTR(-EEXIST);
	}

	new_list = new_prog_list(prog);
	if (IS_ERR(new_list))
		return ERR_CAST(new_list);

	/* duplicate the domain if not referenced only once */
	if (refcount_read(&current_domain->usage) == 1) {
		oneref_domain = current_domain;
	} else {
		size_t i;

		oneref_domain = new_landlock_domain(NULL);
		if (IS_ERR(oneref_domain)) {
			put_prog_list(new_list);
			return oneref_domain;
		}
		for (i = 0; i < ARRAY_SIZE(oneref_domain->programs); i++) {
			oneref_domain->programs[i] =
				current_domain->programs[i];
			if (oneref_domain->programs[i])
				refcount_inc(&oneref_domain->programs[i]->usage);
		}
		landlock_put_domain(current_domain);
		/* @current_domain may be a dangling pointer now */
		current_domain = NULL;
	}

	/* no need to increment usage (pointer replacement) */
	new_list->prev = oneref_domain->programs[hook];
	oneref_domain->programs[hook] = new_list;
	return oneref_domain;
}
