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

static void put_landlock_prog_list(struct landlock_prog_list *prog_list)
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
			put_landlock_prog_list(domain->programs[i]);
		kfree(domain);
	}
}

static struct landlock_domain *new_landlock_domain(void)
{
	struct landlock_domain *domain;

	/* array filled with NULL values */
	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return ERR_PTR(-ENOMEM);
	refcount_set(&domain->usage, 1);
	return domain;
}

/**
 * store_landlock_prog - prepend and deduplicate a Landlock prog_list
 *
 * Prepend @prog to @init_domain while ignoring @prog if they are already in
 * @ref_domain.  Whatever is the result of this function call, you can call
 * bpf_prog_put(@prog) after.
 *
 * @init_domain: empty domain to prepend to
 * @ref_domain: domain to check for duplicate programs
 * @prog: program to prepend
 *
 * Return -errno on error or 0 if @prog was successfully stored.
 */
static int store_landlock_prog(struct landlock_domain *init_domain,
		const struct landlock_domain *ref_domain,
		struct bpf_prog *prog)
{
	struct landlock_prog_list *tmp_list = NULL;
	int err;
	size_t hook;
	enum landlock_hook_type last_type;
	struct bpf_prog *new = prog;

	/* allocate all the memory we need */
	struct landlock_prog_list *new_list;

	last_type = get_hook_type(new);

	/* ignore duplicate programs */
	if (ref_domain) {
		struct landlock_prog_list *ref;

		hook = get_hook_index(get_hook_type(new));
		for (ref = ref_domain->programs[hook]; ref;
				ref = ref->prev) {
			if (ref->prog == new)
				return -EINVAL;
		}
	}

	new = bpf_prog_inc(new);
	if (IS_ERR(new)) {
		err = PTR_ERR(new);
		goto put_tmp_list;
	}
	new_list = kzalloc(sizeof(*new_list), GFP_KERNEL);
	if (!new_list) {
		bpf_prog_put(new);
		err = -ENOMEM;
		goto put_tmp_list;
	}
	/* ignore Landlock types in this tmp_list */
	new_list->prog = new;
	new_list->prev = tmp_list;
	refcount_set(&new_list->usage, 1);
	tmp_list = new_list;

	if (!tmp_list)
		/* inform user space that this program was already added */
		return -EEXIST;

	/* properly store the list (without error cases) */
	while (tmp_list) {
		struct landlock_prog_list *new_list;

		new_list = tmp_list;
		tmp_list = tmp_list->prev;
		/* do not increment the previous prog list usage */
		hook = get_hook_index(get_hook_type(new_list->prog));
		new_list->prev = init_domain->programs[hook];
		/* no need to add from the last program to the first because
		 * each of them are a different Landlock type */
		smp_store_release(&init_domain->programs[hook], new_list);
	}
	return 0;

put_tmp_list:
	put_landlock_prog_list(tmp_list);
	return err;
}

/* limit Landlock programs set to 256KB */
#define LANDLOCK_PROGRAMS_MAX_PAGES (1 << 6)

/**
 * landlock_prepend_prog - attach a Landlock prog_list to @current_domain
 *
 * Whatever is the result of this function call, you can call
 * bpf_prog_put(@prog) after.
 *
 * @current_domain: landlock_domain pointer, must be (RCU-)locked (if needed)
 *                  to prevent a concurrent put/free. This pointer must not be
 *                  freed after the call.
 * @prog: non-NULL Landlock prog_list to prepend to @current_domain. @prog will
 *        be owned by landlock_prepend_prog() and freed if an error happened.
 *
 * Return @current_domain or a new pointer when OK. Return a pointer error
 * otherwise.
 */
struct landlock_domain *landlock_prepend_prog(
		struct landlock_domain *current_domain,
		struct bpf_prog *prog)
{
	struct landlock_domain *new_domain = current_domain;
	unsigned long pages;
	int err;
	size_t i;
	struct landlock_domain tmp_domain = {};

	if (prog->type != BPF_PROG_TYPE_LANDLOCK_HOOK)
		return ERR_PTR(-EINVAL);

	/* validate memory size allocation */
	pages = prog->pages;
	if (current_domain) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(current_domain->programs); i++) {
			struct landlock_prog_list *walker_p;

			for (walker_p = current_domain->programs[i];
					walker_p; walker_p = walker_p->prev)
				pages += walker_p->prog->pages;
		}
		/* count a struct landlock_domain if we need to allocate one */
		if (refcount_read(&current_domain->usage) != 1)
			pages += round_up(sizeof(*current_domain), PAGE_SIZE)
				/ PAGE_SIZE;
	}
	if (pages > LANDLOCK_PROGRAMS_MAX_PAGES)
		return ERR_PTR(-E2BIG);

	/* ensure early that we can allocate enough memory for the new
	 * prog_lists */
	err = store_landlock_prog(&tmp_domain, current_domain, prog);
	if (err)
		return ERR_PTR(err);

	/*
	 * Each task_struct points to an array of prog list pointers.  These
	 * tables are duplicated when additions are made (which means each
	 * table needs to be refcounted for the processes using it). When a new
	 * table is created, all the refcounters on the prog_list are bumped
	 * (to track each table that references the prog). When a new prog is
	 * added, it's just prepended to the list for the new table to point
	 * at.
	 *
	 * Manage all the possible errors before this step to not uselessly
	 * duplicate current_domain and avoid a rollback.
	 */
	if (!new_domain) {
		/*
		 * If there is no Landlock domain used by the current task,
		 * then create a new one.
		 */
		new_domain = new_landlock_domain();
		if (IS_ERR(new_domain))
			goto put_tmp_lists;
	} else if (refcount_read(&current_domain->usage) > 1) {
		/*
		 * If the current task is not the sole user of its Landlock
		 * domain, then duplicate it.
		 */
		new_domain = new_landlock_domain();
		if (IS_ERR(new_domain))
			goto put_tmp_lists;
		for (i = 0; i < ARRAY_SIZE(new_domain->programs); i++) {
			new_domain->programs[i] =
				READ_ONCE(current_domain->programs[i]);
			if (new_domain->programs[i])
				refcount_inc(&new_domain->programs[i]->usage);
		}

		/*
		 * Landlock domain from the current task will not be freed here
		 * because the usage is strictly greater than 1. It is only
		 * prevented to be freed by another task thanks to the caller
		 * of landlock_prepend_prog() which should be locked if needed.
		 */
		landlock_put_domain(current_domain);
	}

	/* prepend tmp_domain to new_domain */
	for (i = 0; i < ARRAY_SIZE(tmp_domain.programs); i++) {
		/* get the last new list */
		struct landlock_prog_list *last_list =
			tmp_domain.programs[i];

		if (last_list) {
			while (last_list->prev)
				last_list = last_list->prev;
			/* no need to increment usage (pointer replacement) */
			last_list->prev = new_domain->programs[i];
			new_domain->programs[i] = tmp_domain.programs[i];
		}
	}
	return new_domain;

put_tmp_lists:
	for (i = 0; i < ARRAY_SIZE(tmp_domain.programs); i++)
		put_landlock_prog_list(tmp_domain.programs[i]);
	return new_domain;
}
