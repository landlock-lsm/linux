// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - enforcing helpers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <asm/barrier.h> /* smp_store_release() */
#include <asm/page.h> /* PAGE_SIZE */
#include <linux/bpf.h> /* bpf_prog_put() */
#include <linux/compiler.h> /* READ_ONCE() */
#include <linux/err.h> /* PTR_ERR() */
#include <linux/errno.h>
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/refcount.h>
#include <linux/slab.h> /* alloc(), kfree() */

#include "common.h" /* struct landlock_prog_list */

/* TODO: use a dedicated kmem_cache_alloc() instead of k*alloc() */

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

void landlock_put_prog_set(struct landlock_prog_set *prog_set)
{
	if (prog_set && refcount_dec_and_test(&prog_set->usage)) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(prog_set->programs); i++)
			put_landlock_prog_list(prog_set->programs[i]);
		kfree(prog_set);
	}
}

void landlock_get_prog_set(struct landlock_prog_set *prog_set)
{
	if (!prog_set)
		return;
	refcount_inc(&prog_set->usage);
}

static struct landlock_prog_set *new_landlock_prog_set(void)
{
	struct landlock_prog_set *ret;

	/* array filled with NULL values */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);
	refcount_set(&ret->usage, 1);
	return ret;
}

/**
 * store_landlock_prog - prepend and deduplicate a Landlock prog_list
 *
 * Prepend @prog to @init_prog_set while ignoring @prog
 * if they are already in @ref_prog_set.  Whatever is the result of this
 * function call, you can call bpf_prog_put(@prog) after.
 *
 * @init_prog_set: empty prog_set to prepend to
 * @ref_prog_set: prog_set to check for duplicate programs
 * @prog: program to prepend
 *
 * Return -errno on error or 0 if @prog was successfully stored.
 */
static int store_landlock_prog(struct landlock_prog_set *init_prog_set,
		const struct landlock_prog_set *ref_prog_set,
		struct bpf_prog *prog)
{
	struct landlock_prog_list *tmp_list = NULL;
	int err;
	u32 hook_idx;
	enum landlock_hook_type last_type;
	struct bpf_prog *new = prog;

	/* allocate all the memory we need */
	struct landlock_prog_list *new_list;

	last_type = get_type(new);

	/* ignore duplicate programs */
	if (ref_prog_set) {
		struct landlock_prog_list *ref;

		hook_idx = get_index(get_type(new));
		for (ref = ref_prog_set->programs[hook_idx];
				ref; ref = ref->prev) {
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
		hook_idx = get_index(get_type(new_list->prog));
		new_list->prev = init_prog_set->programs[hook_idx];
		/* no need to add from the last program to the first because
		 * each of them are a different Landlock type */
		smp_store_release(&init_prog_set->programs[hook_idx], new_list);
	}
	return 0;

put_tmp_list:
	put_landlock_prog_list(tmp_list);
	return err;
}

/* limit Landlock programs set to 256KB */
#define LANDLOCK_PROGRAMS_MAX_PAGES (1 << 6)

/**
 * landlock_prepend_prog - attach a Landlock prog_list to @current_prog_set
 *
 * Whatever is the result of this function call, you can call
 * bpf_prog_put(@prog) after.
 *
 * @current_prog_set: landlock_prog_set pointer, must be locked (if needed) to
 *                    prevent a concurrent put/free. This pointer must not be
 *                    freed after the call.
 * @prog: non-NULL Landlock prog_list to prepend to @current_prog_set. @prog
 *	  will be owned by landlock_prepend_prog() and freed if an error
 *	  happened.
 *
 * Return @current_prog_set or a new pointer when OK. Return a pointer error
 * otherwise.
 */
struct landlock_prog_set *landlock_prepend_prog(
		struct landlock_prog_set *current_prog_set,
		struct bpf_prog *prog)
{
	struct landlock_prog_set *new_prog_set = current_prog_set;
	unsigned long pages;
	int err;
	size_t i;
	struct landlock_prog_set tmp_prog_set = {};

	if (prog->type != BPF_PROG_TYPE_LANDLOCK_HOOK)
		return ERR_PTR(-EINVAL);

	/* validate memory size allocation */
	pages = prog->pages;
	if (current_prog_set) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(current_prog_set->programs); i++) {
			struct landlock_prog_list *walker_p;

			for (walker_p = current_prog_set->programs[i];
					walker_p; walker_p = walker_p->prev)
				pages += walker_p->prog->pages;
		}
		/* count a struct landlock_prog_set if we need to allocate one */
		if (refcount_read(&current_prog_set->usage) != 1)
			pages += round_up(sizeof(*current_prog_set), PAGE_SIZE)
				/ PAGE_SIZE;
	}
	if (pages > LANDLOCK_PROGRAMS_MAX_PAGES)
		return ERR_PTR(-E2BIG);

	/* ensure early that we can allocate enough memory for the new
	 * prog_lists */
	err = store_landlock_prog(&tmp_prog_set, current_prog_set, prog);
	if (err)
		return ERR_PTR(err);

	/*
	 * Each task_struct points to an array of prog list pointers.  These
	 * tables are duplicated when additions are made (which means each
	 * table needs to be refcounted for the processes using it). When a new
	 * table is created, all the refcounters on the prog_list are bumped (to
	 * track each table that references the prog). When a new prog is
	 * added, it's just prepended to the list for the new table to point
	 * at.
	 *
	 * Manage all the possible errors before this step to not uselessly
	 * duplicate current_prog_set and avoid a rollback.
	 */
	if (!new_prog_set) {
		/*
		 * If there is no Landlock program set used by the current task,
		 * then create a new one.
		 */
		new_prog_set = new_landlock_prog_set();
		if (IS_ERR(new_prog_set))
			goto put_tmp_lists;
	} else if (refcount_read(&current_prog_set->usage) > 1) {
		/*
		 * If the current task is not the sole user of its Landlock
		 * program set, then duplicate them.
		 */
		new_prog_set = new_landlock_prog_set();
		if (IS_ERR(new_prog_set))
			goto put_tmp_lists;
		for (i = 0; i < ARRAY_SIZE(new_prog_set->programs); i++) {
			new_prog_set->programs[i] =
				READ_ONCE(current_prog_set->programs[i]);
			if (new_prog_set->programs[i])
				refcount_inc(&new_prog_set->programs[i]->usage);
		}

		/*
		 * Landlock program set from the current task will not be freed
		 * here because the usage is strictly greater than 1. It is
		 * only prevented to be freed by another task thanks to the
		 * caller of landlock_prepend_prog() which should be locked if
		 * needed.
		 */
		landlock_put_prog_set(current_prog_set);
	}

	/* prepend tmp_prog_set to new_prog_set */
	for (i = 0; i < ARRAY_SIZE(tmp_prog_set.programs); i++) {
		/* get the last new list */
		struct landlock_prog_list *last_list =
			tmp_prog_set.programs[i];

		if (last_list) {
			while (last_list->prev)
				last_list = last_list->prev;
			/* no need to increment usage (pointer replacement) */
			last_list->prev = new_prog_set->programs[i];
			new_prog_set->programs[i] = tmp_prog_set.programs[i];
		}
	}
	return new_prog_set;

put_tmp_lists:
	for (i = 0; i < ARRAY_SIZE(tmp_prog_set.programs); i++)
		put_landlock_prog_list(tmp_prog_set.programs[i]);
	return new_prog_set;
}
