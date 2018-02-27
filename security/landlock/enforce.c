/*
 * Landlock LSM - enforcing helpers
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
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

#include "chain.h"
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
		landlock_put_chain(orig->chain);
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
		landlock_put_chain(prog_set->chain_last);
		kfree(prog_set);
	}
}

void landlock_get_prog_set(struct landlock_prog_set *prog_set)
{
	struct landlock_chain *chain;

	if (!prog_set)
		return;
	refcount_inc(&prog_set->usage);
	chain = prog_set->chain_last;
	/* mark all inherited chains as (potentially) shared */
	while (chain && !chain->shared) {
		chain->shared = 1;
		chain = chain->next;
	}
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

/*
 * If a program type is able to fork, this means that there is one amongst
 * multiple programs (types) that may be called after, depending on the action
 * type. This means that if a (sub)type has a "triggers" field (e.g. fs_pick),
 * then it is forkable.
 *
 * Keep in sync with init.c:good_previous_prog().
 */
static bool is_hook_type_forkable(enum landlock_hook_type hook_type)
{
	switch (hook_type) {
	case LANDLOCK_HOOK_FS_WALK:
		return false;
	case LANDLOCK_HOOK_FS_PICK:
		/* can fork to fs_get or fs_ioctl... */
		return true;
	case LANDLOCK_HOOK_FS_GET:
		return false;
	}
	WARN_ON(1);
	return false;
}

/**
 * store_landlock_prog - prepend and deduplicate a Landlock prog_list
 *
 * Prepend @prog to @init_prog_set while ignoring @prog and its chained programs
 * if they are already in @ref_prog_set.  Whatever is the result of this
 * function call, you can call bpf_prog_put(@prog) after.
 *
 * @init_prog_set: empty prog_set to prepend to
 * @ref_prog_set: prog_set to check for duplicate programs
 * @prog: program chain to prepend
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
	bool new_is_last_of_type;
	bool first = true;
	struct landlock_chain *chain = NULL;
	enum landlock_hook_type last_type;
	struct bpf_prog *new = prog;

	/* allocate all the memory we need */
	for (; new; new = new->aux->extra->landlock_hook.previous) {
		bool ignore = false;
		struct landlock_prog_list *new_list;

		new_is_last_of_type = first || (last_type != get_type(new));
		last_type = get_type(new);
		first = false;
		/* ignore duplicate programs */
		if (ref_prog_set) {
			struct landlock_prog_list *ref;
			struct bpf_prog *new_prev;

			/*
			 * The subtype verifier has already checked the
			 * coherency of the program types chained in @new (cf.
			 * good_previous_prog).
			 *
			 * Here we only allow linking to a chain if the common
			 * program's type is able to fork (e.g. fs_pick) and
			 * come from the same task (i.e. not shared).  This
			 * program must also be the last one of its type in
			 * both the @ref and the @new chains.  Finally, two
			 * programs with the same parent must be of different
			 * type.
			 */
			if (WARN_ON(!new->aux->extra))
				continue;
			new_prev = new->aux->extra->landlock_hook.previous;
			hook_idx = get_index(get_type(new));
			for (ref = ref_prog_set->programs[hook_idx];
					ref; ref = ref->prev) {
				struct bpf_prog *ref_prev;

				ignore = (ref->prog == new);
				if (ignore)
					break;
				ref_prev = ref->prog->aux->extra->
					landlock_hook.previous;
				/* deny fork to the same types */
				if (new_prev && new_prev == ref_prev) {
					err = -EINVAL;
					goto put_tmp_list;
				}
			}
			/* remaining programs are already in ref_prog_set */
			if (ignore) {
				bool is_forkable =
					is_hook_type_forkable(get_type(new));

				if (ref->chain->shared || !is_forkable ||
						!new_is_last_of_type ||
						!ref->is_last_of_type) {
					err = -EINVAL;
					goto put_tmp_list;
				}
				/* use the same session (i.e. cookie state) */
				chain = ref->chain;
				/* will increment the usage counter later */
				break;
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
		new_list->is_last_of_type = new_is_last_of_type;
		new_list->prog = new;
		new_list->prev = tmp_list;
		refcount_set(&new_list->usage, 1);
		tmp_list = new_list;
	}

	if (!tmp_list)
		/* inform user space that this program was already added */
		return -EEXIST;

	if (!chain) {
		u8 chain_index;

		if (ref_prog_set) {
			/* this is a new independent chain */
			chain_index = ref_prog_set->chain_last->index + 1;
			/* check for integer overflow */
			if (chain_index < ref_prog_set->chain_last->index) {
				err = -E2BIG;
				goto put_tmp_list;
			}
		} else {
			chain_index = 0;
		}
		chain = landlock_new_chain(chain_index);
		if (IS_ERR(chain)) {
			err = PTR_ERR(chain);
			goto put_tmp_list;
		}
		/* no need to refcount_dec(&init_prog_set->chain_last) */
	}
	init_prog_set->chain_last = chain;

	/* properly store the list (without error cases) */
	while (tmp_list) {
		struct landlock_prog_list *new_list;

		new_list = tmp_list;
		tmp_list = tmp_list->prev;
		/* do not increment the previous prog list usage */
		hook_idx = get_index(get_type(new_list->prog));
		new_list->prev = init_prog_set->programs[hook_idx];
		new_list->chain = chain;
		refcount_inc(&chain->usage);
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
	new_prog_set->chain_last = tmp_prog_set.chain_last;
	return new_prog_set;

put_tmp_lists:
	for (i = 0; i < ARRAY_SIZE(tmp_prog_set.programs); i++)
		put_landlock_prog_list(tmp_prog_set.programs[i]);
	return new_prog_set;
}
