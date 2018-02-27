/*
 * Landlock LSM - chain helpers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/refcount.h>
#include <linux/slab.h>

#include "chain.h"

/* TODO: use a dedicated kmem_cache_alloc() instead of k*alloc() */

/* never return NULL */
struct landlock_chain *landlock_new_chain(u8 index)
{
	struct landlock_chain *chain;

	chain = kzalloc(sizeof(*chain), GFP_KERNEL);
	if (!chain)
		return ERR_PTR(-ENOMEM);
	chain->index = index;
	refcount_set(&chain->usage, 1);
	return chain;
}

void landlock_put_chain(struct landlock_chain *chain)
{
	if (!chain)
		return;
	if (!refcount_dec_and_test(&chain->usage))
		return;
	kfree(chain);
}
