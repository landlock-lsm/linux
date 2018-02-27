/*
 * Landlock LSM - chain headers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_CHAIN_H
#define _SECURITY_LANDLOCK_CHAIN_H

#include <linux/landlock.h> /* struct landlock_chain */
#include <linux/refcount.h>

/*
 * @chain_index: index of the chain (defined by the user, different from a
 *		 program list)
 * @next: point to the next sibling in the same prog_set (used to match a chain
 *	  against the current process)
 * @index: index in the array dedicated to store data for a chain instance
 */
struct landlock_chain {
	struct landlock_chain *next;
	refcount_t usage;
	u8 index;
	u8 shared:1;
};

struct landlock_chain *landlock_new_chain(u8 index);
void landlock_put_chain(struct landlock_chain *chain);

#endif /* _SECURITY_LANDLOCK_CHAIN_H */
