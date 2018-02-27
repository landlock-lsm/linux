/*
 * Landlock LSM - tag headers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_TAG_H
#define _SECURITY_LANDLOCK_TAG_H

#include <linux/spinlock_types.h>

struct landlock_tag;
struct landlock_tag_root;
struct landlock_tag_ref;

struct landlock_tag_object {
	spinlock_t *lock;
	struct landlock_tag_root **root;
	struct landlock_tag_ref **ref;
};

int landlock_set_tag(struct landlock_tag_ref **tag_ref,
		struct landlock_tag_root **tag_root,
		spinlock_t *root_lock,
		struct landlock_chain *chain, u64 value);
u64 landlock_get_tag(const struct landlock_tag_root *tag_root,
		const struct landlock_chain *chain);
void landlock_free_tag_ref(struct landlock_tag_ref *tag_ref,
		struct landlock_tag_root **tag_root, spinlock_t *root_lock);

#endif /* _SECURITY_LANDLOCK_TAG_H */
