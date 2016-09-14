/*
 * Landlock LSM - private headers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h> /* enum landlock_hook_id */

/**
 * get_index - get an index for the rules of struct landlock_hooks
 *
 * @hook_id: a Landlock hook ID
 */
static inline int get_index(enum landlock_hook_id hook_id)
{
	/* hook ID > 0 for loaded programs */
	return hook_id - 1;
}

#endif /* _SECURITY_LANDLOCK_COMMON_H */
