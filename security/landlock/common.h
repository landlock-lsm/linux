/*
 * Landlock LSM - private headers
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h> /* enum bpf_prog_aux */
#include <linux/filter.h> /* bpf_prog */
#include <linux/refcount.h> /* refcount_t */
#include <uapi/linux/landlock.h> /* enum landlock_hook_type */

#define LANDLOCK_NAME "landlock"

/* UAPI bounds and bitmasks */

#define _LANDLOCK_HOOK_LAST LANDLOCK_HOOK_FS_GET

#define _LANDLOCK_OPTION_LAST		LANDLOCK_OPTION_PREVIOUS
#define _LANDLOCK_OPTION_MASK		((_LANDLOCK_OPTION_LAST << 1ULL) - 1)

#define _LANDLOCK_TRIGGER_FS_PICK_LAST	LANDLOCK_TRIGGER_FS_PICK_WRITE
#define _LANDLOCK_TRIGGER_FS_PICK_MASK	((_LANDLOCK_TRIGGER_FS_PICK_LAST << 1ULL) - 1)

struct landlock_chain;

/*
 * @is_last_of_type: in a chain of programs, it marks if this program is the
 *		     last of its type
 */
struct landlock_prog_list {
	struct landlock_prog_list *prev;
	struct bpf_prog *prog;
	struct landlock_chain *chain;
	refcount_t usage;
	u8 is_last_of_type:1;
};

/**
 * struct landlock_prog_set - Landlock programs enforced on a thread
 *
 * This is used for low performance impact when forking a process. Instead of
 * copying the full array and incrementing the usage of each entries, only
 * create a pointer to &struct landlock_prog_set and increments its usage. When
 * prepending a new program, if &struct landlock_prog_set is shared with other
 * tasks, then duplicate it and prepend the program to this new &struct
 * landlock_prog_set.
 *
 * @usage: reference count to manage the object lifetime. When a thread need to
 *	   add Landlock programs and if @usage is greater than 1, then the
 *	   thread must duplicate &struct landlock_prog_set to not change the
 *	   children's programs as well.
 * @chain_last: chain of the last prepended program
 * @programs: array of non-NULL &struct landlock_prog_list pointers
 */
struct landlock_prog_set {
	struct landlock_chain *chain_last;
	struct landlock_prog_list *programs[_LANDLOCK_HOOK_LAST];
	refcount_t usage;
};

/**
 * get_index - get an index for the programs of struct landlock_prog_set
 *
 * @type: a Landlock hook type
 */
static inline int get_index(enum landlock_hook_type type)
{
	/* type ID > 0 for loaded programs */
	return type - 1;
}

static inline enum landlock_hook_type get_type(struct bpf_prog *prog)
{
	return prog->aux->extra->subtype.landlock_hook.type;
}

__maybe_unused
static bool current_has_prog_type(enum landlock_hook_type hook_type)
{
	struct landlock_prog_set *prog_set;

	prog_set = current->seccomp.landlock_prog_set;
	return (prog_set && prog_set->programs[get_index(hook_type)]);
}

#endif /* _SECURITY_LANDLOCK_COMMON_H */
