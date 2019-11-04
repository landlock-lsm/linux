/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - private headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/refcount.h>

enum landlock_hook_type {
	LANDLOCK_HOOK_PTRACE = 1,
};

#define _LANDLOCK_HOOK_LAST LANDLOCK_HOOK_PTRACE

struct landlock_prog_list {
	struct landlock_prog_list *prev;
	struct bpf_prog *prog;
	refcount_t usage;
};

/**
 * struct landlock_domain - Landlock programs enforced on a set of tasks
 *
 * When prepending a new program, if &struct landlock_domain is shared with
 * other tasks, then duplicate it and prepend the program to this new &struct
 * landlock_domain.
 *
 * @usage: reference count to manage the object lifetime. When a task needs to
 *	   add Landlock programs and if @usage is greater than 1, then the
 *	   task must duplicate &struct landlock_domain to not change the
 *	   children's programs as well.
 * @programs: array of non-NULL &struct landlock_prog_list pointers
 */
struct landlock_domain {
	struct landlock_prog_list *programs[_LANDLOCK_HOOK_LAST];
	refcount_t usage;
};

/**
 * get_hook_index - get an index for the programs of struct landlock_prog_set
 *
 * @type: a Landlock hook type
 */
static inline size_t get_hook_index(enum landlock_hook_type type)
{
	/* type ID > 0 for loaded programs */
	return type - 1;
}

static inline enum landlock_hook_type get_hook_type(const struct bpf_prog *prog)
{
	switch (prog->expected_attach_type) {
	case BPF_LANDLOCK_PTRACE:
		return LANDLOCK_HOOK_PTRACE;
	default:
		WARN_ON(1);
		return BPF_LANDLOCK_PTRACE;
	}
}

#endif /* _SECURITY_LANDLOCK_COMMON_H */
