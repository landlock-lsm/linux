/*
 * Landlock LSM - cgroup Checkers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_CGROUPS

#include <asm/current.h>
#include <linux/bpf.h> /* enum bpf_map_array_op */
#include <linux/cgroup-defs.h> /* struct cgroup_subsys_state */
#include <linux/cgroup.h> /* cgroup_is_descendant(), task_css_set() */
#include <linux/errno.h>

#include "checker_cgroup.h"


/*
 * bpf_landlock_cmp_cgroup_beneath
 *
 * Cf. include/uapi/linux/bpf.h
 */
static inline u64 bpf_landlock_cmp_cgroup_beneath(u64 r1_option, u64 r2_map,
		u64 r3_map_op, u64 r4, u64 r5)
{
	u8 option = (u8) r1_option;
	struct bpf_map *map = (struct bpf_map *) (unsigned long) r2_map;
	enum bpf_map_array_op map_op = r3_map_op;
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct cgroup *cg1, *cg2;
	struct map_landlock_handle *handle;
	int i;

	/* ARG_CONST_PTR_TO_LANDLOCK_HANDLE_CGROUP is an arraymap */
	if (unlikely(!map)) {
		WARN_ON(1);
		return -EFAULT;
	}
	if (unlikely((option | _LANDLOCK_FLAG_OPT_MASK) != _LANDLOCK_FLAG_OPT_MASK))
		return -EINVAL;

	/* for now, only handle OP_OR */
	switch (map_op) {
	case BPF_MAP_ARRAY_OP_OR:
		break;
	case BPF_MAP_ARRAY_OP_UNSPEC:
	case BPF_MAP_ARRAY_OP_AND:
	case BPF_MAP_ARRAY_OP_XOR:
	default:
		return -EINVAL;
	}

	synchronize_rcu();

	for (i = 0; i < array->n_entries; i++) {
		handle = (struct map_landlock_handle *)
				(array->value + array->elem_size * i);

		/* protected by the proto types, should not happen */
		if (unlikely(handle->type != BPF_MAP_HANDLE_TYPE_LANDLOCK_CGROUP_FD)) {
			WARN_ON(1);
			return -EFAULT;
		}
		if (unlikely(!handle->css)) {
			WARN_ON(1);
			return -EFAULT;
		}

		if (option & LANDLOCK_FLAG_OPT_REVERSE) {
			cg1 = handle->css->cgroup;
			cg2 = task_css_set(current)->dfl_cgrp;
		} else {
			cg1 = task_css_set(current)->dfl_cgrp;
			cg2 = handle->css->cgroup;
		}

		if (cgroup_is_descendant(cg1, cg2))
			return 0;
	}
	return 1;
}

const struct bpf_func_proto bpf_landlock_cmp_cgroup_beneath_proto = {
	.func		= bpf_landlock_cmp_cgroup_beneath,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_CONST_PTR_TO_LANDLOCK_HANDLE_CGROUP,
	.arg3_type	= ARG_ANYTHING,
};

#endif	/* CONFIG_CGROUPS */
