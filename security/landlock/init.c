// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - init
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/bpf.h> /* enum bpf_access_type */
#include <linux/capability.h> /* capable */
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/lsm_hooks.h>

#include "common.h" /* LANDLOCK_* */
#include "hooks_fs.h"
#include "hooks_ptrace.h"

static bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, const struct bpf_prog *prog,
		struct bpf_insn_access_aux *info)
{
	const union bpf_prog_subtype *prog_subtype;
	enum bpf_reg_type reg_type = NOT_INIT;
	int max_size = 0;

	if (WARN_ON(!prog->aux->extra))
		return false;
	prog_subtype = &prog->aux->extra->subtype;

	if (off < 0)
		return false;
	if (size <= 0 || size > sizeof(__u64))
		return false;

	/* set register type and max size */
	switch (prog_subtype->landlock_hook.type) {
	case LANDLOCK_HOOK_FS_PICK:
		if (!landlock_is_valid_access_fs_pick(off, type, &reg_type,
					&max_size))
			return false;
		break;
	case LANDLOCK_HOOK_FS_WALK:
		if (!landlock_is_valid_access_fs_walk(off, type, &reg_type,
					&max_size))
			return false;
		break;
	default:
		WARN_ON(1);
		return false;
	}

	/* check memory range access */
	switch (reg_type) {
	case NOT_INIT:
		return false;
	case SCALAR_VALUE:
		/* allow partial raw value */
		if (size > max_size)
			return false;
		info->ctx_field_size = max_size;
		break;
	default:
		/* deny partial pointer */
		if (size != max_size)
			return false;
	}

	info->reg_type = reg_type;
	return true;
}

static bool bpf_landlock_is_valid_subtype(struct bpf_prog_extra *prog_extra)
{
	const union bpf_prog_subtype *subtype;

	if (!prog_extra)
		return false;
	subtype = &prog_extra->subtype;

	switch (subtype->landlock_hook.type) {
	case LANDLOCK_HOOK_FS_PICK:
		if (!subtype->landlock_hook.triggers ||
				subtype->landlock_hook.triggers &
				~_LANDLOCK_TRIGGER_FS_PICK_MASK)
			return false;
		break;
	case LANDLOCK_HOOK_FS_WALK:
		if (subtype->landlock_hook.triggers)
			return false;
		break;
	default:
		return false;
	}

	return true;
}

static const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id,
		const struct bpf_prog *prog)
{
	u64 hook_type;

	if (WARN_ON(!prog->aux->extra))
		return NULL;
	hook_type = prog->aux->extra->subtype.landlock_hook.type;

	/* generic functions */
	/* TODO: do we need/want update/delete functions for every LL prog?
	 * => impurity vs. audit */
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	default:
		break;
	}

	switch (hook_type) {
	case LANDLOCK_HOOK_FS_WALK:
	case LANDLOCK_HOOK_FS_PICK:
		switch (func_id) {
		case BPF_FUNC_inode_map_lookup:
			return &bpf_inode_map_lookup_proto;
		default:
			break;
		}
		break;
	}
	return NULL;
}

const struct bpf_verifier_ops landlock_verifier_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
	.is_valid_subtype = bpf_landlock_is_valid_subtype,
};

const struct bpf_prog_ops landlock_prog_ops = {};

static int __init landlock_init(void)
{
	pr_info(LANDLOCK_NAME ": Initializing (sandbox with seccomp)\n");
	landlock_add_hooks_ptrace();
	landlock_add_hooks_fs();
	return 0;
}

struct lsm_blob_sizes landlock_blob_sizes __lsm_ro_after_init = {};

DEFINE_LSM(LANDLOCK_NAME) = {
	.name = LANDLOCK_NAME,
	.order = LSM_ORDER_LAST,
	.blobs = &landlock_blob_sizes,
	.init = landlock_init,
};
