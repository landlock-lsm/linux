/*
 * Landlock LSM - init
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_access_type */
#include <linux/capability.h> /* capable */
#include <linux/filter.h> /* struct bpf_prog */
#include <linux/lsm_hooks.h>

#include "common.h" /* LANDLOCK_* */
#include "hooks_fs.h"
#include "hooks_cred.h"
#include "hooks_ptrace.h"

static bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, struct bpf_insn_access_aux *info,
		const struct bpf_prog_extra *prog_extra)
{
	const union bpf_prog_subtype *prog_subtype;
	enum bpf_reg_type reg_type = NOT_INIT;
	int max_size = 0;

	if (WARN_ON(!prog_extra))
		return false;
	prog_subtype = &prog_extra->subtype;

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
	case LANDLOCK_HOOK_FS_GET:
		if (!landlock_is_valid_access_fs_get(off, type, &reg_type,
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

/*
 * Check order of Landlock programs
 *
 * Keep in sync with enforce.c:is_hook_type_forkable().
 */
static bool good_previous_prog(enum landlock_hook_type current_type,
		const struct bpf_prog *previous)
{
	enum landlock_hook_type previous_type;

	if (previous->type != BPF_PROG_TYPE_LANDLOCK_HOOK)
		return false;
	if (WARN_ON(!previous->aux->extra))
		return false;
	previous_type = previous->aux->extra->subtype.landlock_hook.type;
	switch (current_type) {
	case LANDLOCK_HOOK_FS_PICK:
		switch (previous_type) {
		case LANDLOCK_HOOK_FS_PICK:
		case LANDLOCK_HOOK_FS_WALK:
			return true;
		default:
			return false;
		}
	case LANDLOCK_HOOK_FS_GET:
		/* In the future, fs_get could be chained with another fs_get
		 * (different triggers), but not for now. */
		if (previous_type != LANDLOCK_HOOK_FS_PICK)
			return false;
		return true;
	case LANDLOCK_HOOK_FS_WALK:
		return false;
	}
	WARN_ON(1);
	return false;
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
	case LANDLOCK_HOOK_FS_GET:
		if (subtype->landlock_hook.triggers)
			return false;
		break;
	default:
		return false;
	}

	if (subtype->landlock_hook.options & ~_LANDLOCK_OPTION_MASK)
		return false;
	if (subtype->landlock_hook.options & LANDLOCK_OPTION_PREVIOUS) {
		struct bpf_prog *previous;

		/* check and save the chained program */
		previous = bpf_prog_get(subtype->landlock_hook.previous);
		if (IS_ERR(previous))
			return false;
		if (!good_previous_prog(subtype->landlock_hook.type,
					previous)) {
			bpf_prog_put(previous);
			return false;
		}
		/* It is not possible to create loops because the current
		 * program does not exist yet. */
		prog_extra->landlock_hook.previous = previous;
	}

	return true;
}

static const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id,
		const struct bpf_prog_extra *prog_extra)
{
	u64 hook_type;

	if (WARN_ON(!prog_extra))
		return NULL;
	hook_type = prog_extra->subtype.landlock_hook.type;

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
		case BPF_FUNC_inode_get_tag:
			return &bpf_inode_get_tag_proto;
		default:
			break;
		}
		break;
	case LANDLOCK_HOOK_FS_GET:
		switch (func_id) {
		case BPF_FUNC_inode_get_tag:
			return &bpf_inode_get_tag_proto;
		case BPF_FUNC_landlock_set_tag:
			return &bpf_landlock_set_tag_proto;
		default:
			break;
		}
		break;
	}
	return NULL;
}

static void bpf_landlock_put_extra(struct bpf_prog_extra *prog_extra)
{
	if (WARN_ON(!prog_extra))
		return;
	if (prog_extra->landlock_hook.previous)
		bpf_prog_put(prog_extra->landlock_hook.previous);
}

const struct bpf_verifier_ops landlock_verifier_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
	.is_valid_subtype = bpf_landlock_is_valid_subtype,
};

const struct bpf_prog_ops landlock_prog_ops = {
	.put_extra = bpf_landlock_put_extra,
};

void __init landlock_add_hooks(void)
{
	pr_info(LANDLOCK_NAME ": Ready to sandbox with seccomp\n");
	landlock_add_hooks_cred();
	landlock_add_hooks_ptrace();
	landlock_add_hooks_fs();
}
