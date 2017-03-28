/*
 * Landlock LSM - init
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_access_type */
#include <linux/capability.h> /* capable */
#include <linux/landlock.h> /* LANDLOCK_VERSION */
#include <linux/lsm_hooks.h>

#include "hooks_fs.h"
#include "hooks_ptrace.h"


static inline bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, enum bpf_reg_type *reg_type,
		union bpf_prog_subtype *prog_subtype)
{
	if (WARN_ON(!prog_subtype))
		return false;

	switch (prog_subtype->landlock_rule.event) {
	case LANDLOCK_SUBTYPE_EVENT_FS:
		return landlock_is_valid_access_event_FS(off, size, type,
				reg_type, prog_subtype);
	case LANDLOCK_SUBTYPE_EVENT_UNSPEC:
	default:
		return false;
	}
}

static inline bool bpf_landlock_is_valid_subtype(
		union bpf_prog_subtype *prog_subtype)
{
	if (WARN_ON(!prog_subtype))
		return false;

	switch (prog_subtype->landlock_rule.event) {
	case LANDLOCK_SUBTYPE_EVENT_FS:
		break;
	case LANDLOCK_SUBTYPE_EVENT_UNSPEC:
	default:
		return false;
	}

	if (!prog_subtype->landlock_rule.version ||
			prog_subtype->landlock_rule.version > LANDLOCK_VERSION)
		return false;
	if (!prog_subtype->landlock_rule.event ||
			prog_subtype->landlock_rule.event > _LANDLOCK_SUBTYPE_EVENT_LAST)
		return false;
	if (prog_subtype->landlock_rule.ability & ~_LANDLOCK_SUBTYPE_ABILITY_MASK)
		return false;
	if (prog_subtype->landlock_rule.option & ~_LANDLOCK_SUBTYPE_OPTION_MASK)
		return false;

	/* check ability flags */
	if (prog_subtype->landlock_rule.ability & LANDLOCK_SUBTYPE_ABILITY_WRITE &&
			!capable(CAP_SYS_ADMIN))
		return false;
	if (prog_subtype->landlock_rule.ability & LANDLOCK_SUBTYPE_ABILITY_DEBUG &&
			!capable(CAP_SYS_ADMIN))
		return false;

	return true;
}

static inline const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id, union bpf_prog_subtype *prog_subtype)
{
	bool event_fs = (prog_subtype->landlock_rule.event ==
			LANDLOCK_SUBTYPE_EVENT_FS);
	bool ability_write = !!(prog_subtype->landlock_rule.ability &
			LANDLOCK_SUBTYPE_ABILITY_WRITE);
	bool ability_debug = !!(prog_subtype->landlock_rule.ability &
			LANDLOCK_SUBTYPE_ABILITY_DEBUG);

	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;

	/* event_fs */
	case BPF_FUNC_handle_fs_get_mode:
		if (event_fs)
			return &bpf_handle_fs_get_mode_proto;
		return NULL;

	/* ability_write */
	case BPF_FUNC_map_delete_elem:
		if (ability_write)
			return &bpf_map_delete_elem_proto;
		return NULL;
	case BPF_FUNC_map_update_elem:
		if (ability_write)
			return &bpf_map_update_elem_proto;
		return NULL;

	/* ability_debug */
	case BPF_FUNC_get_current_comm:
		if (ability_debug)
			return &bpf_get_current_comm_proto;
		return NULL;
	case BPF_FUNC_get_current_pid_tgid:
		if (ability_debug)
			return &bpf_get_current_pid_tgid_proto;
		return NULL;
	case BPF_FUNC_get_current_uid_gid:
		if (ability_debug)
			return &bpf_get_current_uid_gid_proto;
		return NULL;
	case BPF_FUNC_trace_printk:
		if (ability_debug)
			return bpf_get_trace_printk_proto();
		return NULL;

	default:
		return NULL;
	}
}

static const struct bpf_verifier_ops bpf_landlock_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
	.is_valid_subtype = bpf_landlock_is_valid_subtype,
};

static struct bpf_prog_type_list bpf_landlock_type __ro_after_init = {
	.ops = &bpf_landlock_ops,
	.type = BPF_PROG_TYPE_LANDLOCK,
};

void __init landlock_add_hooks(void)
{
	pr_info("landlock: Version %u, ready to sandbox with %s\n",
			LANDLOCK_VERSION, "seccomp");
	landlock_add_hooks_ptrace();
	landlock_add_hooks_fs();
	security_add_hooks(NULL, 0, "landlock");
	bpf_register_prog_type(&bpf_landlock_type);
}
