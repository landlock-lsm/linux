/*
 * Landlock LSM - init
 *
 * Copyright © 2016-2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_access_type */
#include <linux/capability.h> /* capable */
#include <linux/lsm_hooks.h>

#include "common.h" /* LANDLOCK_* */
#include "hooks_fs.h"
#include "hooks_ptrace.h"


static inline bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, struct bpf_insn_access_aux *info,
		const union bpf_prog_subtype *prog_subtype)
{
	if (WARN_ON(!prog_subtype))
		return false;

	switch (prog_subtype->landlock_rule.event) {
	case LANDLOCK_SUBTYPE_EVENT_FS:
		return landlock_is_valid_access_event_FS(off, size, type,
				&info->reg_type, prog_subtype);
	case LANDLOCK_SUBTYPE_EVENT_UNSPEC:
	default:
		return false;
	}
}

static inline bool bpf_landlock_is_valid_subtype(
		const union bpf_prog_subtype *prog_subtype)
{
	if (WARN_ON(!prog_subtype))
		return false;

	switch (prog_subtype->landlock_rule.event) {
	case LANDLOCK_SUBTYPE_EVENT_FS:
	case LANDLOCK_SUBTYPE_EVENT_FS_IOCTL:
	case LANDLOCK_SUBTYPE_EVENT_FS_LOCK:
	case LANDLOCK_SUBTYPE_EVENT_FS_FCNTL:
		break;
	case LANDLOCK_SUBTYPE_EVENT_UNSPEC:
	default:
		return false;
	}

	/* check Landlock ABI compatibility */
	if (!prog_subtype->landlock_rule.abi ||
			prog_subtype->landlock_rule.abi > LANDLOCK_ABI)
		return false;
	/* check if the rule's event, ability and option make sense */
	if (!prog_subtype->landlock_rule.event ||
			prog_subtype->landlock_rule.event >
			_LANDLOCK_SUBTYPE_EVENT_LAST)
		return false;
	if (prog_subtype->landlock_rule.ability &
			~_LANDLOCK_SUBTYPE_ABILITY_MASK)
		return false;
	if (prog_subtype->landlock_rule.option &
			~_LANDLOCK_SUBTYPE_OPTION_MASK)
		return false;

	/* the ability to debug requires global CAP_SYS_ADMIN */
	if (prog_subtype->landlock_rule.ability &
			LANDLOCK_SUBTYPE_ABILITY_DEBUG &&
			!capable(CAP_SYS_ADMIN))
		return false;

	return true;
}

static inline const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id,
		const union bpf_prog_subtype *prog_subtype)
{
	/* context-dependant functions */
	switch (prog_subtype->landlock_rule.event) {
	case LANDLOCK_SUBTYPE_EVENT_FS:
	case LANDLOCK_SUBTYPE_EVENT_FS_IOCTL:
	case LANDLOCK_SUBTYPE_EVENT_FS_LOCK:
	case LANDLOCK_SUBTYPE_EVENT_FS_FCNTL:
		switch (func_id) {
		case BPF_FUNC_handle_fs_get_mode:
			return &bpf_handle_fs_get_mode_proto;
		default:
			break;
		}
	}

	/* generic functions */
	if (prog_subtype->landlock_rule.ability &
			LANDLOCK_SUBTYPE_ABILITY_DEBUG) {
		switch (func_id) {
		case BPF_FUNC_get_current_comm:
			return &bpf_get_current_comm_proto;
		case BPF_FUNC_get_current_pid_tgid:
			return &bpf_get_current_pid_tgid_proto;
		case BPF_FUNC_get_current_uid_gid:
			return &bpf_get_current_uid_gid_proto;
		case BPF_FUNC_trace_printk:
			return bpf_get_trace_printk_proto();
		default:
			break;
		}
	}
	return NULL;
}

const struct bpf_verifier_ops bpf_landlock_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
	.is_valid_subtype = bpf_landlock_is_valid_subtype,
};

void __init landlock_add_hooks(void)
{
	pr_info("%s: ABI %u, ready to sandbox with %s\n",
			LANDLOCK_NAME, LANDLOCK_ABI, "seccomp");
	landlock_add_hooks_ptrace();
	landlock_add_hooks_fs();
}
