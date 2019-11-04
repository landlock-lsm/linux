// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - eBPF program verifications
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/bpf.h>
#include <linux/filter.h>

#include "common.h"
#include "bpf_ptrace.h"

static bool bpf_landlock_is_valid_access(int off, int size,
		enum bpf_access_type type, const struct bpf_prog *prog,
		struct bpf_insn_access_aux *info)
{
	enum bpf_reg_type reg_type = NOT_INIT;
	int max_size = 0;

	if (WARN_ON(!prog->expected_attach_type))
		return false;

	if (off < 0)
		return false;
	if (size <= 0 || size > sizeof(__u64))
		return false;

	/* set register type and max size */
	switch (get_hook_type(prog)) {
	case LANDLOCK_HOOK_PTRACE:
		if (!landlock_is_valid_access_ptrace(off, type, &reg_type,
					&max_size))
			return false;
		break;
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

static const struct bpf_func_proto *bpf_landlock_func_proto(
		enum bpf_func_id func_id,
		const struct bpf_prog *prog)
{
	if (WARN_ON(!prog->expected_attach_type))
		return NULL;

	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	default:
		return NULL;
	}
}

const struct bpf_verifier_ops landlock_verifier_ops = {
	.get_func_proto	= bpf_landlock_func_proto,
	.is_valid_access = bpf_landlock_is_valid_access,
};

const struct bpf_prog_ops landlock_prog_ops = {};
