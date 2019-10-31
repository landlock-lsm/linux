// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - eBPF ptrace
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019 ANSSI
 */

#include <linux/bpf.h>
#include <uapi/linux/landlock.h>

#include "bpf_ptrace.h"

bool landlock_is_valid_access_ptrace(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size)
{
	if (type != BPF_READ)
		return false;

	switch (off) {
	case offsetof(struct landlock_context_ptrace, tracer):
		/* fall through */
	case offsetof(struct landlock_context_ptrace, tracee):
		*reg_type = PTR_TO_TASK;
		*max_size = sizeof(u64);
		return true;
	default:
		return false;
	}
}
