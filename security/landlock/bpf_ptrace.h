/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - eBPF ptrace headers
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_BPF_PTRACE_H
#define _SECURITY_LANDLOCK_BPF_PTRACE_H

#include <linux/bpf.h>

bool landlock_is_valid_access_ptrace(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size);

#endif /* _SECURITY_LANDLOCK_BPF_PTRACE_H */
