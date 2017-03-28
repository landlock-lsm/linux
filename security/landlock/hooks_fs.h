/*
 * Landlock LSM - filesystem hooks
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_access_type */


bool landlock_is_valid_access_event_FS(
		int off, int size, enum bpf_access_type type,
		enum bpf_reg_type *reg_type,
		union bpf_prog_subtype *prog_subtype);

__init void landlock_add_hooks_fs(void);
