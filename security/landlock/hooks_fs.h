/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - filesystem hooks
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/bpf.h> /* enum bpf_access_type */

__init void landlock_add_hooks_fs(void);

/* fs_pick */

struct landlock_hook_ctx_fs_pick;

bool landlock_is_valid_access_fs_pick(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size);

const struct landlock_ctx_fs_pick *landlock_get_ctx_fs_pick(
		const struct landlock_hook_ctx_fs_pick *hook_ctx);

/* fs_walk */

struct landlock_hook_ctx_fs_walk;

bool landlock_is_valid_access_fs_walk(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size);

const struct landlock_ctx_fs_walk *landlock_get_ctx_fs_walk(
		const struct landlock_hook_ctx_fs_walk *hook_ctx);
