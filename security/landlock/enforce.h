/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - enforcing helpers headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_ENFORCE_H
#define _SECURITY_LANDLOCK_ENFORCE_H

struct landlock_prog_set *landlock_prepend_prog(
		struct landlock_prog_set *current_prog_set,
		struct bpf_prog *prog);
void landlock_put_prog_set(struct landlock_prog_set *prog_set);
void landlock_get_prog_set(struct landlock_prog_set *prog_set);

#endif /* _SECURITY_LANDLOCK_ENFORCE_H */
