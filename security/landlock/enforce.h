/*
 * Landlock LSM - enforcing helpers headers
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_ENFORCE_H
#define _SECURITY_LANDLOCK_ENFORCE_H

struct landlock_prog_set *landlock_prepend_prog(
		struct landlock_prog_set *current_prog_set,
		struct bpf_prog *prog);
void landlock_put_prog_set(struct landlock_prog_set *prog_set);
void landlock_get_prog_set(struct landlock_prog_set *prog_set);

#endif /* _SECURITY_LANDLOCK_ENFORCE_H */
