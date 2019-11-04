/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - domain management headers
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_DOMAIN_MANAGE_H
#define _SECURITY_LANDLOCK_DOMAIN_MANAGE_H

#include <linux/filter.h>

#include "common.h"

void landlock_get_domain(struct landlock_domain *domain);
void landlock_put_domain(struct landlock_domain *domain);

struct landlock_domain *landlock_prepend_prog(struct landlock_domain *domain,
		struct bpf_prog *prog);

#endif /* _SECURITY_LANDLOCK_DOMAIN_MANAGE_H */
