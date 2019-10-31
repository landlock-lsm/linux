// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - credential hooks
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/cred.h>
#include <linux/lsm_hooks.h>

#include "common.h"
#include "domain_manage.h"
#include "hooks_cred.h"

static int hook_cred_prepare(struct cred *new, const struct cred *old,
		gfp_t gfp)
{
	const struct landlock_cred_security *cred_old = landlock_cred(old);
	struct landlock_cred_security *cred_new = landlock_cred(new);
	struct landlock_domain *dom_old;

	dom_old = cred_old->domain;
	if (dom_old) {
		landlock_get_domain(dom_old);
		cred_new->domain = dom_old;
	} else {
		cred_new->domain = NULL;
	}
	return 0;
}

static void hook_cred_free(struct cred *cred)
{
	landlock_put_domain(landlock_cred(cred)->domain);
}

static struct security_hook_list landlock_hooks[] = {
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_free, hook_cred_free),
};

__init void landlock_add_hooks_cred(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
