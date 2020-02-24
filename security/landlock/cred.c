// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Credential hooks
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/cred.h>
#include <linux/lsm_hooks.h>

#include "cred.h"
#include "ruleset.h"
#include "setup.h"

static int hook_cred_prepare(struct cred *new, const struct cred *old,
		gfp_t gfp)
{
	const struct landlock_cred_security *cred_old = landlock_cred(old);
	struct landlock_cred_security *cred_new = landlock_cred(new);
	struct landlock_ruleset *dom_old;

	dom_old = cred_old->domain;
	if (dom_old) {
		landlock_get_ruleset(dom_old);
		cred_new->domain = dom_old;
	} else {
		cred_new->domain = NULL;
	}
	return 0;
}

static void hook_cred_free(struct cred *cred)
{
	landlock_put_ruleset_enqueue(landlock_cred(cred)->domain);
}

static struct security_hook_list landlock_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_free, hook_cred_free),
};

__init void landlock_add_hooks_cred(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
