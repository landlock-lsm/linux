// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - initialization
 *
 * Copyright © 2016-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#include <linux/lsm_hooks.h>

#include "common.h"
#include "hooks_cred.h"

static int __init landlock_init(void)
{
	pr_info(LANDLOCK_NAME ": Registering hooks\n");
	landlock_add_hooks_cred();
	return 0;
}

struct lsm_blob_sizes landlock_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct landlock_cred_security),
};

DEFINE_LSM(LANDLOCK_NAME) = {
	.name = LANDLOCK_NAME,
	.order = LSM_ORDER_LAST,
	.blobs = &landlock_blob_sizes,
	.init = landlock_init,
};
