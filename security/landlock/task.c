/*
 * Landlock LSM - task helpers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/types.h> /* gfp_t */

#include "hooks_fs.h" /* landlock_free_walk_list() */
#include "tag_fs.h"
#include "task.h"

/* TODO: inherit tsec->root and tsec->cwd on fork/execve */

void landlock_free_task_security(struct landlock_task_security *tsec)
{
	if (!tsec)
		return;
	landlock_free_walk_list(tsec->walk_list);
	landlock_free_tag_fs(tsec->root);
	landlock_free_tag_fs(tsec->cwd);
	kfree(tsec);
}

struct landlock_task_security *landlock_new_task_security(gfp_t gfp)
{
	return kzalloc(sizeof(struct landlock_task_security), gfp);
}
