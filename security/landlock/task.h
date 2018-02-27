/*
 * Landlock LSM - task headers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_TASK_H
#define _SECURITY_LANDLOCK_TASK_H

#include <linux/types.h> /* gfp_t */

#include "hooks_fs.h"
#include "tag_fs.h"

/* exclusively used by the current task (i.e. no concurrent access) */
struct landlock_task_security {
	struct landlock_walk_list *walk_list;
	struct landlock_tag_fs *root, *cwd;
};

struct landlock_task_security *landlock_new_task_security(gfp_t gfp);
void landlock_free_task_security(struct landlock_task_security *tsec);

#endif /* _SECURITY_LANDLOCK_TASK_H */
