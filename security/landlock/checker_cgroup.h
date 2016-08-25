/*
 * Landlock LSM - cgroup Checkers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_CGROUPS
#ifndef _SECURITY_LANDLOCK_CHECKER_CGROUP_H
#define _SECURITY_LANDLOCK_CHECKER_CGROUP_H

extern const struct bpf_func_proto bpf_landlock_cmp_cgroup_beneath_proto;

#endif /* _SECURITY_LANDLOCK_CHECKER_CGROUP_H */
#endif /* CONFIG_CGROUPS */
