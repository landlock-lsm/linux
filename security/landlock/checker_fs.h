/*
 * Landlock LSM - File System Checkers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_CHECKER_FS_H
#define _SECURITY_LANDLOCK_CHECKER_FS_H

#include <linux/fs.h>
#include <linux/seccomp.h>

extern const struct bpf_func_proto bpf_landlock_cmp_fs_prop_with_struct_file_proto;
extern const struct bpf_func_proto bpf_landlock_cmp_fs_beneath_with_struct_file_proto;

#endif /* _SECURITY_LANDLOCK_CHECKER_FS_H */
