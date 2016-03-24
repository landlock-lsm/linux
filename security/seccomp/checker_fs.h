/*
 * Seccomp Linux Security Module - File System Checkers
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_SECCOMP_CHECKER_FS_H
#define _SECURITY_SECCOMP_CHECKER_FS_H

#include <linux/fs.h>

int seccomp_check_file(const struct file *);

#endif /* _SECURITY_SECCOMP_CHECKER_FS_H */
