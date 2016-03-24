/*
 * Seccomp Linux Security Module
 *
 * Copyright (C) 2016  Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/syscalls.h>	/* syscall_argdesc */

extern const struct syscall_argdesc __start_syscalls_argdesc[];
extern const struct syscall_argdesc __stop_syscalls_argdesc[];

#ifdef CONFIG_COMPAT
extern const struct syscall_argdesc __start_compat_syscalls_argdesc[];
extern const struct syscall_argdesc __stop_compat_syscalls_argdesc[];
#endif	/* CONFIG_COMPAT */
