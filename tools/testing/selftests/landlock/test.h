/*
 * Landlock helpers
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <errno.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "../kselftest_harness.h"
#include "../../../../samples/bpf/bpf_load.h"

#ifndef SECCOMP_PREPEND_LANDLOCK_RULE
#define SECCOMP_PREPEND_LANDLOCK_RULE	2
#endif

#ifndef seccomp
static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}
#endif
