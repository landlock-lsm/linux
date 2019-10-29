/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Landlock - UAPI headers
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2019 ANSSI
 */

#ifndef _UAPI__LINUX_LANDLOCK_H__
#define _UAPI__LINUX_LANDLOCK_H__

#include <linux/types.h>

/**
 * DOC: landlock_ret
 *
 * The return value of a landlock program is a bitmask that can allow or deny
 * the action for which the program is run.
 *
 * In the future, this could be used to trigger an audit event as well.
 *
 * - %LANDLOCK_RET_ALLOW
 * - %LANDLOCK_RET_DENY
 */
#define LANDLOCK_RET_ALLOW	0
#define LANDLOCK_RET_DENY	1

/**
 * struct landlock_context_ptrace - context accessible to BPF_LANDLOCK_PTRACE
 *
 * @tracer: pointer to the task requesting to debug @tracee
 * @tracee: pointer to the task being debugged
 */
struct landlock_context_ptrace {
	__u64 tracer;
	__u64 tracee;
};

#endif /* _UAPI__LINUX_LANDLOCK_H__ */
