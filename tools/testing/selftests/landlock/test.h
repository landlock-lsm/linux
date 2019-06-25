/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Landlock helpers
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019 ANSSI
 */

#include <bpf/bpf.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "../kselftest_harness.h"
#include "../../../../samples/bpf/bpf_load.h"

#ifndef SECCOMP_PREPEND_LANDLOCK_PROG
#define SECCOMP_PREPEND_LANDLOCK_PROG	4
#endif

#ifndef seccomp
static int __attribute__((unused)) seccomp(unsigned int op, unsigned int flags,
		void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}
#endif

/* bpf_load_program() with subtype */
static int __attribute__((unused)) ll_bpf_load_program(
		const struct bpf_insn *insns, size_t insns_cnt, char *log_buf,
		size_t log_buf_sz, const union bpf_prog_subtype *subtype)
{
	struct bpf_load_program_attr load_attr;

	memset(&load_attr, 0, sizeof(struct bpf_load_program_attr));
	load_attr.prog_type = BPF_PROG_TYPE_LANDLOCK_HOOK;
	load_attr.prog_subtype = subtype;
	load_attr.insns = insns;
	load_attr.insns_cnt = insns_cnt;
	load_attr.license = "GPL";

	return bpf_load_program_xattr(&load_attr, log_buf, log_buf_sz);
}
