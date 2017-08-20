/*
 * Landlock rule - partial read-only filesystem
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

/*
 * This file contains a function that will be compiled to eBPF bytecode thanks
 * to LLVM/Clang.
 *
 * Each SEC() means that the following function or variable will be part of a
 * custom ELF section. This sections are then processed by the userspace part
 * (see landlock1_user.c) to extract eBPF bytecode and take into account
 * variables describing the eBPF program subtype or its license.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/stat.h> /* S_ISCHR() */
#include "bpf_helpers.h"

/*
 * The function landlock_fs_prog1() is a simple Landlock rule enforced on a set
 * of processes. This rule will be run for each file-system operations and will
 * then forbid any write on a file-descriptor except if this file-descriptor
 * point to a pipe. Hence, it will not be possible to create new files nor to
 * modify a regular file.
 *
 * The argument ctx contains the context of the rule when it is run, which
 * enable to check which action on which file is requested. This context can
 * change for each run of the rule.
 */
SEC("landlock1")
static int landlock_fs_prog1(struct landlock_context *ctx)
{
	char fmt_error_mode[] = "landlock1: error: get_mode:%lld\n";
	char fmt_error_access[] = "landlock1: error: access denied\n";
	long long ret;

	/*
	 * The argument ctx->arg2 contains bitflags of actions for which the
	 * rule is run.  The flag LANDLOCK_ACTION_FS_WRITE means that a write
	 * is requested by one of the userspace processes restricted by this
	 * rule. The following test allows any actions which does not include a
	 * write.
	 */
	if (!(ctx->arg2 & LANDLOCK_ACTION_FS_WRITE))
		return 0;

	/*
	 * The argument ctx->arg1 is a file handle for which the process want
	 * to access. The function bpf_handle_fs_get_mode() return the mode of
	 * a file (e.g. S_IFBLK, S_IFDIR, S_IFREG...). If there is an error,
	 * for example if the argument is not a file handle, then an
	 * -errno value is returned. Otherwise the caller get the file mode as
	 *  with stat(2).
	 */
	ret = bpf_handle_fs_get_mode((void *)ctx->arg1);
	if (ret < 0) {

		/*
		 * The bpf_trace_printk() function enable to write in the
		 * kernel eBPF debug log, accessible through
		 * /sys/kernel/debug/tracing/trace_pipe . To be allowed to call
		 * this function, a Landlock rule must have the
		 * LANDLOCK_SUBTYPE_ABILITY_DEBUG ability, which is only
		 * allowed for CAP_SYS_ADMIN.
		 */
		bpf_trace_printk(fmt_error_mode, sizeof(fmt_error_mode), ret);
		return 1;
	}

	/*
	 * This check allows the action on the file if it is a directory or a
	 * pipe. Otherwise, a message is printed to the eBPF log.
	 */
	if (S_ISCHR(ret) || S_ISFIFO(ret))
		return 0;
	bpf_trace_printk(fmt_error_access, sizeof(fmt_error_access));
	return 1;
}

/*
 * This subtype enable to set the ABI, which ensure that the eBPF context and
 * program behavior will be compatible with this Landlock rule.
 */
SEC("subtype")
static const union bpf_prog_subtype _subtype = {
	.landlock_rule = {
		.abi = 1,
		.event = LANDLOCK_SUBTYPE_EVENT_FS,
		.ability = LANDLOCK_SUBTYPE_ABILITY_DEBUG,
	}
};

SEC("license")
static const char _license[] = "GPL";
