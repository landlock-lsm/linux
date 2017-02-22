/*
 * Landlock LSM - Sample 1 (BPF program)
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/stat.h> /* S_ISCHR() */
#include "bpf_helpers.h"

SEC("landlock1")
static int landlock_fs_prog1(struct landlock_context *ctx)
{
	char fmt_error[] = "landlock1: error: get_mode:%lld\n";
	char fmt_name[] = "landlock1: syscall:%d\n";
	long long ret;

	if (!(ctx->arg2 & LANDLOCK_ACTION_FS_WRITE))
		return 0;
	ret = bpf_handle_fs_get_mode((void *)ctx->arg1);
	if (ret < 0) {
		bpf_trace_printk(fmt_error, sizeof(fmt_error), ret);
		return 1;
	}
	if (S_ISCHR(ret))
		return 0;
	bpf_trace_printk(fmt_name, sizeof(fmt_name), ctx->syscall_nr);
	return 1;
}

SEC("subtype")
static union bpf_prog_subtype _subtype = {
	.landlock_rule = {
		.version = 1,
		.event = LANDLOCK_SUBTYPE_EVENT_FS,
		.ability = LANDLOCK_SUBTYPE_ABILITY_DEBUG,
	}
};

SEC("license")
static char _license[] = "GPL";
