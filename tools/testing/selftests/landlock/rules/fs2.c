/*
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * Landlock test - No-open filesystem
 */

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("landlock1")
static int landlock_fs_prog1(struct landlock_context *ctx)
{
	if (!(ctx->arg2 & LANDLOCK_ACTION_FS_GET))
		return 0;
	return 1;
}

SEC("subtype")
static union bpf_prog_subtype _subtype = {
	.landlock_rule = {
		.version = 1,
		.event = LANDLOCK_SUBTYPE_EVENT_FS,
	}
};

SEC("license")
static char _license[] = "GPL";
