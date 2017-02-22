/*
 * Landlock LSM - Sample 1 (userland)
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include "bpf_load.h"
#include "libbpf.h"

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h> /* open() */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef seccomp
static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}
#endif

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))
#define MAX_ERRNO	4095


struct landlock_rule {
	enum landlock_subtype_event event;
	struct bpf_insn *bpf;
	size_t size;
};

static int apply_sandbox(int prog_fd)
{
	int ret = 0;

	/* set up the test sandbox */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(no_new_priv)");
		return 1;
	}
	if (seccomp(SECCOMP_ADD_LANDLOCK_RULE, 0, &prog_fd)) {
		perror("seccomp(set_hook)");
		ret = 1;
	}
	close(prog_fd);

	return ret;
}

int main(int argc, char * const argv[], char * const *envp)
{
	char filename[256];
	char *cmd_path;
	char * const *cmd_argv;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <cmd> [args]...\n\n", argv[0]);
		fprintf(stderr, "Launch a command in a read-only environment "
				"(except for character devices).\n");
		fprintf(stderr, "Display debug with: "
				"cat /sys/kernel/debug/tracing/trace_pipe &\n");
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}
	if (!prog_fd[0]) {
		if (errno) {
			printf("load_bpf_file: %s\n", strerror(errno));
		} else {
			printf("load_bpf_file: Error\n");
		}
		return 1;
	}

	if (apply_sandbox(prog_fd[0]))
		return 1;
	cmd_path = argv[1];
	cmd_argv = argv + 1;
	fprintf(stderr, "Launching a new sandboxed process.\n");
	execve(cmd_path, cmd_argv, envp);
	perror("execve");
	return 1;
}
