// SPDX-License-Identifier: BSD-3-Clause
/*
 * Simple Landlock sandbox manager able to launch a process restricted by a
 * user-defined filesystem access-control security policy.
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef landlock

#ifndef __NR_landlock
#define __NR_landlock 436
#endif

static inline int landlock(unsigned int command, unsigned int options,
		size_t attr_size, void *attr_ptr)
{
	errno = 0;
	return syscall(__NR_landlock, command, options, attr_size, attr_ptr, 0,
			NULL);
}
#endif

#define ENV_FS_RO_NAME "LL_FS_RO"
#define ENV_FS_RW_NAME "LL_FS_RW"
#define ENV_PATH_TOKEN ":"

static int parse_path(char *env_path, const char ***path_list)
{
	int i, path_nb = 0;

	if (env_path) {
		path_nb++;
		for (i = 0; env_path[i]; i++) {
			if (env_path[i] == ENV_PATH_TOKEN[0])
				path_nb++;
		}
	}
	*path_list = malloc(path_nb * sizeof(**path_list));
	for (i = 0; i < path_nb; i++)
		(*path_list)[i] = strsep(&env_path, ENV_PATH_TOKEN);

	return path_nb;
}

static int populate_ruleset(const struct landlock_attr_features *attr_features,
		const char *env_var, int ruleset_fd, __u64 allowed_access)
{
	int path_nb, i;
	char *env_path_name;
	const char **path_list = NULL;
	struct landlock_attr_path_beneath path_beneath = {
		.ruleset_fd = ruleset_fd,
		.allowed_access = allowed_access,
		.parent_fd = -1,
	};

	env_path_name = getenv(env_var);
	if (!env_path_name) {
		fprintf(stderr, "Missing environment variable %s\n", env_var);
		return 1;
	}
	env_path_name = strdup(env_path_name);
	unsetenv(env_var);
	path_nb = parse_path(env_path_name, &path_list);
	if (path_nb == 1 && path_list[0][0] == '\0') {
		fprintf(stderr, "Missing path in %s\n", env_var);
		goto err_free_name;
	}

	/* follow a best-effort approach */
	path_beneath.allowed_access &= attr_features->access_fs;
	for (i = 0; i < path_nb; i++) {
		path_beneath.parent_fd = open(path_list[i],
				O_PATH | O_NOFOLLOW | O_CLOEXEC);
		if (path_beneath.parent_fd < 0) {
			fprintf(stderr, "Failed to open \"%s\": %s\n",
					path_list[i],
					strerror(errno));
			goto err_free_name;
		}
		if (landlock(LANDLOCK_CMD_ADD_RULE,
					LANDLOCK_OPT_ADD_RULE_PATH_BENEATH,
					sizeof(path_beneath), &path_beneath)) {
			fprintf(stderr, "Failed to update the ruleset with \"%s\": %s\n",
					path_list[i], strerror(errno));
			close(path_beneath.parent_fd);
			goto err_free_name;
		}
		close(path_beneath.parent_fd);
	}
	free(env_path_name);
	return 0;

err_free_name:
	free(env_path_name);
	return 1;
}

#define ACCESS_FS_ROUGHLY_READ ( \
	LANDLOCK_ACCESS_FS_READ | \
	LANDLOCK_ACCESS_FS_READDIR | \
	LANDLOCK_ACCESS_FS_GETATTR | \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_CHROOT)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_LOCK | \
	LANDLOCK_ACCESS_FS_CHMOD | \
	LANDLOCK_ACCESS_FS_CHOWN | \
	LANDLOCK_ACCESS_FS_CHGRP | \
	LANDLOCK_ACCESS_FS_IOCTL | \
	LANDLOCK_ACCESS_FS_LINK_TO | \
	LANDLOCK_ACCESS_FS_RENAME_FROM | \
	LANDLOCK_ACCESS_FS_RENAME_TO | \
	LANDLOCK_ACCESS_FS_RMDIR | \
	LANDLOCK_ACCESS_FS_UNLINK | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM)

int main(int argc, char * const argv[], char * const *envp)
{
	char *cmd_path;
	char * const *cmd_argv;
	int ruleset_fd;
	struct landlock_attr_features attr_features;
	struct landlock_attr_ruleset ruleset = {
		/* only restrict open and getattr */
		.handled_access_fs = ACCESS_FS_ROUGHLY_READ |
			ACCESS_FS_ROUGHLY_WRITE,
	};
	struct landlock_attr_enforce attr_enforce = {};

	if (argc < 2) {
		fprintf(stderr, "usage: %s=\"...\" %s=\"...\" %s <cmd> [args]...\n\n",
				ENV_FS_RO_NAME, ENV_FS_RW_NAME, argv[0]);
		fprintf(stderr, "Launch a command in a restricted environment.\n\n");
		fprintf(stderr, "Environment variables containing paths, each separated by a colon:\n");
		fprintf(stderr, "* %s: list of paths allowed to be used in a read-only way.\n",
				ENV_FS_RO_NAME);
		fprintf(stderr, "* %s: list of paths allowed to be used in a read-write way.\n",
				ENV_FS_RO_NAME);
		fprintf(stderr, "\nexample:\n"
				"%s=\"/bin:/lib:/usr\" "
				"%s=\"/dev/pts\" "
				"%s /bin/bash -i\n",
				ENV_FS_RO_NAME, ENV_FS_RW_NAME, argv[0]);
		return 1;
	}

	if (landlock(LANDLOCK_CMD_GET_FEATURES, LANDLOCK_OPT_GET_FEATURES,
				sizeof(attr_features), &attr_features)) {
		perror("Failed to probe the Landlock supported features");
		switch (errno) {
		case ENOSYS:
			fprintf(stderr, "Hint: this kernel does not support Landlock.\n");
			break;
		case ENOPKG:
			fprintf(stderr, "Hint: Landlock is currently disabled. It can be enabled in the kernel configuration or at boot with the \"lsm=landlock\" parameter.\n");
			break;
		}
		return 1;
	}
	/* follow a best-effort approach */
	ruleset.handled_access_fs &= attr_features.access_fs;
	ruleset_fd = landlock(LANDLOCK_CMD_CREATE_RULESET,
			LANDLOCK_OPT_CREATE_RULESET, sizeof(ruleset),
			&ruleset);
	if (ruleset_fd < 0) {
		perror("Failed to create a ruleset");
		return 1;
	}
	if (populate_ruleset(&attr_features, ENV_FS_RO_NAME, ruleset_fd,
				ACCESS_FS_ROUGHLY_READ)) {
		goto err_close_ruleset;
	}
	if (populate_ruleset(&attr_features, ENV_FS_RW_NAME, ruleset_fd,
				ACCESS_FS_ROUGHLY_READ |
				ACCESS_FS_ROUGHLY_WRITE)) {
		goto err_close_ruleset;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("Failed to restrict privileges");
		goto err_close_ruleset;
	}
	attr_enforce.ruleset_fd = ruleset_fd;
	if (landlock(LANDLOCK_CMD_ENFORCE_RULESET,
				LANDLOCK_OPT_ENFORCE_RULESET,
				sizeof(attr_enforce), &attr_enforce)) {
		perror("Failed to enforce ruleset");
		goto err_close_ruleset;
	}
	close(ruleset_fd);

	cmd_path = argv[1];
	cmd_argv = argv + 1;
	execve(cmd_path, cmd_argv, envp);
	fprintf(stderr, "Failed to execute \"%s\"\n", cmd_path);
	fprintf(stderr, "Hint: access to the binary or its shared libraries may be denied.\n");
	return 1;

err_close_ruleset:
	close(ruleset_fd);
	return 1;
}
