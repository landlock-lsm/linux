// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock sample 1 - deny access to a set of directories (blacklisting)
 *
 * Copyright © 2017-2019 Mickaël Salaün <mic@digikod.net>
 */

#include "bpf/libbpf.h"
#include "bpf_load.h"
#include "landlock1.h" /* MAP_FLAG_DENY */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h> /* open() */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/landlock.h>
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

static int apply_sandbox(int prog_fd)
{
	int ret = 0;

	/* set up the test sandbox */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(no_new_priv)");
		return 1;
	}
	if (seccomp(SECCOMP_PREPEND_LANDLOCK_PROG, 0, &prog_fd)) {
		perror("seccomp(set_hook)");
		ret = 1;
	}
	close(prog_fd);

	return ret;
}

#define ENV_FS_PATH_DENY_NAME "LL_PATH_DENY"
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

static int populate_map(const char *env_var, unsigned long long value,
		int map_fd)
{
	int path_nb, ref_fd, i;
	char *env_path_name;
	const char **path_list = NULL;

	env_path_name = getenv(env_var);
	if (!env_path_name)
		return 0;
	env_path_name = strdup(env_path_name);
	path_nb = parse_path(env_path_name, &path_list);

	for (i = 0; i < path_nb; i++) {
		ref_fd = open(path_list[i], O_RDONLY | O_CLOEXEC);
		if (ref_fd < 0) {
			fprintf(stderr, "Failed to open \"%s\": %s\n",
					path_list[i],
					strerror(errno));
			return 1;
		}
		if (bpf_map_update_elem(map_fd, &ref_fd, &value, BPF_ANY)) {
			fprintf(stderr, "Failed to update the map with"
					" \"%s\": %s\n", path_list[i],
					strerror(errno));
			return 1;
		}
		close(ref_fd);
	}
	free(env_path_name);
	return 0;
}

/* need to call bpf_object__close(obj) once every FD is used */
static int ll_load_file(const char *filename, struct bpf_object **obj,
		int *ll_map, int *ll_prog_walk, int *ll_prog_pick)
{
	int first_bpf_prog, map_fd, prog_walk_fd, prog_pick_fd, err;
	struct bpf_map *map;
	struct bpf_program *prog;
	struct bpf_object *tmp_obj;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_UNSPEC,
		.file = filename,
	};

	/*
	 * allowed:
	 * - LANDLOCK_TRIGGER_FS_PICK_LINK
	 * - LANDLOCK_TRIGGER_FS_PICK_LINKTO
	 * - LANDLOCK_TRIGGER_FS_PICK_RECEIVE
	 * - LANDLOCK_TRIGGER_FS_PICK_MOUNTON
	 */
	prog_load_attr.expected_attach_triggers =
		LANDLOCK_TRIGGER_FS_PICK_APPEND |
		LANDLOCK_TRIGGER_FS_PICK_CHDIR |
		LANDLOCK_TRIGGER_FS_PICK_CHROOT |
		LANDLOCK_TRIGGER_FS_PICK_CREATE |
		LANDLOCK_TRIGGER_FS_PICK_EXECUTE |
		LANDLOCK_TRIGGER_FS_PICK_FCNTL |
		LANDLOCK_TRIGGER_FS_PICK_GETATTR |
		LANDLOCK_TRIGGER_FS_PICK_IOCTL |
		LANDLOCK_TRIGGER_FS_PICK_LOCK |
		LANDLOCK_TRIGGER_FS_PICK_MAP |
		LANDLOCK_TRIGGER_FS_PICK_OPEN |
		LANDLOCK_TRIGGER_FS_PICK_READ |
		LANDLOCK_TRIGGER_FS_PICK_READDIR |
		LANDLOCK_TRIGGER_FS_PICK_RENAME |
		LANDLOCK_TRIGGER_FS_PICK_RENAMETO |
		LANDLOCK_TRIGGER_FS_PICK_RMDIR |
		LANDLOCK_TRIGGER_FS_PICK_SETATTR |
		LANDLOCK_TRIGGER_FS_PICK_TRANSFER |
		LANDLOCK_TRIGGER_FS_PICK_UNLINK |
		LANDLOCK_TRIGGER_FS_PICK_WRITE;

	if (access(filename, O_RDONLY) < 0) {
		printf("Failed to access file %s: %s\n", filename,
				strerror(errno));
		return 1;
	}
	err = bpf_prog_load_xattr(&prog_load_attr, &tmp_obj, &first_bpf_prog);
	if (err) {
		printf("Failed to parse file %s: %s\n", filename, strerror(err));
		goto error_load;
	}

	map = bpf_object__find_map_by_name(tmp_obj, "inode_map");
	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		printf("Map not found: %s\n", strerror(map_fd));
		goto put_obj;
	}

	prog = bpf_object__find_program_by_title(tmp_obj, "landlock/fs_walk");
	if (!prog) {
		printf("Program for FS_WALK not found in file %s\n", filename);
		goto put_obj;
	}
	prog_walk_fd = bpf_program__fd(prog);
	if (prog_walk_fd < 0) {
		printf("Failed to load the FS_WALK program from file %s\n",
				strerror(prog_walk_fd));
		goto put_obj;
	}

	prog = bpf_object__find_program_by_title(tmp_obj, "landlock/fs_pick");
	if (!prog) {
		printf("Failed to get a file descriptor for program %s from file %s\n",
				bpf_program__title(prog, false), filename);
		goto put_obj;
	}
	prog_pick_fd = bpf_program__fd(prog);
	if (prog_pick_fd < 0) {
		printf("Failed to get a file descriptor for program %s from file %s\n",
				bpf_program__title(prog, false), filename);
		goto put_obj;
	}

	*obj = tmp_obj;
	*ll_prog_walk = prog_walk_fd;
	*ll_prog_pick = prog_pick_fd;
	*ll_map = map_fd;
	return 0;

put_obj:
	/* All FDs are closed with bpf_object__close() */
	bpf_object__close(tmp_obj);
error_load:
	printf("ERROR: load_bpf_file failed for: %s\n", filename);
	printf("  Output from verifier:\n%s\n------\n", bpf_log_buf);
	return 1;
}

int main(int argc, char * const argv[], char * const *envp)
{
	char filename[256];
	char *cmd_path;
	char * const *cmd_argv;
	struct bpf_object *obj;
	int ll_map, ll_prog_walk, ll_prog_pick;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <cmd> [args]...\n\n", argv[0]);
		fprintf(stderr, "Launch a command in a restricted environment.\n\n");
		fprintf(stderr, "Environment variables containing paths, each separated by a colon:\n");
		fprintf(stderr, "* %s: list of files and directories which are denied\n",
				ENV_FS_PATH_DENY_NAME);
		fprintf(stderr, "\nexample:\n"
				"%s=\"${HOME}/.ssh:${HOME}/Images\" "
				"%s /bin/sh -i\n",
				ENV_FS_PATH_DENY_NAME, argv[0]);
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (ll_load_file(filename, &obj, &ll_map, &ll_prog_walk, &ll_prog_pick))
		return 1;

	if (populate_map(ENV_FS_PATH_DENY_NAME, MAP_FLAG_DENY, ll_map))
		return 1;
	//close(ll_map);

	fprintf(stderr, "Launching a new sandboxed process\n");
	if (apply_sandbox(ll_prog_walk))
		return 1;
	//close(ll_prog_walk);
	if (apply_sandbox(ll_prog_pick))
		return 1;
	//close(ll_prog_pick);
	//bpf_object__close(obj);
	cmd_path = argv[1];
	cmd_argv = argv + 1;
	execve(cmd_path, cmd_argv, envp);
	perror("Failed to call execve");
	return 1;
}
