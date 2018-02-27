/*
 * inode map for Landlock
 *
 * Copyright © 2017-2018 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/resource.h> /* RLIMIT_NOFILE */
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/file.h> /* fput() */
#include <linux/filter.h> /* BPF_CALL_2() */
#include <linux/fs.h> /* struct file */
#include <linux/mm.h>
#include <linux/mount.h> /* MNT_INTERNAL */
#include <linux/path.h> /* struct path */
#include <linux/sched/signal.h> /* rlimit() */
#include <linux/security.h>
#include <linux/slab.h>

struct inode_elem {
	struct inode *inode;
	u64 value;
};

struct inode_array {
	struct bpf_map map;
	size_t nb_entries;
	struct inode_elem elems[0];
};

/* must call iput(inode) after this call */
static struct inode *inode_from_fd(int ufd, bool check_access)
{
	struct inode *ret;
	struct fd f;
	int deny;

	f = fdget(ufd);
	if (unlikely(!f.file || !file_inode(f.file))) {
		ret = ERR_PTR(-EBADF);
		goto put_fd;
	}
	/* TODO: add this check when called from an eBPF program too (already
	 * checked by the LSM parent hooks anyway) */
	if (unlikely(IS_PRIVATE(file_inode(f.file)))) {
		ret = ERR_PTR(-EINVAL);
		goto put_fd;
	}
	/* check if the FD is tied to a mount point */
	/* TODO: add this check when called from an eBPF program too */
	if (unlikely(!f.file->f_path.mnt || f.file->f_path.mnt->mnt_flags &
				MNT_INTERNAL)) {
		ret = ERR_PTR(-EINVAL);
		goto put_fd;
	}
	if (check_access) {
		/* need to be allowed to access attributes from this file to
		 * then be able to compare an inode to this entry */
		deny = security_inode_getattr(&f.file->f_path);
		if (deny) {
			ret = ERR_PTR(deny);
			goto put_fd;
		}
	}
	ret = file_inode(f.file);
	ihold(ret);

put_fd:
	fdput(f);
	return ret;
}

/* (never) called from eBPF program */
static int fake_map_delete_elem(struct bpf_map *map, void *key)
{
	WARN_ON(1);
	return -EINVAL;
}

/* called from syscall */
static int sys_inode_map_delete_elem(struct bpf_map *map, struct inode *key)
{
	struct inode_array *array = container_of(map, struct inode_array, map);
	struct inode *inode;
	int i;

	WARN_ON_ONCE(!rcu_read_lock_held());
	for (i = 0; i < array->map.max_entries; i++) {
		if (array->elems[i].inode == key) {
			inode = xchg(&array->elems[i].inode, NULL);
			array->nb_entries--;
			iput(inode);
			return 0;
		}
	}
	return -ENOENT;
}

/* called from syscall */
int bpf_inode_map_delete_elem(struct bpf_map *map, int *key)
{
	struct inode *inode;
	int err;

	inode = inode_from_fd(*key, false);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	err = sys_inode_map_delete_elem(map, inode);
	iput(inode);
	return err;
}

static void inode_map_free(struct bpf_map *map)
{
	struct inode_array *array = container_of(map, struct inode_array, map);
	int i;

	synchronize_rcu();
	for (i = 0; i < array->map.max_entries; i++)
		iput(array->elems[i].inode);
	bpf_map_area_free(array);
}

static struct bpf_map *inode_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct inode_array *array;
	u64 array_size;

	/* only allow root to create this type of map (for now), should be
	 * removed when Landlock will be usable by unprivileged users */
	if (!capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);

	/* the key is a file descriptor and the value must be 64-bits (for
	 * now) */
	if (attr->max_entries == 0 || attr->key_size != sizeof(u32) ||
	    attr->value_size != FIELD_SIZEOF(struct inode_elem, value) ||
	    attr->map_flags & ~(BPF_F_RDONLY | BPF_F_WRONLY) ||
	    numa_node != NUMA_NO_NODE)
		return ERR_PTR(-EINVAL);

	if (attr->value_size > KMALLOC_MAX_SIZE)
		/* if value_size is bigger, the user space won't be able to
		 * access the elements.
		 */
		return ERR_PTR(-E2BIG);

	/*
	 * Limit number of entries in an inode map to the maximum number of
	 * open files for the current process. The maximum number of file
	 * references (including all inode maps) for a process is then
	 * (RLIMIT_NOFILE - 1) * RLIMIT_NOFILE. If the process' RLIMIT_NOFILE
	 * is 0, then any entry update is forbidden.
	 *
	 * An eBPF program can inherit all the inode map FD. The worse case is
	 * to fill a bunch of arraymaps, create an eBPF program, close the
	 * inode map FDs, and start again. The maximum number of inode map
	 * entries can then be close to RLIMIT_NOFILE^3.
	 */
	if (attr->max_entries > rlimit(RLIMIT_NOFILE))
		return ERR_PTR(-EMFILE);

	array_size = sizeof(*array);
	array_size += (u64) attr->max_entries * sizeof(struct inode_elem);

	/* make sure there is no u32 overflow later in round_up() */
	if (array_size >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-ENOMEM);

	/* allocate all map elements and zero-initialize them */
	array = bpf_map_area_alloc(array_size, numa_node);
	if (!array)
		return ERR_PTR(-ENOMEM);

	/* copy mandatory map attributes */
	array->map.key_size = attr->key_size;
	array->map.map_flags = attr->map_flags;
	array->map.map_type = attr->map_type;
	array->map.max_entries = attr->max_entries;
	array->map.numa_node = numa_node;
	array->map.pages = round_up(array_size, PAGE_SIZE) >> PAGE_SHIFT;
	array->map.value_size = attr->value_size;

	return &array->map;
}

/* (never) called from eBPF program */
static void *fake_map_lookup_elem(struct bpf_map *map, void *key)
{
	WARN_ON(1);
	return ERR_PTR(-EINVAL);
}

/* called from syscall (wrapped) and eBPF program */
static u64 inode_map_lookup_elem(struct bpf_map *map, struct inode *key)
{
	struct inode_array *array = container_of(map, struct inode_array, map);
	size_t i;
	u64 ret = 0;

	WARN_ON_ONCE(!rcu_read_lock_held());
	/* TODO: use rbtree to switch to O(log n) */
	for (i = 0; i < array->map.max_entries; i++) {
		if (array->elems[i].inode == key) {
			ret = array->elems[i].value;
			break;
		}
	}
	return ret;
}

/* key is an FD when called from a syscall, but an inode pointer when called
 * from an eBPF program */

/* called from syscall */
int bpf_inode_map_lookup_elem(struct bpf_map *map, int *key, u64 *value)
{
	struct inode *inode;

	inode = inode_from_fd(*key, false);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	*value = inode_map_lookup_elem(map, inode);
	iput(inode);
	if (!value)
		return -ENOENT;
	return 0;
}

/* (never) called from eBPF program */
static int fake_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 flags)
{
	WARN_ON(1);
	/* do not leak an inode accessed by a Landlock program */
	return -EINVAL;
}

/* called from syscall */
static int sys_inode_map_update_elem(struct bpf_map *map, struct inode *key,
		u64 *value, u64 flags)
{
	struct inode_array *array = container_of(map, struct inode_array, map);
	size_t i;

	if (unlikely(flags != BPF_ANY))
		return -EINVAL;

	if (unlikely(array->nb_entries >= array->map.max_entries))
		/* all elements were pre-allocated, cannot insert a new one */
		return -E2BIG;

	for (i = 0; i < array->map.max_entries; i++) {
		if (!array->elems[i].inode) {
			/* the inode (key) is already grabbed by the caller */
			ihold(key);
			array->elems[i].inode = key;
			array->elems[i].value = *value;
			array->nb_entries++;
			return 0;
		}
	}
	WARN_ON(1);
	return -ENOENT;
}

/* called from syscall */
int bpf_inode_map_update_elem(struct bpf_map *map, int *key, u64 *value,
			      u64 flags)
{
	struct inode *inode;
	int err;

	WARN_ON_ONCE(!rcu_read_lock_held());
	inode = inode_from_fd(*key, true);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	err = sys_inode_map_update_elem(map, inode, value, flags);
	iput(inode);
	return err;
}

/* called from syscall or (never) from eBPF program */
static int fake_map_get_next_key(struct bpf_map *map, void *key,
				 void *next_key)
{
	/* do not leak a file descriptor */
	return -EINVAL;
}

/* void map for eBPF program */
const struct bpf_map_ops inode_ops = {
	.map_alloc = inode_map_alloc,
	.map_free = inode_map_free,
	.map_get_next_key = fake_map_get_next_key,
	.map_lookup_elem = fake_map_lookup_elem,
	.map_delete_elem = fake_map_delete_elem,
	.map_update_elem = fake_map_update_elem,
};

BPF_CALL_2(bpf_inode_map_lookup, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return inode_map_lookup_elem(map, key);
}

const struct bpf_func_proto bpf_inode_map_lookup_proto = {
	.func		= bpf_inode_map_lookup,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_INODE,
};
