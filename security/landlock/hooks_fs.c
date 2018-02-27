/*
 * Landlock LSM - filesystem hooks
 *
 * Copyright © 2016-2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/bpf.h> /* enum bpf_access_type */
#include <linux/kernel.h> /* ARRAY_SIZE */
#include <linux/lsm_hooks.h>
#include <linux/rcupdate.h> /* synchronize_rcu() */
#include <linux/stat.h> /* S_ISDIR */
#include <linux/stddef.h> /* offsetof */
#include <linux/types.h> /* uintptr_t */
#include <linux/workqueue.h> /* INIT_WORK() */

/* permissions translation */
#include <linux/fs.h> /* MAY_* */
#include <linux/mman.h> /* PROT_* */
#include <linux/namei.h>

/* hook arguments */
#include <linux/cred.h>
#include <linux/dcache.h> /* struct dentry */
#include <linux/fs.h> /* struct inode, struct iattr */
#include <linux/mm_types.h> /* struct vm_area_struct */
#include <linux/mount.h> /* struct vfsmount */
#include <linux/path.h> /* struct path */
#include <linux/sched.h> /* struct task_struct */
#include <linux/time.h> /* struct timespec */

#include "chain.h"
#include "common.h"
#include "hooks_fs.h"
#include "hooks.h"
#include "tag.h"
#include "task.h"

/* fs_pick */

#include <asm/page.h> /* PAGE_SIZE */
#include <asm/syscall.h>
#include <linux/dcache.h> /* d_path, dentry_path_raw */
#include <linux/err.h> /* *_ERR */
#include <linux/gfp.h> /* __get_free_page, GFP_KERNEL */
#include <linux/path.h> /* struct path */
#include <linux/sched/task_stack.h> /* task_pt_regs dependency */

bool landlock_is_valid_access_fs_pick(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size)
{
	switch (off) {
	case offsetof(struct landlock_ctx_fs_pick, cookie):
		if (type != BPF_READ && type != BPF_WRITE)
			return false;
		*reg_type = SCALAR_VALUE;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_pick, chain):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_LL_CHAIN;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_pick, inode):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_INODE;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_pick, inode_lookup):
		if (type != BPF_READ)
			return false;
		*reg_type = SCALAR_VALUE;
		/* TODO: check the bit mask */
		*max_size = sizeof(u8);
		return true;
	default:
		return false;
	}
}

bool landlock_is_valid_access_fs_walk(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size)
{
	switch (off) {
	case offsetof(struct landlock_ctx_fs_walk, cookie):
		if (type != BPF_READ && type != BPF_WRITE)
			return false;
		*reg_type = SCALAR_VALUE;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_walk, chain):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_LL_CHAIN;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_walk, inode):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_INODE;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_walk, inode_lookup):
		if (type != BPF_READ)
			return false;
		*reg_type = SCALAR_VALUE;
		/* TODO: check the bit mask */
		*max_size = sizeof(u8);
		return true;
	default:
		return false;
	}
}

bool landlock_is_valid_access_fs_get(int off, enum bpf_access_type type,
		enum bpf_reg_type *reg_type, int *max_size)
{
	switch (off) {
	case offsetof(struct landlock_ctx_fs_get, cookie):
		/* fs_get is the last possible hook, hence not useful to allow
		 * cookie modification */
		if (type != BPF_READ)
			return false;
		*reg_type = SCALAR_VALUE;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_get, chain):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_LL_CHAIN;
		*max_size = sizeof(u64);
		return true;
	case offsetof(struct landlock_ctx_fs_get, tag_object):
		if (type != BPF_READ)
			return false;
		*reg_type = PTR_TO_LL_TAG_OBJ;
		*max_size = sizeof(u64);
		return true;
	default:
		return false;
	}
}

/* fs_walk */

struct landlock_walk_state {
	u64 cookie;
};

struct landlock_walk_list {
	/* array of states */
	struct work_struct work;
	struct landlock_walk_state *state;
	struct inode *last_inode;
	struct task_struct *task;
	struct landlock_walk_list *next;
	enum namei_type lookup_type;
};

/* allocate an array of states nested in a new struct landlock_walk_list */
/* never return NULL */
/* TODO: use a dedicated kmem_cache_alloc() instead of k*alloc() */
static struct landlock_walk_list *new_walk_list(struct task_struct *task)
{
	struct landlock_walk_list *walk_list;
	struct landlock_walk_state *walk_state;
	struct landlock_prog_set *prog_set =
		task->seccomp.landlock_prog_set;

	/* allocate an array of cookies: one for each fs_walk program */
	if (WARN_ON(!prog_set))
		return ERR_PTR(-EFAULT);
	/* fill with zero */
	walk_state = kcalloc(prog_set->chain_last->index + 1,
			sizeof(*walk_state), GFP_ATOMIC);
	if (!walk_state)
		return ERR_PTR(-ENOMEM);
	walk_list = kzalloc(sizeof(*walk_list), GFP_ATOMIC);
	if (!walk_list) {
		kfree(walk_state);
		return ERR_PTR(-ENOMEM);
	}
	walk_list->state = walk_state;
	walk_list->task = task;
	return walk_list;
}

static void free_walk_list(struct landlock_walk_list *walker)
{
	while (walker) {
		struct landlock_walk_list *freeme = walker;

		walker = walker->next;
		/* iput() might sleep */
		iput(freeme->last_inode);
		kfree(freeme->state);
		kfree(freeme);
	}
}

/* called from workqueue */
static void free_walk_list_deferred(struct work_struct *work)
{
	struct landlock_walk_list *walk_list;

	synchronize_rcu();
	walk_list = container_of(work, struct landlock_walk_list, work);
	free_walk_list(walk_list);
}

void landlock_free_walk_list(struct landlock_walk_list *freeme)
{
	if (!freeme)
		return;
	INIT_WORK(&freeme->work, free_walk_list_deferred);
	schedule_work(&freeme->work);
}

/* return NULL if there is no fs_walk programs */
static struct landlock_walk_list *get_current_walk_list(
		const struct inode *inode)
{
	struct landlock_walk_list **walk_list;
	struct nameidata_lookup *lookup;

	lookup = current_nameidata_lookup(inode);
	if (IS_ERR(lookup))
		/* -ENOENT */
		return ERR_CAST(lookup);
	if (WARN_ON(!lookup))
		return ERR_PTR(-EFAULT);
	walk_list = (struct landlock_walk_list **)&lookup->security;
	if (!*walk_list) {
		struct landlock_walk_list *new_list;

		/* allocate a landlock_walk_list to be able to move it without
		 * new allocation in hook_nameidata_put_lookup() */
		new_list = new_walk_list(current);
		if (IS_ERR_OR_NULL(new_list))
			/* no fs_walk prog */
			return ERR_CAST(new_list);
		*walk_list = new_list;
	}
	(*walk_list)->lookup_type = lookup->type;
	return *walk_list;
}

static inline u8 translate_lookup(enum namei_type type)
{
	/* TODO: Use bitmask instead, and add an autonomous LOOKUP_ROOT
	 * (doesn't show when encountering a LAST_DOTDOT)? */
	BUILD_BUG_ON(LAST_ROOT != LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_ROOT);
	BUILD_BUG_ON(LAST_DOT != LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOT);
	BUILD_BUG_ON(LAST_DOTDOT != LANDLOCK_CTX_FS_WALK_INODE_LOOKUP_DOTDOT);
	return type & 3;
}

/* for now, handle syscalls dealing with up to 2 concurrent path walks */
#define LANDLOCK_MAX_CONCURRENT_WALK 2

/* retrieve the walk state strictly associated to an inode (i.e. when the
 * actual walk is done) */
/* never return NULL */
static struct landlock_walk_list *get_saved_walk_list(struct inode *inode)
{
	struct landlock_task_security *tsec;
	struct landlock_walk_list **walker, *walk_match = NULL;
	unsigned int walk_nb = 0;

	tsec = current_security();
	if (WARN_ON(!tsec) || WARN_ON(!inode))
		return ERR_PTR(-EFAULT);
	/* find the walk that match the inode */
	walker = &tsec->walk_list;
	while (*walker) {
		walk_nb++;
		if (walk_nb > LANDLOCK_MAX_CONCURRENT_WALK) {
			free_walk_list(*walker);
			*walker = NULL;
			break;
		}
		if (!walk_match && (*walker)->last_inode == inode)
			walk_match = *walker;
		walker = &(*walker)->next;
	}
	if (!walk_match) {
		/* create empty walk states */
		walk_match = new_walk_list(current);
		if (WARN_ON(!walk_match))
			return ERR_PTR(-EFAULT);
		ihold(inode);
		walk_match->last_inode = inode;
		walk_match->next = tsec->walk_list;
		tsec->walk_list = walk_match;
	}
	return walk_match;
}

/* Move the walk state/list in current->security.  It will be freed by
 * hook_cred_free(). */
static void hook_nameidata_put_lookup(struct nameidata_lookup *lookup,
		struct inode *inode)
{
	struct landlock_task_security *tsec;
	struct landlock_walk_list *walk_list = lookup->security;

	if (!landlocked(current))
		return;
	if (!walk_list)
		return;
	if (!inode)
		goto free_list;
	if (WARN_ON(walk_list->task != current))
		goto free_list;
	tsec = current_security();
	if (WARN_ON(!tsec))
		goto free_list;
	inode = igrab(inode);
	if (!inode)
		goto free_list;
	walk_list->lookup_type = lookup->type;
	walk_list->last_inode = inode;
	walk_list->next = tsec->walk_list;
	tsec->walk_list = walk_list;
	return;

free_list:
	landlock_free_walk_list(walk_list);
}

struct landlock_hook_ctx_fs_walk {
	struct landlock_walk_state *state;
	struct landlock_ctx_fs_walk prog_ctx;
};

/* set cookie and chain */
struct landlock_ctx_fs_walk *landlock_update_ctx_fs_walk(
		struct landlock_hook_ctx_fs_walk *hook_ctx,
		const struct landlock_chain *chain)
{
	if (WARN_ON(!hook_ctx))
		return NULL;
	if (WARN_ON(!hook_ctx->state))
		return NULL;
	/* cookie initially contains zero */
	hook_ctx->prog_ctx.cookie = hook_ctx->state[chain->index].cookie;
	hook_ctx->prog_ctx.chain = (uintptr_t)chain;
	return &hook_ctx->prog_ctx;
}

/* save cookie */
int landlock_save_ctx_fs_walk(struct landlock_hook_ctx_fs_walk *hook_ctx,
		struct landlock_chain *chain)
{
	if (WARN_ON(!hook_ctx))
		return 1;
	if (WARN_ON(!hook_ctx->state))
		return 1;
	hook_ctx->state[chain->index].cookie = hook_ctx->prog_ctx.cookie;
	return 0;
}

static int decide_fs_walk(int may_mask, struct inode *inode)
{
	struct landlock_walk_list *walk_list;
	struct landlock_hook_ctx_fs_walk fs_walk = {};
	struct landlock_hook_ctx hook_ctx = {
		.fs_walk = &fs_walk,
	};
	const enum landlock_hook_type hook_type = LANDLOCK_HOOK_FS_WALK;

	if (!current_has_prog_type(hook_type))
		/* no fs_walk */
		return 0;
	if (WARN_ON(!inode))
		return -EFAULT;
	walk_list = get_current_walk_list(inode);
	if (IS_ERR_OR_NULL(walk_list))
		/* error or no fs_walk */
		return PTR_ERR(walk_list);

	fs_walk.state = walk_list->state;
	/* init common data: inode, is_dot, is_dotdot, is_root */
	fs_walk.prog_ctx.inode = (uintptr_t)inode;
	fs_walk.prog_ctx.inode_lookup =
		translate_lookup(walk_list->lookup_type);
	return landlock_decide(hook_type, &hook_ctx, 0);
}

/* fs_pick */

struct landlock_hook_ctx_fs_pick {
	__u64 triggers;
	struct landlock_walk_state *state;
	struct landlock_ctx_fs_pick prog_ctx;
};

/* set cookie and chain */
struct landlock_ctx_fs_pick *landlock_update_ctx_fs_pick(
		struct landlock_hook_ctx_fs_pick *hook_ctx,
		const struct landlock_chain *chain)
{
	if (WARN_ON(!hook_ctx))
		return NULL;
	if (WARN_ON(!hook_ctx->state))
		return NULL;
	/* cookie initially contains zero */
	hook_ctx->prog_ctx.cookie = hook_ctx->state[chain->index].cookie;
	hook_ctx->prog_ctx.chain = (uintptr_t)chain;
	return &hook_ctx->prog_ctx;
}

/* save cookie */
int landlock_save_ctx_fs_pick(struct landlock_hook_ctx_fs_pick *hook_ctx,
		struct landlock_chain *chain)
{
	if (WARN_ON(!hook_ctx))
		return 1;
	if (WARN_ON(!hook_ctx->state))
		return 1;
	hook_ctx->state[chain->index].cookie = hook_ctx->prog_ctx.cookie;
	return 0;
}

static int decide_fs_pick(__u64 triggers, struct inode *inode)
{
	struct landlock_walk_list *walk_list;
	struct landlock_hook_ctx_fs_pick fs_pick = {};
	struct landlock_hook_ctx hook_ctx = {
		.fs_pick = &fs_pick,
	};
	const enum landlock_hook_type hook_type = LANDLOCK_HOOK_FS_PICK;

	if (WARN_ON(!triggers))
		return 0;
	if (!current_has_prog_type(hook_type))
		/* no fs_pick */
		return 0;
	if (WARN_ON(!inode))
		return -EFAULT;
	/* first, try to get the current walk (e.g. open(2)) */
	walk_list = get_current_walk_list(inode);
	if (!walk_list || PTR_ERR(walk_list) == -ENOENT) {
		/* otherwise, the path walk may have end (e.g. access(2)) */
		walk_list = get_saved_walk_list(inode);
		if (IS_ERR(walk_list))
			return PTR_ERR(walk_list);
		if (WARN_ON(!walk_list))
			return -EFAULT;
	}
	if (IS_ERR(walk_list))
		return PTR_ERR(walk_list);

	fs_pick.state = walk_list->state;
	fs_pick.triggers = triggers,
	/* init common data: inode */
	fs_pick.prog_ctx.inode = (uintptr_t)inode;
	fs_pick.prog_ctx.inode_lookup =
		translate_lookup(walk_list->lookup_type);
	return landlock_decide(hook_type, &hook_ctx, fs_pick.triggers);
}

/* fs_get */

struct landlock_hook_ctx_fs_get {
	struct landlock_walk_state *state;
	struct landlock_ctx_fs_get prog_ctx;
};

/* set cookie and chain */
struct landlock_ctx_fs_get *landlock_update_ctx_fs_get(
		struct landlock_hook_ctx_fs_get *hook_ctx,
		const struct landlock_chain *chain)
{
	if (WARN_ON(!hook_ctx))
		return NULL;
	if (WARN_ON(!hook_ctx->state))
		return NULL;
	hook_ctx->prog_ctx.cookie = hook_ctx->state[chain->index].cookie;
	hook_ctx->prog_ctx.chain = (uintptr_t)chain;
	return &hook_ctx->prog_ctx;
}

static int decide_fs_get(struct inode *inode,
		struct landlock_tag_ref **tag_ref)
{
	struct landlock_walk_list *walk_list;
	struct landlock_hook_ctx_fs_get fs_get = {};
	struct landlock_hook_ctx hook_ctx = {
		.fs_get = &fs_get,
	};
	struct landlock_tag_object tag_obj = {
		.lock = &inode->i_lock,
		.root = (struct landlock_tag_root **)&inode->i_security,
		.ref = tag_ref,
	};
	const enum landlock_hook_type hook_type = LANDLOCK_HOOK_FS_GET;

	if (!current_has_prog_type(hook_type))
		/* no fs_get */
		return 0;
	if (WARN_ON(!inode))
		return -EFAULT;
	walk_list = get_saved_walk_list(inode);
	if (IS_ERR(walk_list))
		return PTR_ERR(walk_list);
	if (WARN_ON(!walk_list))
		return -EFAULT;
	fs_get.state = walk_list->state;
	/* init common data: tag_obj */
	fs_get.prog_ctx.tag_object = (uintptr_t)&tag_obj;
	return landlock_decide(hook_type, &hook_ctx, 0);
}

/* helpers */

static u64 fs_may_to_triggers(int may_mask, umode_t mode)
{
	u64 ret = 0;

	if (may_mask & MAY_EXEC)
		ret |= LANDLOCK_TRIGGER_FS_PICK_EXECUTE;
	if (may_mask & MAY_READ) {
		if (S_ISDIR(mode))
			ret |= LANDLOCK_TRIGGER_FS_PICK_READDIR;
		else
			ret |= LANDLOCK_TRIGGER_FS_PICK_READ;
	}
	if (may_mask & MAY_WRITE)
		ret |= LANDLOCK_TRIGGER_FS_PICK_WRITE;
	if (may_mask & MAY_APPEND)
		ret |= LANDLOCK_TRIGGER_FS_PICK_APPEND;
	/* do not (re-)run fs_pick in hook_file_open() */
	if (may_mask & MAY_OPEN)
		ret |= LANDLOCK_TRIGGER_FS_PICK_OPEN;
	if (may_mask & MAY_CHROOT)
		ret |= LANDLOCK_TRIGGER_FS_PICK_CHROOT;
	else if (may_mask & MAY_CHDIR)
		ret |= LANDLOCK_TRIGGER_FS_PICK_CHDIR;
	/* XXX: ignore MAY_ACCESS */
	WARN_ON(!ret);
	return ret;
}

static inline u64 mem_prot_to_triggers(unsigned long prot, bool private)
{
	u64 ret = LANDLOCK_TRIGGER_FS_PICK_MAP;

	/* private mapping do not write to files */
	if (!private && (prot & PROT_WRITE))
		ret |= LANDLOCK_TRIGGER_FS_PICK_WRITE;
	if (prot & PROT_READ)
		ret |= LANDLOCK_TRIGGER_FS_PICK_READ;
	if (prot & PROT_EXEC)
		ret |= LANDLOCK_TRIGGER_FS_PICK_EXECUTE;
	WARN_ON(!ret);
	return ret;
}

/* binder hooks */

static int hook_binder_transfer_file(struct task_struct *from,
		struct task_struct *to, struct file *file)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_TRANSFER,
			file_inode(file));
}

/* sb hooks */

static int hook_sb_statfs(struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			dentry->d_inode);
}

/* TODO: handle mount source and remount */
static int hook_sb_mount(const char *dev_name, const struct path *path,
		const char *type, unsigned long flags, void *data)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!path))
		return 0;
	if (WARN_ON(!path->dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_MOUNTON,
			path->dentry->d_inode);
}

/*
 * The @old_path is similar to a destination mount point.
 */
static int hook_sb_pivotroot(const struct path *old_path,
		const struct path *new_path)
{
	int err;
	struct landlock_task_security *tsec;

	if (!landlocked(current))
		return 0;
	if (WARN_ON(!old_path))
		return 0;
	if (WARN_ON(!old_path->dentry))
		return 0;
	err = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_MOUNTON,
			old_path->dentry->d_inode);
	if (err)
		return err;
	err = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CHROOT,
			new_path->dentry->d_inode);
	if (err)
		return err;

	/* handle root directory tag */
	tsec = current_security();
	if (!tsec->root) {
		struct landlock_tag_fs *new_tag_fs;

		new_tag_fs = landlock_new_tag_fs(new_path->dentry->d_inode);
		if (IS_ERR(new_tag_fs))
			return PTR_ERR(new_tag_fs);
		tsec->root = new_tag_fs;
	} else {
		landlock_reset_tag_fs(tsec->root, new_path->dentry->d_inode);
	}
	return decide_fs_get(tsec->root->inode, &tsec->root->ref);
}

/* inode hooks */

/* a directory inode contains only one dentry */
static int hook_inode_create(struct inode *dir, struct dentry *dentry,
		umode_t mode)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!old_dentry)) {
		int ret = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_LINK,
				old_dentry->d_inode);
		if (ret)
			return ret;
	}
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_LINKTO, dir);
}

static int hook_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_UNLINK,
			dentry->d_inode);
}

static int hook_inode_symlink(struct inode *dir, struct dentry *dentry,
		const char *old_name)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_mkdir(struct inode *dir, struct dentry *dentry,
		umode_t mode)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RMDIR, dentry->d_inode);
}

static int hook_inode_mknod(struct inode *dir, struct dentry *dentry,
		umode_t mode, dev_t dev)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_CREATE, dir);
}

static int hook_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	if (!landlocked(current))
		return 0;
	/* TODO: add artificial walk session from old_dir to old_dentry */
	if (!WARN_ON(!old_dentry)) {
		int ret = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RENAME,
				old_dentry->d_inode);
		if (ret)
			return ret;
	}
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RENAMETO, new_dir);
}

static int hook_inode_readlink(struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_READ, dentry->d_inode);
}

/* ignore the inode_follow_link hook (could set is_symlink in the fs_walk
 * context) */

static int hook_inode_permission(struct inode *inode, int mask)
{
	int err;
	u64 triggers;
	struct landlock_tag_fs **tag_fs;
	struct landlock_task_security *tsec;

	if (!landlocked(current))
		return 0;
	if (WARN_ON(!inode))
		return 0;

	triggers = fs_may_to_triggers(mask, inode->i_mode);
	/* decide_fs_walk() is exclusive with decide_fs_pick(): in a path walk,
	 * ignore execute-only access on directory for any fs_pick program. */
	if (triggers == LANDLOCK_TRIGGER_FS_PICK_EXECUTE &&
			S_ISDIR(inode->i_mode))
		return decide_fs_walk(mask, inode);

	err = decide_fs_pick(triggers, inode);
	if (err)
		return err;

	/* handle current working directory and root directory tags */
	tsec = current_security();
	if (triggers & LANDLOCK_TRIGGER_FS_PICK_CHDIR)
		tag_fs = &tsec->cwd;
	else if (triggers & LANDLOCK_TRIGGER_FS_PICK_CHROOT)
		tag_fs = &tsec->root;
	else
		return 0;
	if (!*tag_fs) {
		struct landlock_tag_fs *new_tag_fs;

		new_tag_fs = landlock_new_tag_fs(inode);
		if (IS_ERR(new_tag_fs))
			return PTR_ERR(new_tag_fs);
		*tag_fs = new_tag_fs;
	} else {
		landlock_reset_tag_fs(*tag_fs, inode);
	}
	return decide_fs_get((*tag_fs)->inode, &(*tag_fs)->ref);
}

static int hook_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR,
			dentry->d_inode);
}

static int hook_inode_getattr(const struct path *path)
{
	/* TODO: link parent inode and path */
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!path))
		return 0;
	if (WARN_ON(!path->dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			path->dentry->d_inode);
}

static int hook_inode_setxattr(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR,
			dentry->d_inode);
}

static int hook_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			dentry->d_inode);
}

static int hook_inode_listxattr(struct dentry *dentry)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR,
			dentry->d_inode);
}

static int hook_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!dentry))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR,
			dentry->d_inode);
}

static int hook_inode_getsecurity(struct inode *inode, const char *name,
		void **buffer, bool alloc)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR, inode);
}

static int hook_inode_setsecurity(struct inode *inode, const char *name,
		const void *value, size_t size, int flag)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_SETATTR, inode);
}

static int hook_inode_listsecurity(struct inode *inode, char *buffer,
		size_t buffer_size)
{
	if (!landlocked(current))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_GETATTR, inode);
}

/* file hooks */

static int hook_file_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_IOCTL,
			file_inode(file));
}

static int hook_file_lock(struct file *file, unsigned int cmd)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_LOCK, file_inode(file));
}

static int hook_file_fcntl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	return decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_FCNTL,
			file_inode(file));
}

static int hook_mmap_file(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags)
{
	if (!landlocked(current))
		return 0;
	/* file can be null for anonymous mmap */
	if (!file)
		return 0;
	return decide_fs_pick(mem_prot_to_triggers(prot, flags & MAP_PRIVATE),
			file_inode(file));
}

static int hook_file_mprotect(struct vm_area_struct *vma,
		unsigned long reqprot, unsigned long prot)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!vma))
		return 0;
	if (!vma->vm_file)
		return 0;
	return decide_fs_pick(mem_prot_to_triggers(prot,
				!(vma->vm_flags & VM_SHARED)),
			file_inode(vma->vm_file));
}

static int hook_file_receive(struct file *file)
{
	int err;

	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	err = decide_fs_pick(LANDLOCK_TRIGGER_FS_PICK_RECEIVE,
			file_inode(file));
	if (err)
		return err;

	return decide_fs_get(file_inode(file),
			(struct landlock_tag_ref **)&file->f_security);
}

static int hook_file_open(struct file *file, const struct cred *cred)
{
	if (!landlocked(current))
		return 0;
	if (WARN_ON(!file))
		return 0;
	/* do not re-run fs_pick/LANDLOCK_TRIGGER_FS_PICK_OPEN here for now */
	return decide_fs_get(file_inode(file),
			(struct landlock_tag_ref **)&file->f_security);
}

static void hook_inode_free_security(struct inode *inode)
{
	if (!landlocked(current))
		return;
	WARN_ON(inode->i_security);
}

static void hook_file_free_security(struct file *file)
{
	if (!landlocked(current))
		return;
	/* free inode tags */
	if (!file_inode(file))
		return;
	landlock_free_tag_ref(file->f_security, (struct landlock_tag_root **)
			&file_inode(file)->i_security,
			&file_inode(file)->i_lock);
}

static struct security_hook_list landlock_hooks[] = {
	LSM_HOOK_INIT(binder_transfer_file, hook_binder_transfer_file),

	LSM_HOOK_INIT(sb_statfs, hook_sb_statfs),
	LSM_HOOK_INIT(sb_mount, hook_sb_mount),
	LSM_HOOK_INIT(sb_pivotroot, hook_sb_pivotroot),

	LSM_HOOK_INIT(inode_create, hook_inode_create),
	LSM_HOOK_INIT(inode_link, hook_inode_link),
	LSM_HOOK_INIT(inode_unlink, hook_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, hook_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, hook_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, hook_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, hook_inode_mknod),
	LSM_HOOK_INIT(inode_rename, hook_inode_rename),
	LSM_HOOK_INIT(inode_readlink, hook_inode_readlink),
	LSM_HOOK_INIT(inode_permission, hook_inode_permission),
	LSM_HOOK_INIT(inode_setattr, hook_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, hook_inode_getattr),
	LSM_HOOK_INIT(inode_setxattr, hook_inode_setxattr),
	LSM_HOOK_INIT(inode_getxattr, hook_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, hook_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, hook_inode_removexattr),
	LSM_HOOK_INIT(inode_getsecurity, hook_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, hook_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, hook_inode_listsecurity),
	LSM_HOOK_INIT(nameidata_put_lookup, hook_nameidata_put_lookup),

	/* do not handle file_permission for now */
	LSM_HOOK_INIT(inode_free_security, hook_inode_free_security),
	LSM_HOOK_INIT(file_free_security, hook_file_free_security),
	LSM_HOOK_INIT(file_ioctl, hook_file_ioctl),
	LSM_HOOK_INIT(file_lock, hook_file_lock),
	LSM_HOOK_INIT(file_fcntl, hook_file_fcntl),
	LSM_HOOK_INIT(mmap_file, hook_mmap_file),
	LSM_HOOK_INIT(file_mprotect, hook_file_mprotect),
	LSM_HOOK_INIT(file_receive, hook_file_receive),
	LSM_HOOK_INIT(file_open, hook_file_open),
};

__init void landlock_add_hooks_fs(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			LANDLOCK_NAME);
}
