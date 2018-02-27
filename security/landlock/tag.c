/*
 * Landlock LSM - tag helpers
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018 ANSSI
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/atomic.h>
#include <linux/landlock.h> /* landlock_set_object_tag */
#include <linux/rculist.h>
#include <linux/refcount.h>
#include <linux/slab.h>

#include "chain.h"
#include "tag.h"

/* TODO: use a dedicated kmem_cache_alloc() instead of k*alloc() */

/*
 * @list_object: list of tags tied to a kernel object, e.g. inode
 * @rcu_free: for freeing this tag
 */
struct landlock_tag {
	struct list_head list_object;
	struct rcu_head rcu_put;
	struct landlock_chain *chain;
	atomic64_t value;
	/* usage is only for tag_ref, not for tag_root nor tag list */
	refcount_t usage;
};

/* never return NULL */
static struct landlock_tag *new_tag(struct landlock_chain *chain, u64 value)
{
	struct landlock_tag *tag;

	tag = kzalloc(sizeof(*tag), GFP_ATOMIC);
	if (!tag)
		return ERR_PTR(-ENOMEM);
	if (WARN_ON(!refcount_inc_not_zero(&chain->usage))) {
		kfree(tag);
		return ERR_PTR(-EFAULT);
	}
	tag->chain = chain;
	INIT_LIST_HEAD(&tag->list_object);
	refcount_set(&tag->usage, 1);
	atomic64_set(&tag->value, value);
	return tag;
}

static void free_tag(struct landlock_tag *tag)
{
	if (!tag)
		return;
	if (WARN_ON(refcount_read(&tag->usage)))
		return;
	landlock_put_chain(tag->chain);
	kfree(tag);
}

struct landlock_tag_root {
	spinlock_t appending;
	struct list_head tag_list;
	struct rcu_head rcu_put;
	refcount_t tag_nb;
};

/* never return NULL */
static struct landlock_tag_root *new_tag_root(struct landlock_chain *chain,
		u64 value)
{
	struct landlock_tag_root *root;
	struct landlock_tag *tag;

	root = kzalloc(sizeof(*root), GFP_ATOMIC);
	if (!root)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&root->appending);
	refcount_set(&root->tag_nb, 1);
	INIT_LIST_HEAD(&root->tag_list);

	tag = new_tag(chain, value);
	if (IS_ERR(tag)) {
		kfree(root);
		return ERR_CAST(tag);
	}
	list_add_tail(&tag->list_object, &root->tag_list);
	return root;
}

static void free_tag_root(struct landlock_tag_root *root)
{
	if (!root)
		return;
	if (WARN_ON(refcount_read(&root->tag_nb)))
		return;
	/* the tag list should be singular it is a call from put_tag() or empty
	 * if it is a call from landlock_set_tag():free_ref */
	if (WARN_ON(!list_is_singular(&root->tag_list) &&
				!list_empty(&root->tag_list)))
		return;
	kfree(root);
}

static void put_tag_root_rcu(struct rcu_head *head)
{
	struct landlock_tag_root *root;

	root = container_of(head, struct landlock_tag_root, rcu_put);
	free_tag_root(root);
}

/* return true if the tag_root is queued for freeing, false otherwise */
static void put_tag_root(struct landlock_tag_root **root,
		spinlock_t *root_lock)
{
	struct landlock_tag_root *freeme;

	if (!root || WARN_ON(!root_lock))
		return;

	rcu_read_lock();
	freeme = rcu_dereference(*root);
	if (WARN_ON(!freeme))
		goto out_rcu;
	if (!refcount_dec_and_lock(&freeme->tag_nb, root_lock))
		goto out_rcu;

	rcu_assign_pointer(*root, NULL);
	spin_unlock(root_lock);
	call_rcu(&freeme->rcu_put, put_tag_root_rcu);

out_rcu:
	rcu_read_unlock();
}

static void put_tag_rcu(struct rcu_head *head)
{
	struct landlock_tag *tag;

	tag = container_of(head, struct landlock_tag, rcu_put);
	free_tag(tag);
}

/* put @tag if not recycled in an RCU */
/* Only called to free an object; a chain deleting will happen after all the
 * tagged struct files are deleted because their tied task is being deleted as
 * well.  Then, there is no need to expressively delete the tag associated to a
 * chain when this chain is getting deleted. */
static void put_tag(struct landlock_tag *tag, struct landlock_tag_root **root,
		spinlock_t *root_lock)
{
	if (!tag)
		return;
	if (!refcount_dec_and_test(&tag->usage))
		return;
	put_tag_root(root, root_lock);
	list_del_rcu(&tag->list_object);
	call_rcu(&tag->rcu_put, put_tag_rcu);
}

/*
 * landlock_tag_ref - Account for tags
 *
 * @tag_nb: count the number of tags pointed by @tag, will free the struct when
 *	    reaching zero
 */
struct landlock_tag_ref {
	struct landlock_tag_ref *next;
	struct landlock_tag *tag;
};

/* never return NULL */
static struct landlock_tag_ref *landlock_new_tag_ref(void)
{
	struct landlock_tag_ref *ret;

	ret = kzalloc(sizeof(*ret), GFP_ATOMIC);
	if (!ret)
		return ERR_PTR(-ENOMEM);
	return ret;
}

void landlock_free_tag_ref(struct landlock_tag_ref *tag_ref,
		struct landlock_tag_root **tag_root, spinlock_t *root_lock)
{
	while (tag_ref) {
		struct landlock_tag_ref *freeme = tag_ref;

		tag_ref = tag_ref->next;
		put_tag(freeme->tag, tag_root, root_lock);
		kfree(freeme);
	}
}

/* tweaked from rculist.h */
#define list_for_each_entry_nopre_rcu(pos, head, member)		\
	for (; &pos->member != (head);					\
	     pos = list_entry_rcu((pos)->member.next, typeof(*(pos)), member))

int landlock_set_tag(struct landlock_tag_ref **tag_ref,
		struct landlock_tag_root **tag_root,
		spinlock_t *root_lock,
		struct landlock_chain *chain, u64 value)
{
	struct landlock_tag_root *root;
	struct landlock_tag_ref *ref, **ref_next, **ref_walk, **ref_prev;
	struct landlock_tag *tag, *last_tag;
	int err;

	if (WARN_ON(!tag_ref) || WARN_ON(!tag_root))
		return -EFAULT;

	/* start by looking for a (protected) ref to the tag */
	ref_walk = tag_ref;
	ref_prev = tag_ref;
	ref_next = tag_ref;
	tag = NULL;
	while (*ref_walk) {
		ref_next = &(*ref_walk)->next;
		if (!WARN_ON(!(*ref_walk)->tag) &&
				(*ref_walk)->tag->chain == chain) {
			tag = (*ref_walk)->tag;
			break;
		}
		ref_prev = ref_walk;
		ref_walk = &(*ref_walk)->next;
	}
	if (tag) {
		if (value) {
			/* the tag already exist (and is protected) */
			atomic64_set(&tag->value, value);
		} else {
			/* a value of zero means to delete the tag */
			put_tag(tag, tag_root, root_lock);
			*ref_prev = *ref_next;
			kfree(*ref_walk);
		}
		return 0;
	} else if (!value) {
		/* do not create a tag with a value of zero */
		return 0;
	}

	/* create a new tag and a dedicated ref earlier to keep a consistent
	 * usage of the tag in case of memory allocation error */
	ref = landlock_new_tag_ref();
	if (IS_ERR(ref))
		return PTR_ERR(ref);

	/* lock-less as possible */
	rcu_read_lock();
	root = rcu_dereference(*tag_root);
	/* if tag_root does not exist or is being deleted */
	if (!root || !refcount_inc_not_zero(&root->tag_nb)) {
		/* may need to create a new tag_root */
		spin_lock(root_lock);
		/* the root may have been created meanwhile, recheck */
		root = rcu_dereference(*tag_root);
		if (root) {
			refcount_inc(&root->tag_nb);
			spin_unlock(root_lock);
		} else {
			/* create a tag_root populated with the tag */
			root = new_tag_root(chain, value);
			if (IS_ERR(root)) {
				spin_unlock(root_lock);
				err = PTR_ERR(root);
				tag_root = NULL;
				goto free_ref;
			}
			rcu_assign_pointer(*tag_root, root);
			spin_unlock(root_lock);
			tag = list_first_entry(&root->tag_list, typeof(*tag),
					list_object);
			goto register_tag;
		}
	}

	last_tag = NULL;
	/* look for the tag */
	list_for_each_entry_rcu(tag, &root->tag_list, list_object) {
		/* ignore tag being deleted */
		if (tag->chain == chain &&
				refcount_inc_not_zero(&tag->usage)) {
			atomic64_set(&tag->value, value);
			goto register_tag;
		}
		last_tag = tag;
	}
	/*
	 * Did not find a matching chain: lock tag_root, continue an exclusive
	 * appending walk through the list (a new tag may have been appended
	 * after the first walk), and if not matching one of the potential new
	 * tags, then append a new one.
	 */
	spin_lock(&root->appending);
	if (last_tag)
		tag = list_entry_rcu(last_tag->list_object.next, typeof(*tag),
				list_object);
	else
		tag = list_entry_rcu(root->tag_list.next, typeof(*tag),
				list_object);
	list_for_each_entry_nopre_rcu(tag, &root->tag_list, list_object) {
		/* ignore tag being deleted */
		if (tag->chain == chain &&
				refcount_inc_not_zero(&tag->usage)) {
			spin_unlock(&root->appending);
			atomic64_set(&tag->value, value);
			goto register_tag;
		}
	}
	/* did not find any tag, create a new one */
	tag = new_tag(chain, value);
	if (IS_ERR(tag)) {
		spin_unlock(&root->appending);
		err = PTR_ERR(tag);
		goto free_ref;
	}
	list_add_tail_rcu(&tag->list_object, &root->tag_list);
	spin_unlock(&root->appending);

register_tag:
	rcu_read_unlock();
	ref->tag = tag;
	*ref_next = ref;
	return 0;

free_ref:
	put_tag_root(tag_root, root_lock);
	rcu_read_unlock();
	landlock_free_tag_ref(ref, NULL, NULL);
	return err;
}

int landlock_set_object_tag(struct landlock_tag_object *tag_obj,
		struct landlock_chain *chain, u64 value)
{
	if (WARN_ON(!tag_obj))
		return -EFAULT;
	return landlock_set_tag(tag_obj->ref, tag_obj->root, tag_obj->lock,
			chain, value);
}

u64 landlock_get_tag(const struct landlock_tag_root *tag_root,
		const struct landlock_chain *chain)
{
	const struct landlock_tag_root *root;
	struct landlock_tag *tag;
	u64 ret = 0;

	rcu_read_lock();
	root = rcu_dereference(tag_root);
	if (!root)
		goto out_rcu;

	/* no need to check if it is being deleted, it is guarded by RCU */
	list_for_each_entry_rcu(tag, &root->tag_list, list_object) {
		/* may return to-be-deleted tag */
		if (tag->chain == chain) {
			ret = atomic64_read(&tag->value);
			goto out_rcu;
		}
	}

out_rcu:
	rcu_read_unlock();
	return ret;
}
