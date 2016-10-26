#ifndef _BPF_CGROUP_H
#define _BPF_CGROUP_H

#include <linux/bpf.h>
#include <linux/jump_label.h>
#include <uapi/linux/bpf.h>

struct sock;
struct cgroup;
struct sk_buff;

#ifdef CONFIG_CGROUP_BPF

extern struct static_key_false cgroup_bpf_enabled_key;
#define cgroup_bpf_enabled static_branch_unlikely(&cgroup_bpf_enabled_key)

#ifdef CONFIG_SECURITY_LANDLOCK
struct landlock_hooks;
#endif /* CONFIG_SECURITY_LANDLOCK */

struct bpf_object {
	struct bpf_prog *prog;
#ifdef CONFIG_SECURITY_LANDLOCK
	struct landlock_hooks *hooks;
#endif /* CONFIG_SECURITY_LANDLOCK */
};

struct cgroup_bpf {
	/*
	 * Store two sets of bpf_prog pointers, one for programs that are
	 * pinned directly to this cgroup, and one for those that are effective
	 * when this cgroup is accessed.
	 */
	struct bpf_object pinned[MAX_BPF_ATTACH_TYPE];
	struct bpf_object effective[MAX_BPF_ATTACH_TYPE];
};

void cgroup_bpf_put(struct cgroup *cgrp);
void cgroup_bpf_inherit(struct cgroup *cgrp, struct cgroup *parent);

int __cgroup_bpf_update(struct cgroup *cgrp,
			 struct cgroup *parent,
			 struct bpf_prog *prog,
			 enum bpf_attach_type type);

/* Wrapper for __cgroup_bpf_update() protected by cgroup_mutex */
int cgroup_bpf_update(struct cgroup *cgrp,
		       struct bpf_prog *prog,
		       enum bpf_attach_type type);

int __cgroup_bpf_run_filter(struct sock *sk,
			    struct sk_buff *skb,
			    enum bpf_attach_type type);

/* Wrapper for __cgroup_bpf_run_filter() guarded by cgroup_bpf_enabled */
static inline int cgroup_bpf_run_filter(struct sock *sk,
					struct sk_buff *skb,
					enum bpf_attach_type type)
{
	if (cgroup_bpf_enabled)
		return __cgroup_bpf_run_filter(sk, skb, type);

	return 0;
}

#else

struct cgroup_bpf {};
static inline void cgroup_bpf_put(struct cgroup *cgrp) {}
static inline void cgroup_bpf_inherit(struct cgroup *cgrp,
				      struct cgroup *parent) {}

static inline int cgroup_bpf_run_filter(struct sock *sk,
					struct sk_buff *skb,
					enum bpf_attach_type type)
{
	return 0;
}

#endif /* CONFIG_CGROUP_BPF */

#endif /* _BPF_CGROUP_H */
