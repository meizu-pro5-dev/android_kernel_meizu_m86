#ifndef _LINUX_BPF_CGROUP_H
#define _LINUX_BPF_CGROUP_H

/*
 * The 3.10 cgroup core has no native unified hierarchy.  This header keeps
 * the cgroup BPF state independent from the legacy controller state while
 * exposing only the small cgroup2/socket-filter interface used by Android.
 */

#include <linux/bpf.h>
#include <linux/jump_label.h>
#include <uapi/linux/bpf.h>

struct sock;
struct cgroup;
struct sk_buff;

#ifdef CONFIG_CGROUP_BPF

extern struct static_key cgroup_bpf_enabled_key;
#define cgroup_bpf_enabled static_key_false(&cgroup_bpf_enabled_key)

struct bpf_prog_list {
	struct list_head node;
	struct bpf_prog *prog;
};

struct cgroup_bpf {
	/* Effective programs for this cgroup, inherited from its ancestors. */
	struct bpf_prog_array __rcu *effective[MAX_BPF_ATTACH_TYPE];

	/* Programs attached directly to this cgroup and their policy flags. */
	struct list_head progs[MAX_BPF_ATTACH_TYPE];
	u32 flags[MAX_BPF_ATTACH_TYPE];

	/* Temporary arrays built before an update is published. */
	struct bpf_prog_array __rcu *inactive;
};

void cgroup_bpf_put(struct cgroup *cgrp);
int cgroup_bpf_inherit(struct cgroup *cgrp);

int __cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog,
			enum bpf_attach_type type, u32 flags);
int __cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
			enum bpf_attach_type type, u32 flags);

int cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog,
		      enum bpf_attach_type type, u32 flags);
int cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
		      enum bpf_attach_type type, u32 flags);

int __cgroup_bpf_run_filter(struct sock *sk, struct sk_buff *skb,
			    enum bpf_attach_type type);

/* Run each direction at its existing single socket/network hook. */
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb) \
({ \
	int __ret = 0; \
	if (cgroup_bpf_enabled) \
		__ret = __cgroup_bpf_run_filter((sk), (skb), \
					BPF_CGROUP_INET_INGRESS); \
	__ret; \
})

#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sock, skb) \
({ \
	int __ret = 0; \
	if (cgroup_bpf_enabled && (sock) && (skb) && (sock) == (skb)->sk) \
		__ret = __cgroup_bpf_run_filter((sock), (skb), \
					BPF_CGROUP_INET_EGRESS); \
	__ret; \
})

#else /* !CONFIG_CGROUP_BPF */

struct cgroup_bpf {};

static inline void cgroup_bpf_put(struct cgroup *cgrp)
{
}

static inline int cgroup_bpf_inherit(struct cgroup *cgrp)
{
	return 0;
}

#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb) ({ 0; })

#endif /* CONFIG_CGROUP_BPF */

#endif /* _LINUX_BPF_CGROUP_H */
