/*
 * eBPF programs attached to the controller-less cgroup2 compatibility tree.
 *
 * This is deliberately limited to the two inet packet attach points needed
 * by Android netd.  Legacy cgroup controllers remain owned by kernel/cgroup.c
 * and are not changed by this file.
 */

#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/cgroup.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include <net/sock.h>
#include <net/tcp_states.h>

struct static_key cgroup_bpf_enabled_key = STATIC_KEY_INIT_FALSE;
EXPORT_SYMBOL(cgroup_bpf_enabled_key);

void cgroup_bpf_put(struct cgroup *cgrp)
{
	unsigned int type;

	for (type = 0; type < ARRAY_SIZE(cgrp->bpf.progs); type++) {
		struct list_head *progs = &cgrp->bpf.progs[type];
		struct bpf_prog_list *pl, *tmp;

		list_for_each_entry_safe(pl, tmp, progs, node) {
			list_del(&pl->node);
			bpf_prog_put(pl->prog);
			kfree(pl);
			static_key_slow_dec(&cgroup_bpf_enabled_key);
		}

		bpf_prog_array_free(cgrp->bpf.effective[type]);
		cgrp->bpf.effective[type] = NULL;
	}

	bpf_prog_array_free(cgrp->bpf.inactive);
	cgrp->bpf.inactive = NULL;
}

/* The list is bounded and is only walked while cgroup_mutex is held. */
static u32 prog_list_length(struct list_head *head)
{
	struct bpf_prog_list *pl;
	u32 cnt = 0;

	list_for_each_entry(pl, head, node)
		if (pl->prog)
			cnt++;

	return cnt;
}

static bool hierarchy_allows_attach(struct cgroup *cgrp,
				    enum bpf_attach_type type)
{
	struct cgroup *parent = cgrp->parent;

	while (parent) {
		u32 flags = parent->bpf.flags[type];
		u32 cnt = prog_list_length(&parent->bpf.progs[type]);

		if (flags & BPF_F_ALLOW_MULTI)
			return true;
		if (cnt > 1)
			return false;
		if (cnt == 1)
			return !!(flags & BPF_F_ALLOW_OVERRIDE);
		parent = parent->parent;
	}

	return true;
}

static int compute_effective_progs(struct cgroup *cgrp,
				   enum bpf_attach_type type,
				   struct bpf_prog_array __rcu **array,
				   gfp_t gfp)
{
	struct bpf_prog_array __rcu *progs;
	struct bpf_prog_list *pl;
	struct cgroup *p = cgrp;
	u32 count = 0;

	/* A cgroup's own programs win over an ancestor's override program. */
	do {
		if (count == 0 || (p->bpf.flags[type] & BPF_F_ALLOW_MULTI))
			count += prog_list_length(&p->bpf.progs[type]);
		p = p->parent;
	} while (p);

	progs = bpf_prog_array_alloc(count, gfp);
	if (!progs)
		return -ENOMEM;

	count = 0;
	p = cgrp;
	do {
		if (count == 0 || (p->bpf.flags[type] & BPF_F_ALLOW_MULTI)) {
			list_for_each_entry(pl, &p->bpf.progs[type], node) {
				if (!pl->prog)
					continue;
				rcu_dereference_protected(progs, 1)->progs[count++] =
					pl->prog;
			}
		}
		p = p->parent;
	} while (p);

	*array = progs;
	return 0;
}

static void activate_effective_progs(struct cgroup *cgrp,
				     enum bpf_attach_type type,
				     struct bpf_prog_array __rcu *array)
{
	struct bpf_prog_array __rcu *old_array;

	old_array = xchg(&cgrp->bpf.effective[type], array);
	bpf_prog_array_free(old_array);
}

int cgroup_bpf_inherit(struct cgroup *cgrp)
{
#define NR ARRAY_SIZE(cgrp->bpf.effective)
	struct bpf_prog_array __rcu *arrays[NR] = {};
	int type;

	for (type = 0; type < NR; type++)
		INIT_LIST_HEAD(&cgrp->bpf.progs[type]);

	for (type = 0; type < NR; type++)
		if (compute_effective_progs(cgrp, type, &arrays[type], GFP_KERNEL))
			goto cleanup;

	for (type = 0; type < NR; type++)
		activate_effective_progs(cgrp, type, arrays[type]);

	return 0;

cleanup:
	for (type = 0; type < NR; type++)
		bpf_prog_array_free(arrays[type]);
	return -ENOMEM;
}

#define BPF_CGROUP_MAX_PROGS 64

int __cgroup_bpf_attach(struct cgroup *cgrp, struct bpf_prog *prog,
			enum bpf_attach_type type, u32 flags)
{
	struct list_head *progs;
	struct bpf_prog *old_prog = NULL;
	struct bpf_prog_list *pl;
	struct cgroup *desc;
	bool allocated = false;
	u32 old_flags;
	int err;

	if (!cgrp || !prog || type >= MAX_BPF_ATTACH_TYPE)
		return -EINVAL;
	if (cgroup_is_removed(cgrp))
		return -ENODEV;
	if (flags & ~(BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI))
		return -EINVAL;
	if ((flags & BPF_F_ALLOW_OVERRIDE) && (flags & BPF_F_ALLOW_MULTI))
		return -EINVAL;
	progs = &cgrp->bpf.progs[type];
	if (!hierarchy_allows_attach(cgrp, type))
		return -EPERM;

	if (!list_empty(progs) && cgrp->bpf.flags[type] != flags)
		return -EPERM;
	if (prog_list_length(progs) >= BPF_CGROUP_MAX_PROGS)
		return -E2BIG;

	if (flags & BPF_F_ALLOW_MULTI) {
		list_for_each_entry(pl, progs, node)
			if (pl->prog == prog)
				return -EEXIST;

		pl = kmalloc(sizeof(*pl), GFP_KERNEL);
		if (!pl)
			return -ENOMEM;
		pl->prog = prog;
		list_add_tail(&pl->node, progs);
		allocated = true;
	} else if (list_empty(progs)) {
		pl = kmalloc(sizeof(*pl), GFP_KERNEL);
		if (!pl)
			return -ENOMEM;
		list_add_tail(&pl->node, progs);
		allocated = true;
	} else {
		pl = list_first_entry(progs, struct bpf_prog_list, node);
		old_prog = pl->prog;
	}
	pl->prog = prog;

	old_flags = cgrp->bpf.flags[type];
	cgrp->bpf.flags[type] = flags;

	rcu_read_lock();
	cgroup_for_each_descendant_pre(desc, cgrp) {
		err = compute_effective_progs(desc, type, &desc->bpf.inactive,
					       GFP_ATOMIC);
		if (err)
			goto cleanup;
	}

	cgroup_for_each_descendant_pre(desc, cgrp) {
		activate_effective_progs(desc, type, desc->bpf.inactive);
		desc->bpf.inactive = NULL;
	}
	rcu_read_unlock();

	static_key_slow_inc(&cgroup_bpf_enabled_key);
	if (old_prog) {
		bpf_prog_put(old_prog);
		static_key_slow_dec(&cgroup_bpf_enabled_key);
	}
	return 0;

cleanup:
	cgroup_for_each_descendant_pre(desc, cgrp) {
		bpf_prog_array_free(desc->bpf.inactive);
		desc->bpf.inactive = NULL;
	}
	rcu_read_unlock();

	cgrp->bpf.flags[type] = old_flags;
	if (allocated) {
		list_del(&pl->node);
		kfree(pl);
	} else {
		pl->prog = old_prog;
	}
	return err;
}

int __cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
			enum bpf_attach_type type, u32 flags)
{
	struct list_head *progs;
	struct bpf_prog *old_prog = NULL;
	struct bpf_prog_list *pl;
	struct cgroup *desc;
	int err;

	if (!cgrp || type >= MAX_BPF_ATTACH_TYPE || flags)
		return -EINVAL;
	if (cgroup_is_removed(cgrp))
		return -ENODEV;
	progs = &cgrp->bpf.progs[type];
	if (cgrp->bpf.flags[type] & BPF_F_ALLOW_MULTI) {
		if (!prog)
			return -EINVAL;
		list_for_each_entry(pl, progs, node) {
			if (pl->prog != prog)
				continue;
			old_prog = prog;
			break;
		}
		if (!old_prog)
			return -ENOENT;
	} else {
		if (list_empty(progs))
			return -ENOENT;
		pl = list_first_entry(progs, struct bpf_prog_list, node);
		old_prog = pl->prog;
	}

	/* Temporarily hide the selected program while rebuilding descendants. */
	pl->prog = NULL;
	rcu_read_lock();
	cgroup_for_each_descendant_pre(desc, cgrp) {
		err = compute_effective_progs(desc, type, &desc->bpf.inactive,
					       GFP_ATOMIC);
		if (err)
			goto cleanup;
	}

	cgroup_for_each_descendant_pre(desc, cgrp) {
		activate_effective_progs(desc, type, desc->bpf.inactive);
		desc->bpf.inactive = NULL;
	}
	rcu_read_unlock();

	list_del(&pl->node);
	kfree(pl);
	if (list_empty(progs))
		cgrp->bpf.flags[type] = 0;
	bpf_prog_put(old_prog);
	static_key_slow_dec(&cgroup_bpf_enabled_key);
	return 0;

cleanup:
	cgroup_for_each_descendant_pre(desc, cgrp) {
		bpf_prog_array_free(desc->bpf.inactive);
		desc->bpf.inactive = NULL;
	}
	rcu_read_unlock();
	pl->prog = old_prog;
	return err;
}

int __cgroup_bpf_run_filter(struct sock *sk, struct sk_buff *skb,
			    enum bpf_attach_type type)
{
	unsigned int offset;
	struct sock *save_sk;
	struct cgroup *cgrp;
	u32 ret;

	if (!sk || !skb || type >= MAX_BPF_ATTACH_TYPE)
		return -EINVAL;
	if (!sk_fullsock(sk))
		return 0;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
		return 0;
	if (skb->data < skb_network_header(skb))
		return -EINVAL;
	offset = skb->data - skb_network_header(skb);
	if (offset > skb_headroom(skb))
		return -EINVAL;

	cgrp = sk->skcg;
	if (!cgrp)
		return 0;

	save_sk = skb->sk;
	skb->sk = sk;
	__skb_push(skb, offset);
	ret = BPF_PROG_RUN_ARRAY(cgrp->bpf.effective[type], skb,
				 bpf_prog_run_save_cb);
	__skb_pull(skb, offset);
	skb->sk = save_sk;

	return ret == 1 ? 0 : -EPERM;
}
EXPORT_SYMBOL(__cgroup_bpf_run_filter);
