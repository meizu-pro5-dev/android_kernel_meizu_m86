/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_BPF_PERF_EVENT_H__
#define _UAPI__LINUX_BPF_PERF_EVENT_H__

#include <linux/types.h>
#include <linux/ptrace.h>

/*
 * Context made visible to BPF programs attached to a perf event.  Keep this
 * header deliberately small: the kernel-only representation is declared in
 * <linux/perf_event.h> and is translated by the verifier.
 */
struct bpf_perf_event_data {
	struct pt_regs regs;
	__u64 sample_period;
};

#endif /* _UAPI__LINUX_BPF_PERF_EVENT_H__ */
