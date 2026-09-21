// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Who changed the network — an fentry on rtnetlink_rcv_msg, passive and fail-open.
//
// The netlink change recorder (internal/netlinkwatch) hears every link, address,
// route and neighbor change over RTNL multicast, but a multicast notification does
// not say who asked for it. rtnetlink_rcv_msg runs synchronously, in the task that
// called sendmsg() on its NETLINK_ROUTE socket, so at this point the current task
// IS the requester. For every request that MODIFIES state this records:
//
//   - the process: comm (16 bytes), tgid and thread id,
//   - its cgroup id (userspace maps it to a workload; it is the same id the rest
//     of the agent already uses),
//   - the RTM_* message type, and
//   - a monotonic timestamp (userspace joins it to the recorded change by type
//     and time).
//
// Not recorded: argv, environment, the message payload, or anything about the
// object being changed. Read-only requests (RTM_GET*, dumps) are dropped in the
// kernel before anything is reserved, so a monitoring tool listing routes costs
// nothing. It only observes: the return value is ignored and no packet, message or
// program state is changed.
//
// Requests from the kernel itself (carrier loss, router advertisements handled in
// the kernel) never pass through here, so a change with no matching record was not
// issued by a process. That absence is information, and userspace reports it as
// such only while this sensor is running.
//
// Ring buffer, not a map of counters: the join needs each request. If it fills,
// events are dropped and counted (rtnl_stats), never blocked on. Every netns's
// requests reach here (the function is global); userspace keeps only the ones that
// match what the agent recorded in the host namespace.
//
// No BTF field access and no CO-RE: the only kernel memory read is the 16-byte
// struct nlmsghdr, a stable uAPI layout, fetched with bpf_probe_read_kernel from
// the second argument. The program is attached by name (fentry needs the running
// kernel's BTF only to resolve the function's address and signature).

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_kernel;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

/* linux/netlink.h's struct nlmsghdr, restated so this object needs no more than
 * linux/bpf.h. The layout is uAPI and never changes. */
struct rtnl_nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

/* One request that modifies network state. Mirrored by internal/rtnlactor.Record;
 * 48 bytes, little endian, checked by both sides. */
struct rtnl_event {
	__u64 ts_ns;      /* bpf_ktime_get_ns(): CLOCK_MONOTONIC */
	__u64 cgroup_id;  /* the requester's cgroup */
	__u32 tgid;       /* process id */
	__u32 pid;        /* thread id */
	__u16 nlmsg_type; /* RTM_NEWLINK ... */
	__u16 _pad0;
	__u32 _pad1;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 262144);
} rtnl_events SEC(".maps");

/* [0] = requests dropped because the ring buffer was full. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rtnl_stats SEC(".maps");

/* RTM_NEWLINK 16, DELLINK 17, SETLINK 19, NEWADDR 20, DELADDR 21, NEWROUTE 24,
 * DELROUTE 25, NEWNEIGH 28, DELNEIGH 29. The GET* types (18, 22, 26, 30) and every
 * other family are ignored. */
static inline int modifies_network(__u16 t)
{
	switch (t) {
	case 16: case 17: case 19:
	case 20: case 21:
	case 24: case 25:
	case 28: case 29:
		return 1;
	}
	return 0;
}

/* rtnetlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
 *                   struct netlink_ext_ack *extack): the fentry context is the
 * array of the traced function's arguments. */
SEC("fentry/rtnetlink_rcv_msg")
int netra_rtnl_msg(unsigned long long *ctx)
{
	struct rtnl_nlmsghdr hdr = {};
	struct rtnl_event *e;
	__u64 pt;

	if (bpf_probe_read_kernel(&hdr, sizeof(hdr), (const void *)ctx[1]) != 0)
		return 0;
	if (!modifies_network(hdr.nlmsg_type))
		return 0;

	e = bpf_ringbuf_reserve(&rtnl_events, sizeof(*e), 0);
	if (!e) {
		__u32 k = 0;
		__u64 *drops = bpf_map_lookup_elem(&rtnl_stats, &k);
		if (drops)
			__sync_fetch_and_add(drops, 1);
		return 0;
	}
	pt = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->tgid = pt >> 32;
	e->pid = (__u32)pt;
	e->nlmsg_type = hdr.nlmsg_type;
	e->_pad0 = 0;
	e->_pad1 = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
