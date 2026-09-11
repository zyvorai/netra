// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
// Netra standalone eBPF network observability/security datapath.
// It owns only Netra maps and does not depend on Cilium maps or programs.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

#define DIR_INGRESS 1
#define DIR_EGRESS  2
#define HOOK_TC      1
#define HOOK_CGROUP  2
#define HOOK_XDP     3
#define HOOK_SOCKET  4
#define HOOK_SOCKOPS 5
#define ACT_ALLOW    0
#define ACT_BLOCK    1
#define EVT_FLOW     1
#define EVT_DNS      2
#define EVT_CONNECT  3
#define EVT_BLOCK    4
#define EVT_DNS_RESPONSE 5
#define EVT_TCP_HEALTH 6
#define REASON_NONE  0
#define REASON_EXACT 1
#define REASON_CIDR  2
#define REASON_PORT  3
#define REASON_UID   4
#define REASON_RATE  5
#define REASON_DNS   6
#define REASON_PROCESS 7
#define FAMILY_V4    4
#define FAMILY_V6    6

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static int (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *skops, int flags) = (void *)BPF_FUNC_sock_ops_cb_flags_set;

// Legacy v0.6 destination stats are retained so existing pinned maps can be reused.
struct dest_key {
    __u32 dst_ip;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad;
};
struct dest_value {
    __u64 packets;
    __u64 bytes;
    __u64 blocked;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dest_key);
    __type(value, struct dest_value);
} dest_stats SEC(".maps");

struct flow_key {
    __u8 family;
    __u8 direction;
    __u8 hook;
    __u8 protocol;
    __u16 src_port;
    __u16 dst_port;
    __u8 src_addr[16];
    __u8 dst_addr[16];
};
struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 blocked;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_stats SEC(".maps");

struct workload_flow_key {
    __u64 cgroup_id;
    struct flow_key flow;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct workload_flow_key);
    __type(value, struct flow_value);
} workload_flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_v4 SEC(".maps");

struct ip6_key { __u8 addr[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6_key);
    __type(value, __u8);
} blocked_v6 SEC(".maps");

struct lpm4_key { __u32 prefixlen; __u8 data[5]; } __attribute__((packed));
struct lpm6_key { __u32 prefixlen; __u8 data[17]; } __attribute__((packed));
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} blocked_cidr_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} blocked_cidr_v6 SEC(".maps");

struct port_key { __u8 direction; __u8 protocol; __u16 port; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct port_key);
    __type(value, __u8);
} blocked_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_uids SEC(".maps");

struct dns_key { char name[96]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dns_key);
    __type(value, __u8);
} blocked_dns SEC(".maps");

struct comm_key { char name[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct comm_key);
    __type(value, __u8);
} blocked_comms SEC(".maps");

struct rate_state { __u64 second; __u64 count; __u64 dropped; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} rate_v4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct rate_state);
} rate_state_v4 SEC(".maps");

// key 0: 0=observe, 1=enforce.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

// scope_config key 0: 0=all cgroups, 1=selected cgroups only.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} scope_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} enforced_cgroups SEC(".maps");


// Socket owner identity is captured at connect() time and joined to sockops
// callbacks by socket cookie. This avoids attributing sockops callbacks to the
// kthread/softirq that happened to execute them.
struct socket_owner_value {
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct socket_owner_value);
} socket_owner SEC(".maps");

struct tcp_health_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 pad[3];
    __u32 local_ip4;
    __u32 remote_ip4;
    __u8 local_ip6[16];
    __u8 remote_ip6[16];
    __u16 local_port;
    __u16 remote_port;
};
struct tcp_health_value {
    __u64 active_established;
    __u64 passive_established;
    __u64 closes;
    __u64 retrans;
    __u64 rto;
    __u64 rtt_samples;
    __u64 srtt_us;
    __u64 rtt_min_us;
    __u64 snd_cwnd;
    __u64 bytes_acked;
    __u64 bytes_received;
    __u64 segs_in;
    __u64 segs_out;
    __u64 last_ns;
    __u32 pid;
    __u32 uid;
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct tcp_health_key);
    __type(value, struct tcp_health_value);
} tcp_health SEC(".maps");

struct tcp_signal_value {
    __u64 syn;
    __u64 syn_ack;
    __u64 fin;
    __u64 rst;
    __u64 packets;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct tcp_signal_value);
} tcp_signals SEC(".maps");

struct dns_pending_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 pad0;
    __u16 client_port;
    __u16 txid;
    __u16 pad1;
    __u8 server[16];
};
struct dns_pending_value {
    __u64 start_ns;
    char name[96];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_pending_key);
    __type(value, struct dns_pending_value);
} dns_pending SEC(".maps");

struct dns_health_key {
    __u64 cgroup_id;
    char name[96];
};
struct dns_health_value {
    __u64 queries;
    __u64 responses;
    __u64 failures;
    __u64 total_latency_us;
    __u64 max_latency_us;
    __u64 last_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_health_key);
    __type(value, struct dns_health_value);
} dns_health SEC(".maps");

struct obs_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u32 ifindex;
    __u32 length;
    __u8 src_addr[16];
    __u8 dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 family;
    __u8 protocol;
    __u8 direction;
    __u8 hook;
    __u8 action;
    __u8 event_type;
    __u8 tcp_flags;
    __u8 reason;
    char comm[16];
    char dns[96];
    __u32 latency_us;
    __u8 dns_rcode;
    __u8 pad_event[3];
} __attribute__((packed));
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline int enforcing(void)
{
    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&config_map, &key);
    return mode && *mode == 1;
}

static __always_inline int scope_allows(__u64 cgroup_id)
{
    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&scope_config, &key);
    if (!mode || *mode == 0) return 1;
    if (!cgroup_id) return 0;
    return bpf_map_lookup_elem(&enforced_cgroups, &cgroup_id) != 0;
}

static __always_inline void copy4(__u8 out[16], __u32 addr)
{
    __builtin_memset(out, 0, 16);
    __builtin_memcpy(out, &addr, 4);
}
static __always_inline void copy16(__u8 out[16], const void *addr)
{
    __builtin_memcpy(out, addr, 16);
}

static __always_inline int blocked_port(__u8 direction, __u8 proto, __u16 port)
{
    struct port_key k = {.direction = direction, .protocol = proto, .port = port};
    if (bpf_map_lookup_elem(&blocked_ports, &k)) return 1;
    k.protocol = 0;
    return bpf_map_lookup_elem(&blocked_ports, &k) != 0;
}

static __always_inline int blocked_cidr4(__u8 direction, __u32 addr)
{
    struct lpm4_key k = {.prefixlen = 40};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], &addr, 4);
    return bpf_map_lookup_elem(&blocked_cidr_v4, &k) != 0;
}
static __always_inline int blocked_cidr6(__u8 direction, const __u8 addr[16])
{
    struct lpm6_key k = {.prefixlen = 136};
    k.data[0] = direction;
    __builtin_memcpy(&k.data[1], addr, 16);
    return bpf_map_lookup_elem(&blocked_cidr_v6, &k) != 0;
}

static __always_inline int rate_limited4(__u32 dst)
{
    __u32 *pps = bpf_map_lookup_elem(&rate_v4, &dst);
    if (!pps || !*pps) return 0;
    __u64 sec = bpf_ktime_get_ns() / 1000000000ULL;
    struct rate_state zero = {.second = sec, .count = 0, .dropped = 0};
    struct rate_state *st = bpf_map_lookup_elem(&rate_state_v4, &dst);
    if (!st) {
        bpf_map_update_elem(&rate_state_v4, &dst, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&rate_state_v4, &dst);
        if (!st) return 0;
    }
    if (st->second != sec) {
        st->second = sec;
        st->count = 1;
        return 0;
    }
    __u64 old = __sync_fetch_and_add(&st->count, 1);
    if (old >= *pps) {
        __sync_fetch_and_add(&st->dropped, 1);
        return 1;
    }
    return 0;
}

static __always_inline void update_flow(__u8 family, __u8 direction, __u8 hook, __u8 proto,
                                        __u16 sport, __u16 dport, const __u8 src[16], const __u8 dst[16],
                                        __u32 len, int blocked, __u64 cgroup_id)
{
    struct flow_key k = {.family=family,.direction=direction,.hook=hook,.protocol=proto,.src_port=sport,.dst_port=dport};
    __builtin_memcpy(k.src_addr, src, 16);
    __builtin_memcpy(k.dst_addr, dst, 16);
    struct flow_value zero = {};
    struct flow_value *v = bpf_map_lookup_elem(&flow_stats, &k);
    if (!v) {
        bpf_map_update_elem(&flow_stats, &k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&flow_stats, &k);
    }
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, len);
        if (blocked) __sync_fetch_and_add(&v->blocked, 1);
        v->last_ns = bpf_ktime_get_ns();
    }
    if (cgroup_id) {
        struct workload_flow_key wk = {.cgroup_id = cgroup_id};
        __builtin_memcpy(&wk.flow, &k, sizeof(k));
        struct flow_value *wv = bpf_map_lookup_elem(&workload_flow_stats, &wk);
        if (!wv) {
            bpf_map_update_elem(&workload_flow_stats, &wk, &zero, BPF_NOEXIST);
            wv = bpf_map_lookup_elem(&workload_flow_stats, &wk);
        }
        if (wv) {
            __sync_fetch_and_add(&wv->packets, 1);
            __sync_fetch_and_add(&wv->bytes, len);
            if (blocked) __sync_fetch_and_add(&wv->blocked, 1);
            wv->last_ns = bpf_ktime_get_ns();
        }
    }
}

static __always_inline struct obs_event *new_event(__u8 family, __u8 direction, __u8 hook, __u8 proto,
                                                    __u8 action, __u8 type, __u8 reason)
{
    struct obs_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->family = family;
    e->direction = direction;
    e->hook = hook;
    e->protocol = proto;
    e->action = action;
    e->event_type = type;
    e->reason = reason;
    return e;
}

static __always_inline void submit_packet_event(__u8 family, __u8 direction, __u8 hook, __u8 proto,
                                                 __u8 action, __u8 type, __u8 reason, __u32 ifindex,
                                                 __u32 len, const __u8 src[16], const __u8 dst[16],
                                                 __u16 sport, __u16 dport, __u8 tcp_flags,
                                                 const char *dns, int dns_len, __u64 cgroup_id)
{
    struct obs_event *e = new_event(family,direction,hook,proto,action,type,reason);
    if (!e) return;
    e->ifindex=ifindex; e->length=len; e->src_port=sport; e->dst_port=dport; e->tcp_flags=tcp_flags; e->cgroup_id=cgroup_id;
    __builtin_memcpy(e->src_addr,src,16); __builtin_memcpy(e->dst_addr,dst,16);
    if (dns && dns_len > 0) {
        #pragma unroll
        for (int i=0;i<96;i++) { if (i < dns_len) e->dns[i]=dns[i]; }
    }
    bpf_ringbuf_submit(e,0);
}

static __always_inline void submit_socket_event(struct bpf_sock_addr *ctx, __u8 family, __u8 proto,
                                                 __u8 action, __u8 reason, const __u8 dst[16])
{
    struct obs_event *e = new_event(family,DIR_EGRESS,HOOK_SOCKET,proto,action,
                                    action==ACT_BLOCK?EVT_BLOCK:EVT_CONNECT,reason);
    if (!e) return;
    __u64 pt=bpf_get_current_pid_tgid(), ug=bpf_get_current_uid_gid();
    e->pid=(__u32)(pt>>32); e->uid=(__u32)ug; e->cgroup_id=bpf_get_current_cgroup_id();
    e->dst_port=(__u16)ctx->user_port; __builtin_memcpy(e->dst_addr,dst,16);
    bpf_get_current_comm(e->comm,sizeof(e->comm));
    bpf_ringbuf_submit(e,0);
}

static __always_inline int decide4(__u8 direction, __u32 addr, __u8 proto, __u16 dport, __u8 *reason, int apply_rate, __u64 cgroup_id)
{
    if (!enforcing() || !scope_allows(cgroup_id)) return 0;
    if (direction==DIR_EGRESS && bpf_map_lookup_elem(&blocked_v4,&addr)) { *reason=REASON_EXACT; return 1; }
    if (blocked_cidr4(direction,addr)) { *reason=REASON_CIDR; return 1; }
    if (dport && blocked_port(direction,proto,dport)) { *reason=REASON_PORT; return 1; }
    if (apply_rate && direction==DIR_EGRESS && rate_limited4(addr)) { *reason=REASON_RATE; return 1; }
    return 0;
}
static __always_inline int decide6(__u8 direction, const __u8 addr[16], __u8 proto, __u16 dport, __u8 *reason, __u64 cgroup_id)
{
    if (!enforcing() || !scope_allows(cgroup_id)) return 0;
    struct ip6_key k={}; __builtin_memcpy(k.addr,addr,16);
    if (direction==DIR_EGRESS && bpf_map_lookup_elem(&blocked_v6,&k)) { *reason=REASON_EXACT; return 1; }
    if (blocked_cidr6(direction,addr)) { *reason=REASON_CIDR; return 1; }
    if (dport && blocked_port(direction,proto,dport)) { *reason=REASON_PORT; return 1; }
    return 0;
}

static __always_inline int dns_qname(void *payload, void *data_end, char out[96])
{
    unsigned char *p = payload;
    if ((void *)(p+12) > data_end) return 0;
    p += 12;
    int oi=0, remaining=0;
    #pragma unroll
    for (int i=0;i<96;i++) {
        if ((void *)(p+1)>data_end || oi>=95) break;
        unsigned char c=*p++;
        if (remaining==0) {
            if (c==0) break;
            if ((c&0xc0)!=0 || c>63) break;
            if (oi>0) out[oi++]='.';
            remaining=c;
        } else {
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            out[oi++]=(char)c;
            remaining--;
        }
    }
    if (oi<96) out[oi]=0;
    return oi;
}


static __always_inline void track_tcp_signal(__u64 cgroup_id, __u8 flags)
{
    struct tcp_signal_value zero = {};
    struct tcp_signal_value *v = bpf_map_lookup_elem(&tcp_signals, &cgroup_id);
    if (!v) {
        bpf_map_update_elem(&tcp_signals, &cgroup_id, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&tcp_signals, &cgroup_id);
    }
    if (!v) return;
    __sync_fetch_and_add(&v->packets, 1);
    if (flags & 0x02) {
        if (flags & 0x10) __sync_fetch_and_add(&v->syn_ack, 1);
        else __sync_fetch_and_add(&v->syn, 1);
    }
    if (flags & 0x01) __sync_fetch_and_add(&v->fin, 1);
    if (flags & 0x04) __sync_fetch_and_add(&v->rst, 1);
}

static __always_inline void dns_query_track(__u64 cgroup_id, __u8 family, const __u8 server[16],
                                             __u16 client_port, void *payload, void *data_end,
                                             const char name[96], int name_len)
{
    unsigned char *p = payload;
    if (!cgroup_id || name_len <= 0 || (void *)(p + 12) > data_end) return;
    struct dns_pending_key pk = {.cgroup_id = cgroup_id, .family = family,
                                 .client_port = client_port,
                                 .txid = ((__u16)p[0] << 8) | p[1]};
    __builtin_memcpy(pk.server, server, 16);
    struct dns_pending_value pv = {.start_ns = bpf_ktime_get_ns()};
    __builtin_memcpy(pv.name, name, 96);
    bpf_map_update_elem(&dns_pending, &pk, &pv, BPF_ANY);

    struct dns_health_key hk = {.cgroup_id = cgroup_id};
    __builtin_memcpy(hk.name, name, 96);
    struct dns_health_value zero = {};
    struct dns_health_value *hv = bpf_map_lookup_elem(&dns_health, &hk);
    if (!hv) {
        bpf_map_update_elem(&dns_health, &hk, &zero, BPF_NOEXIST);
        hv = bpf_map_lookup_elem(&dns_health, &hk);
    }
    if (hv) {
        __sync_fetch_and_add(&hv->queries, 1);
        hv->last_ns = bpf_ktime_get_ns();
    }
}

static __always_inline void dns_response_track(__u64 cgroup_id, __u8 family, const __u8 server[16],
                                                __u16 client_port, void *payload, void *data_end,
                                                __u32 ifindex, __u32 len,
                                                const __u8 src[16], const __u8 dst[16])
{
    unsigned char *p = payload;
    if (!cgroup_id || (void *)(p + 12) > data_end) return;
    struct dns_pending_key pk = {.cgroup_id = cgroup_id, .family = family,
                                 .client_port = client_port,
                                 .txid = ((__u16)p[0] << 8) | p[1]};
    __builtin_memcpy(pk.server, server, 16);
    struct dns_pending_value *pv = bpf_map_lookup_elem(&dns_pending, &pk);
    if (!pv) return;

    __u64 now = bpf_ktime_get_ns();
    __u64 latency_us = (now - pv->start_ns) / 1000ULL;
    __u8 rcode = p[3] & 0x0f;
    struct dns_health_key hk = {.cgroup_id = cgroup_id};
    __builtin_memcpy(hk.name, pv->name, 96);
    struct dns_health_value zero = {};
    struct dns_health_value *hv = bpf_map_lookup_elem(&dns_health, &hk);
    if (!hv) {
        bpf_map_update_elem(&dns_health, &hk, &zero, BPF_NOEXIST);
        hv = bpf_map_lookup_elem(&dns_health, &hk);
    }
    if (hv) {
        __sync_fetch_and_add(&hv->responses, 1);
        if (rcode) __sync_fetch_and_add(&hv->failures, 1);
        __sync_fetch_and_add(&hv->total_latency_us, latency_us);
        if (latency_us > hv->max_latency_us) hv->max_latency_us = latency_us;
        hv->last_ns = now;
    }
    struct obs_event *e = new_event(family, DIR_INGRESS, HOOK_CGROUP, IPPROTO_UDP, ACT_ALLOW, EVT_DNS_RESPONSE, REASON_NONE);
    if (e) {
        e->cgroup_id = cgroup_id;
        e->ifindex = ifindex;
        e->length = len;
        e->src_port = __builtin_bswap16(53);
        e->dst_port = client_port;
        e->latency_us = (__u32)(latency_us > 0xffffffffULL ? 0xffffffffULL : latency_us);
        e->dns_rcode = rcode;
        __builtin_memcpy(e->src_addr, src, 16);
        __builtin_memcpy(e->dst_addr, dst, 16);
        __builtin_memcpy(e->dns, pv->name, 96);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&dns_pending, &pk);
}

static __always_inline int handle_v4(void *data, void *data_end, __u32 ifindex, __u32 len,
                                     __u8 direction, __u8 hook, int l2, int allow_value)
{
    struct iphdr *ip;
    if (l2) {
        struct ethhdr *eth=data;
        if ((void *)(eth+1)>data_end || eth->h_proto!=__builtin_bswap16(ETH_P_IP)) return allow_value;
        ip=(void *)(eth+1);
    } else ip=data;
    if ((void *)(ip+1)>data_end || ip->version!=4 || ip->ihl<5) return allow_value;
    void *l4=(void *)ip + ip->ihl*4;
    if (l4>data_end) return allow_value;
    __u16 sport=0,dport=0; __u8 flags=0; void *payload=0;
    if (ip->protocol==IPPROTO_TCP) {
        struct tcphdr *tcp=l4; if ((void *)(tcp+1)>data_end) return allow_value;
        sport=tcp->source; dport=tcp->dest; flags=*(((unsigned char *)tcp)+13);
    } else if (ip->protocol==IPPROTO_UDP) {
        struct udphdr *udp=l4; if ((void *)(udp+1)>data_end) return allow_value;
        sport=udp->source; dport=udp->dest; payload=(void *)(udp+1);
    }
    __u32 peer = direction==DIR_EGRESS ? ip->daddr : ip->saddr;
    __u16 policy_port = dport;
    __u64 cgroup_id = hook==HOOK_CGROUP ? bpf_get_current_cgroup_id() : 0;
    if (ip->protocol==IPPROTO_TCP) track_tcp_signal(cgroup_id, flags);
    __u8 reason=0; int blocked=decide4(direction,peer,ip->protocol,policy_port,&reason,1,cgroup_id);
    char dns_name[96]={}; int dns_len=0;
    if (direction==DIR_EGRESS && ip->protocol==IPPROTO_UDP && dport==__builtin_bswap16(53) && payload) {
        dns_len=dns_qname(payload,data_end,dns_name);
        if (!blocked && enforcing() && scope_allows(cgroup_id) && dns_len>0) { struct dns_key dk={}; __builtin_memcpy(dk.name,dns_name,96); if (bpf_map_lookup_elem(&blocked_dns,&dk)) { blocked=1; reason=REASON_DNS; } }
    }
    __u8 src[16],dst[16]; copy4(src,ip->saddr); copy4(dst,ip->daddr);
    if (direction==DIR_EGRESS && ip->protocol==IPPROTO_UDP && dport==__builtin_bswap16(53) && dns_len>0) dns_query_track(cgroup_id,FAMILY_V4,dst,sport,payload,data_end,dns_name,dns_len);
    if (direction==DIR_INGRESS && ip->protocol==IPPROTO_UDP && sport==__builtin_bswap16(53) && payload) dns_response_track(cgroup_id,FAMILY_V4,src,dport,payload,data_end,ifindex,len,src,dst);
    update_flow(FAMILY_V4,direction,hook,ip->protocol,sport,dport,src,dst,len,blocked,cgroup_id);
    if (direction==DIR_EGRESS) {
        struct dest_key lk={.dst_ip=ip->daddr,.dst_port=dport,.protocol=ip->protocol,.pad=0};
        struct dest_value zero={}; struct dest_value *lv=bpf_map_lookup_elem(&dest_stats,&lk);
        if(!lv){bpf_map_update_elem(&dest_stats,&lk,&zero,BPF_NOEXIST);lv=bpf_map_lookup_elem(&dest_stats,&lk);} if(lv){__sync_fetch_and_add(&lv->packets,1);__sync_fetch_and_add(&lv->bytes,len);if(blocked)__sync_fetch_and_add(&lv->blocked,1);lv->last_ns=bpf_ktime_get_ns();}
    }
    if (blocked) submit_packet_event(FAMILY_V4,direction,hook,ip->protocol,ACT_BLOCK,EVT_BLOCK,reason,ifindex,len,src,dst,sport,dport,flags,dns_name,dns_len,cgroup_id);
    else {
        // Exact counters are retained; ring buffer is sampled 1/64 by timestamp bits.
        if ((bpf_ktime_get_ns() & 63)==1) submit_packet_event(FAMILY_V4,direction,hook,ip->protocol,ACT_ALLOW,EVT_FLOW,0,ifindex,len,src,dst,sport,dport,flags,0,0,cgroup_id);
        if(dns_len>0) submit_packet_event(FAMILY_V4,direction,hook,ip->protocol,ACT_ALLOW,EVT_DNS,0,ifindex,len,src,dst,sport,dport,0,dns_name,dns_len,cgroup_id);
    }
    return blocked ? (allow_value==TC_ACT_OK ? TC_ACT_SHOT : 0) : allow_value;
}

static __always_inline int handle_v6(void *data, void *data_end, __u32 ifindex, __u32 len,
                                     __u8 direction, __u8 hook, int l2, int allow_value)
{
    struct ipv6hdr *ip6;
    if (l2) {
        struct ethhdr *eth=data;
        if ((void *)(eth+1)>data_end || eth->h_proto!=__builtin_bswap16(ETH_P_IPV6)) return allow_value;
        ip6=(void *)(eth+1);
    } else ip6=data;
    if ((void *)(ip6+1)>data_end) return allow_value;
    void *l4=(void *)(ip6+1); __u8 proto=ip6->nexthdr; __u16 sport=0,dport=0; __u8 flags=0; void *payload=0;
    if (proto==IPPROTO_TCP) { struct tcphdr *tcp=l4;if((void *)(tcp+1)>data_end)return allow_value;sport=tcp->source;dport=tcp->dest;flags=*(((unsigned char*)tcp)+13); }
    else if(proto==IPPROTO_UDP){struct udphdr *udp=l4;if((void *)(udp+1)>data_end)return allow_value;sport=udp->source;dport=udp->dest;payload=(void *)(udp+1);}
    const __u8 *peer=direction==DIR_EGRESS?(const __u8 *)&ip6->daddr:(const __u8 *)&ip6->saddr;
    __u16 policy_port=dport;__u64 cgroup_id=hook==HOOK_CGROUP?bpf_get_current_cgroup_id():0;if(proto==IPPROTO_TCP)track_tcp_signal(cgroup_id,flags);__u8 reason=0;int blocked=decide6(direction,peer,proto,policy_port,&reason,cgroup_id);
    char dns_name[96]={};int dns_len=0;if(direction==DIR_EGRESS&&proto==IPPROTO_UDP&&dport==__builtin_bswap16(53)&&payload){dns_len=dns_qname(payload,data_end,dns_name);if(!blocked&&enforcing()&&scope_allows(cgroup_id)&&dns_len>0){struct dns_key dk={};__builtin_memcpy(dk.name,dns_name,96);if(bpf_map_lookup_elem(&blocked_dns,&dk)){blocked=1;reason=REASON_DNS;}}}
    __u8 src[16],dst[16];copy16(src,&ip6->saddr);copy16(dst,&ip6->daddr);if(direction==DIR_EGRESS&&proto==IPPROTO_UDP&&dport==__builtin_bswap16(53)&&dns_len>0)dns_query_track(cgroup_id,FAMILY_V6,dst,sport,payload,data_end,dns_name,dns_len);if(direction==DIR_INGRESS&&proto==IPPROTO_UDP&&sport==__builtin_bswap16(53)&&payload)dns_response_track(cgroup_id,FAMILY_V6,src,dport,payload,data_end,ifindex,len,src,dst);update_flow(FAMILY_V6,direction,hook,proto,sport,dport,src,dst,len,blocked,cgroup_id);
    if(blocked) submit_packet_event(FAMILY_V6,direction,hook,proto,ACT_BLOCK,EVT_BLOCK,reason,ifindex,len,src,dst,sport,dport,flags,dns_name,dns_len,cgroup_id);
    else { if((bpf_ktime_get_ns()&63)==1)submit_packet_event(FAMILY_V6,direction,hook,proto,ACT_ALLOW,EVT_FLOW,0,ifindex,len,src,dst,sport,dport,flags,0,0,cgroup_id); if(dns_len>0)submit_packet_event(FAMILY_V6,direction,hook,proto,ACT_ALLOW,EVT_DNS,0,ifindex,len,src,dst,sport,dport,0,dns_name,dns_len,cgroup_id); }
    return blocked ? (allow_value==TC_ACT_OK ? TC_ACT_SHOT : 0) : allow_value;
}

static __always_inline int handle_l2(struct __sk_buff *skb, __u8 direction)
{
    void *data=(void *)(long)skb->data,*end=(void *)(long)skb->data_end;
    struct ethhdr *eth=data;if((void *)(eth+1)>end)return TC_ACT_OK;
    if(eth->h_proto==__builtin_bswap16(ETH_P_IP))return handle_v4(data,end,skb->ifindex,skb->len,direction,HOOK_TC,1,TC_ACT_OK);
    if(eth->h_proto==__builtin_bswap16(ETH_P_IPV6))return handle_v6(data,end,skb->ifindex,skb->len,direction,HOOK_TC,1,TC_ACT_OK);
    return TC_ACT_OK;
}
static __always_inline int handle_l3(struct __sk_buff *skb, __u8 direction)
{
    void *data=(void *)(long)skb->data,*end=(void *)(long)skb->data_end;if(data>=end)return 1;
    __u8 version=(*(__u8*)data)>>4;
    if(version==4)return handle_v4(data,end,skb->ifindex,skb->len,direction,HOOK_CGROUP,0,1);
    if(version==6)return handle_v6(data,end,skb->ifindex,skb->len,direction,HOOK_CGROUP,0,1);
    return 1;
}

SEC("tc/egress") int netra_egress(struct __sk_buff *skb){ return handle_l2(skb,DIR_EGRESS); }
SEC("tc/ingress") int netra_ingress(struct __sk_buff *skb){ return handle_l2(skb,DIR_INGRESS); }
SEC("cgroup_skb/egress") int netra_cgroup_egress(struct __sk_buff *skb){ return handle_l3(skb,DIR_EGRESS); }
SEC("cgroup_skb/ingress") int netra_cgroup_ingress(struct __sk_buff *skb){ return handle_l3(skb,DIR_INGRESS); }

static __always_inline int socket4(struct bpf_sock_addr *ctx,__u8 proto)
{
    __u32 dst=ctx->user_ip4;__u16 dport=(__u16)ctx->user_port;__u8 reason=0;__u8 addr[16];copy4(addr,dst);
    __u32 uid=(__u32)bpf_get_current_uid_gid();__u64 cgroup_id=bpf_get_current_cgroup_id();
    int blocked=0;if(enforcing()&&scope_allows(cgroup_id)&&bpf_map_lookup_elem(&blocked_uids,&uid)){reason=REASON_UID;blocked=1;}else if(enforcing()&&scope_allows(cgroup_id)){struct comm_key ck={};bpf_get_current_comm(ck.name,sizeof(ck.name));if(bpf_map_lookup_elem(&blocked_comms,&ck)){reason=REASON_PROCESS;blocked=1;}}if(!blocked)blocked=decide4(DIR_EGRESS,dst,proto,dport,&reason,0,cgroup_id);
    if (!blocked && proto==IPPROTO_TCP) { __u64 cookie=bpf_get_socket_cookie(ctx); if(cookie){ struct socket_owner_value ov={.cgroup_id=cgroup_id,.pid=(__u32)(bpf_get_current_pid_tgid()>>32),.uid=uid}; bpf_get_current_comm(ov.comm,sizeof(ov.comm)); bpf_map_update_elem(&socket_owner,&cookie,&ov,BPF_ANY); } }
    submit_socket_event(ctx,FAMILY_V4,proto,blocked?ACT_BLOCK:ACT_ALLOW,reason,addr);return blocked?0:1;
}
static __always_inline int socket6(struct bpf_sock_addr *ctx,__u8 proto)
{
    __u8 addr[16];__builtin_memcpy(addr,ctx->user_ip6,16);__u16 dport=(__u16)ctx->user_port;__u8 reason=0;__u32 uid=(__u32)bpf_get_current_uid_gid();__u64 cgroup_id=bpf_get_current_cgroup_id();
    int blocked=0;if(enforcing()&&scope_allows(cgroup_id)&&bpf_map_lookup_elem(&blocked_uids,&uid)){reason=REASON_UID;blocked=1;}else if(enforcing()&&scope_allows(cgroup_id)){struct comm_key ck={};bpf_get_current_comm(ck.name,sizeof(ck.name));if(bpf_map_lookup_elem(&blocked_comms,&ck)){reason=REASON_PROCESS;blocked=1;}}if(!blocked)blocked=decide6(DIR_EGRESS,addr,proto,dport,&reason,cgroup_id);
    if (!blocked && proto==IPPROTO_TCP) { __u64 cookie=bpf_get_socket_cookie(ctx); if(cookie){ struct socket_owner_value ov={.cgroup_id=cgroup_id,.pid=(__u32)(bpf_get_current_pid_tgid()>>32),.uid=uid}; bpf_get_current_comm(ov.comm,sizeof(ov.comm)); bpf_map_update_elem(&socket_owner,&cookie,&ov,BPF_ANY); } }
    submit_socket_event(ctx,FAMILY_V6,proto,blocked?ACT_BLOCK:ACT_ALLOW,reason,addr);return blocked?0:1;
}
SEC("cgroup/connect4") int netra_connect4(struct bpf_sock_addr *ctx){return socket4(ctx,IPPROTO_TCP);}
SEC("cgroup/connect6") int netra_connect6(struct bpf_sock_addr *ctx){return socket6(ctx,IPPROTO_TCP);}
SEC("cgroup/sendmsg4") int netra_sendmsg4(struct bpf_sock_addr *ctx){return socket4(ctx,IPPROTO_UDP);}
SEC("cgroup/sendmsg6") int netra_sendmsg6(struct bpf_sock_addr *ctx){return socket6(ctx,IPPROTO_UDP);}


static __always_inline void tcp_health_key_from_sockops(struct bpf_sock_ops *skops, __u64 cgroup_id,
                                                         struct tcp_health_key *k)
{
    __builtin_memset(k, 0, sizeof(*k));
    k->cgroup_id = cgroup_id;
    k->family = skops->family == 2 ? FAMILY_V4 : FAMILY_V6;
    if (skops->family == 2) {
        k->local_ip4 = skops->local_ip4;
        k->remote_ip4 = skops->remote_ip4;
    } else {
        __builtin_memcpy(k->local_ip6, skops->local_ip6, 16);
        __builtin_memcpy(k->remote_ip6, skops->remote_ip6, 16);
    }
    k->local_port = (__u16)skops->local_port;
    k->remote_port = (__u16)__builtin_bswap32(skops->remote_port);
}

SEC("sockops") int netra_sockops(struct bpf_sock_ops *skops)
{
    if (skops->family != 2 && skops->family != 10) return 0;
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct socket_owner_value *owner = cookie ? bpf_map_lookup_elem(&socket_owner, &cookie) : 0;
    __u64 cgroup_id = owner ? owner->cgroup_id : 0;
    struct tcp_health_key key;
    tcp_health_key_from_sockops(skops, cgroup_id, &key);
    struct tcp_health_value zero = {};
    struct tcp_health_value *v = bpf_map_lookup_elem(&tcp_health, &key);
    if (!v) {
        bpf_map_update_elem(&tcp_health, &key, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&tcp_health, &key);
    }
    if (!v) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (owner) {
        v->pid = owner->pid;
        v->uid = owner->uid;
        __builtin_memcpy(v->comm, owner->comm, 16);
    }
    v->last_ns = now;
    if (skops->is_fullsock) {
        v->srtt_us = ((__u64)skops->srtt_us) >> 3;
        v->rtt_min_us = skops->rtt_min;
        v->snd_cwnd = skops->snd_cwnd;
        v->bytes_acked = skops->bytes_acked;
        v->bytes_received = skops->bytes_received;
        v->segs_in = skops->segs_in;
        v->segs_out = skops->segs_out;
    }
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        __sync_fetch_and_add(&v->active_established, 1);
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RETRANS_CB_FLAG |
                                         BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        __sync_fetch_and_add(&v->passive_established, 1);
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RETRANS_CB_FLAG |
                                         BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG);
        break;
    case BPF_SOCK_OPS_RTO_CB:
        __sync_fetch_and_add(&v->rto, 1);
        break;
    case BPF_SOCK_OPS_RETRANS_CB:
        __sync_fetch_and_add(&v->retrans, 1);
        break;
    case BPF_SOCK_OPS_RTT_CB:
        __sync_fetch_and_add(&v->rtt_samples, 1);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        // args[1] is the new TCP state. TCP_CLOSE is 7 in the Linux UAPI.
        if (skops->args[1] == 7) __sync_fetch_and_add(&v->closes, 1);
        break;
    default:
        break;
    }
    return 0;
}

SEC("xdp") int netra_xdp_ingress(struct xdp_md *ctx)
{
    void *data=(void *)(long)ctx->data,*end=(void *)(long)ctx->data_end;struct ethhdr *eth=data;if((void *)(eth+1)>end)return XDP_PASS;
    if(!enforcing())return XDP_PASS;
    if(eth->h_proto==__builtin_bswap16(ETH_P_IP)){
        struct iphdr *ip=(void *)(eth+1);if((void *)(ip+1)>end)return XDP_PASS;void *l4=(void *)ip+ip->ihl*4;__u16 sport=0,dport=0;if(ip->protocol==IPPROTO_TCP){struct tcphdr*t=l4;if((void*)(t+1)>end)return XDP_PASS;sport=t->source;dport=t->dest;}else if(ip->protocol==IPPROTO_UDP){struct udphdr*u=l4;if((void*)(u+1)>end)return XDP_PASS;sport=u->source;dport=u->dest;}__u8 reason=0;if(decide4(DIR_INGRESS,ip->saddr,ip->protocol,dport,&reason,0,0)){__u8 src[16],dst[16];copy4(src,ip->saddr);copy4(dst,ip->daddr);update_flow(FAMILY_V4,DIR_INGRESS,HOOK_XDP,ip->protocol,sport,dport,src,dst,(__u32)((long)end-(long)data),1,0);submit_packet_event(FAMILY_V4,DIR_INGRESS,HOOK_XDP,ip->protocol,ACT_BLOCK,EVT_BLOCK,reason,ctx->ingress_ifindex,(__u32)((long)end-(long)data),src,dst,sport,dport,0,0,0,0);return XDP_DROP;}
    } else if(eth->h_proto==__builtin_bswap16(ETH_P_IPV6)){
        struct ipv6hdr *ip6=(void *)(eth+1);if((void *)(ip6+1)>end)return XDP_PASS;void*l4=(void *)(ip6+1);__u16 sport=0,dport=0;if(ip6->nexthdr==IPPROTO_TCP){struct tcphdr*t=l4;if((void*)(t+1)>end)return XDP_PASS;sport=t->source;dport=t->dest;}else if(ip6->nexthdr==IPPROTO_UDP){struct udphdr*u=l4;if((void*)(u+1)>end)return XDP_PASS;sport=u->source;dport=u->dest;}__u8 reason=0;if(decide6(DIR_INGRESS,(const __u8*)&ip6->saddr,ip6->nexthdr,dport,&reason,0)){__u8 src[16],dst[16];copy16(src,&ip6->saddr);copy16(dst,&ip6->daddr);update_flow(FAMILY_V6,DIR_INGRESS,HOOK_XDP,ip6->nexthdr,sport,dport,src,dst,(__u32)((long)end-(long)data),1,0);submit_packet_event(FAMILY_V6,DIR_INGRESS,HOOK_XDP,ip6->nexthdr,ACT_BLOCK,EVT_BLOCK,reason,ctx->ingress_ifindex,(__u32)((long)end-(long)data),src,dst,sport,dport,0,0,0,0);return XDP_DROP;}
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
