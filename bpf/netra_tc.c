// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
// Netra TC egress fast path. Intentionally independent of Cilium maps.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

struct dest_key {
    __u32 dst_ip;     // IPv4 bytes as present on the wire
    __u16 dst_port;   // L4 destination port in network byte order
    __u8 protocol;
    __u8 pad;
};

struct dest_value {
    __u64 packets;
    __u64 bytes;
    __u64 blocked;
    __u64 last_ns;
};

struct flow_event {
    __u64 ts_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 ifindex;
    __u32 length;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;      // 0 observe/allow, 1 denied by Netra fast path
    __u8 pad[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dest_key);
    __type(value, struct dest_value);
} dest_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_v4 SEC(".maps");

// key 0: 0=observe, 1=enforce exact IPv4 deny map.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline void emit_event(struct __sk_buff *skb, struct iphdr *ip, __u16 sport, __u16 dport, __u8 action)
{
    struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns = bpf_ktime_get_ns();
    e->src_ip = ip->saddr;
    e->dst_ip = ip->daddr;
    e->ifindex = skb->ifindex;
    e->length = skb->len;
    e->src_port = sport;
    e->dst_port = dport;
    e->protocol = ip->protocol;
    e->action = action;
    bpf_ringbuf_submit(e, 0);
}

SEC("tc/egress")
int netra_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->version != 4)
        return TC_ACT_OK;
    if (ip->ihl < 5)
        return TC_ACT_OK;

    void *l4 = (void *)ip + ip->ihl * 4;
    if (l4 > data_end)
        return TC_ACT_OK;

    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = udp->source;
        dport = udp->dest;
    }

    struct dest_key key = {
        .dst_ip = ip->daddr,
        .dst_port = dport,
        .protocol = ip->protocol,
        .pad = 0,
    };
    struct dest_value zero = {};
    struct dest_value *v = bpf_map_lookup_elem(&dest_stats, &key);
    if (!v) {
        bpf_map_update_elem(&dest_stats, &key, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&dest_stats, &key);
    }
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, skb->len);
        v->last_ns = bpf_ktime_get_ns();
    }

    __u32 cfg_key = 0;
    __u32 *mode = bpf_map_lookup_elem(&config_map, &cfg_key);
    __u8 *blocked = bpf_map_lookup_elem(&blocked_v4, &ip->daddr);
    if (mode && *mode == 1 && blocked) {
        if (v)
            __sync_fetch_and_add(&v->blocked, 1);
        emit_event(skb, ip, sport, dport, 1);
        return TC_ACT_SHOT;
    }

    // Sample 1/64 packets into the ring buffer; counters remain exact.
    if (v && ((v->packets & 63) == 1))
        emit_event(skb, ip, sport, dport, 0);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
