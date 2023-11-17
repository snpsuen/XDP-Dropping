// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "dropping.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint8_t);
} dropping_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ping_ring SEC(".maps");

SEC("xdp")
int processping(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct pingmsg_t msg = {0};

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void*)eth + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr* iph = (void*)eth + sizeof(struct ethhdr);
    if ((void*)iph + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;
    
    if (ip->protocol == IPPROTO_ICMP) {
        msg.proto = IPPROTO_ICMP;
        msg.saddr = ip->saddr;
        msg.daddr = ip->daddr;

        bpf_ringbuf_output(&ping_ring, &msg, sizeof(msg), BPF_RB_FORCE_WAKEUP);

        if (bpf_map_lookup_elem(&dropping_hash, &ip->saddr)) {
            return XDP_DROP;
        } 
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
