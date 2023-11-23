// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include "vmlinux0.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint8_t);
} pingalert_map;

SEC("xdp")
int processping(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	
	struct ethhdr *eth = (struct ethhdr *)data;
	if ((void*)eth + sizeof(struct ethhdr) > data_end)
		return XDP_ABORTED;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;
	
	struct iphdr* iph = (void*)eth + sizeof(struct ethhdr);
	if ((void*)iph + sizeof(struct iphdr) > data_end)
		return XDP_ABORTED;
	if (iph->protocol != IPPROTO_ICMP)
		return XDP_PASS;
	
	if (iph->protocol == IPPROTO_ICMP) {		
		if (bpf_map_lookup_elem(&pingalert_hash, &iph->saddr)) {
			bpf_printk("Alert! Source IP %pI4 is pinging ...\n", &iph->saddr);
	}
    
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
