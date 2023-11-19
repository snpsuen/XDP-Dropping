// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include "vmlinux0.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "dropping.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, uint32_t);
  __type(value, uint8_t);
} dropping_hash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint16_t);
	__type(value, struct pingmsg_t);
	__uint(max_entries, 1024);
} pingtraffic_array SEC(".maps");

SEC("xdp")
int processping(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct pingmsg_t msg = {0};
  static uint16_t skey = 0;
  
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
    msg.timestamp = bpf_ktime_get_ns();
    msg.saddr = iph->saddr;
    msg.daddr = iph->daddr;

    uint16_t key = skey % 1024
    int ret = bpf_map_update_elem(pingtraffic_array, &key, sizeof(uint32_t), &msg, sizeof(struct pingmesg_t), BPF_ANY);
    if (ret) {
      fprintf(stderr, "failed to update element in pingtraffic_array\n");
      return XDP_ABORTED;
    }
    skey++;

    if (bpf_map_lookup_elem(&dropping_hash, &iph->saddr))
      return XDP_DROP;

  }
    
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
