#define ETH_P_IP 0x0800
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_RB_FORCE_WAKEUP 2

struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  __u32 ingress_ifindex;
  __u32 rx_queue_index;
  __u32 egress_ifindex;
};
