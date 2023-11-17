#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>

#include "dropping.h"
#include "dropping.skel.h"

void handle_sigint(int sig) {
    printf("Terminating\n");
    exit(0);
}

int handle_ping(void *ctx, void *data, size_t len)  {
    struct pingmsg_t *msg = (struct pingmsg_t *)data;
    char str_s[INET_ADDRSTRLEN];
    char str_d[INET_ADDRSTRLEN];
    printf("--- Received ping! ---\n");
    if (inet_ntop(AF_INET, &(msg->saddr), str_s, INET_ADDRSTRLEN)) {
        printf("src ip: %s\n", str_s);
    }
    if (inet_ntop(AF_INET, &(msg->daddr), str_d, INET_ADDRSTRLEN)) {
        printf("dst ip: %s\n", str_d);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int err;
    unsigned int ifindex;
    char* ifname;
    int interval;
    
    switch(argc) {
        case 1:
            ifname = "eth0";
            interval = 1000;
            break;
        case 2:
            ifname = argv[1];
            interval = 1000;
            break;
        default:
            ifname = argv[1];
            interval = atoi(argv[2]);
    }

    // Set up signal handler to exit
    signal(SIGINT, handle_sigint);

    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("failed to resolve iface to ifindex");
        return EXIT_FAILURE;
    }

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("failed to increase RLIMIT_MEMLOCK");
        return EXIT_FAILURE;
    }
    
    // Load and verify BPF application
    struct dropping_bpf *dpbpf = dropping_bpf__open_and_load();
    if (!dpbpf) {
        fprintf(stderr, "Failed to open and open BPF object\n");
        return EXIT_FAILURE;
    }

    // Attach xdp program to interface
    struct bpf_link *link = bpf_program__attach_xdp(dpbpf->progs.processping, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to call bpf_program__attach_xdp\n");
        return EXIT_FAILURE;
    }

    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(dpbpf->obj, "ping_ring");
    if (!ringbuf_map)
    {
        fprintf(stderr, "Failed to get ring buffer map\n");
        return 1;
    }

    struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_ping, NULL, NULL);
    if (!ringbuf)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }



    printf("Successfully started! Please Ctrl+C to stop.\n");


    struct bpf_map *map_hash = bpf_object__find_map_by_name(skel->obj, "ping_hash");
    if (!map_hash) {
        fprintf(stderr, "!map_hash\n");
        return 1;
    }

    const char* ip_host_str = "192.168.1.10";
    uint32_t ip_host;
    inet_pton(AF_INET, ip_host_str, &ip_host);

    const char* ip_server_str = "8.8.8.8";
    uint32_t ip_server;
    inet_pton(AF_INET, ip_server_str, &ip_server);

    err = bpf_map__update_elem(map_hash, &ip_server, sizeof(uint32_t), &ip_server, sizeof(uint32_t), BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to update element in ping_hash\n");
        return 1;
    }

    // Poll the ring buffer
    while (1)
    {
        if (ring_buffer__poll(ringbuf, 1000 /* timeout, ms */) < 0)
        {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    return 0;
}
