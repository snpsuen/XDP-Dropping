#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
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
    if (sig == SIGINT) {
        printf("Program terminates\n");
        exit(0);
    }
}

int handle_ping(void *ctx, void *data, size_t len)  {
    struct pingmsg_t* msg = (struct pingmsg_t *)data;
    void* ptr = ctx;
    size_t size = len;

    char str_s[INET_ADDRSTRLEN];
    char str_d[INET_ADDRSTRLEN];
    printf("--- Received ping! ---\n");
    printf("ctx = %x, len = %d\n", (long)ptr, (int)size);
    
    if (inet_ntop(AF_INET, &(msg->saddr), str_s, INET_ADDRSTRLEN))
        printf("src ip: %s\n", str_s);
    if (inet_ntop(AF_INET, &(msg->daddr), str_d, INET_ADDRSTRLEN))
        printf("dst ip: %s\n", str_d);
    return 0;
}

int main(int argc, char *argv[]) {
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

    ifindex = if_nametoindex(ifname);
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

    int map_fd = bpf_object__find_map_fd_by_name(dpbpf->obj, "ping_ring");
    if (map_fd < 0)
    {
        fprintf(stderr, "Failed to find the fd for the ring buffer map\n");
        return EXIT_FAILURE;
    }

    struct ring_buffer *ringbuf = ring_buffer__new(map_fd, handle_ping, NULL, NULL);
    if (!ringbuf)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        return EXIT_FAILURE;
    }

    printf("Successfully started! Please Ctrl+C to stop.\n");

    struct bpf_map *phmap = bpf_object__find_map_by_name(dpbpf->obj, "dropping_hash");
    if (!phmap) {
        fprintf(stderr, "Failed to find the ping hash map\n");
        return EXIT_FAILURE;
    }


    const char* sourceip = "192.168.1.1";
    uint32_t key;
    inet_pton(AF_INET, sourceip, &key);
    uint8_t value = 1;

    int ret = bpf_map__update_elem(phmap, &key, sizeof(uint32_t), &value, sizeof(uint8_t), BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "failed to update element in dropping_hash\n");
        return EXIT_FAILURE;
    }

    // Poll the ring buffer
    while (1) {
        if (ring_buffer__poll(ringbuf, interval /* timeout, ms */) < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    return 0;
}
