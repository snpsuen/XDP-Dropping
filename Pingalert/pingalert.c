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

int handle_ping(void*, void *data, size_t)  {
    struct pingmsg_t* msg = (struct pingmsg_t *)data;
    char str_s[INET_ADDRSTRLEN];
    char str_d[INET_ADDRSTRLEN];
    
    printf("--- Received ping! ---\n");
    printf("timestamp: %lld\n", msg->timestamp);
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
  
union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY;  /* mandatory */
        .key_size = sizeof(__u32);       /* mandatory */
        .value_size = sizeof(__u8);     /* mandatory */
        .max_entries = 1024;              /* mandatory */
        .map_flags = !BPF_F_NO_COMMON_LRU;
        .map_name = "pingalert_map";
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint8_t);
} drop

int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

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
    struct dropping_bpf* dpbpf = dropping_bpf__open_and_load();
    if (!dpbpf) {
        fprintf(stderr, "Failed to open and open BPF object\n");
        return EXIT_FAILURE;
    }

    // Attach xdp program to interface
    struct bpf_link* bpflink = bpf_program__attach_xdp(dpbpf->progs.processping, ifindex);
    if (!bpflink) {
        fprintf(stderr, "Failed to call bpf_program__attach_xdp\n");
        return EXIT_FAILURE;
    }

    struct bpf_map* dpmap = bpf_object__find_map_by_name(dpbpf->obj, "dropping_hash");
    if (!dpmap) {
        fprintf(stderr, "Failed to find the ping hash map\n");
        return EXIT_FAILURE;
    }

    printf("Successfully started! Please Ctrl+C to stop.\n");
    while (1) {
        char blocked[INET_ADDRSTRLEN];
        memset(blocked, 0, sizeof(blocked));   
        printf("Enter blocked ping source IP or Q/q to quit: ");
        if (fgets(blocked, sizeof(blocked), stdin) == NULL) { 
            printf("Fail to read the input stream"); 
            continue;
        }
        blocked[strlen(blocked)-1] = 0;
        if ((strcmp(blocked, "Q") == 0) || (strcmp(blocked, "q") == 0))
            break;

        unsigned int addrkey;
        inet_pton(AF_INET, blocked, &addrkey);
        unsigned char confirmed = 1;
        int ret = bpf_map__update_elem(dpmap, &addrkey, sizeof(unsigned int), &confirmed, sizeof(unsigned char), BPF_ANY);
        if (ret < 0)
            fprintf(stderr, "failed to update element in dropping_hash\n");

    }

    // Poll the ring buffer
    printf("Polling the ring buffer ...\n");
    while (1) {
        if (ring_buffer__poll(ringbuf, interval /* timeout, ms */) < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    return 0;
}
