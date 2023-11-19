#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char *argv[]) {
    unsigned int ifindex;
    char* ifname;
    int interval, ret;
    
    switch(argc) {
        case 1:
            ifname = "eth0";
            interval = 1;
            break;
        case 2:
            ifname = argv[1];
            interval = 1;
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

    struct bpf_map* ptmap = bpf_object__find_map_by_name(dpbpf->obj, "pingtraffic_array");
    if (!ptmap) {
        fprintf(stderr, "Failed to find the fd for the ping traffic array map\n");
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
        blocked[strlen(blocked)] = 0;
        if (strcmp(blocked, "Q") || strcmp(blocked, "q"))
            break;

        unsigned int addrkey;
        inet_pton(AF_INET, blocked, &addrkey);
        unsigned char confirmed = 1;
        ret = bpf_map__update_elem(dpmap, &addrkey, sizeof(unsigned int), &confirmed, sizeof(unsigned char), BPF_ANY);
        if (ret < 0)
            fprintf(stderr, "failed to update element in dropping_hash\n");

    }
    
    // Poll the ping traffic array
    unsigned short key = 0;
    struct pingmsg_t msg;
    while (1) {
        ret = bpf_map__lookup_elem(ptmap, &key, sizeof(uint32_t), &msg, sizeof(uint8_t), BPF_ANY);
        if (ret == 0) {
            char str_s[INET_ADDRSTRLEN];
            char str_d[INET_ADDRSTRLEN];
            printf("--- Received ping! ---\n");
            printf("timestamp: %lld\n", msg.timestamp);
            if (inet_ntop(AF_INET, &(msg.saddr), str_s, INET_ADDRSTRLEN))
                printf("src ip: %s\n", str_s);
            if (inet_ntop(AF_INET, &(msg.daddr), str_d, INET_ADDRSTRLEN))
                printf("dst ip: %s\n", str_d);

            key = (key + 1)%1024;
        }
        sleep(interval);
    }
    
    return 0;
}
