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
#include "pingalert.skel.h"


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

  
	union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH;  /* mandatory */
        .key_size = sizeof(__u32);       /* mandatory */
        .value_size = sizeof(__u8);     /* mandatory */
        .max_entries = 1024;              /* mandatory */
        .map_name = "pingalert_map";
	};

	int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0) {
		perror("failed to create ping alert map");
		return EXIT_FAILURE;
	}
		
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
    struct pingalert_bpf* pabpf = pingalert_bpf__open_and_load();
    if (!dpbpf) {
        fprintf(stderr, "Failed to open and open BPF object\n");
        return EXIT_FAILURE;
    }

    // Attach xdp program to interface
    struct bpf_link* bpflink = bpf_program__attach_xdp(pabpf->progs.processping, ifindex);
    if (!bpflink) {
        fprintf(stderr, "Failed to call bpf_program__attach_xdp\n");
        return EXIT_FAILURE;
    }

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
        int ret = bpf_map_update_elem(map_fd, &addrkey, sizeof(unsigned int), &confirmed, sizeof(unsigned char), BPF_ANY);
        if (ret < 0)
            fprintf(stderr, "failed to update element in pingalert_map\n");

    }


    return 0;
}
