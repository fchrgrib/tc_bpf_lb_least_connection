// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
/* Copyright (c) 2022 Red Hat */
#include <signal.h>
#include <unistd.h>
#include "tc.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>


#include <net/if.h>
#include <arpa/inet.h>


#define LO_IFINDEX	1


static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
        int ifindex;

        /* Nodeport demo program, assumes 2 backends for now (provided via cli) */
        /* later pull a variable # set of backends from k8s controller watch updates */

        uint16_t nodeport;

        struct np_backends {
            __u32    be1;
            __u32    be2;
            __u16    targetPort;
        };

        struct np_backends backends;

        if (argc < 5) {
                fprintf(stderr, "Usage: tc <interface_name> nodeport <be pod ip1> <be pod ip2> <targetPort>\n");
                return 1;
        }

        ifindex = if_nametoindex(argv[1]);
        if (!ifindex) {
                fprintf(stderr, "Bad interface name\n");
                return 1;
        }

        nodeport = atoi(argv[2]);
        if (nodeport < 30000 || nodeport > 32000) {
                fprintf(stderr, "Nodeport value must be in range <30000, 32000>\n");
                return 1;
        }

		

        inet_aton(argv[3], (struct in_addr *)&(backends.be1));
        inet_aton(argv[4], (struct in_addr *)&(backends.be2));

        if (backends.be1 == 0  || backends.be2 == 0) {
                fprintf(stderr, "Invalid backend IP values\n");
                return 1;
        }
 
        if (argc < 6) 
            backends.targetPort = 80;
        else
            backends.targetPort = atoi(argv[5]);

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		.ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		.handle = 1, .priority = 1);
	bool hook_created = false;
	struct tc_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

        /* hack # of backends hard coded to 2 for initial demo */
        __u16   key = nodeport;

        err = bpf_map__update_elem(skel->maps.svc_map, &key, sizeof(key), 
                                                       &backends, sizeof(backends),
                                                       BPF_ANY); 
	if (err ) {
		fprintf(stderr, "Failed to update svc_map: %d\n", err);
		fprintf(stderr, "continuing with default backend mappings \n");
		goto cleanup;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");
	
	int svc_pod_ips = bpf_obj_get("/sys/fs/bpf/service_pod_ips");
	if (svc_pod_ips < 0) {
		printf("bpf_obj_get() failed for service_pod_ips\n");
	} else {
		printf("bpf_obj_get() returned fd svc %d\n", svc_pod_ips);
	}

	int hash_map = bpf_obj_get("/sys/fs/bpf/hash_map");
	if (hash_map < 0) {
		printf("bpf_obj_get() failed for hash_map\n");
	} else {
		printf("bpf_obj_get() returned fd %d\n", hash_map);
	}

	while (!exiting) {
		fprintf(stderr, ".");

		char key_ip[32] = {0}, next_key[32] = {0};
		struct pod_ip_value {
			__u64 unused1;      // First 8 bytes (00 00 00 00 00 00 00 00)
			__u16 unused2;      // Next 2 bytes (00 00)
			__u16 network_flags;// Next 2 bytes (ff ff) - possibly flags?
			__u32 ip_address;   // Last 4 bytes (0a 20 00 02) - IP in network byte order
		}  value_ip = {0};
		__u32 value = 0;
		__u32 min_conn = ~0;
		__u32 selected_ip = 0;

		while (bpf_map_get_next_key(svc_pod_ips, &key_ip, &next_key) == 0) {
			printf("bpf_map_get_next_key() returned %s\n", next_key);
			bpf_map_lookup_elem(svc_pod_ips, &next_key, &value_ip);

			// Check if the IP address is valid
			if (value_ip.ip_address != 0) {
				printf("Valid IP address: %u\n", value_ip.ip_address);
			} else {
				printf("Invalid IP address: %u\n", value_ip.ip_address);
			}
			bpf_map_lookup_elem(hash_map, &value_ip.ip_address, &value);
			// select the ip address if hash map not found
			if(value == 0) {
				selected_ip = value_ip.ip_address;
				break;
			}
			if (value < min_conn) {
						min_conn = value;
						selected_ip = value_ip.ip_address;
			}
			printf("bpf_map_lookup_elem() returned %u\n", value_ip.ip_address);
			memcpy(&key_ip, &next_key, sizeof(key_ip));
		}

		int key_selected = 0;
		if (bpf_map__update_elem(skel->maps.selected, &key_selected, sizeof(key_selected), &selected_ip, sizeof(selected_ip), BPF_ANY) < 0) {
			printf("bpf_map_update_elem() failed\n");
		} else {
			printf("bpf_map_update_elem() returned selected_ip %u\n", selected_ip);
		}
		sleep(1);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	close(svc_pod_ips);
	close(hash_map);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc_bpf__destroy(skel);
	return -err;
}