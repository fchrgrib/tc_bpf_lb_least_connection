// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
/* Copyright (c) 2022 Red Hat */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Set this flag to enable/ disable debug messages */
#define DEBUG_ENABLED true

#define DEBUG_BPF_PRINTK(...) if(DEBUG_ENABLED) {bpf_printk(__VA_ARGS__);}

#define TC_ACT_OK	0
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define TEST_NODEPORT   ((unsigned short) 30080)

struct np_backends {
        char service_name[32];
        __u16    targetPort;
        __u16    pad;
};

/* Simplified map definition for initial POC */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, __u16);
        __type(value, struct np_backends);
} svc_map SEC(".maps");

struct ip_value_pair {
    __u32 ip;
    int value;
};

// Structure to pass data between BPF programs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ip_value_pair);
    __uint(max_entries, 1);
} min_value_result SEC(".maps");

struct bpf_ct_opts {
        s32 netns_id;
        s32 error;
        u8 l4proto;
        u8 dir;
        u8 reserved[2];
};

struct nf_conn *
bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, u32,
                  struct bpf_ct_opts *, u32) __ksym;

struct nf_conn *
bpf_skb_ct_alloc(struct __sk_buff *skb_ctx, struct bpf_sock_tuple *bpf_tuple,
                 u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;

struct nf_conn *bpf_ct_insert_entry(struct nf_conn *nfct_i) __ksym;

int bpf_ct_set_nat_info(struct nf_conn *nfct,
                        union nf_inet_addr *addr, int port,
                        enum nf_nat_manip_type manip) __ksym;

void bpf_ct_set_timeout(struct nf_conn *nfct, u32 timeout) __ksym;

int bpf_ct_set_status(const struct nf_conn *nfct, u32 status) __ksym;

void bpf_ct_release(struct nf_conn *) __ksym;

/* Not marking this function to be inline for now */
int nodeport_lb4(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    u64 nh_off = sizeof(*eth);
    struct np_backends *lkup;
    char service_name[32];

    if (data + nh_off > data_end)
        return TC_ACT_OK;

    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP: {
            struct bpf_sock_tuple bpf_tuple = {};
            struct iphdr *iph = data + nh_off;
            struct bpf_ct_opts opts_def = {
                    .netns_id = -1,
            };
            struct nf_conn *ct;

            if ((void *)(iph + 1) > data_end)
                return TC_ACT_OK;

            opts_def.l4proto = iph->protocol;
            bpf_tuple.ipv4.saddr = iph->saddr;
            bpf_tuple.ipv4.daddr = iph->daddr;

            if (iph->protocol == IPPROTO_TCP) {
                    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                    if ((void *)(tcph + 1) > data_end)
                        return TC_ACT_OK;

                    bpf_tuple.ipv4.sport = tcph->source;
                    bpf_tuple.ipv4.dport = tcph->dest;
            } else if (iph->protocol == IPPROTO_UDP) {
                    struct udphdr *udph = (struct udphdr *)(iph + 1);

                    if ((void *)(udph + 1) > data_end)
                        return TC_ACT_OK;

                    bpf_tuple.ipv4.sport = udph->source;
                    bpf_tuple.ipv4.dport = udph->dest;
            } else {
                    return TC_ACT_OK;
            }

            u16 key = bpf_ntohs(bpf_tuple.ipv4.dport);

            lkup = (struct np_backends *) bpf_map_lookup_elem(&svc_map, &key);

            if (!lkup) {
                DEBUG_BPF_PRINTK("lkup result: NULL \n");
                return TC_ACT_OK;
            }

            // Get service name from lookup
            bpf_probe_read_kernel_str(service_name, sizeof(service_name), lkup->service_name);
            DEBUG_BPF_PRINTK("Found service: %s \n", service_name);

            ct = bpf_skb_ct_lookup(ctx, &bpf_tuple,
                                   sizeof(bpf_tuple.ipv4),
                                   &opts_def, sizeof(opts_def));
            
            if (ct) {
                DEBUG_BPF_PRINTK("CT lookup (ct found) 0x%X\n", ct);
                DEBUG_BPF_PRINTK("Timeout %u  status 0x%X dport 0x%X \n",  
                            ct->timeout, ct->status, bpf_tuple.ipv4.dport);
                if (iph->protocol == IPPROTO_TCP) {
                    DEBUG_BPF_PRINTK("TCP proto state %u flags  %u/ %u  last_dir  %u  \n",
                            ct->proto.tcp.state,
                            ct->proto.tcp.seen[0].flags, ct->proto.tcp.seen[1].flags,
                            ct->proto.tcp.last_dir);
                }
                bpf_ct_release(ct);
            } else {
                DEBUG_BPF_PRINTK("CT lookup (no entry) 0x%X\n", 0);
                DEBUG_BPF_PRINTK("dport 0x%X\n", bpf_tuple.ipv4.dport);
                DEBUG_BPF_PRINTK("Got IP packet: dest: %pI4, protocol: %u", 
                            &(iph->daddr), iph->protocol);
                
                /* Create a new CT entry */
                struct nf_conn *nct = bpf_skb_ct_alloc(ctx,
                            &bpf_tuple, sizeof(bpf_tuple.ipv4),
                            &opts_def, sizeof(opts_def));

                if (!nct) {
                    DEBUG_BPF_PRINTK("bpf_skb_ct_alloc() failed\n");
                    return TC_ACT_OK;
                }

                int service_pod_ips = bpf_obj_get("/sys/fs/bpf/tc/globals/service_pod_ips");
                if (service_pod_ips < 0) {
                    DEBUG_BPF_PRINTK("Failed to get service_pod_ips map\n");
                    return TC_ACT_OK;
                }

                int hash_map = bpf_obj_get("/sys/fs/bpf/tc/globals/hash_map");
                if (hash_map < 0) {
                    DEBUG_BPF_PRINTK("Failed to get hash_map\n");
                    return TC_ACT_OK;
                }

                // Variables for iteration
                __u32 min_value = sizeof(__u32);
                __u32 min_ip = 0;
                bool found = false;

                // Setup for iterating through service_pod_ips map
                char key[32];
                __u8 ip_bytes[16];
                __u32 next_key[32] = {0};
                __u32 lookup_key[32] = {0};

                // The prefix we're looking for
                char target_prefix[] = "test_backend";
                int prefix_len = sizeof(target_prefix) - 1; // Exclude null terminator

                // Start iteration
                while (bpf_map_get_next_key(service_pod_ips, lookup_key, next_key) == 0) {
                    // Copy next_key to lookup_key for next iteration
                    memcpy(lookup_key, next_key, sizeof(lookup_key));
                    
                    // Check if key starts with our target prefix
                    if (memcmp(lookup_key, target_prefix, prefix_len) == 0) {
                        // Get the value (IP address in 16-byte format)
                        if (bpf_map_lookup_elem(service_pod_ips, lookup_key, ip_bytes) != 0) {
                            DEBUG_BPF_PRINTK("Failed to lookup IP for key\n");
                            continue;
                        }
                        
                        // Extract IPv4 address from the 16-byte format
                        // In IPv4-mapped IPv6 addresses, the IPv4 address is in the last 4 bytes
                        __u32 ip_addr = *(__u32 *)&ip_bytes[12];
                        
                        // Now use this IP as key to lookup value in hash_map
                        int value;
                        if (bpf_map_lookup_elem(hash_map, &ip_addr, &value) != 0) {
                            DEBUG_BPF_PRINTK("No value for IP in hash_map\n");
                            continue;
                        }
                        
                        // Check if this is the minimum value so far
                        if (value < min_value) {
                            min_value = value;
                            min_ip = ip_addr;
                            found = true;
                            
                            DEBUG_BPF_PRINTK("New min: IP: %u.%u.%u.%u, value: %d\n",
                                        (ip_addr & 0xFF),
                                        ((ip_addr >> 8) & 0xFF),
                                        ((ip_addr >> 16) & 0xFF),
                                        ((ip_addr >> 24) & 0xFF),
                                        value);
                        }
                    }
                }

                // Store the result in our result map if we found any matches
                if (found) {
                    __u32 idx = 0;
                    struct ip_value_pair result = {
                        .ip = min_ip,
                        .value = min_value
                    };
                    bpf_map_update_elem(&min_value_result, &idx, &result, BPF_ANY);
                    
                    DEBUG_BPF_PRINTK("Final min: IP: %u.%u.%u.%u, value: %d\n",
                                (min_ip & 0xFF),
                                ((min_ip >> 8) & 0xFF),
                                ((min_ip >> 16) & 0xFF),
                                ((min_ip >> 24) & 0xFF),
                                min_value);
                } else {
                    DEBUG_BPF_PRINTK("No matching IPs found\n");
                }

                // Clean up
                bpf_obj_put(service_pod_ips);
                bpf_obj_put(hash_map);
                /* Add DNAT info */

                addr.ip = min_ip;
                bpf_ct_set_nat_info(nct, &addr, lkup->targetPort, NF_NAT_MANIP_DST);

                /* Now add SNAT (masquerade) info */
                addr.ip = bpf_tuple.ipv4.daddr;
                bpf_ct_set_nat_info(nct, &addr, -1, NF_NAT_MANIP_SRC);

                bpf_ct_set_timeout(nct, 30000);
                bpf_ct_set_status(nct, IP_CT_NEW);

                ct = bpf_ct_insert_entry(nct);
                DEBUG_BPF_PRINTK("bpf_ct_insert_entry() returned ct 0x%x\n", ct);

                if (ct) {
                    bpf_ct_release(ct);
                }
            }
        }
        break;
    default:
        break;
    }

    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    return nodeport_lb4(ctx);
}

char __license[] SEC("license") = "GPL";