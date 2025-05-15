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

/* Define maps for connection tracking */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10240);
        __type(key, __u32);
        __type(value, __u32);
} hash_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 100);
        __type(key, char[32]);
        __type(value, __u32[4]);
} service_pod_ips SEC(".maps");

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

/* Function to check if string matches a pattern */
static __always_inline bool string_starts_with(const char *str, const char *prefix, size_t prefix_len) {
    // Simple loop-based string comparison for BPF
    for (int i = 0; i < prefix_len; i++) {
        if (str[i] != prefix[i] || str[i] == 0)
            return false;
    }
    return true;
}

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
            bpf_probe_read_str(service_name, sizeof(service_name), lkup->service_name);
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

                union nf_inet_addr addr = {};
                __u32 min_val = ~0U; // Initialize with max unsigned value
                __u32 selected_ip = 0;
                const char service_prefix[] = "test-backend";
                const size_t prefix_len = sizeof(service_prefix) - 1;

                // Iterate through service_pod_ips map
                char key_pod[32] = {0};
                char next_key_pod[32] = {0};
                bool first_iteration = true;

                // BPF loop with fixed iterations for verifier
                #pragma unroll
                for (int i = 0; i < 20; i++) {
                    int err = bpf_map_get_next_key(&service_pod_ips, 
                                                  first_iteration ? NULL : &key_pod, 
                                                  &next_key_pod);
                    if (err < 0)
                        break;
                    
                    first_iteration = false;
                    
                    if (string_starts_with(next_key_pod, service_prefix, prefix_len)) {
                        __u32 *ip_array = bpf_map_lookup_elem(&service_pod_ips, &next_key_pod);
                        
                        if (ip_array) {
                            __u32 pod_ip = ip_array[3]; // Last element is the IP
                            
                            // Get connection count
                            __u32 *count = bpf_map_lookup_elem(&hash_map, &pod_ip);
                            __u32 conn_count = count ? *count : 0;
                            
                            if (conn_count < min_val) {
                                min_val = conn_count;
                                selected_ip = pod_ip;
                            }
                        }
                    }
                    
                    // Copy next_key to key for next iteration
                    __builtin_memcpy(&key_pod, &next_key_pod, sizeof(key_pod));
                }

                // If we found a valid IP, use it
                if (selected_ip != 0) {
                    addr.ip = selected_ip;
                    
                    // Update connection count
                    __u32 new_count = min_val + 1;
                    bpf_map_update_elem(&hash_map, &selected_ip, &new_count, BPF_ANY);
                } else {
                    // Fallback: Use the original destination IP
                    addr.ip = iph->daddr;
                }

                /* Add DNAT info */
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