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

extern int bpf_obj_get(const char *pathname) __ksym;
extern int bpf_map_get_next_key(void *map, const void *key, void *next_key) __ksym;
extern int memcmp(const void *s1, const void *s2, __u64 n) __ksym;

// static __always_inline int nodeport_lb4(struct __sk_buff *ctx) {

/* Not marking this function to be inline for now */
int nodeport_lb4(struct __sk_buff *ctx) {

        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth = data;
        u64 nh_off = sizeof(*eth);
        struct np_backends *lkup;
        char service_name[32];
        __be32  b1;
        __be32  b2;

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
                // bool ret;

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

                // Skip all BPF-CT unless port is of the target nodeport 
/**
                if (bpf_tuple.ipv4.dport != bpf_ntohs(TEST_NODEPORT)) {
                        return TC_ACT_OK;
                }
**/

                u16 key = bpf_ntohs(bpf_tuple.ipv4.dport);

                lkup = (struct np_backends *) bpf_map_lookup_elem(&svc_map, &key);

                if (lkup) {
                    // b1 = lkup->be1;
                    // b2 = lkup->be2;
                    // initialize service_name from lkup
                    bpf_probe_read_str(service_name, sizeof(service_name),
                                       lkup->service_name);
                    DEBUG_BPF_PRINTK("lkup result: Full BE1 0x%X  BE2 0x%X \n",
                                      b1, b2)
                } else {
                    DEBUG_BPF_PRINTK("lkup result: NULL \n")
                    return TC_ACT_OK;
                }


                ct = bpf_skb_ct_lookup(ctx, &bpf_tuple,
                                       sizeof(bpf_tuple.ipv4),
                                       &opts_def, sizeof(opts_def));
                // ret = !!ct;
                if (ct) {
                    DEBUG_BPF_PRINTK("CT lookup (ct found) 0x%X\n", ct)
                    DEBUG_BPF_PRINTK("Timeout %u  status 0x%X dport 0x%X \n",  
                                ct->timeout, ct->status, bpf_tuple.ipv4.dport)
                    if (iph->protocol == IPPROTO_TCP) {
                        DEBUG_BPF_PRINTK("TCP proto state %u flags  %u/ %u  last_dir  %u  \n",
                                ct->proto.tcp.state,
                                ct->proto.tcp.seen[0].flags, ct->proto.tcp.seen[1].flags,
                                ct->proto.tcp.last_dir)
                    }
                    bpf_ct_release(ct);
                } else {
                    DEBUG_BPF_PRINTK("CT lookup (no entry) 0x%X\n", 0)
                    DEBUG_BPF_PRINTK("dport 0x%X 0x%X\n",  
                                bpf_tuple.ipv4.dport, bpf_htons(TEST_NODEPORT))
                    DEBUG_BPF_PRINTK("Got IP packet: dest: %pI4, protocol: %u", 
                                &(iph->daddr), iph->protocol)
                    /* Create a new CT entry */

                    struct nf_conn *nct = bpf_skb_ct_alloc(ctx,
                                &bpf_tuple, sizeof(bpf_tuple.ipv4),
                                &opts_def, sizeof(opts_def));

                    if (!nct) {
                        DEBUG_BPF_PRINTK("bpf_skb_ct_alloc() failed\n")
                        return TC_ACT_OK;
                    }

                    // Rudimentary load balancing for now based on received source port

                    union nf_inet_addr addr = {};

                    int map_count_fd = bpf_obj_get("/sys/fs/bpf/hash_map");     
                    if (map_count_fd < 0) {
                        DEBUG_BPF_PRINTK("bpf_obj_get() failed\n")
                        return TC_ACT_OK;
                    }

                    int map_pods_fd = bpf_obj_get("/sys/fs/bpf/service_pod_ips");
                    if (map_pods_fd < 0) {
                        DEBUG_BPF_PRINTK("bpf_obj_get() failed\n")
                        return TC_ACT_OK;
                    }

                    char key_pod[32] = {0};
                    char next_key_pod[32] = {0};
                    __u32 min_val = ~0U; // Initialize with max unsigned value
                    __u32 selected_ip = 0;
                    const char service_name[12] = "test-backend";

                    // Find pod with minimum connection count
                    while (bpf_map_get_next_key(&map_pods_fd, key_pod, next_key_pod) == 0) {
                        if (strncmp(next_key_pod, service_name, 12) == 0) {
                            __u32 *value_pod = bpf_map_lookup_elem(&map_pods_fd, next_key_pod);
                            
                            if (value_pod) {
                                __u32 pod_ip = value_pod[3]; // Last 4 bytes contain IP
                                
                                // Get connection count
                                __u32 *count = bpf_map_lookup_elem(&map_count_fd, &pod_ip);
                                if (count && *count < min_val) {
                                    min_val = *count;
                                    selected_ip = pod_ip;
                                }
                            }
                        }
                        __builtin_memcpy(key_pod, next_key_pod, sizeof(key_pod));
                    }

                    addr.ip = selected_ip;

 
                    // addr.ip = b1;

                    // if (bpf_htons(bpf_tuple.ipv4.sport) % 2) {
                    //     addr.ip = b2;
                    // }

                    /* Add DNAT info */
                    bpf_ct_set_nat_info(nct, &addr, lkup->targetPort, NF_NAT_MANIP_DST);

                    /* Now add SNAT (masquerade) info */
                    /* For now using the node IP, check this TODO */
                    /* addr.ip = 0x0101F00a;     Kind-Net bridge IP 10.240.1.1 */

                    addr.ip = bpf_tuple.ipv4.daddr;

                    bpf_ct_set_nat_info(nct, &addr, -1, NF_NAT_MANIP_SRC);

                    bpf_ct_set_timeout(nct, 30000);
                    bpf_ct_set_status(nct, IP_CT_NEW);

                    ct = bpf_ct_insert_entry(nct);

                    DEBUG_BPF_PRINTK("bpf_ct_insert_entry() returned ct 0x%x\n", ct)

                    if (ct) {
                        bpf_ct_release(ct);
                    }
                }
        }
        default:
                break;
        }
out:

    return TC_ACT_OK;

}


SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    int ret = TC_ACT_OK;

    ret = nodeport_lb4(ctx);
	return ret;
}

char __license[] SEC("license") = "GPL";