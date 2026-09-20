// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
/* Copyright (c) 2022 Red Hat */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Set this flag to enable/ disable debug messages */
#define DEBUG_ENABLED false

#define DEBUG_BPF_PRINTK(...) if(DEBUG_ENABLED) {bpf_printk(__VA_ARGS__);}


#define TC_ACT_OK	0
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define TEST_NODEPORT   ((unsigned short) 30080)
#define MAX_BACKENDS  256
#define MAX_SERVICES  64
#define STALE_NS      (45ULL * 1000 * 1000 * 1000)  // tracker heartbeat TTL

struct backend {
    __u32 ip;          // pod IP, network bytes as u32 (your convention)
    __u8  valid;       // 1 = usable right now
    __u8  draining;    // 1 = terminating: no NEW flows, existing keep working
    __u8  pad[2];
};

struct svc_config {
    __u32 slot_base;   // where this service's slice starts in backends[]
    __u32 n_backends;  // how many valid entries right now (<= MAX_BACKENDS)
    __u32 target_port; // port to DNAT to (pod's containerPort)
    __u32 pad;
    __u64 heartbeat;   // bumped by userspace every reconcile (staleness guard)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SERVICES);
    __type(key, __u16);
    __type(value, struct svc_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);   // tracker opens /sys/fs/bpf/svc_map
} svc_map SEC(".maps");

/**
We will store the backends on each services here, you can choose
based on slot_based based on svc_map that we choose 
**/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SERVICES * MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(pinning, LIBBPF_PIN_BY_NAME);   // tracker opens /sys/fs/bpf/backends
} backends SEC(".maps");

/* Per-service liveness, written by the datapath itself: when the heartbeat
 * changes we record the time; if it stops changing for STALE_NS the tracker is
 * considered dead and we fall back to kube-proxy. Not shared, so no pinning. */
struct svc_seen {
    __u64 heartbeat;
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SERVICES);
    __type(key, __u32);
    __type(value, struct svc_seen);
} svc_seen SEC(".maps");

/* Per-service decision counters, exported by the tracker as Prometheus
 * metrics. Pinned so userspace can read them. Plain increments are fine:
 * approximate stats are all we need and it avoids another atomic helper. */
struct svc_stats {
    __u64 assigned;        // new flows DNATed to a backend
    __u64 no_backend;      // new flows dropped through (no healthy backend)
    __u64 stale_fallback;  // new flows skipped because the heartbeat went stale
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SERVICES);
    __type(key, __u32);
    __type(value, struct svc_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);   // tracker reads /sys/fs/bpf/svc_stats
} svc_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 10240);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} hash_map SEC(".maps");

/* Counts published by map_sync for pods running on OTHER nodes. This node's own
 * counts live in hash_map; the selector sums the two. map_sync is the only
 * writer here (single-writer rule: no clobbering local increments). */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 65536);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} remote_counts SEC(".maps");

/* Balanced target ports, written by the tracker and read by the tracepoint.
 * Declared here as well so the loader always pins it, even in a base-only
 * install without the active-conn DaemonSet. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16);
  __type(value, __u8);
  __uint(max_entries, 1024);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} svc_ports SEC(".maps");

struct bpf_ct_opts {
        s32 netns_id;
        s32 error;
        u8 l4proto;
        u8 dir;
        u8 reserved[2];
};

/* Conntrack types used by the bpf_ct_* kfuncs. These live in the nf_conntrack
 * module, which the upstream (core-only) vmlinux.h does not include. Define the
 * minimal layouts we need here; they mirror the kernel definitions so kfunc
 * BTF matching succeeds. */
struct nf_conn;

enum ip_conntrack_info {
        IP_CT_ESTABLISHED = 0,
        IP_CT_RELATED = 1,
        IP_CT_NEW = 2,
};

enum nf_nat_manip_type {
        NF_NAT_MANIP_SRC = 0,
        NF_NAT_MANIP_DST = 1,
};

union nf_inet_addr {
        __u32 all[4];
        __be32 ip;
        __be32 ip6[4];
        struct in_addr in;
        struct in6_addr in6;
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

/* Total active connections for a pod = this node's view + every peer's view. */
static __always_inline __u32 count_of(__u32 ip){
    __u32 total = 0;
    int *c = bpf_map_lookup_elem(&hash_map, &ip);
    if (c && *c > 0)
        total += (__u32)*c;
    int *r = bpf_map_lookup_elem(&remote_counts, &ip);
    if (r && *r > 0)
        total += (__u32)*r;
    return total;
}

static __always_inline int backend_ok(struct backend *b){
    return b && b->valid && !b->draining;
}

static __always_inline void stat_assigned(__u32 slot)
{
    struct svc_stats *st = bpf_map_lookup_elem(&svc_stats, &slot);
    if (st)
        st->assigned++;
}

static __always_inline void stat_no_backend(__u32 slot)
{
    struct svc_stats *st = bpf_map_lookup_elem(&svc_stats, &slot);
    if (st)
        st->no_backend++;
}

static __always_inline void stat_stale(__u32 slot)
{
    struct svc_stats *st = bpf_map_lookup_elem(&svc_stats, &slot);
    if (st)
        st->stale_fallback++;
}

/* 
Pick backend using P2C logic that have O(1) complexity
will pick 2 sample of backend and compare the active connection each of the
will return the backend that have least connection than the other
you can custom this function if you can
*/ 
static __always_inline __u32 pick_backend(struct svc_config *cfg)
{
    __u32 n = cfg->n_backends;
    if (n == 0)
        return 0;

    if (n == 1) {   // only one choice
        __u32 k = cfg->slot_base;
        struct backend *b = bpf_map_lookup_elem(&backends, &k);
        return backend_ok(b) ? b->ip : 0;
    }

    // two distinct random indices in [0, n)
    __u32 i   = bpf_get_prandom_u32() % n;
    __u32 off = 1 + (bpf_get_prandom_u32() % (n - 1));  // 1..n-1  => j != i
    __u32 j   = (i + off) % n;

    __u32 ki = cfg->slot_base + i;
    __u32 kj = cfg->slot_base + j;
    struct backend *bi = bpf_map_lookup_elem(&backends, &ki);
    struct backend *bj = bpf_map_lookup_elem(&backends, &kj);

    int oki = backend_ok(bi);
    int okj = backend_ok(bj);
    if (!oki && !okj) return 0;
    if (!oki)         return bj->ip;
    if (!okj)         return bi->ip;

    __u32 ci = count_of(bi->ip);
    __u32 cj = count_of(bj->ip);
    if (ci < cj) return bi->ip;
    if (cj < ci) return bj->ip;

    // equal load: coin flip so ties don't always favor the same pod
    return (bpf_get_prandom_u32() & 1) ? bi->ip : bj->ip;
}

/* Not marking this function to be inline for now */
int nodeport_lb4(struct __sk_buff *ctx) {

        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth = data;
        u64 nh_off = sizeof(*eth);

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


                ct = bpf_skb_ct_lookup(ctx, &bpf_tuple,
                                       sizeof(bpf_tuple.ipv4),
                                       &opts_def, sizeof(opts_def));

                if (ct) {
                    DEBUG_BPF_PRINTK("CT lookup (ct found) 0x%X\n", ct)
                    bpf_ct_release(ct);
                } else {
                    /* New flow. Pick a backend FIRST, then allocate the CT entry:
                     * selecting before allocating avoids leaking an nf_conn on
                     * the early-return paths below. */

                    __u16 dport = bpf_ntohs(bpf_tuple.ipv4.dport);

                    struct svc_config *cfg = bpf_map_lookup_elem(&svc_map, &dport);
                    if (!cfg)
                        return TC_ACT_OK;   // not our port: fall back to kube-proxy

                    // Staleness: if the tracker's heartbeat stops changing, the
                    // control plane is dead -> fall back instead of routing to
                    // backends that may no longer exist.
                    __u64 now = bpf_ktime_get_ns();
                    __u32 slot = cfg->slot_base / MAX_BACKENDS;
                    struct svc_seen *seen = bpf_map_lookup_elem(&svc_seen, &slot);
                    if (seen) {
                        if (seen->heartbeat != cfg->heartbeat) {
                            seen->heartbeat = cfg->heartbeat;
                            seen->last_seen_ns = now;
                        } else if (now - seen->last_seen_ns > STALE_NS) {
                            stat_stale(slot);
                            return TC_ACT_OK;
                        }
                    }

                    __u32 backend_ip = pick_backend(cfg);
                    if (backend_ip == 0) {
                        stat_no_backend(slot);
                        return TC_ACT_OK;   // no healthy backend: fall back
                    }

                    struct nf_conn *nct = bpf_skb_ct_alloc(ctx,
                                &bpf_tuple, sizeof(bpf_tuple.ipv4),
                                &opts_def, sizeof(opts_def));
                    if (!nct) {
                        DEBUG_BPF_PRINTK("bpf_skb_ct_alloc() failed\n")
                        return TC_ACT_OK;
                    }


                    /* Add DNAT info */
                    union nf_inet_addr addr = {};

                    addr.ip = backend_ip;
                    bpf_ct_set_nat_info(nct, &addr, cfg->target_port, NF_NAT_MANIP_DST);

                    /* Add SNAT (masquerade) back to the node IP that received
                     * the packet, so replies come back through this node. */
                    addr.ip = bpf_tuple.ipv4.daddr;
                    bpf_ct_set_nat_info(nct, &addr, -1, NF_NAT_MANIP_SRC);

                    bpf_ct_set_timeout(nct, 30000);
                    bpf_ct_set_status(nct, IP_CT_NEW);

                    ct = bpf_ct_insert_entry(nct);

                    DEBUG_BPF_PRINTK("bpf_ct_insert_entry() returned ct 0x%x\n", ct)

                    if (ct) {
                        bpf_ct_release(ct);
                        stat_assigned(slot);
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