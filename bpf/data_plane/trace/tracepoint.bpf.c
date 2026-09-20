// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2

// TCP states
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

// Active TCP connections per pod IPv4 address.
//
// The key is the pod's own address (the server-side socket's local address),
// stored the same way the datapath and selector use it: the 4 network-order
// address bytes copied verbatim into a u32. On a little-endian host that means
// the value equals binary.LittleEndian.Uint32(addr_bytes). Keeping this in the
// same representation as `hash_map` / `selected` is what makes the
// tracepoint -> fentry -> hash_map -> selector chain line up.
//
// The name must fit in BPF_OBJ_NAME_LEN-1 (15) chars: the kernel truncates
// longer names, and map_sync matches on the exact kernel-visible name.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);
    __type(value, u32);
} pod_conn_counts SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    u32 saddr;

    if (ctx->family != AF_INET)
        return 0;

    if (ctx->newstate != TCP_ESTABLISHED && ctx->newstate != TCP_CLOSE)
        return 0;

    // Don't let map_sync's own gRPC traffic (50051) pollute the counts.
    // Check both directions: sport on the receiving node, dport on the sender.
    if (ctx->sport == bpf_htons(50051) || ctx->dport == bpf_htons(50051))
        return 0;

    // Read the local address bytes as-is so the u32 value matches the
    // datapath's network-order convention (see map comment above).
    bpf_probe_read_kernel(&saddr, sizeof(saddr), ctx->saddr);

    if (ctx->newstate == TCP_ESTABLISHED) {
        u32 *existing = bpf_map_lookup_elem(&pod_conn_counts, &saddr);
        u32 count = existing ? *existing + 1 : 1;
        bpf_map_update_elem(&pod_conn_counts, &saddr, &count, BPF_ANY);
    } else {
        u32 *existing = bpf_map_lookup_elem(&pod_conn_counts, &saddr);
        if (existing && *existing > 0) {
            u32 count = *existing - 1;
            bpf_map_update_elem(&pod_conn_counts, &saddr, &count, BPF_ANY);
        }
    }

    return 0;
}
