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

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 10240);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} hash_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16);
  __type(value, __u8);
  __uint(max_entries, 1024);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} svc_ports SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    u8 newstate = ctx->newstate;

    if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE)
        return 0;
    if (ctx->family != AF_INET)
        return 0;

    // Only server-side sockets of a backend: local port == a balanced targetPort.
    u16 sport = bpf_ntohs(ctx->sport);
    if (!bpf_map_lookup_elem(&svc_ports, &sport))
        return 0;

    u32 saddr;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), ctx->saddr);

    if (newstate == TCP_ESTABLISHED) {
        int *c = bpf_map_lookup_elem(&hash_map, &saddr);
        if (c)
            __sync_fetch_and_add(c, 1);
        else {
            int one = 1;
            bpf_map_update_elem(&hash_map, &saddr, &one, BPF_ANY);
        }
    } else { // TCP_CLOSE
        int *c = bpf_map_lookup_elem(&hash_map, &saddr);
        if (c && *c > 0)
            __sync_fetch_and_add(c, -1);
    }

    return 0;
}
