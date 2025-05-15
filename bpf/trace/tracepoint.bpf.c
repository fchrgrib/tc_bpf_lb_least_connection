//go:build ignore
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Format for bpf_printk output
#define IP_FORMAT "%u.%u.%u.%u"
#define IP_FORMAT_ARGS(ip) ((ip) & 0xff), (((ip) >> 8) & 0xff), (((ip) >> 16) & 0xff), ((ip) >> 24)
#define AF_INET 2

// TCP states
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

struct conn_info_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 pid;
    __u64 ts;
    __u8 type;
    __u8 old_state;
    __u8 new_state;
    char comm[16];
};

// BPF map to track connection counts by pod IP (source address)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);
    __type(value, u32);
} pod_connection_counts SEC(".maps");

// BPF map to share data with user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Track TCP state changes
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Debug - verify the program is loading
    bpf_printk("eBPF program loaded and running");
    
    struct conn_info_t conn_info = {};
    u16 family;
    u8 oldstate, newstate;
    u32 saddr, daddr;
    u16 sport, dport;
    
    // Extract fields with safer approach
    // Some kernels have different layouts, so use a more compatible approach
    
    // Get family - safe extraction with bounds check
    bpf_probe_read(&family, sizeof(family), &ctx->family);
    if (family != AF_INET) {
        return 0;  // Only handle IPv4
    }
    
    // Extract TCP state info
    bpf_probe_read(&oldstate, sizeof(oldstate), &ctx->oldstate);
    bpf_probe_read(&newstate, sizeof(newstate), &ctx->newstate);
    
    // Only care about established or closed connections
    if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE) {
        return 0;
    }
    
    // Extract IPs with a more portable approach
    bpf_probe_read(&saddr, sizeof(saddr), &ctx->saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &ctx->daddr);
    
    // Get ports
    bpf_probe_read(&sport, sizeof(sport), &ctx->sport);
    bpf_probe_read(&dport, sizeof(dport), &ctx->dport);
    
    // Fill conn_info
    conn_info.saddr = saddr;
    conn_info.daddr = daddr;
    conn_info.sport = bpf_ntohs(sport);  // Convert from network to host order
    conn_info.dport = bpf_ntohs(dport);
    conn_info.pid = bpf_get_current_pid_tgid() >> 32;
    conn_info.ts = bpf_ktime_get_ns();
    conn_info.old_state = oldstate;
    conn_info.new_state = newstate;
    bpf_get_current_comm(&conn_info.comm, sizeof(conn_info.comm));
    
    // Log basic info via bpf_printk for debugging
    bpf_printk("TCP conn change: %d->%d, SRC IP: " IP_FORMAT, 
               oldstate, newstate, IP_FORMAT_ARGS(saddr));
    
    // Handle new established connections - increment counter
    if (newstate == TCP_ESTABLISHED) {
        conn_info.type = 1; // established
        
        u32 *count = bpf_map_lookup_elem(&pod_connection_counts, &saddr);
        u32 new_count = 1;
        
        if (count) {
            new_count = *count + 1;
        }
        
        bpf_map_update_elem(&pod_connection_counts, &saddr, &new_count, BPF_ANY);
        bpf_printk("Connection ESTABLISHED for " IP_FORMAT ": Count %u", 
                  IP_FORMAT_ARGS(saddr), new_count);
    }
    
    // Handle connections being closed - decrement counter
    if (newstate == TCP_CLOSE) {
        conn_info.type = 2; // closed
        
        u32 *count = bpf_map_lookup_elem(&pod_connection_counts, &saddr);
        if (count && *count > 0) {
            u32 new_count = *count - 1;
            bpf_map_update_elem(&pod_connection_counts, &saddr, &new_count, BPF_ANY);
            bpf_printk("Connection CLOSED for " IP_FORMAT ": Count %u", 
                      IP_FORMAT_ARGS(saddr), new_count);
        }
    }
    
    // Output event to user space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &conn_info, sizeof(conn_info));
    
    return 0;
}