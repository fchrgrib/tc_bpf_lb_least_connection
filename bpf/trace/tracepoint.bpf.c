//go:build ignore
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tracepoint.h"  // This should match your .bpf.c filename

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Format for bpf_printk output
#define IP_FORMAT "%u.%u.%u.%u"
#define IP_FORMAT_ARGS(ip) ((ip) & 0xff), (((ip) >> 8) & 0xff), (((ip) >> 16) & 0xff), ((ip) >> 24)
#define AF_INET 2

// TCP states
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

// struct conn_info_t {
//     __u32 saddr;
//     __u32 daddr;
//     __u16 sport;
//     __u16 dport;
//     __u32 pid;
//     __u64 ts;
//     __u8 type;
//     __u8 old_state;
//     __u8 new_state;
//     char comm[16];
// };

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
    struct conn_info_t conn_info = {};
    u16 family;
    u8 oldstate, newstate;
    u32 saddr, daddr;
    u16 sport, dport;
    
    // Read important fields with safe accessors
    bpf_probe_read_kernel(&family, sizeof(family), &ctx->family);
    bpf_probe_read_kernel(&oldstate, sizeof(oldstate), &ctx->oldstate);
    bpf_probe_read_kernel(&newstate, sizeof(newstate), &ctx->newstate);
    bpf_probe_read_kernel(&sport, sizeof(sport), &ctx->sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), &ctx->dport);
    
    // Filter for IPv4 connections
    if (family != AF_INET)
        return 0;
    
    // Get process info
    conn_info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&conn_info.comm, sizeof(conn_info.comm));
    conn_info.ts = bpf_ktime_get_ns();
    conn_info.old_state = oldstate;
    conn_info.new_state = newstate;
    
    // Read source and destination addresses safely
    // For IPv4 addresses in the tracepoint
    u8 saddr_bytes[4];
    u8 daddr_bytes[4];
    bpf_probe_read_kernel(&saddr_bytes, sizeof(saddr_bytes), ctx->saddr);
    bpf_probe_read_kernel(&daddr_bytes, sizeof(daddr_bytes), ctx->daddr);
    
    // Convert bytes to host byte order integers
    saddr = saddr_bytes[0] | (saddr_bytes[1] << 8) | (saddr_bytes[2] << 16) | (saddr_bytes[3] << 24);
    daddr = daddr_bytes[0] | (daddr_bytes[1] << 8) | (daddr_bytes[2] << 16) | (daddr_bytes[3] << 24);
    
    conn_info.saddr = saddr;
    conn_info.daddr = daddr;
    conn_info.sport = sport;
    conn_info.dport = dport;
    
    // Handle new established connections
    if (conn_info.daddr == 16777343 || conn_info.dport == 50051) {
            return 0;
    }
    if (newstate == TCP_ESTABLISHED) {
        // Set the connection type
        conn_info.type = 1;
        
        // Increment connection count
        u32 count = 1;
        u32 *existing = bpf_map_lookup_elem(&pod_connection_counts, &conn_info.saddr);
        if (existing) {
            count = *existing + 1;
        }
        bpf_map_update_elem(&pod_connection_counts, &conn_info.saddr, &count, BPF_ANY);
        
        // Debug output
        bpf_printk("TCP Connected: PID: %d, Comm: %s", conn_info.pid, conn_info.comm);
        bpf_printk("SRC: " IP_FORMAT ":%d", IP_FORMAT_ARGS(conn_info.saddr), conn_info.sport);
        bpf_printk("DST: " IP_FORMAT ":%d", IP_FORMAT_ARGS(conn_info.daddr), conn_info.dport);
        bpf_printk("Connection add count for " IP_FORMAT ": %u", IP_FORMAT_ARGS(conn_info.saddr), count);
    }
    
    // Handle connections being closed
    if (newstate == TCP_CLOSE) {
        // Set the connection type
        conn_info.type = 2;
        
        // Decrement connection count
        u32 *existing = bpf_map_lookup_elem(&pod_connection_counts, &conn_info.saddr);
        if (existing && *existing > 0) {
            u32 count = *existing - 1;
            bpf_map_update_elem(&pod_connection_counts, &conn_info.saddr, &count, BPF_ANY);
            
            // Debug output
            bpf_printk("TCP Closed: PID: %d, Comm: %s", conn_info.pid, conn_info.comm);
            bpf_printk("SRC: " IP_FORMAT ":%d", IP_FORMAT_ARGS(conn_info.saddr), conn_info.sport);
            bpf_printk("DST: " IP_FORMAT ":%d", IP_FORMAT_ARGS(conn_info.daddr), conn_info.dport);
            bpf_printk("Connection subs count for " IP_FORMAT ": %u", IP_FORMAT_ARGS(conn_info.saddr), count);
        }
    }
    
    // Send event to user space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &conn_info, sizeof(conn_info));
    
    return 0;
}