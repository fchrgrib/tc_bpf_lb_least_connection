// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "tracepoint.skel.h"  // This should match your .bpf.c filename

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
    stop = 1;
}

int main(int argc, char **argv)
{
    struct tracepoint_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    /* Load and verify BPF application */
    skel = tracepoint_bpf__open_and_load();  // Must match your skeleton name
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Attach tracepoint */
    err = tracepoint_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("Successfully attached tracepoint! Monitoring TCP connections...\n");
    printf("Run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output\n");

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    while (!stop) {
        sleep(1);
    }

cleanup:
    tracepoint_bpf__destroy(skel);
    return err;
}