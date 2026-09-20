// active-conn: counts ACTIVE TCP connections per pod IP.
//
// This is the "Active Connection Program" from the design: it attaches to
// tracepoint/sock/inet_sock_set_state and maintains
//
//	+1 on TCP_ESTABLISHED, -1 on TCP_CLOSE
//
// keyed by the POD's own address (the server-side socket's local address),
// which is exactly the key the least-connection selector looks up.
//
// The map is intentionally NOT pinned: fentry hooks htab_map_update_elem
// globally, so map_sync picks up these updates and syncs them into the pinned
// hash_map regardless. Pinning is only useful for manual inspection.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang tracepoint ../../data_plane/trace/tracepoint.bpf.c -- -I../../../lib/vmlinux.h/include/x86 -I../../../lib/libbpf/include/uapi

import (
	"context"
	"errors"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	pinPath := flag.String("pin-path", "",
		"optional: pin maps under this dir (e.g. /sys/fs/bpf) for `bpftool map dump` debugging")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock: %v", err)
	}

	objs := tracepointObjects{}
	opts := &ebpf.CollectionOptions{}
	if *pinPath != "" {
		opts.Maps.PinPath = *pinPath
		log.Printf("pinning maps under %s", *pinPath)
	}

	if err := loadTracepointObjects(&objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier error: %+v", ve)
		}
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	// Tracepoints are system-wide: one attach sees every socket in every
	// network namespace on this node, so no hostNetwork/hostPID is needed.
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint sock/inet_sock_set_state: %v", err)
	}
	defer tp.Close()

	log.Printf("attached tracepoint sock/inet_sock_set_state (prog fd=%d); "+
		"counting active connections per pod IP", objs.TraceInetSockSetState.FD())

	// Graceful shutdown: SIGTERM (pod delete / node drain) detaches cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Println("received signal, detaching tracepoint and exiting")
}
