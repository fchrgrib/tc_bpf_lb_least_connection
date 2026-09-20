package main

// tc-loader: attaches the TC eBPF datapath to the host interface.
//
// It no longer makes any routing decision and no longer writes any map.
// Loading the object creates and pins the maps the userspace tracker writes:
//   /sys/fs/bpf/svc_map   (nodePort -> svc_config)
//   /sys/fs/bpf/backends  (slot    -> backend)
//   /sys/fs/bpf/hash_map  (pod IP  -> active connections)
// The datapath picks the backend per new flow (see pick_backend in tc.bpf.c).

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang tc ../../data_plane/tc/tc.bpf.c -- -I../../../lib/vmlinux.h/include/x86 -I../../../lib/libbpf/include/uapi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
)

func main() {
	ifaceName, err := resolveIface()
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("Using interface %s", ifaceName)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock: %v", err)
	}

	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error: %+v", ve)
		}
		log.Fatalf("Loading BPF objects: %v", err)
	}
	defer objs.Close()

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Fatalf("Opening TC netlink: %v", err)
	}
	defer tcnl.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %v", ifaceName, err)
	}

	// clsact qdisc (idempotent: may already exist from a previous run).
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  syscall.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(0xFFFF, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Add(&qdisc); err != nil && !errors.Is(err, syscall.EEXIST) {
		log.Printf("Adding clsact qdisc (continuing): %v", err)
	}

	// Attach the datapath program.
	progFD := uint32(objs.TcIngress.FD())
	filterName := ifaceName
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  syscall.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(0xFFFF, 0xFFF2),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:   &progFD,
				Name: &filterName,
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		log.Fatalf("Adding TC filter: %v", err)
	}
	log.Printf("Attached TC program to %s", ifaceName)

	// Nothing to do: the tracker feeds svc_map/backends while the datapath
	// selects per flow. Just wait for SIGTERM and detach cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Println("Detaching TC filter...")
	if err := tcnl.Filter().Delete(&filter); err != nil {
		log.Printf("Failed to delete filter: %v", err)
	}
	log.Println("Shutdown complete")
}

// resolveIface picks the datapath interface: explicit CLI arg, then LB_IFACE,
// then the default-route interface, then any non-loopback interface. This used
// to live in entrypoint.sh; keeping it here removes the shell script entirely.
func resolveIface() (string, error) {
	if len(os.Args) > 1 && os.Args[1] != "" {
		return os.Args[1], nil
	}
	if v := os.Getenv("LB_IFACE"); v != "" {
		return v, nil
	}
	if name, err := defaultRouteIface(); err == nil {
		return name, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("cannot list interfaces: %w", err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			return i.Name, nil
		}
	}
	return "", fmt.Errorf("no usable interface found; set LB_IFACE")
}

// defaultRouteIface parses /proc/net/route for the default route (dest 0.0.0.0).
// The container runs with hostNetwork=true, so this is the host's routing table.
func defaultRouteIface() (string, error) {
	return defaultRouteIfaceFrom("/proc/net/route")
}

func defaultRouteIfaceFrom(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags ... e.g. "eth0 00000000 0101A8C0 ..."
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no default route in %s", path)
}
