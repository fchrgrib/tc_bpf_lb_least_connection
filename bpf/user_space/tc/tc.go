package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang tc ../../data_plane/tc/tc.bpf.c -- -I../../../lib/vmlinux.h/include/x86 -I../../../lib/libbpf/include/uapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
)

func main() {
	if len(os.Args) < 6 {
		log.Fatalf("Usage: %s <interface> <nodeport> <backend1_ip> <backend2_ip> <target_port>", os.Args[0])
	}

	ifaceName := os.Args[1]
	nodeport := parseUint16(os.Args[2])
	// Backends are optional static fallbacks; "auto"/empty/0.0.0.0 rely purely
	// on the tracker-populated service_pod_ips map.
	be1IP := parseOptionalIP(os.Args[3])
	be2IP := parseOptionalIP(os.Args[4])
	targetPort := parseUint16(os.Args[5])

	// Remove resource limits
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock: %v", err)
	}

	// Load BPF program
	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error: %+v", ve)
		}
		log.Fatalf("Loading BPF objects: %v", err)
	}
	defer objs.Close()

	// Update svc_map
	backends := tcNpBackends{
		Be1:        be1IP,
		Be2:        be2IP,
		TargetPort: targetPort,
	}
	if err := objs.SvcMap.Update(nodeport, backends, ebpf.UpdateAny); err != nil {
		log.Fatalf("Updating svc_map: %v", err)
	}
	if be1IP != 0 || be2IP != 0 {
		log.Printf("Updated svc_map for nodeport %d -> fallback backends %s, %s",
			nodeport, formatIP(be1IP), formatIP(be2IP))
	} else {
		log.Printf("Updated svc_map for nodeport %d -> dynamic backends only", nodeport)
	}

	// Open TC handle
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Fatalf("Opening TC netlink: %v", err)
	}
	defer tcnl.Close()

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %v", ifaceName, err)
	}

	// Create clsact qdisc
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

	// Attach BPF filter
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

	// Open pinned maps
	svcPodIPs, err := ebpf.LoadPinnedMap("/sys/fs/bpf/service_pod_ips", nil)
	if err != nil {
		log.Printf("Warning: service_pod_ips map not found: %v", err)
	} else {
		defer svcPodIPs.Close()
	}

	hashMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/hash_map", nil)
	if err != nil {
		log.Printf("Warning: hash_map not found: %v", err)
	} else {
		defer hashMap.Close()
	}

	// Signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Received signal, shutting down...")
		cancel()
	}()

	// Main loop: find least-connection backend
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Cleaning up TC filter...")
			if err := tcnl.Filter().Delete(&filter); err != nil {
				log.Printf("Failed to delete filter: %v", err)
			}
			log.Println("Shutdown complete")
			return
		case <-ticker.C:
			if svcPodIPs == nil {
				continue
			}

			selectedIP := findLeastConnection(svcPodIPs, hashMap)
			if selectedIP == 0 {
				continue
			}

			var key uint32 = 0
			if err := objs.Selected.Update(key, selectedIP, ebpf.UpdateAny); err != nil {
				log.Printf("Failed to update selected: %v", err)
			} else {
				log.Printf("Selected backend: %s", formatIP(selectedIP))
			}
		}
	}
}

func findLeastConnection(svcPodIPs, hashMap *ebpf.Map) uint32 {
	var minConn uint32 = ^uint32(0)
	var selectedIP uint32

	var key [32]byte
	var value [16]byte
	iter := svcPodIPs.Iterate()

	for iter.Next(&key, &value) {
		// The tracker stores the address via ip.To16(); the last 4 bytes are
		// the IPv4 address in network order. The datapath (and the tracepoint
		// counter map key) represent an address by copying those 4 bytes
		// verbatim into a u32, i.e. little-endian on x86. Matching that here is
		// what makes the hash_map lookup and the `selected` DNAT value line up.
		ip := binary.LittleEndian.Uint32(value[12:16])
		if ip == 0 {
			continue
		}

		var connCount uint32
		if hashMap != nil {
			if err := hashMap.Lookup(ip, &connCount); err != nil {
				connCount = 0
			}
		}

		if connCount == 0 {
			return ip
		}

		if connCount < minConn {
			minConn = connCount
			selectedIP = ip
		}
	}

	return selectedIP
}

func parseUint16(s string) uint16 {
	var val uint16
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		log.Fatalf("Invalid number %s: %v", s, err)
	}
	return val
}

func parseIP(s string) uint32 {
	ip := net.ParseIP(s)
	if ip == nil {
		log.Fatalf("Invalid IP: %s", s)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		log.Fatalf("Not an IPv4 address: %s", s)
	}
	// Little-endian: mirror the datapath's "raw network bytes as a u32"
	// convention (see findLeastConnection).
	return binary.LittleEndian.Uint32(ip4)
}

// parseOptionalIP returns 0 (meaning "no static fallback") for auto/empty/0.0.0.0,
// and fatals only on a genuinely malformed address.
func parseOptionalIP(s string) uint32 {
	switch s {
	case "", "auto", "0.0.0.0":
		return 0
	}
	return parseIP(s)
}

func formatIP(ip uint32) string {
	bytes := make([]byte, 4)
	// Little-endian to undo the datapath's raw-bytes-as-u32 representation.
	binary.LittleEndian.PutUint32(bytes, ip)
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).String()
}
