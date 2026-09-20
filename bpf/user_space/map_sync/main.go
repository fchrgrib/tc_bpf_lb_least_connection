package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type Config fentry ../../data_plane/fentry/fentry.c -cflags "-I../../../lib/vmlinux.h/include/x86"

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"
	"unsafe"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var debug bool
var dbglog = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)

func dlogf(format string, v ...any) {
	if debug {
		dbglog.Printf(format, v...)
	}
}

var kasp = keepalive.ServerParameters{
	MaxConnectionIdle: 30 * time.Second,
	Time:              5 * time.Second,
	Timeout:           1 * time.Second,
}

type Node struct {
	UnimplementedSyncServiceServer
	fentryObjs fentryObjects
}

func (n *Node) SetValue(ctx context.Context, in *ValueRequest) (*Empty, error) {
	value := in.GetValue()
	key := in.GetKey()
	_type := in.GetType()

	switch MapUpdater(_type).String() {
	case "UPDATE":
		if err := n.fentryObjs.HashMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("map update key=%d: %w", key, err)
		}
		dlogf("Client updated key %d to value %d", key, value)
	case "DELETE":
		if err := n.fentryObjs.HashMap.Delete(key); err != nil {
			return nil, fmt.Errorf("map delete key=%d: %w", key, err)
		}
		dlogf("Client deleted key %d", key)
	default:
		return nil, fmt.Errorf("unknown update type %d", _type)
	}

	return &Empty{}, nil
}

// buildServerCreds loads the server TLS keypair. When caFile is set, client
// certs are required and verified (mutual TLS). Empty cert/key => plaintext.
func buildServerCreds(certFile, keyFile, caFile string) (grpc.ServerOption, error) {
	if certFile == "" || keyFile == "" {
		log.Println("WARNING: TLS disabled (no -tls-cert/-tls-key); gRPC is plaintext")
		return grpc.EmptyServerOption{}, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA file %s has no valid certificates", caFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert // enforce mTLS
	} else {
		log.Println("WARNING: -tls-ca not set; server-auth TLS only, clients not verified")
	}
	return grpc.Creds(credentials.NewTLS(cfg)), nil
}

// buildClientCreds loads the client keypair + CA. Empty => plaintext.
func buildClientCreds(certFile, keyFile, caFile, serverName string) (grpc.DialOption, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client keypair: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file %s has no valid certificates", caFile)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName, // must be in cert SANs (service DNS name)
		MinVersion:   tls.VersionTLS12,
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), nil
}

// resolvePeers returns peer IPs from a headless service DNS name, excluding self.
func resolvePeers(dnsName, selfIP string) []string {
	if dnsName == "" {
		return nil
	}
	ips, err := net.LookupHost(dnsName)
	if err != nil {
		log.Printf("peer discovery %s failed: %v", dnsName, err)
		return nil
	}
	var peers []string
	for _, ip := range ips {
		if ip == selfIP {
			continue
		}
		peers = append(peers, ip)
	}
	sort.Strings(peers)
	return peers
}

func startServer(node *Node, port string, creds grpc.ServerOption) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(creds, grpc.KeepaliveParams(kasp),
		grpc.MaxRecvMsgSize(1<<20))
	RegisterSyncServiceServer(s, node)

	log.Printf("Server is running at %s", port)
	if err := s.Serve(l); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	peerIP := flag.String("ip", "", "Peer IP to sync to (legacy single-peer mode)")
	peerDNS := flag.String("peer-dns", "", "Headless service DNS to discover all peers (preferred)")
	podIP := flag.String("pod-ip", os.Getenv("POD_IP"), "This pod's own IP (excluded from peers)")
	serverPort := flag.Int("port", 50051, "Current host listen port")
	tlsCert := flag.String("tls-cert", "", "Server/client TLS certificate path")
	tlsKey := flag.String("tls-key", "", "Server/client TLS private key path")
	tlsCA := flag.String("tls-ca", "", "CA bundle to verify peers (enables mTLS)")
	tlsName := flag.String("tls-server-name", "", "Expected cert SAN when dialing peers")
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.Parse()

	if debug {
		log.Println("Debug mode enabled")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fentryObjs := fentryObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}
	if err := loadFentryObjects(&fentryObjs, opts); err != nil {
		log.Fatal(err)
	}
	defer fentryObjs.Close()

	fUpdate, err := link.AttachTracing(link.TracingOptions{
		Program: fentryObjs.fentryPrograms.BpfProgKernHmapupdate,
	})
	if err != nil {
		log.Fatalf("opening htab_map_update_elem fentry: %s", err)
	}
	defer fUpdate.Close()

	fDelete, err := link.AttachTracing(link.TracingOptions{
		Program: fentryObjs.fentryPrograms.BpfProgKernHmapdelete,
	})
	if err != nil {
		log.Fatalf("opening htab_map_delete_elem fentry: %s", err)
	}
	defer fDelete.Close()

	var key uint32 = 0
	config := fentryConfig{
		HostPort: uint16(*serverPort),
		HostPid:  uint64(os.Getpid()),
	}
	err = fentryObjs.fentryMaps.MapConfig.Update(&key, &config, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to update the map: %v", err)
	}

	serverCreds, err := buildServerCreds(*tlsCert, *tlsKey, *tlsCA)
	if err != nil {
		log.Fatal(err)
	}
	clientCreds, err := buildClientCreds(*tlsCert, *tlsKey, *tlsCA, *tlsName)
	if err != nil {
		log.Fatal(err)
	}

	go startServer(&Node{fentryObjs: fentryObjs}, ":"+fmt.Sprint(*serverPort), serverCreds)

	rd, err := ringbuf.NewReader(fentryObjs.MapEvents)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	eventChan := make(chan *MapData, 1000)
	batchInterval := 10 * time.Second
	var batchMap = make(map[uint32]*MapData)
	var mu = &sync.Mutex{}

	// Ringbuf reader (producer)
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("Ringbuf read error: %v", err)
				continue
			}
			if len(record.RawSample) < int(unsafe.Sizeof(MapData{})) {
				log.Printf("short ringbuf sample (%d bytes), skipping", len(record.RawSample))
				continue
			}
			event := (*MapData)(unsafe.Pointer(&record.RawSample[0]))
			eventChan <- event
		}
	}()

	applyLocal := func(e *MapData) {
		k := uint32(e.Key)
		v := uint32(e.Value)
		switch MapUpdater(e.UpdateType).String() {
		case "UPDATE":
			if err := fentryObjs.HashMap.Update(&k, &v, ebpf.UpdateAny); err != nil {
				log.Printf("Local update failed: %v", err)
			}
		case "DELETE":
			if err := fentryObjs.HashMap.Delete(&k); err != nil {
				log.Printf("Local delete failed: %v", err)
			}
		}
	}

	// Batch processor (consumer)
	go func() {
		ticker := time.NewTicker(batchInterval)
		defer ticker.Stop()

		for {
			select {
			case ev := <-eventChan:
				mu.Lock()
				batchMap[ev.Key] = ev
				mu.Unlock()

			case <-ticker.C:
				mu.Lock()
				toSend := make([]*MapData, 0, len(batchMap))
				for _, v := range batchMap {
					toSend = append(toSend, v)
				}
				batchMap = make(map[uint32]*MapData)
				mu.Unlock()

				if len(toSend) == 0 {
					continue
				}

				// Apply locally once.
				for _, e := range toSend {
					applyLocal(e)
				}

				// Discover peers: headless DNS (preferred) or legacy single -ip.
				peers := resolvePeers(*peerDNS, *podIP)
				if len(peers) == 0 && *peerIP != "" {
					peers = []string{*peerIP}
				}
				if len(peers) == 0 {
					dlogf("no peers discovered, skipping remote sync")
					continue
				}

				for _, peer := range peers {
					addr := net.JoinHostPort(peer, fmt.Sprint(*serverPort))
					conn, err := grpc.NewClient(addr, clientCreds)
					if err != nil {
						log.Printf("Failed to connect to peer %s: %v", addr, err)
						continue
					}
					client := NewSyncServiceClient(conn)
					for _, e := range toSend {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						_, err := client.SetValue(ctx, &ValueRequest{
							Key:   int32(e.Key),
							Value: int32(e.Value),
							Type:  int32(e.UpdateType),
							Mapid: int32(e.MapID),
						})
						cancel()
						if err != nil {
							log.Printf("Could not set value on peer %s: %v", addr, err)
						}
					}
					conn.Close()
				}
			}
		}
	}()

	select {} // block forever
}
