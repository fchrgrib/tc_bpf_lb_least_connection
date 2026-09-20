package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
)

const (
	snapshotBegin = 2 // ValueRequest.type: start of a snapshot (clears peer table)
	kvSet         = 0 // ValueRequest.type: a normal entry
)

const (
	hashMapPinPath   = "/sys/fs/bpf/hash_map"      // local counts (read)
	remoteMapPinPath = "/sys/fs/bpf/remote_counts" // peer counts (write)
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

// ── aggregate state ─────────────────────────────────────────────────────────

type peerState struct {
	table map[uint32]int32
	seen  time.Time
}
type syncer struct {
	remote *ebpf.Map

	mu          sync.Mutex
	peers       map[string]*peerState
	written     map[uint32]int32
	lastApply   time.Time
	writeErrors uint64
}

func newSyncer(remote *ebpf.Map) *syncer {
	return &syncer{
		remote:  remote,
		peers:   map[string]*peerState{},
		written: map[uint32]int32{},
	}
}

func (s *syncer) apply(host string, req *ValueRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.peers[host]
	if p == nil {
		p = &peerState{table: map[uint32]int32{}}
		s.peers[host] = p
	}
	p.seen = time.Now()
	s.lastApply = p.seen

	switch req.GetType() {
	case snapshotBegin:
		// New snapshot: drop this publisher's old contribution, then rebuild
		// from the entries that follow.
		for ip := range p.table {
			delete(p.table, ip)
			s.flushLocked(ip)
		}
		dlogf("peer %s: snapshot epoch %d begins", host, req.GetMapid())
	case kvSet:
		ip := uint32(req.GetKey())
		p.table[ip] = req.GetValue()
		s.flushLocked(ip)
	default:
		return fmt.Errorf("unknown sync type %d", req.GetType())
	}
	return nil
}

// flushLocked recomputes the aggregate for one pod IP from every peer table and
// persists it if it changed. Caller holds s.mu.
func (s *syncer) flushLocked(ip uint32) {
	var total int32
	for _, p := range s.peers {
		total += p.table[ip]
	}

	if total <= 0 {
		if _, ok := s.written[ip]; !ok {
			return // nothing persisted, nothing to remove
		}
		if s.remote != nil {
			if err := s.remote.Delete(ip); err != nil {
				log.Printf("remote_counts delete %s: %v", u32ToIP(ip), err)
				s.writeErrors++
				return // keep `written` so we retry later
			}
		}
		delete(s.written, ip)
		return
	}

	if s.written[ip] == total {
		return
	}
	if s.remote != nil {
		if err := s.remote.Update(ip, total, ebpf.UpdateAny); err != nil {
			log.Printf("remote_counts update %s: %v", u32ToIP(ip), err)
			s.writeErrors++
			return // keep old `written` so we retry later
		}
	}
	s.written[ip] = total
}

// evictStale drops the contribution of any peer that has gone silent, so a
// dead node's counts do not linger forever.
func (s *syncer) evictStale(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for host, p := range s.peers {
		if time.Since(p.seen) <= ttl {
			continue
		}
		log.Printf("peer %s silent for %s; dropping its counts", host, ttl)
		for ip := range p.table {
			delete(p.table, ip)
			s.flushLocked(ip)
		}
		delete(s.peers, host)
	}
}

// reconcileAll re-asserts every known pod IP, repairing any write that failed
// transiently. This makes the map converge to the peer tables.
func (s *syncer) reconcileAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	ips := map[uint32]struct{}{}
	for ip := range s.written {
		ips[ip] = struct{}{}
	}
	for _, p := range s.peers {
		for ip := range p.table {
			ips[ip] = struct{}{}
		}
	}
	for ip := range ips {
		s.flushLocked(ip)
	}
}

// serveMetrics exposes sync health as plain Prometheus text (no client dep).
func (s *syncer) serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		peers := len(s.peers)
		entries := len(s.written)
		errs := s.writeErrors
		last := s.lastApply
		s.mu.Unlock()

		age := -1.0
		if !last.IsZero() {
			age = time.Since(last).Seconds()
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP lb_sync_peers Number of peers currently contributing counts\n")
		fmt.Fprintf(w, "# TYPE lb_sync_peers gauge\nlb_sync_peers %d\n", peers)
		fmt.Fprintf(w, "# HELP lb_sync_entries Pod IPs currently in remote_counts\n")
		fmt.Fprintf(w, "# TYPE lb_sync_entries gauge\nlb_sync_entries %d\n", entries)
		fmt.Fprintf(w, "# HELP lb_sync_write_errors_total Failed writes to remote_counts\n")
		fmt.Fprintf(w, "# TYPE lb_sync_write_errors_total counter\nlb_sync_write_errors_total %d\n", errs)
		fmt.Fprintf(w, "# HELP lb_sync_last_apply_age_seconds Seconds since the last peer snapshot (-1 = never)\n")
		fmt.Fprintf(w, "# TYPE lb_sync_last_apply_age_seconds gauge\nlb_sync_last_apply_age_seconds %.3f\n", age)
	})
	log.Printf("metrics: http://%s/metrics", addr)
	srv := &http.Server{Addr: addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("metrics server stopped: %v", err)
	}
}

// ── gRPC server ─────────────────────────────────────────────────────────────

type syncServer struct {
	UnimplementedSyncServiceServer
	syncer *syncer
}

func (s *syncServer) SetValue(ctx context.Context, in *ValueRequest) (*Empty, error) {
	if err := s.syncer.apply(peerHost(ctx), in); err != nil {
		return nil, err
	}
	return &Empty{}, nil
}

func peerHost(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			return host
		}
		return p.Addr.String()
	}
	return "unknown"
}

func startServer(node *syncServer, port int, creds grpc.ServerOption) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("listen :%d: %v", port, err)
	}
	s := grpc.NewServer(creds, grpc.KeepaliveParams(kasp), grpc.MaxRecvMsgSize(1<<20))
	RegisterSyncServiceServer(s, node)
	log.Printf("server listening on :%d", port)
	if err := s.Serve(l); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// ── publisher ───────────────────────────────────────────────────────────────

type publisher struct {
	local    *ebpf.Map
	port     int
	peerDNS  string
	peerIP   string
	podIP    string
	interval time.Duration
	creds    grpc.DialOption

	mu    sync.Mutex
	conns map[string]*grpc.ClientConn

	epoch int32
}

func (p *publisher) connFor(addr string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.conns[addr]; c != nil {
		return c, nil
	}
	c, err := grpc.NewClient(addr, p.creds)
	if err != nil {
		return nil, err
	}
	p.conns[addr] = c
	return c, nil
}

func (p *publisher) dropConn(addr string) {
	p.mu.Lock()
	if c := p.conns[addr]; c != nil {
		c.Close()
		delete(p.conns, addr)
	}
	p.mu.Unlock()
}

func (p *publisher) run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.round(ctx)
		}
	}
}

func (p *publisher) round(ctx context.Context) {
	local, err := readLocal(p.local)
	if err != nil {
		log.Printf("read local counts: %v", err)
		return
	}

	peers := resolvePeers(p.peerDNS, p.podIP)
	if len(peers) == 0 && p.peerIP != "" {
		peers = []string{p.peerIP}
	}
	if len(peers) == 0 {
		dlogf("no peers discovered, nothing to publish")
		return
	}

	epoch := atomic.AddInt32(&p.epoch, 1)
	for _, ip := range peers {
		if ip == p.podIP {
			continue
		}
		addr := net.JoinHostPort(ip, fmt.Sprint(p.port))
		conn, err := p.connFor(addr)
		if err != nil {
			log.Printf("connect %s: %v", addr, err)
			continue
		}
		if err := p.publish(ctx, NewSyncServiceClient(conn), addr, epoch, local); err != nil {
			log.Printf("publish to %s: %v", addr, err)
			p.dropConn(addr)
		}
	}
}

func (p *publisher) publish(ctx context.Context, client SyncServiceClient, addr string, epoch int32, local map[uint32]int32) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if _, err := client.SetValue(cctx, &ValueRequest{Type: snapshotBegin, Mapid: epoch}); err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	for ip, v := range local {
		if _, err := client.SetValue(cctx, &ValueRequest{
			Key: int32(ip), Value: v, Type: kvSet, Mapid: epoch,
		}); err != nil {
			return fmt.Errorf("entry %s: %w", u32ToIP(ip), err)
		}
	}
	dlogf("published %d entries to %s (epoch %d)", len(local), addr, epoch)
	return nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func readLocal(m *ebpf.Map) (map[uint32]int32, error) {
	out := make(map[uint32]int32)
	var key, val int
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val > 0 {
			out[uint32(key)] = int32(val)
		}
	}
	return out, iter.Err()
}

func clearMap(m *ebpf.Map) {
	var key, val int
	var keys []int
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		m.Delete(k)
	}
}

func openPinned(path string) (*ebpf.Map, error) {
	var last error
	for i := 0; i < 60; i++ {
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err == nil {
			return m, nil
		}
		last = err
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("open %s: %w", path, last)
}

func u32ToIP(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
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

func main() {
	peerIP := flag.String("ip", "", "Peer IP to sync to (legacy single-peer mode)")
	peerDNS := flag.String("peer-dns", "", "Headless service DNS to discover all peers (preferred)")
	podIP := flag.String("pod-ip", os.Getenv("POD_IP"), "This pod's own IP (excluded from peers)")
	serverPort := flag.Int("port", 50051, "gRPC listen port")
	metricsAddr := flag.String("metrics-addr", ":9102", "Prometheus metrics listen address")
	interval := flag.Duration("interval", 3*time.Second, "how often to publish a full snapshot")
	peerTTL := flag.Duration("peer-ttl", 15*time.Second, "drop a peer's counts after this much silence")
	tlsCert := flag.String("tls-cert", "", "Server/client TLS certificate path")
	tlsKey := flag.String("tls-key", "", "Server/client TLS private key path")
	tlsCA := flag.String("tls-ca", "", "CA bundle to verify peers (enables mTLS)")
	tlsName := flag.String("tls-server-name", "", "Expected cert SAN when dialing peers")
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.Parse()

	if *podIP == "" {
		log.Println("WARNING: POD_IP/-pod-ip is empty; this node may sync with itself and double-count counts. Set the downward-API POD_IP env.")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	remote, err := openPinned(remoteMapPinPath)
	if err != nil {
		log.Fatal(err)
	}
	defer remote.Close()
	local, err := openPinned(hashMapPinPath)
	if err != nil {
		log.Fatal(err)
	}
	defer local.Close()

	// Snapshots from a previous run of this pod are stale; start clean.
	clearMap(remote)
	log.Printf("using %s (local) and %s (remote), interval=%s", hashMapPinPath, remoteMapPinPath, *interval)

	s := newSyncer(remote)

	serverCreds, err := buildServerCreds(*tlsCert, *tlsKey, *tlsCA)
	if err != nil {
		log.Fatal(err)
	}
	clientCreds, err := buildClientCreds(*tlsCert, *tlsKey, *tlsCA, *tlsName)
	if err != nil {
		log.Fatal(err)
	}

	go startServer(&syncServer{syncer: s}, *serverPort, serverCreds)
	go s.serveMetrics(*metricsAddr)

	pub := &publisher{
		local:    local,
		port:     *serverPort,
		peerDNS:  *peerDNS,
		peerIP:   *peerIP,
		podIP:    *podIP,
		interval: *interval,
		creds:    clientCreds,
		conns:    map[string]*grpc.ClientConn{},
	}
	go pub.run(ctx)

	go func() {
		t := time.NewTicker(*peerTTL / 2)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.evictStale(*peerTTL)
				s.reconcileAll()
			}
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
}
