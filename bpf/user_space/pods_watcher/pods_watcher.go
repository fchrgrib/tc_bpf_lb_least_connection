package main

// The tracker owns the DATA the datapath reads. It never makes routing
// decisions. For every opted-in Service it writes a slice of pinned maps
// declared in bpf/data_plane/tc/tc.bpf.c:
//
//	svc_map   : u16 nodePort -> struct svc_config
//	backends  : u32 index    -> struct backend       (slot = slotBase + i)
//	svc_ports : u16 targetPort -> mark               (read by the tracepoint)
//
// The Go structs below MUST match the C definitions byte for byte, otherwise
// the datapath reads garbage.

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	maxBackends = 256
	maxServices = 64

	heartbeatEvery = 15 * time.Second
	// Keep a removed target port in svc_ports for this long so connections that
	// are still open can still be decremented when they close.
	portGrace = 2 * time.Minute

	svcMapPinPath      = "/sys/fs/bpf/svc_map"
	backendsMapPinPath = "/sys/fs/bpf/backends"
	svcPortsPinPath    = "/sys/fs/bpf/svc_ports"
	svcStatsPinPath    = "/sys/fs/bpf/svc_stats"
	hashMapPinPath     = "/sys/fs/bpf/hash_map"
	remoteMapPinPath   = "/sys/fs/bpf/remote_counts"
)

// svcStats mirrors `struct svc_stats` in tc.bpf.c (24 bytes).
type svcStats struct {
	Assigned      uint64
	NoBackend     uint64
	StaleFallback uint64
}

// backend mirrors `struct backend` in tc.bpf.c (8 bytes).
type backend struct {
	IP       uint32
	Valid    uint8
	Draining uint8
	_        [2]uint8
}

// svcConfig mirrors `struct svc_config` in tc.bpf.c (24 bytes).
type svcConfig struct {
	SlotBase   uint32
	NBackends  uint32
	TargetPort uint32
	_          uint32
	Heartbeat  uint64
}

type maps struct {
	svc      *ebpf.Map
	backends *ebpf.Map
	ports    *ebpf.Map // svc_ports: target ports the tracepoint should count
	stats    *ebpf.Map // svc_stats: per-service datapath counters
	counts   *ebpf.Map // local counts (reset on IP reuse)
	remote   *ebpf.Map // peer counts (reset on IP reuse)
}

type serviceKey struct {
	namespace string
	name      string
}

func (k serviceKey) String() string { return k.namespace + "/" + k.name }

type serviceState struct {
	key        serviceKey
	nodePort   uint16
	targetPort uint32
	slot       uint32
	ctx        context.Context // cancelled when the service is removed
	cancel     context.CancelFunc

	mu          sync.Mutex // guards the fields below
	ips         []uint32
	ipUID       map[uint32]string // pod IP -> endpoint UID (detect IP reuse)
	highWater   int               // how many slots are currently valid
	initialized bool              // first publish => clear the whole tail once
}

type tracker struct {
	client *kubernetes.Clientset
	maps   *maps

	mu           sync.Mutex
	slotUsed     map[uint32]serviceKey
	services     map[serviceKey]*serviceState
	activePorts  map[uint16]bool      // ports currently present in svc_ports
	retiredPorts map[uint16]time.Time // ports scheduled for removal
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// openPinnedMap waits for a map created/pinned by the tc-loader (tc.bpf.c).
// The tracker container may start before the loader, so retry for a while.
func openPinnedMap(path string, stop <-chan struct{}) (*ebpf.Map, error) {
	var lastErr error
	for i := 0; i < 60; i++ {
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err == nil {
			return m, nil
		}
		lastErr = err
		select {
		case <-stop:
			return nil, fmt.Errorf("interrupted while waiting for %s", path)
		case <-time.After(time.Second):
		}
	}
	return nil, fmt.Errorf("open %s: %w", path, lastErr)
}

func u32ToIP(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

// ── stale-state cleanup ─────────────────────────────────────────────────────

// Pinned maps survive pod restarts. Without clearing them, a Service that was
// deleted while the tracker was down would keep its old svc_map entry and
// backend slots, and the datapath would keep routing to it.
func (m *maps) resetStaleMaps() {
	clearU16Keyed(m.svc, func() any { return &svcConfig{} })
	clearU16Keyed(m.ports, func() any { return new(uint8) })

	if m.backends != nil {
		var key uint32
		var val backend
		var used []uint32
		iter := m.backends.Iterate()
		for iter.Next(&key, &val) {
			if val.Valid != 0 || val.IP != 0 {
				used = append(used, key)
			}
		}
		for _, k := range used {
			m.backends.Update(k, backend{}, ebpf.UpdateAny)
		}
	}

	if m.stats != nil {
		for i := uint32(0); i < maxServices; i++ {
			m.stats.Update(i, svcStats{}, ebpf.UpdateAny)
		}
	}
}

// clearU16Keyed deletes every entry from a hash map keyed by u16. newVal must
// return a pointer to a value buffer of the map's exact value size.
func clearU16Keyed(mp *ebpf.Map, newVal func() any) {
	if mp == nil || mp.KeySize() != 2 {
		return
	}
	var key uint16
	var keys []uint16
	iter := mp.Iterate()
	for iter.Next(&key, newVal()) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		mp.Delete(k)
	}
}

func equalIPs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// capBackends truncates a backend list to the per-service slot capacity.
func capBackends(ips []uint32) []uint32 {
	if len(ips) <= maxBackends {
		return ips
	}
	return ips[:maxBackends]
}

// ── slot allocation ─────────────────────────────────────────────────────────

// allocSlotLocked returns the lowest free slot. Caller holds t.mu.
func (t *tracker) allocSlotLocked(key serviceKey) (uint32, bool) {
	for s := uint32(0); s < maxServices; s++ {
		if _, used := t.slotUsed[s]; !used {
			t.slotUsed[s] = key
			return s, true
		}
	}
	return 0, false
}

// refreshPortsLocked publishes the set of balanced target ports to svc_ports
// (read by the tracepoint). Removed ports are kept for a grace period so that
// connections still open on them can be decremented when they close; expirePorts
// removes them afterwards. Caller holds t.mu.
func (t *tracker) refreshPortsLocked() {
	desired := map[uint16]bool{}
	for _, st := range t.services {
		if st.targetPort > 0 && st.targetPort <= 65535 {
			desired[uint16(st.targetPort)] = true
		}
	}
	if t.maps.ports == nil {
		t.activePorts = desired
		return
	}
	for p := range desired {
		delete(t.retiredPorts, p) // in use again: cancel any pending removal
		if !t.activePorts[p] {
			if err := t.maps.ports.Update(p, uint8(1), ebpf.UpdateAny); err != nil {
				log.Printf("svc_ports add %d: %v", p, err)
				continue
			}
			t.activePorts[p] = true
		}
	}
	for p := range t.activePorts {
		if !desired[p] {
			if _, ok := t.retiredPorts[p]; !ok {
				t.retiredPorts[p] = time.Now()
			}
		}
	}
}

// expirePorts removes retired target ports after the grace period. Called from
// the heartbeat loop, so it must take t.mu itself.
func (t *tracker) expirePorts() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.maps.ports == nil {
		return
	}
	now := time.Now()
	for p, at := range t.retiredPorts {
		if now.Sub(at) < portGrace {
			continue
		}
		if err := t.maps.ports.Delete(p); err != nil {
			log.Printf("svc_ports del %d: %v", p, err)
			continue
		}
		delete(t.retiredPorts, p)
		delete(t.activePorts, p)
	}
}

// ── publishing to the datapath ──────────────────────────────────────────────

// writeConfigLocked publishes svc_map (slot base, backend count, target port
// and a fresh heartbeat). Caller holds st.mu.
func (t *tracker) writeConfigLocked(st *serviceState, n uint32) {
	cfg := svcConfig{
		SlotBase:   st.slot * maxBackends,
		NBackends:  n,
		TargetPort: st.targetPort,
		Heartbeat:  uint64(time.Now().UnixNano()),
	}
	if err := t.maps.svc.Update(st.nodePort, cfg, ebpf.UpdateAny); err != nil {
		log.Printf("svc_map[%d]: %v", st.nodePort, err)
	}
}

// writeServiceLocked publishes the backend list safely: fill the new slots,
// publish the new count, then clear the tail. This ordering means the datapath
// never sees a count that points at slots which are still stale. Caller holds
// st.mu.
func (t *tracker) writeServiceLocked(st *serviceState, ips []uint32) {
	slotBase := st.slot * maxBackends
	n := len(ips)

	for i := 0; i < n; i++ {
		if err := t.maps.backends.Update(slotBase+uint32(i),
			backend{IP: ips[i], Valid: 1}, ebpf.UpdateAny); err != nil {
			log.Printf("backends[%d]: %v", slotBase+uint32(i), err)
			return
		}
	}

	t.writeConfigLocked(st, uint32(n))

	// Invalidate above n. On the first publish we don't know what a previous
	// run left pinned, so clear the whole tail once.
	to := maxBackends
	if st.initialized && st.highWater > n {
		to = st.highWater
	}
	for i := n; i < to; i++ {
		if err := t.maps.backends.Update(slotBase+uint32(i),
			backend{}, ebpf.UpdateAny); err != nil {
			log.Printf("backends clear[%d]: %v", slotBase+uint32(i), err)
			return
		}
	}

	st.highWater = n
	st.initialized = true
}

// reconcileEndpoints recomputes a service's backend list from its
// EndpointSlices and republishes it when it changed. It also resets the
// connection count of any IP that was reused by a different pod.
func (t *tracker) reconcileEndpoints(st *serviceState, slices []discoveryv1.EndpointSlice) {
	type ep struct {
		ip  uint32
		uid string
	}
	var eps []ep
	for i := range slices {
		for j := range slices[i].Endpoints {
			e := &slices[i].Endpoints[j]
			if e.Conditions.Ready != nil && !*e.Conditions.Ready {
				continue // not ready -> no new flows
			}
			if e.Conditions.Terminating != nil && *e.Conditions.Terminating {
				continue // draining -> no new flows, existing conns keep working
			}
			uid := ""
			if e.TargetRef != nil {
				uid = string(e.TargetRef.UID)
			}
			for _, addr := range e.Addresses {
				v4 := net.ParseIP(addr).To4()
				if v4 == nil {
					continue // IPv4 only for now
				}
				eps = append(eps, ep{ip: binary.LittleEndian.Uint32(v4), uid: uid})
			}
		}
	}
	sort.Slice(eps, func(a, b int) bool { return eps[a].ip < eps[b].ip })

	var ips []uint32
	for i, e := range eps {
		if i > 0 && e.ip == eps[i-1].ip {
			continue // dedupe (a pod can appear in several slices)
		}
		ips = append(ips, e.ip)
	}
	if len(ips) > maxBackends {
		log.Printf("service %s: %d ready backends exceeds maxBackends=%d; truncating",
			st.key, len(ips), maxBackends)
		ips = capBackends(ips)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// The service may have been removed while we were listing.
	if st.ctx.Err() != nil {
		return
	}

	// Reset stale counts when an IP now belongs to a different pod. We keep the
	// last UID per IP even after it leaves the endpoint list, so a pod that
	// disappears and an IP that later reappears still triggers a reset.
	for _, e := range eps {
		if old, seen := st.ipUID[e.ip]; seen && e.uid != "" && old != e.uid {
			t.resetCounts(e.ip)
		}
		if e.uid != "" {
			st.ipUID[e.ip] = e.uid
		}
	}

	if equalIPs(st.ips, ips) {
		// Unchanged: just refresh the heartbeat so the datapath does not treat
		// this service as stale.
		t.writeConfigLocked(st, uint32(len(ips)))
		return
	}

	st.ips = ips
	log.Printf("service %s: nodePort %d -> %d backend(s)", st.key, st.nodePort, len(ips))
	t.writeServiceLocked(st, ips)
}

// resetCounts clears a pod IP's local and remote counts (used when the IP is
// reused by a new pod, so the new pod does not inherit the old load).
func (t *tracker) resetCounts(ip uint32) {
	if t.maps.counts != nil {
		if err := t.maps.counts.Delete(ip); err == nil {
			log.Printf("reset stale local count for reused IP %s", u32ToIP(ip))
		}
	}
	if t.maps.remote != nil {
		t.maps.remote.Delete(ip)
	}
}

// ── Kubernetes watches ──────────────────────────────────────────────────────

func nodePortOf(svc *corev1.Service) (uint16, uint32, bool) {
	var nodePort uint16
	var targetPort uint32
	count := 0
	for _, p := range svc.Spec.Ports {
		if p.NodePort == 0 {
			continue
		}
		count++
		if count > 1 {
			continue
		}
		nodePort = uint16(p.NodePort)
		targetPort = uint32(p.TargetPort.IntVal)
		if targetPort == 0 {
			targetPort = uint32(p.Port) // named targetPort: best effort
		}
	}
	if count > 1 {
		log.Printf("service %s/%s has %d NodePorts; only the first is balanced",
			svc.Namespace, svc.Name, count)
	}
	return nodePort, targetPort, count > 0
}

func (t *tracker) upsertService(ctx context.Context, svc *corev1.Service, nameFilter string) {
	if svc.Spec.Type != corev1.ServiceTypeNodePort {
		return
	}
	if nameFilter != "" && svc.Name != nameFilter {
		return
	}
	nodePort, targetPort, ok := nodePortOf(svc)
	if !ok {
		return
	}

	key := serviceKey{namespace: svc.Namespace, name: svc.Name}

	t.mu.Lock()
	defer t.mu.Unlock()

	if st, exists := t.services[key]; exists {
		if st.nodePort != nodePort {
			// NodePort changed (Service recreate): drop the old svc_map key.
			t.maps.svc.Delete(st.nodePort)
			st.nodePort = nodePort
		}
		if st.targetPort != targetPort {
			st.targetPort = targetPort
			t.refreshPortsLocked()
		}
		return
	}

	slot, ok := t.allocSlotLocked(key)
	if !ok {
		log.Printf("service %s: no free slot (max %d services)", key, maxServices)
		return
	}

	sctx, cancel := context.WithCancel(ctx)
	st := &serviceState{
		key:        key,
		nodePort:   nodePort,
		targetPort: targetPort,
		slot:       slot,
		ctx:        sctx,
		cancel:     cancel,
		ipUID:      map[uint32]string{},
	}
	t.services[key] = st
	t.refreshPortsLocked()
	log.Printf("service %s: registered nodePort %d -> targetPort %d (slot %d)",
		key, nodePort, targetPort, slot)

	go t.watchEndpoints(st)
}

func (t *tracker) removeService(key serviceKey) {
	t.mu.Lock()
	st, ok := t.services[key]
	if ok {
		delete(t.services, key)
		delete(t.slotUsed, st.slot)
		t.refreshPortsLocked()
	}
	t.mu.Unlock()
	if !ok {
		return
	}

	// Stop the watcher before touching the maps it writes.
	st.cancel()

	st.mu.Lock()
	defer st.mu.Unlock()

	if err := t.maps.svc.Delete(st.nodePort); err != nil {
		log.Printf("svc_map delete[%d]: %v", st.nodePort, err)
	}
	slotBase := st.slot * maxBackends
	for i := 0; i < maxBackends; i++ {
		t.maps.backends.Update(slotBase+uint32(i), backend{}, ebpf.UpdateAny)
	}
	if t.maps.stats != nil {
		t.maps.stats.Update(st.slot, svcStats{}, ebpf.UpdateAny)
	}
	log.Printf("service %s: removed", key)
}

// watchEndpoints keeps one service's backend list in sync. It is best-effort:
// the periodic heartbeat also relists, so a dropped watch cannot leave the
// datapath stale for long. It exits when the service is removed (st.ctx).
func (t *tracker) watchEndpoints(st *serviceState) {
	labelSel := "kubernetes.io/service-name=" + st.key.name
	for {
		if st.ctx.Err() != nil {
			return
		}
		t.relistEndpoints(st)

		w, err := t.client.DiscoveryV1().EndpointSlices(st.key.namespace).Watch(
			st.ctx, metav1.ListOptions{LabelSelector: labelSel})
		if err != nil {
			if t.sleep(st.ctx, 2*time.Second) {
				return
			}
			continue
		}
		for ev := range w.ResultChan() {
			if st.ctx.Err() != nil {
				break
			}
			if ev.Type == watch.Error {
				continue
			}
			t.relistEndpoints(st)
		}
		w.Stop()
		if t.sleep(st.ctx, 2*time.Second) {
			return
		}
	}
}

func (t *tracker) relistEndpoints(st *serviceState) {
	sl, err := t.client.DiscoveryV1().EndpointSlices(st.key.namespace).List(st.ctx,
		metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + st.key.name})
	if err != nil {
		if st.ctx.Err() == nil {
			log.Printf("list endpoints %s: %v", st.key, err)
		}
		return
	}
	t.reconcileEndpoints(st, sl.Items)
}

func (t *tracker) sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(d):
		return false
	}
}

// watchServices discovers Services (by label selector, or just LB_SERVICE_NAME)
// and registers/unregisters them.
func (t *tracker) watchServices(ctx context.Context, namespace, selector, nameFilter string) {
	for {
		list, err := t.client.CoreV1().Services(namespace).List(ctx,
			metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			log.Printf("list services: %v", err)
			if t.sleep(ctx, 2*time.Second) {
				return
			}
			continue
		}
		for i := range list.Items {
			t.upsertService(ctx, &list.Items[i], nameFilter)
		}

		w, err := t.client.CoreV1().Services(namespace).Watch(ctx, metav1.ListOptions{
			LabelSelector:   selector,
			ResourceVersion: list.ResourceVersion,
		})
		if err != nil {
			log.Printf("watch services: %v", err)
			if t.sleep(ctx, 2*time.Second) {
				return
			}
			continue
		}

		for ev := range w.ResultChan() {
			svc, ok := ev.Object.(*corev1.Service)
			if !ok {
				continue
			}
			switch ev.Type {
			case watch.Added, watch.Modified:
				t.upsertService(ctx, svc, nameFilter)
			case watch.Deleted:
				t.removeService(serviceKey{namespace: svc.Namespace, name: svc.Name})
			}
		}
		w.Stop()
		if t.sleep(ctx, 2*time.Second) {
			return
		}
	}
}

// heartbeatLoop relists every service regularly: this refreshes the heartbeat
// (so the datapath does not consider the tracker dead) and repairs any missed
// watch event.
func (t *tracker) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.expirePorts()
			t.mu.Lock()
			states := make([]*serviceState, 0, len(t.services))
			for _, st := range t.services {
				states = append(states, st)
			}
			t.mu.Unlock()
			for _, st := range states {
				t.relistEndpoints(st)
			}
		}
	}
}

// ── metrics ─────────────────────────────────────────────────────────────────

// nodeCount returns the connection count this node knows about a backend:
// its own local counter plus everything map_sync learned from peers.
func (t *tracker) nodeCount(ip uint32) uint32 {
	var total uint32
	var v int32
	if t.maps.counts != nil {
		if err := t.maps.counts.Lookup(ip, &v); err == nil && v > 0 {
			total += uint32(v)
		}
	}
	if t.maps.remote != nil {
		if err := t.maps.remote.Lookup(ip, &v); err == nil && v > 0 {
			total += uint32(v)
		}
	}
	return total
}

func (t *tracker) serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", t.metricsHandler)
	log.Printf("metrics: http://%s/metrics", addr)
	srv := &http.Server{Addr: addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("metrics server stopped: %v", err)
	}
}

func (t *tracker) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	t.mu.Lock()
	states := make([]*serviceState, 0, len(t.services))
	for _, st := range t.services {
		states = append(states, st)
	}
	ports := len(t.activePorts) + len(t.retiredPorts)
	t.mu.Unlock()

	fmt.Fprintf(w, "# HELP lb_services Number of Services being balanced\n")
	fmt.Fprintf(w, "# TYPE lb_services gauge\nlb_services %d\n", len(states))
	fmt.Fprintf(w, "# HELP lb_balanced_ports Target ports currently counted by the tracepoint\n")
	fmt.Fprintf(w, "# TYPE lb_balanced_ports gauge\nlb_balanced_ports %d\n", ports)

	fmt.Fprintf(w, "# HELP lb_backends Ready backends per Service\n")
	fmt.Fprintf(w, "# TYPE lb_backends gauge\n")
	for _, st := range states {
		st.mu.Lock()
		n := len(st.ips)
		st.mu.Unlock()
		fmt.Fprintf(w, "lb_backends{service=%q,node_port=%q} %d\n",
			st.key.String(), fmt.Sprint(st.nodePort), n)
	}

	fmt.Fprintf(w, "# HELP lb_backend_connections Active connections per backend (local + remote)\n")
	fmt.Fprintf(w, "# TYPE lb_backend_connections gauge\n")
	for _, st := range states {
		st.mu.Lock()
		ips := append([]uint32(nil), st.ips...)
		st.mu.Unlock()
		for _, ip := range ips {
			fmt.Fprintf(w, "lb_backend_connections{service=%q,backend_ip=%q} %d\n",
				st.key.String(), u32ToIP(ip), t.nodeCount(ip))
		}
	}

	if t.maps.stats == nil {
		return
	}
	fmt.Fprintf(w, "# HELP lb_flows_assigned_total New flows DNATed to a backend\n")
	fmt.Fprintf(w, "# TYPE lb_flows_assigned_total counter\n")
	fmt.Fprintf(w, "# HELP lb_no_backend_total New flows with no healthy backend (fell back)\n")
	fmt.Fprintf(w, "# TYPE lb_no_backend_total counter\n")
	fmt.Fprintf(w, "# HELP lb_stale_fallback_total New flows skipped while the control plane was stale\n")
	fmt.Fprintf(w, "# TYPE lb_stale_fallback_total counter\n")
	for _, st := range states {
		var s svcStats
		if err := t.maps.stats.Lookup(st.slot, &s); err != nil {
			continue
		}
		svc := st.key.String()
		fmt.Fprintf(w, "lb_flows_assigned_total{service=%q} %d\n", svc, s.Assigned)
		fmt.Fprintf(w, "lb_no_backend_total{service=%q} %d\n", svc, s.NoBackend)
		fmt.Fprintf(w, "lb_stale_fallback_total{service=%q} %d\n", svc, s.StaleFallback)
	}
}

func main() {
	namespace := getenv("LB_NAMESPACE", "default")
	selector := getenv("LB_SERVICE_SELECTOR", "")
	nameFilter := os.Getenv("LB_SERVICE_NAME")
	// Config modes, in priority order:
	//   1. LB_SERVICE_SELECTOR: balance every matching Service
	//   2. LB_SERVICE_NAME: balance exactly that Service (back-compat)
	//   3. neither: balance every NodePort Service in the namespace
	if selector != "" {
		log.Printf("tracking Services in %s matching %q", namespace, selector)
	} else if nameFilter != "" {
		log.Printf("tracking Service %s/%s", namespace, nameFilter)
	} else {
		log.Printf("tracking all NodePort Services in %s", namespace)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Kubernetes client: in-cluster first, fallback to KUBECONFIG for local dev.
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := getenv("KUBECONFIG", getenv("HOME", "")+"/.kube/config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("build kubeconfig (in-cluster: %v): %v", err, err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("create clientset: %v", err)
	}

	stop := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stop)
	}()

	m := &maps{}
	if m.svc, err = openPinnedMap(svcMapPinPath, stop); err != nil {
		log.Fatalf("%v", err)
	}
	defer m.svc.Close()
	if m.backends, err = openPinnedMap(backendsMapPinPath, stop); err != nil {
		log.Fatalf("%v", err)
	}
	defer m.backends.Close()
	if m.ports, err = openPinnedMap(svcPortsPinPath, stop); err != nil {
		log.Fatalf("%v", err)
	}
	defer m.ports.Close()
	if m.stats, err = openPinnedMap(svcStatsPinPath, stop); err != nil {
		log.Fatalf("%v", err)
	}
	defer m.stats.Close()
	if m.counts, err = ebpf.LoadPinnedMap(hashMapPinPath, nil); err != nil {
		log.Printf("note: %s not open (%v); stale counts on IP reuse won't be reset", hashMapPinPath, err)
		m.counts = nil
	} else {
		defer m.counts.Close()
	}
	if m.remote, err = ebpf.LoadPinnedMap(remoteMapPinPath, nil); err != nil {
		log.Printf("note: %s not open (%v); remote counts on IP reuse won't be reset", remoteMapPinPath, err)
		m.remote = nil
	} else {
		defer m.remote.Close()
	}

	m.resetStaleMaps()
	log.Println("cleared stale map state from a previous run")

	t := &tracker{
		client:       clientset,
		maps:         m,
		slotUsed:     map[uint32]serviceKey{},
		services:     map[serviceKey]*serviceState{},
		activePorts:  map[uint16]bool{},
		retiredPorts: map[uint16]time.Time{},
	}

	go t.heartbeatLoop(ctx)
	go t.serveMetrics(getenv("METRICS_ADDR", ":9101"))
	t.watchServices(ctx, namespace, selector, nameFilter)

	log.Println("shutting down")
}
