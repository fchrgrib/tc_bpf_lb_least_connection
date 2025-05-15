package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel tracepoint ../../bpf/trace/tracepoint.bpf.c -cflags "-I../../bpf/trace -I../../vmlinux.h/include/x86"

// NodeData represents the connection data for a node
type NodeData struct {
	Timestamp time.Time         `json:"timestamp"`
	Counts    map[string]uint32 `json:"counts"`
}

// GlobalConnectionStore provides a global view of connection counts
type GlobalConnectionStore struct {
	mu         sync.RWMutex
	nodeData   map[string]NodeData // nodeName -> NodeData
	podDetails map[string]string   // podIP -> namespace/name
	k8sClient  *kubernetes.Clientset
	configMap  string
	namespace  string
}

// NewGlobalConnectionStore creates a new connection store
func NewGlobalConnectionStore(client *kubernetes.Clientset, namespace, configMap string) *GlobalConnectionStore {
	return &GlobalConnectionStore{
		nodeData:   make(map[string]NodeData),
		podDetails: make(map[string]string),
		k8sClient:  client,
		configMap:  configMap,
		namespace:  namespace,
	}
}

// UpdateNodeData updates the connection data for a node
func (g *GlobalConnectionStore) UpdateNodeData(nodeName string, counts map[string]uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nodeData[nodeName] = NodeData{
		Timestamp: time.Now(),
		Counts:    counts,
	}
}

// GetConnectionCountForPod gets the total connection count for a pod across all nodes
func (g *GlobalConnectionStore) GetConnectionCountForPod(podIP string) uint32 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var total uint32
	for _, nodeData := range g.nodeData {
		if count, exists := nodeData.Counts[podIP]; exists {
			total += count
		}
	}

	return total
}

// GetAllConnectionCounts gets all pod connection counts
func (g *GlobalConnectionStore) GetAllConnectionCounts() map[string]uint32 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	results := make(map[string]uint32)

	// Combine counts from all nodes
	for _, nodeData := range g.nodeData {
		for podIP, count := range nodeData.Counts {
			results[podIP] += count
		}
	}

	return results
}

// SyncToConfigMap syncs the global state to a Kubernetes ConfigMap
func (g *GlobalConnectionStore) SyncToConfigMap() error {
	g.mu.RLock()
	nodeDataCopy := make(map[string]NodeData)
	for k, v := range g.nodeData {
		countsCopy := make(map[string]uint32)
		for ip, count := range v.Counts {
			countsCopy[ip] = count
		}
		nodeDataCopy[k] = NodeData{
			Timestamp: v.Timestamp,
			Counts:    countsCopy,
		}
	}
	g.mu.RUnlock()

	// Convert to JSON for ConfigMap storage
	data, err := json.Marshal(nodeDataCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal connection data: %v", err)
	}

	// Calculated aggregate counts
	aggCounts := make(map[string]uint32)
	for _, nodeData := range nodeDataCopy {
		for podIP, count := range nodeData.Counts {
			aggCounts[podIP] += count
		}
	}

	aggData, err := json.Marshal(aggCounts)
	if err != nil {
		return fmt.Errorf("failed to marshal aggregate counts: %v", err)
	}

	// Update ConfigMap
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := g.k8sClient.CoreV1().ConfigMaps(g.namespace).Get(
			context.Background(), g.configMap, metav1.GetOptions{})

		if err != nil {
			// Create if doesn't exist
			if err := g.createConfigMap(); err != nil {
				return err
			}
			cm, err = g.k8sClient.CoreV1().ConfigMaps(g.namespace).Get(
				context.Background(), g.configMap, metav1.GetOptions{})
			if err != nil {
				return err
			}
		}

		// Update data
		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}
		cm.Data["nodeData"] = string(data)
		cm.Data["aggregateCounts"] = string(aggData)

		_, err = g.k8sClient.CoreV1().ConfigMaps(g.namespace).Update(
			context.Background(), cm, metav1.UpdateOptions{})
		return err
	})
}

// createConfigMap creates the ConfigMap if it doesn't exist
func (g *GlobalConnectionStore) createConfigMap() error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: g.configMap,
		},
		Data: map[string]string{
			"nodeData":        "{}",
			"aggregateCounts": "{}",
		},
	}

	_, err := g.k8sClient.CoreV1().ConfigMaps(g.namespace).Create(
		context.Background(), cm, metav1.CreateOptions{})
	return err
}

// UpdatePodDetails refreshes the pod details map
func (g *GlobalConnectionStore) UpdatePodDetails(podDetails map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.podDetails = podDetails
}

// GetPodDetails gets the pod namespace/name for an IP
func (g *GlobalConnectionStore) GetPodDetails(podIP string) string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if details, exists := g.podDetails[podIP]; exists {
		return details
	}
	return "unknown"
}

// SyncFromConfigMap syncs node data from config map
func (g *GlobalConnectionStore) SyncFromConfigMap() error {
	cm, err := g.k8sClient.CoreV1().ConfigMaps(g.namespace).Get(
		context.Background(), g.configMap, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get ConfigMap: %v", err)
	}

	if cm.Data == nil || cm.Data["nodeData"] == "" {
		return nil // No data yet
	}

	var nodeData map[string]NodeData
	if err := json.Unmarshal([]byte(cm.Data["nodeData"]), &nodeData); err != nil {
		return fmt.Errorf("failed to unmarshal node data: %v", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodeData = nodeData

	return nil
}

func main() {
	// Set up logging
	log.Println("Starting conntracker with global synchronization...")

	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Failed to remove memlock limit: %v", err)
	}

	// Load eBPF program
	log.Println("Loading eBPF program...")
	objs := tracepointObjects{}
	if err := loadTracepointObjects(&objs, nil); err != nil {
		log.Printf("Failed to load eBPF objects: %v", err)
		log.Println("Creating dummy map for testing...")
		dummyMapSpec := &ebpf.MapSpec{
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 1024,
		}
		dummyMap, err := ebpf.NewMap(dummyMapSpec)
		if err != nil {
			log.Fatalf("Failed to create dummy map: %v", err)
		}
		objs.PodConnectionCounts = dummyMap
		goto skipTracepoint
	}
	defer objs.Close()

	// Attach tracepoint
	log.Println("Attaching tracepoint...")
	{
		tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
		if err != nil {
			log.Printf("Failed to attach tracepoint: %v", err)
		} else {
			log.Println("Successfully attached tracepoint")
			defer tp.Close()
		}
	}

skipTracepoint:
	// Get node name
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatal("Failed to get hostname and NODE_NAME not set")
		}
		nodeName = hostname
		log.Printf("NODE_NAME not set, using hostname: %s", nodeName)
	}

	// Initialize Kubernetes client
	log.Println("Initializing Kubernetes client...")
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create clientset: %v", err)
	}

	// Initialize global connection store
	globalStore := NewGlobalConnectionStore(clientset, "default", "connection-counts")

	// Set up signal handling
	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Received termination signal")
		close(stopCh)
	}()

	// Start pod IP sync
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if err := syncPodIPs(clientset, objs.PodConnectionCounts, globalStore); err != nil {
					log.Printf("Failed to sync pod IPs: %v", err)
				}
			}
		}
	}()

	// Start connection count sync
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				counts := collectConnectionData(objs.PodConnectionCounts)
				globalStore.UpdateNodeData(nodeName, counts)

				if err := globalStore.SyncToConfigMap(); err != nil {
					log.Printf("Failed to sync to ConfigMap: %v", err)
				}

				// Periodically pull other nodes' data
				if err := globalStore.SyncFromConfigMap(); err != nil {
					log.Printf("Failed to sync from ConfigMap: %v", err)
				}

				logGlobalConnectionStats(globalStore)
			}
		}
	}()

	// Start metrics server
	log.Println("Starting metrics server on :8080...")
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		serveMetrics(w, globalStore)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start metrics server: %v", err)
	}
}

// syncPodIPs syncs pod IPs with the BPF map and updates the global store
func syncPodIPs(clientset *kubernetes.Clientset, connMap *ebpf.Map, globalStore *GlobalConnectionStore) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	log.Printf("Found %d pods across all namespaces", len(pods.Items))

	currentIPs := make(map[uint32]struct{})
	podDetails := make(map[string]string) // podIP -> namespace/name

	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" || pod.Status.Phase != corev1.PodRunning {
			continue
		}

		ip := net.ParseIP(pod.Status.PodIP).To4()
		if ip == nil {
			continue
		}

		// Use little-endian for consistency with kernel side
		key := binary.LittleEndian.Uint32(ip)
		currentIPs[key] = struct{}{}
		podDetails[pod.Status.PodIP] = fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		// Initialize if not exists with 0 connections
		var count uint32
		if err := connMap.Lookup(&key, &count); err != nil {
			count = 0 // Start with 0 connections
			if err := connMap.Put(&key, &count); err != nil {
				log.Printf("Failed to init entry for %s (%s): %v", pod.Status.PodIP, podDetails[pod.Status.PodIP], err)
			}
		}
	}

	// Update pod details in global store
	globalStore.UpdatePodDetails(podDetails)

	// Cleanup stale entries
	var key uint32
	var count uint32
	iter := connMap.Iterate()
	for iter.Next(&key, &count) {
		if _, exists := currentIPs[key]; !exists {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, key)
			log.Printf("Removing stale entry for %s", ip.String())

			if err := connMap.Delete(&key); err != nil {
				log.Printf("Failed to delete stale entry %d: %v", key, err)
			}
		}
	}

	return nil
}

// collectConnectionData collects connection data from BPF map
func collectConnectionData(connMap *ebpf.Map) map[string]uint32 {
	result := make(map[string]uint32)
	var key uint32
	var count uint32

	iter := connMap.Iterate()
	for iter.Next(&key, &count) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key)
		result[ip.String()] = count
	}

	return result
}

// logGlobalConnectionStats logs global connection stats
func logGlobalConnectionStats(store *GlobalConnectionStore) {
	counts := store.GetAllConnectionCounts()

	log.Println("Global connection stats:")
	if len(counts) == 0 {
		log.Println("  No connection stats available")
	} else {
		for ip, count := range counts {
			details := store.GetPodDetails(ip)
			log.Printf("  %s (%s): %d active connections", ip, details, count)
		}
	}
}

// serveMetrics serves metrics in Prometheus format
func serveMetrics(w http.ResponseWriter, store *GlobalConnectionStore) {
	fmt.Fprintln(w, "# HELP pod_connections_active Number of active connections per pod")
	fmt.Fprintln(w, "# TYPE pod_connections_active gauge")

	counts := store.GetAllConnectionCounts()

	if len(counts) == 0 {
		fmt.Fprintln(w, "# No connection data available")
		return
	}

	for ip, count := range counts {
		details := store.GetPodDetails(ip)
		parts := splitPodDetails(details)

		// Only include namespace/name labels if available
		if parts[0] != "unknown" {
			fmt.Fprintf(w,
				"pod_connections_active{ip=\"%s\",namespace=\"%s\",pod=\"%s\"} %d\n",
				ip, parts[0], parts[1], count)
		} else {
			fmt.Fprintf(w, "pod_connections_active{ip=\"%s\"} %d\n", ip, count)
		}
	}
}

// splitPodDetails splits namespace/name into [namespace, name]
func splitPodDetails(details string) []string {
	if details == "unknown" {
		return []string{"unknown", "unknown"}
	}

	parts := []string{"unknown", "unknown"}
	if len(details) > 0 {
		parts = []string{"unknown", "unknown"}
		// Split by / but handle case where there is no /
		idx := -1
		for i, c := range details {
			if c == '/' {
				idx = i
				break
			}
		}

		if idx > 0 {
			parts[0] = details[:idx]
			parts[1] = details[idx+1:]
		} else {
			parts[1] = details
		}
	}

	return parts
}
