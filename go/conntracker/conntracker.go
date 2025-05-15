package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel tracepoint ../../bpf/trace/tracepoint.bpf.c -cflags "-I../../bpf/trace -I../../vmlinux.h/include/x86"

type ConnectionStats struct {
	PodIP       string
	ActiveConns uint32
}

func main() {
	// Enable debug logging
	log.Println("Starting conntracker...")

	// Print kernel version for debugging
	kernelVersion, err := os.ReadFile("/proc/version")
	if err == nil {
		log.Printf("Kernel version: %s", string(kernelVersion))
	} else {
		log.Printf("Failed to read kernel version: %v", err)
	}

	// Verify BPF filesystem is mounted
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		log.Printf("Warning: BPF filesystem not mounted at /sys/fs/bpf")
	} else {
		log.Println("BPF filesystem is available at /sys/fs/bpf")
	}

	// Check for kernel headers
	if _, err := os.Stat("/usr/src/linux-headers"); os.IsNotExist(err) {
		log.Printf("Warning: Kernel headers directory not found at /usr/src/linux-headers")
	} else {
		log.Println("Kernel headers directory found at /usr/src/linux-headers")
	}

	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Failed to remove memlock limit: %v", err)
		// Continue anyway - this might work in privileged containers
	}

	// Load eBPF program with more verbose error handling
	log.Println("Loading eBPF program...")
	objs := tracepointObjects{}
	if err := loadTracepointObjects(&objs, nil); err != nil {
		log.Printf("Failed to load eBPF objects: %v", err)
		log.Println("This is likely due to kernel compatibility issues or missing headers.")
		log.Println("Continuing with stub functionality for debugging...")
		// Create a dummy map for testing other functionality
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

	// Attach tracepoint with more verbose error handling
	log.Println("Attaching tracepoint...")
	{
		tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
		if err != nil {
			log.Printf("Failed to attach tracepoint: %v", err)
			log.Println("Continuing with stub functionality for debugging...")
			// Continue without tracepoint for testing
		} else {
			log.Println("Successfully attached tracepoint")
			defer tp.Close()
		}
	}

skipTracepoint:
	// Initialize Kubernetes client using in-cluster config
	log.Println("Initializing Kubernetes client...")
	var config *rest.Config
	var clientset *kubernetes.Clientset

	// First try in-cluster config
	config, err = rest.InClusterConfig()
	if err != nil {
		log.Printf("Failed to get in-cluster config: %v", err)
		log.Println("Falling back to kubeconfig from env...")

		// If USE_INCLUSTER_CONFIG is not set to true, we can try kubeconfig
		if os.Getenv("USE_INCLUSTER_CONFIG") != "true" {
			kubeconfigPath := os.Getenv("KUBECONFIG")
			if kubeconfigPath == "" {
				log.Println("KUBECONFIG env var is empty or not set")
			}
			log.Fatalf("Could not configure Kubernetes client: %v", err)
		} else {
			log.Fatalf("In-cluster config required but failed: %v", err)
		}
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create clientset: %v", err)
	}

	// Test Kubernetes API access
	log.Println("Testing Kubernetes API access...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		log.Printf("Kubernetes API test failed: %v", err)
		log.Println("This indicates permission issues with the ServiceAccount")
	} else {
		log.Println("Successfully connected to Kubernetes API")
	}

	// Set up signal handling
	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Received termination signal")
		close(stopCh)
	}()

	// Start metrics server
	log.Println("Starting metrics server on :8080...")
	go serveMetrics(objs.PodConnectionCounts)

	// Main sync loop
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("Entering main loop...")
	for {
		select {
		case <-stopCh:
			log.Println("Shutting down...")
			return
		case <-ticker.C:
			if err := syncPodIPs(clientset, objs.PodConnectionCounts); err != nil {
				log.Printf("Sync failed: %v", err)
			} else {
				log.Println("Successfully synced pod IPs")
			}
			logConnectionStats(objs.PodConnectionCounts)
		}
	}
}

func syncPodIPs(clientset *kubernetes.Clientset, connMap *ebpf.Map) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	log.Printf("Found %d pods across all namespaces", len(pods.Items))

	currentIPs := make(map[uint32]struct{})
	podDetails := make(map[uint32]string) // For better logging

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
		podDetails[key] = fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		// Initialize if not exists with 0 connections
		var count uint32
		if err := connMap.Lookup(&key, &count); err != nil {
			count = 0 // Start with 0 connections
			if err := connMap.Put(&key, &count); err != nil {
				log.Printf("Failed to init entry for %s (%s): %v", pod.Status.PodIP, podDetails[key], err)
			} else {
				log.Printf("Initialized connection tracking for %s (%s)", pod.Status.PodIP, podDetails[key])
			}
		}
	}

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

func logConnectionStats(connMap *ebpf.Map) {
	var key uint32
	var count uint32

	stats := make([]ConnectionStats, 0)
	iter := connMap.Iterate()
	for iter.Next(&key, &count) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key)
		stats = append(stats, ConnectionStats{
			PodIP:       ip.String(),
			ActiveConns: count,
		})
	}

	log.Println("Current connection stats:")
	if len(stats) == 0 {
		log.Println("  No connection stats available")
	} else {
		for _, s := range stats {
			log.Printf("  %s: %d active connections", s.PodIP, s.ActiveConns)
		}
	}
}

func serveMetrics(connMap *ebpf.Map) {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Metrics request from %s", r.RemoteAddr)

		fmt.Fprintln(w, "# HELP pod_connections_active Number of active connections per pod")
		fmt.Fprintln(w, "# TYPE pod_connections_active gauge")

		var key uint32
		var count uint32

		iter := connMap.Iterate()
		hasEntries := false
		for iter.Next(&key, &count) {
			hasEntries = true
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, key)
			fmt.Fprintf(w, "pod_connections_active{ip=\"%s\"} %d\n", ip, count)
		}

		if !hasEntries {
			fmt.Fprintln(w, "# No connection data available")
		}
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	log.Println("Starting metrics server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start metrics server: %v", err)
	}
}
