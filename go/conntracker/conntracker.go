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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel connTracker ./bpf/conn_tracker.c -- -I./headers

type ConnStats struct {
	PodIP     string
	ConnCount uint64
}

func main() {
	// Remove resource limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load eBPF program
	objs := connTrackerObjects{}
	if err := loadConnTrackerObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach eBPF program to kernel
	kp, err := link.Kprobe("tcp_connect", objs.CountConnection, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	// Initialize Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create clientset: %v", err)
	}

	// Set up signal handling
	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stopCh)
	}()

	// Start metrics server
	go serveMetrics(objs.ActiveConns)

	// Main sync loop
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			log.Println("Shutting down...")
			return
		case <-ticker.C:
			if err := syncPodConnMap(clientset, objs.ActiveConns); err != nil {
				log.Printf("Sync failed: %v", err)
			}
			logConnectionCounts(objs.ActiveConns)
		}
	}
}

func syncPodConnMap(clientset *kubernetes.Clientset, connMap *ebpf.Map) error {
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	// Create set of current pod IPs
	currentIPs := make(map[uint32]struct{})
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" || pod.Status.Phase != corev1.PodRunning {
			continue
		}

		ip := net.ParseIP(pod.Status.PodIP).To4()
		if ip == nil {
			continue
		}

		key := binary.BigEndian.Uint32(ip)
		currentIPs[key] = struct{}{}

		// Initialize if not exists
		var count uint64
		if err := connMap.Lookup(&key, &count); err != nil {
			if err := connMap.Put(&key, &count); err != nil {
				log.Printf("Failed to init entry for %s: %v", pod.Status.PodIP, err)
			}
		}
	}

	// Cleanup stale entries
	var key uint32
	var count uint64
	iter := connMap.Iterate()
	for iter.Next(&key, &count) {
		if _, exists := currentIPs[key]; !exists {
			if err := connMap.Delete(&key); err != nil {
				log.Printf("Failed to delete stale entry %d: %v", key, err)
			}
		}
	}

	return nil
}

func logConnectionCounts(connMap *ebpf.Map) {
	var key uint32
	var count uint64

	stats := make([]ConnStats, 0)
	iter := connMap.Iterate()
	for iter.Next(&key, &count) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		stats = append(stats, ConnStats{
			PodIP:     ip.String(),
			ConnCount: count,
		})
	}

	log.Println("Current connection counts:")
	for _, s := range stats {
		log.Printf("  %s: %d connections", s.PodIP, s.ConnCount)
	}
}

func serveMetrics(connMap *ebpf.Map) {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		var key uint32
		var count uint64

		iter := connMap.Iterate()
		for iter.Next(&key, &count) {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, key)
			fmt.Fprintf(w, "pod_connections_total{ip=\"%s\"} %d\n", ip, count)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}