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
	"k8s.io/client-go/tools/clientcmd"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel tracepoint ../../bpf/trace/tracepoint.bpf.c -cflags "-I../../bpf/trace -I../../vmlinux.h/include/x86"

type ConnectionStats struct {
	PodIP       string
	ActiveConns uint32
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load eBPF program
	objs := tracepointObjects{}
	if err := loadTracepointObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach tracepoint
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	// Initialize Kubernetes client
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
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
	go serveMetrics(objs.PodConnectionCounts)

	// Main sync loop
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			log.Println("Shutting down...")
			return
		case <-ticker.C:
			if err := syncPodIPs(clientset, objs.PodConnectionCounts); err != nil {
				log.Printf("Sync failed: %v", err)
			}
			logConnectionStats(objs.PodConnectionCounts)
		}
	}
}

func syncPodIPs(clientset *kubernetes.Clientset, connMap *ebpf.Map) error {
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

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
		var count uint32
		if err := connMap.Lookup(&key, &count); err != nil {
			if err := connMap.Put(&key, &count); err != nil {
				log.Printf("Failed to init entry for %s: %v", pod.Status.PodIP, err)
			}
		}
	}

	// Cleanup stale entries
	var key uint32
	var count uint32
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

func logConnectionStats(connMap *ebpf.Map) {
	var key uint32
	var count uint32

	stats := make([]ConnectionStats, 0)
	iter := connMap.Iterate()
	for iter.Next(&key, &count) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		stats = append(stats, ConnectionStats{
			PodIP:       ip.String(),
			ActiveConns: count,
		})
	}

	log.Println("Current connection stats:")
	for _, s := range stats {
		log.Printf("  %s: %d active connections", s.PodIP, s.ActiveConns)
	}
}

func serveMetrics(connMap *ebpf.Map) {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		var key uint32
		var count uint32

		iter := connMap.Iterate()
		for iter.Next(&key, &count) {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, key)
			fmt.Fprintf(w, "pod_connections_active{ip=\"%s\"} %d\n", ip, count)
		}
	})

	log.Println("Starting metrics server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
