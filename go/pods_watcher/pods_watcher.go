package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	serviceName    = "test-service"
	deploymentName = "test-backend"
	namespace      = "default"
	mapKey         = "test_backend_ips" // Key for our eBPF map
)

// eBPF map configuration
var ebpfMapSpec = &ebpf.MapSpec{
	Type:       ebpf.Hash,
	KeySize:    32,   // Fixed size key
	ValueSize:  16,   // IPv6 address size (works for IPv4 too)
	MaxEntries: 100,  // Max pods we expect
	Name:       "service_pod_ips",
}

func main() {
	// Set up signal handling
	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stopCh)
	}()

	// Initialize eBPF map
	podIPMap, err := ebpf.NewMap(ebpfMapSpec)
	if err != nil {
		log.Fatalf("Failed to create eBPF map: %v", err)
	}
	defer podIPMap.Close()

	// Initialize Kubernetes client
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		log.Fatalf("Failed to build kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create clientset: %v", err)
	}

	// Get service to find selector
	svc, err := clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("Failed to get service: %v", err)
	}

	// Create selector from service
	selector := fields.Set{"app": svc.Spec.Selector["app"]}.AsSelector()

	// Initial sync
	if err := syncPodIPs(clientset, podIPMap, selector); err != nil {
		log.Fatalf("Initial sync failed: %v", err)
	}

	// Set up watcher with resync
	watcher, err := clientset.CoreV1().Pods(namespace).Watch(context.TODO(), metav1.ListOptions{
		LabelSelector:   selector.String(),
		ResourceVersion: "0",
		Watch:           true,
		FieldSelector:   fields.Set{"status.phase": string(corev1.PodRunning)}.String(),
	})
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Stop()

	// Resync every 15 minutes to catch any missed events
	resyncTicker := time.NewTicker(15 * time.Minute)
	defer resyncTicker.Stop()

	// Event processing loop
	for {
		select {
		case <-stopCh:
			log.Println("Shutting down gracefully...")
			return

		case <-resyncTicker.C:
			log.Println("Performing periodic resync...")
			if err := syncPodIPs(clientset, podIPMap, selector); err != nil {
				log.Printf("Resync failed: %v", err)
			}

		case event, ok := <-watcher.ResultChan():
			if !ok {
				log.Println("Watcher channel closed, restarting...")
				time.Sleep(2 * time.Second)
				watcher, err = clientset.CoreV1().Pods(namespace).Watch(context.TODO(), metav1.ListOptions{
					LabelSelector: selector.String(),
					Watch:         true,
				})
				if err != nil {
					log.Printf("Failed to restart watcher: %v", err)
					continue
				}
				continue
			}

			switch event.Type {
			case watch.Added, watch.Modified, watch.Deleted:
				if err := syncPodIPs(clientset, podIPMap, selector); err != nil {
					log.Printf("Failed to update eBPF map after %s event: %v", event.Type, err)
				}
			case watch.Error:
				log.Printf("Watcher error: %v", event.Object)
			}
		}
	}
}

func syncPodIPs(clientset *kubernetes.Clientset, podIPMap *ebpf.Map, selector fields.Selector) error {
	// Get current pods
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	// First, clear the current map contents
	var keys []string
	iter := podIPMap.Iterate()
	var key [32]byte
	var value [16]byte
	for iter.Next(&key, &value) {
		keys = append(keys, string(key[:]))
	}
	for _, k := range keys {
		copy(key[:], k)
		if err := podIPMap.Delete(key); err != nil {
			log.Printf("Failed to delete old key %s: %v", k, err)
		}
	}

	// Now update with current pod IPs
	updated := 0
	for _, pod := range pods.Items {
		// Only include ready pods with IPs
		if pod.Status.PodIP == "" || !isPodReady(&pod) {
			continue
		}

		// Use pod name as key
		var key [32]byte
		copy(key[:], pod.Name)

		// Convert IP to 16-byte format (IPv4 or IPv6)
		ip := net.ParseIP(pod.Status.PodIP)
		if ip == nil {
			continue
		}
		var ipBytes [16]byte
		copy(ipBytes[:], ip.To16())

		// Update eBPF map
		if err := podIPMap.Put(key, ipBytes); err != nil {
			log.Printf("Failed to update IP for pod %s: %v", pod.Name, err)
			continue
		}
		updated++
	}

	log.Printf("Updated eBPF map with %d pod IPs for service %s", updated, serviceName)
	return nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}