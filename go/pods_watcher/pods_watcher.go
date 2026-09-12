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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	mapKey = "test_backend_ips" // Key for our eBPF map
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// eBPF map configuration
var ebpfMapSpec = &ebpf.MapSpec{
	Type:       ebpf.Hash,
	KeySize:    32,  // Fixed size key
	ValueSize:  16,  // IPv6 address size (works for IPv4 too)
	MaxEntries: 100, // Max pods we expect
	Name:       "service_pod_ips",
	Pinning:    ebpf.PinByName,
}

func main() {
	// Flexible: choose which Service to load-balance at install time.
	// e.g. LB_SERVICE_NAME=my-api LB_NAMESPACE=prod
	serviceName := getenv("LB_SERVICE_NAME", "test-service")
	namespace := getenv("LB_NAMESPACE", "default")
	log.Printf("Tracking service %s/%s", namespace, serviceName)
	// Set up signal handling
	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stopCh)
	}()

	// Initialize eBPF map
	podIPMap, err := ebpf.NewMapWithOptions(ebpfMapSpec, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf",
	})
	if err != nil {
		log.Fatalf("Failed to create eBPF map: %v", err)
	}
	defer podIPMap.Close()

	// Initialize Kubernetes client.
	// In-cluster first (DaemonSet), fallback to KUBECONFIG for local dev.
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Failed to build kubeconfig (in-cluster: %v): %v", err, err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create clientset: %v", err)
	}

	// Get service to find selector (works with any selector keys, not just "app").
	svc, err := clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("Failed to get service %s/%s: %v", namespace, serviceName, err)
	}
	if len(svc.Spec.Selector) == 0 {
		log.Fatalf("Service %s/%s has no selector, nothing to track", namespace, serviceName)
	}

	// Create selector from the full service selector map.
	selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector})
	if err != nil {
		log.Fatalf("Invalid selector on service %s/%s: %v", namespace, serviceName, err)
	}
	log.Printf("Using pod selector %q from service %s/%s", selector.String(), namespace, serviceName)

	// Initial sync
	if err := syncPodIPs(clientset, namespace, serviceName, podIPMap, selector); err != nil {
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
			if err := syncPodIPs(clientset, namespace, serviceName, podIPMap, selector); err != nil {
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
				if err := syncPodIPs(clientset, namespace, serviceName, podIPMap, selector); err != nil {
					log.Printf("Failed to update eBPF map after %s event: %v", event.Type, err)
				}
			case watch.Error:
				log.Printf("Watcher error: %v", event.Object)
			}
		}
	}
}

func syncPodIPs(clientset *kubernetes.Clientset, namespace, serviceName string, podIPMap *ebpf.Map, selector labels.Selector) error {
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
