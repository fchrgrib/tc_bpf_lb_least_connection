package main

import (
	"encoding/binary"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func leU32(t *testing.T, ip string) uint32 {
	t.Helper()
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		t.Fatalf("bad test IP %q", ip)
	}
	return binary.LittleEndian.Uint32(v4)
}

func TestNodePortOf(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{Port: 80, TargetPort: intstr.FromInt(8080), NodePort: 31001},
			},
		},
	}
	np, tp, ok := nodePortOf(svc)
	if !ok || np != 31001 || tp != 8080 {
		t.Fatalf("got nodePort=%d targetPort=%d ok=%v; want 31001/8080/true", np, tp, ok)
	}
}

func TestNodePortOfNoNodePort(t *testing.T) {
	svc := &corev1.Service{
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 80}}},
	}
	if _, _, ok := nodePortOf(svc); ok {
		t.Fatal("expected ok=false when there is no nodePort")
	}
}

func TestNodePortOfNamedTargetPortFallsBack(t *testing.T) {
	svc := &corev1.Service{
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 9090, TargetPort: intstr.FromString("http"), NodePort: 30080},
			},
		},
	}
	_, tp, ok := nodePortOf(svc)
	if !ok || tp != 9090 {
		t.Fatalf("named targetPort should fall back to spec.port: tp=%d ok=%v", tp, ok)
	}
}

func TestCapBackends(t *testing.T) {
	if got := capBackends(make([]uint32, 5)); len(got) != 5 {
		t.Fatalf("small list should be unchanged, got len %d", len(got))
	}
	if got := capBackends(make([]uint32, maxBackends+10)); len(got) != maxBackends {
		t.Fatalf("large list should be capped to %d, got %d", maxBackends, len(got))
	}
}

func TestEqualIPs(t *testing.T) {
	if !equalIPs([]uint32{1, 2, 3}, []uint32{1, 2, 3}) {
		t.Fatal("expected equal")
	}
	if equalIPs([]uint32{1, 2, 3}, []uint32{1, 2}) {
		t.Fatal("different lengths must not be equal")
	}
	if equalIPs([]uint32{1, 2, 3}, []uint32{1, 2, 4}) {
		t.Fatal("different values must not be equal")
	}
	if !equalIPs(nil, nil) {
		t.Fatal("nil equals nil")
	}
}

func TestU32ToIPRoundTrip(t *testing.T) {
	for _, s := range []string{"10.244.1.5", "192.168.0.1", "1.2.3.200"} {
		if got := u32ToIP(leU32(t, s)); got != s {
			t.Fatalf("u32ToIP(leU32(%q)) = %q", s, got)
		}
	}
}

func TestMetricsHandler(t *testing.T) {
	tr := &tracker{
		slotUsed:     map[uint32]serviceKey{},
		services:     map[serviceKey]*serviceState{},
		activePorts:  map[uint16]bool{443: true},
		retiredPorts: map[uint16]time.Time{80: time.Now()},
		maps:         &maps{}, // stats nil: datapath counters are skipped
	}
	tr.services[serviceKey{"default", "test-service"}] = &serviceState{
		key:      serviceKey{"default", "test-service"},
		nodePort: 30080,
		ips:      []uint32{leU32(t, "10.244.1.5"), leU32(t, "10.244.1.6")},
	}

	rec := httptest.NewRecorder()
	tr.metricsHandler(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"lb_services 1",
		"lb_balanced_ports 2",
		`lb_backends{service="default/test-service",node_port="30080"} 2`,
		`lb_backend_connections{service="default/test-service",backend_ip="10.244.1.5"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, body)
		}
	}
}
