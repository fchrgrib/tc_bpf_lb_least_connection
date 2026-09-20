package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRouteFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultRouteIfaceFrom(t *testing.T) {
	p := writeRouteFile(t, "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"+
		"eth1\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")

	name, err := defaultRouteIfaceFrom(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "eth0" {
		t.Fatalf("got %q, want eth0", name)
	}
}

func TestDefaultRouteIfaceFromNoDefault(t *testing.T) {
	p := writeRouteFile(t, "Iface\tDestination\tGateway\n"+
		"eth1\t0001A8C0\t00000000\n")

	if _, err := defaultRouteIfaceFrom(p); err == nil {
		t.Fatal("expected an error when there is no default route")
	}
}

func TestDefaultRouteIfaceFromMissingFile(t *testing.T) {
	if _, err := defaultRouteIfaceFrom("/nonexistent/route"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
