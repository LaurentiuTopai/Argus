package scanner

import (
	"testing"
	"time"
)

func TestScanPorts(t *testing.T) {
	res := ScanPorts("127.0.0.1", 80, 81, 10, 100*time.Millisecond, nil)
	if res.Target != "127.0.0.1" {
		t.Fatalf("Expected target 127.0.0.1, got %s", res.Target)
	}
}

func TestResolveService(t *testing.T) {
	if resolveService(80) != "http" {
		t.Fatalf("Expected http for port 80")
	}
	if resolveService(443) != "https" {
		t.Fatalf("Expected https for port 443")
	}
}
