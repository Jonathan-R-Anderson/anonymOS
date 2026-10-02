package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestACMEManagerUsesExactHostAndPrivateCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "certificates")
	manager, err := NewACMEManager("GW-Node.Rabbiit.io.", "ops@rabbiit.io", cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.HostPolicy(context.Background(), "gw-node.rabbiit.io"); err != nil {
		t.Fatalf("configured hostname rejected: %v", err)
	}
	for _, hostname := range []string{
		"rabbiit.io", "other.rabbiit.io", "gw-node.rabbiit.io.example",
	} {
		if err := manager.HostPolicy(context.Background(), hostname); err == nil {
			t.Fatalf("unconfigured hostname %q accepted", hostname)
		}
	}
	info, err := os.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("cache permissions = %o, want 0700", info.Mode().Perm())
	}
	tlsConfig := manager.TLSConfig()
	if tlsConfig.GetCertificate == nil {
		t.Fatal("ACME TLS config cannot select or renew certificates")
	}
}

func TestACMEManagerRejectsUnsafeConfiguration(t *testing.T) {
	for _, hostname := range []string{"", "*.rabbiit.io", "https://rabbiit.io", "127.0.0.1"} {
		if _, err := NewACMEManager(hostname, "", t.TempDir()); err == nil {
			t.Fatalf("unsafe hostname %q accepted", hostname)
		}
	}
	if _, err := NewACMEManager("gw-node.rabbiit.io", "", ""); err == nil {
		t.Fatal("empty certificate cache accepted")
	}
}
