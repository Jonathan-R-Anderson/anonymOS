package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validTestConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	cfg.AccessKey = "SYNTEST"
	cfg.SecretKey = "a-secret-key-that-is-at-least-32-bytes"
	return cfg
}

// A NAMED public address is still refused outright, and TLS on the S3 gateway
// does not buy it an exception: the two ports answer to different rules because
// they answer to different people. An operator who types a routable address has
// said where the page is, and the answer is no.
func TestDashboardMustNotBecomePublic(t *testing.T) {
	for _, address := range []string{"198.51.100.10:9090", "[2001:db8::1]:9090"} {
		cfg := validTestConfig(t)
		cfg.UIListen = address
		cfg.UIPassword = "correct-horse-battery-staple"
		cfg.TLSCert = "cert.pem"
		cfg.TLSKey = "key.pem"
		if err := cfg.Validate(); err == nil {
			t.Fatalf("public dashboard binding %s was accepted", address)
		}
	}
}

// 0.0.0.0 and :: are the deliberate exception -- an installer that refuses the
// obvious thing to type is not one people use, and naming an address breaks on
// DHCP, on two NICs, and on a VM whose address nobody knows in advance -- but
// the exception is not free. The password is what carries it, so the bind is
// refused without one and refused with a short one.
func TestAnyInterfaceDashboardIsAllowedOnlyBehindAPassword(t *testing.T) {
	for _, address := range []string{"0.0.0.0:9090", "[::]:9090"} {
		cfg := validTestConfig(t)
		cfg.UIListen, cfg.UIPassword = address, ""
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s was accepted with no password at all", address)
		}
		cfg.UIPassword = "hunter2"
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s was accepted behind a guessable password", address)
		}
		cfg.UIPassword = "correct-horse-battery-staple"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s with a real password was rejected: %v", address, err)
		}
	}
}

func TestPublicS3RequiresTLS(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.S3Listen = "0.0.0.0:9000"
	if err := cfg.Validate(); err == nil {
		t.Fatal("cleartext public S3 binding was accepted")
	}
	cfg.TLSCert = "cert.pem"
	cfg.TLSKey = "key.pem"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("TLS public S3 binding was rejected: %v", err)
	}
}

func TestAxonProxyMustRemainLoopback(t *testing.T) {
	cfg := validTestConfig(t)
	if cfg.Axon.ProxyListen != DefaultProxyListen {
		t.Fatalf("default AXON proxy is %q", cfg.Axon.ProxyListen)
	}
	cfg.Axon.ProxyListen = "0.0.0.0:4480"
	if err := cfg.Validate(); err == nil {
		t.Fatal("an AXON proxy open to the network was accepted")
	}
	cfg.Axon.ProxyListen = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a disabled AXON proxy was rejected: %v", err)
	}
}

func TestAxonSettingsAreChecked(t *testing.T) {
	cases := map[string]func(*AxonConfig){
		"relay with nowhere to listen":       func(a *AxonConfig) { a.Relay = true },
		"listen that is not a multiaddr":     func(a *AxonConfig) { a.Listen = []string{"0.0.0.0:4001"} },
		"seed without a peer id":             func(a *AxonConfig) { a.Seeds = []string{"/ip4/203.0.113.7/tcp/4001"} },
		"origin that is not an AXON address": func(a *AxonConfig) { a.Origin = "rabbiit.io" },
		"announce without a port":            func(a *AxonConfig) { a.Announce = []string{"203.0.113.7"} },
	}
	for name, mutate := range cases {
		cfg := validTestConfig(t)
		mutate(&cfg.Axon)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg := validTestConfig(t)
	cfg.Axon = AxonConfig{
		Listen: []string{"/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/udp/4001/quic-v1"}, Relay: true,
		Announce: []string{"203.0.113.7:4001"},
		Seeds:    []string{"/ip4/203.0.113.8/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid relay configuration was rejected: %v", err)
	}
}

func TestGatewayDefaultDisabledAndRegistryIsPublicConfiguration(t *testing.T) {
	cfg := validTestConfig(t)
	if cfg.Gateway.Enabled {
		t.Fatal("public gateway is enabled by default")
	}
	if cfg.Gateway.RegistrationAPI != "https://rabbiit.io/api/v1/gateways" {
		t.Fatal("unexpected registration API default")
	}
}

func TestGatewayRequiresExternalQuorumConfiguration(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicHostname = "gateway.example.com"
	cfg.Gateway.TLS.CertificatePath = "cert.pem"
	cfg.Gateway.TLS.PrivateKeyPath = "key.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("gateway without addresses/probes was accepted")
	}
	cfg.Gateway.PublicAddresses = []string{"8.8.8.8"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fully configured candidate rejected: %v", err)
	}
}

func TestGatewayRejectsCredentialBearingRegistrationAPI(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicHostname = "gw-001.rabbiit.io"
	cfg.Gateway.TLS.CertificatePath = "cert.pem"
	cfg.Gateway.TLS.PrivateKeyPath = "key.pem"
	cfg.Gateway.PublicAddresses = []string{"8.8.8.8"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}
	cfg.Gateway.RegistrationAPI = "https://user:token@rabbiit.io/api/v1/gateways"
	if err := cfg.Validate(); err == nil {
		t.Fatal("credential-bearing registration API was accepted")
	}
}

func TestGatewayFrontendDefaultsDisabled(t *testing.T) {
	cfg := validTestConfig(t)
	if cfg.Gateway.Frontend.Enabled {
		t.Fatal("gateway frontend is enabled by default")
	}
	if !cfg.Gateway.Frontend.ProxyProtocol {
		t.Fatal("secure frontend default must preserve client addresses")
	}
}

func TestGatewayFrontendValidation(t *testing.T) {
	valid := func() Config {
		cfg := validTestConfig(t)
		cfg.Gateway.Frontend.Enabled = true
		cfg.Gateway.Frontend.OriginAddress = "origin.rabbiit.io:9443"
		cfg.Gateway.Frontend.OriginServerName = "rabbiit.io"
		cfg.Gateway.Frontend.SNIAllowlist = []string{"rabbiit.io", "gw-node.rabbiit.io"}
		return cfg
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid frontend rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing port", func(c *Config) { c.Gateway.Frontend.OriginAddress = "origin.example" }},
		{"empty allowlist", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = nil }},
		{"wildcard allowlist", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = []string{"*.example"} }},
		{"suffix pattern", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = []string{".example"} }},
		{"IP allowlist", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = []string{"203.0.113.1"} }},
		{"private origin", func(c *Config) { c.Gateway.Frontend.OriginAddress = "10.0.0.2:443" }},
		{"loopback origin", func(c *Config) { c.Gateway.Frontend.OriginAddress = "localhost:443" }},
		{"zero connections", func(c *Config) { c.Gateway.Frontend.MaxConnections = 0 }},
		{"zero handshake timeout", func(c *Config) { c.Gateway.Frontend.HandshakeTimeoutSeconds = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid frontend configuration was accepted")
			}
		})
	}
	cfg := valid()
	cfg.Gateway.Frontend.OriginAddress = "127.0.0.1:9443"
	cfg.Gateway.Frontend.AllowPrivateOrigin = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit private-origin escape hatch rejected: %v", err)
	}
}

func TestGatewayFrontendSaveLoadRoundTrip(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Gateway.Frontend.Enabled = true
	cfg.Gateway.Frontend.OriginAddress = "origin.rabbiit.io:9443"
	cfg.Gateway.Frontend.OriginServerName = "rabbiit.io"
	cfg.Gateway.Frontend.SNIAllowlist = []string{"rabbiit.io"}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, cfg, RoleStorage); err != nil {
		t.Fatal(err)
	}
	loaded, created, err := LoadOrCreate(path, RoleStorage)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing config reported as newly created")
	}
	if !reflect.DeepEqual(loaded.Gateway.Frontend, cfg.Gateway.Frontend) {
		t.Fatalf("frontend block changed during round trip:\n got %#v\nwant %#v",
			loaded.Gateway.Frontend, cfg.Gateway.Frontend)
	}
}

// A DRAIN MUST SURVIVE A RESTART, and this is the half of that which lives on
// the machine being retired.
//
// The operator sets it and then, by definition, restarts or powers down this
// node -- that is what a drain is FOR. An intent that lived only in the running
// process would clear itself on the next start, the node would resume
// advertising itself as a destination, and owners would go back to writing onto
// a disk that is on its way out of the building. The config file is the whole of
// the persistence needed here: what is left to move is measured from the disk on
// every pass, so there is no progress to lose, only the intent.
//
// Reverted to prove it fails: `json:"-"` on Config.Draining. The flag is then
// written nowhere and comes back false.
func TestDrainingSurvivesASaveLoadRoundTrip(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Draining = true
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, cfg, RoleStorage); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := LoadOrCreate(path, RoleStorage)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Draining {
		t.Fatal("a node told to drain came back from a restart not draining; it would start accepting shards again")
	}
	// And the field is present in the file even when false, so an operator
	// looking for the switch can find it without knowing its name in advance.
	off := validTestConfig(t)
	off.Draining = false
	offPath := filepath.Join(t.TempDir(), "config.json")
	if err := Save(offPath, off, RoleStorage); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(offPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"draining"`) {
		t.Fatal("the draining switch is absent from a written config, so nobody can find it by reading the file")
	}
}
