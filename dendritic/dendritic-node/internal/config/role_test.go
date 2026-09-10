package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gatewayCandidateConfig is a complete, valid storage node that also runs the
// gateway role. Individual tests then remove pieces of it to prove which
// pieces each runtime role actually depends on.
func gatewayCandidateConfig(t *testing.T) Config {
	t.Helper()
	cfg := validTestConfig(t)
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicHostname = "gw-node.example.com"
	cfg.Gateway.TLS.Mode = "existing"
	cfg.Gateway.TLS.CertificatePath = "cert.pem"
	cfg.Gateway.TLS.PrivateKeyPath = "key.pem"
	cfg.Gateway.PublicAddresses = []string{"198.51.100.10"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}
	return cfg
}

func probeCandidateConfig(t *testing.T) Config {
	t.Helper()
	cfg := gatewayCandidateConfig(t)
	cfg.Gateway.Enabled = false
	cfg.Gateway.ProbeEnabled = true
	cfg.Gateway.ProbeNetwork = "AS64500"
	return cfg
}

// storageRemovals are the settings a dedicated gateway or probe host genuinely
// does not have. None of them may block startup for a storage-free role.
var storageRemovals = []struct {
	name   string
	mutate func(*Config)
}{
	{"missing S3 credentials", func(c *Config) { c.AccessKey, c.SecretKey = "", "" }},
	{"short S3 secret", func(c *Config) { c.SecretKey = "too-short" }},
	{"missing S3 listen address", func(c *Config) { c.S3Listen = "" }},
	{"missing storage capacity", func(c *Config) { c.CapacityBytes = 0 }},
	{"missing erasure layout", func(c *Config) { c.DataShards, c.ParityShards = 0, 0 }},
	{"missing chunk size", func(c *Config) { c.ChunkBytes = 0 }},
	{"missing I2P SAM bridge", func(c *Config) { c.I2PSAM = "" }},
	{"missing I2P HTTP proxy", func(c *Config) { c.I2PHTTPProxy = "" }},
	{"no storage configuration at all", func(c *Config) {
		c.AccessKey, c.SecretKey = "", ""
		c.UIListen, c.S3Listen = "", ""
		c.I2PSAM, c.I2PHTTPProxy = "", ""
		c.CapacityBytes, c.DataShards, c.ParityShards, c.ChunkBytes = 0, 0, 0, 0
	}},
}

// dashboardRules are NOT storage settings even though they used to be checked
// with them. main starts the management page in every mode -- it is the only
// way a gateway-only node is configured at all -- so a gateway host that binds
// it to the world is exactly as exposed as a storage host that does, and every
// role is held to the same rules.
var dashboardRules = []struct {
	name   string
	mutate func(*Config)
}{
	{"malformed dashboard address", func(c *Config) { c.UIListen = "not-an-address" }},
	{"dashboard on every interface with no password", func(c *Config) {
		c.UIListen, c.UIPassword = "0.0.0.0:9090", ""
	}},
	{"dashboard on every IPv6 interface with no password", func(c *Config) {
		c.UIListen, c.UIPassword = "[::]:9090", ""
	}},
	{"dashboard on a public address", func(c *Config) { c.UIListen = "198.51.100.10:9090" }},
	// Default() generates a password for a fresh config, so a rule about
	// missing credentials has to clear it explicitly or it tests nothing.
	{"dashboard on a LAN address with no password", func(c *Config) {
		c.UIListen, c.UIPassword = "192.168.1.50:9090", ""
	}},
	{"dashboard on a LAN address with a guessable password", func(c *Config) {
		c.UIListen, c.UIPassword = "192.168.1.50:9090", "hunter2"
	}},
	{"dashboard username smuggling a second field", func(c *Config) {
		c.UIListen = "192.168.1.50:9090"
		c.UIUsername, c.UIPassword = "admin:extra", "a-long-enough-password"
	}},
}

func TestDashboardRulesApplyToEveryRole(t *testing.T) {
	// RoleManagement included deliberately: it is the role that WRITES the
	// config file, so it is the one that must not be able to persist a
	// dashboard the other roles would refuse to start.
	roles := []Role{RoleStorage, RoleGatewayOnly, RoleProbeOnly, RoleManagement}
	for _, rule := range dashboardRules {
		for _, role := range roles {
			t.Run(rule.name+"/"+string(role), func(t *testing.T) {
				cfg := probeCandidateConfig(t)
				if role != RoleProbeOnly {
					cfg = gatewayCandidateConfig(t)
				}
				rule.mutate(&cfg)
				if err := cfg.ValidateForRole(role); err == nil {
					t.Fatalf("%s accepted an exposed management dashboard", role)
				}
			})
		}
	}
}

// The capability the whole change exists for: the dashboard may move to the
// operator's own network, but only there, and only behind a password.
func TestDashboardOnPrivateAddressRequiresAPassword(t *testing.T) {
	private := []string{
		"192.168.1.50:9090", "10.0.0.4:9090", "172.16.3.9:9090",
		"169.254.7.7:9090", "[fd00::1]:9090",
	}
	for _, address := range private {
		cfg := gatewayCandidateConfig(t)
		cfg.UIListen = address

		cfg.UIPassword = ""
		if err := cfg.ValidateForRole(RoleStorage); err == nil {
			t.Fatalf("%s was accepted with no password", address)
		} else if !strings.Contains(err.Error(), "ui_password") {
			t.Fatalf("%s: error does not say what to set: %v", address, err)
		}

		cfg.UIPassword = "correct-horse-battery-staple"
		if err := cfg.ValidateForRole(RoleStorage); err != nil {
			t.Fatalf("%s with a password was rejected: %v", address, err)
		}
	}
}

// Nothing changes for the people already running it: loopback needs no
// credential, and never asks for one.
func TestLoopbackDashboardNeedsNoPassword(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "localhost:9090", "[::1]:9090"} {
		cfg := gatewayCandidateConfig(t)
		cfg.UIListen, cfg.UIUsername, cfg.UIPassword = address, "", ""
		if err := cfg.ValidateForRole(RoleStorage); err != nil {
			t.Fatalf("loopback dashboard %s was rejected: %v", address, err)
		}
	}
}

// 0.0.0.0 is the obvious thing to type, and every role now accepts it -- but
// only behind a password, and the refusal without one has to name the real
// problem rather than reading like a typo. This is the rule that carries the
// whole exception, so it is checked on every role that can start the page.
func TestAnyInterfaceDashboardIsRefusedWithoutAPassword(t *testing.T) {
	roles := []Role{RoleStorage, RoleGatewayOnly, RoleProbeOnly, RoleManagement}
	for _, address := range []string{"0.0.0.0:9090", "[::]:9090"} {
		for _, role := range roles {
			cfg := gatewayCandidateConfig(t)
			if role == RoleProbeOnly {
				cfg = probeCandidateConfig(t)
			}
			cfg.UIListen, cfg.UIPassword = address, ""
			err := cfg.ValidateForRole(role)
			if err == nil {
				t.Fatalf("%s accepted %s with no password", role, address)
			}
			if !strings.Contains(err.Error(), "every interface") ||
				!strings.Contains(err.Error(), "ui_password") {
				t.Fatalf("%s on %s: refusal does not explain itself: %v", role, address, err)
			}

			cfg.UIPassword = "correct-horse-battery-staple"
			if err := cfg.ValidateForRole(role); err != nil {
				t.Fatalf("%s rejected %s behind a password: %v", role, address, err)
			}
		}
	}
}

func TestGatewayOnlyIgnoresStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleGatewayOnly); err != nil {
				t.Fatalf("gateway-only rejected for a storage setting it never uses: %v", err)
			}
		})
	}
}

func TestProbeOnlyIgnoresStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := probeCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleProbeOnly); err != nil {
				t.Fatalf("probe-only rejected for a storage setting it never uses: %v", err)
			}
		})
	}
}

// The other direction: a storage node must still be held to every one of them.
func TestStorageRoleStillValidatesStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleStorage); err == nil {
				t.Fatal("storage role accepted an unusable storage configuration")
			}
		})
	}
	cfg := gatewayCandidateConfig(t)
	cfg.AccessKey, cfg.SecretKey = "", ""
	err := cfg.ValidateForRole(RoleStorage)
	if err == nil || !strings.Contains(err.Error(), "S3 credentials") {
		t.Fatalf("storage role lost its S3 credential check: %v", err)
	}
}

func TestGatewayOnlyStillRequiresGatewayConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no gateway or probe role", func(c *Config) {
			c.Gateway.Enabled, c.Gateway.ProbeEnabled = false, false
		}},
		{"missing TLS mode", func(c *Config) { c.Gateway.TLS.Mode = "" }},
		{"missing TLS certificate", func(c *Config) { c.Gateway.TLS.CertificatePath = "" }},
		{"missing TLS private key", func(c *Config) { c.Gateway.TLS.PrivateKeyPath = "" }},
		{"missing public hostname", func(c *Config) { c.Gateway.PublicHostname = "" }},
		{"missing registration API", func(c *Config) { c.Gateway.RegistrationAPI = "" }},
		{"credential-bearing registration API", func(c *Config) {
			c.Gateway.RegistrationAPI = "https://user:token@syndichan.org/api/v1/gateways"
		}},
		{"missing public addresses", func(c *Config) { c.Gateway.PublicAddresses = nil }},
		// Clearing probe_urls ENTIRELY is valid now (controller-only
		// verification); dropping it to a partial quorum is the mistake.
		// See TestPartiallyConfiguredQuorumIsStillRejected.
		{"partial probe quorum", func(c *Config) {
			c.Gateway.ProbeURLs = []string{"https://probe-a.example"}
		}},
		{"invalid listen port", func(c *Config) { c.Gateway.ListenPort = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			err := cfg.ValidateForRole(RoleGatewayOnly)
			if err == nil {
				t.Fatal("gateway-only accepted an incomplete gateway configuration")
			}
			// The failure must be about the gateway, never about storage.
			if strings.Contains(err.Error(), "S3") {
				t.Fatalf("gateway-only failed on storage configuration: %v", err)
			}
		})
	}
}

func TestProbeOnlyRequiresProbeRole(t *testing.T) {
	cfg := probeCandidateConfig(t)
	cfg.Gateway.ProbeEnabled = false
	if err := cfg.ValidateForRole(RoleProbeOnly); err == nil {
		t.Fatal("probe-only accepted a config with no probe role")
	}
	cfg = probeCandidateConfig(t)
	cfg.Gateway.Enabled = true
	if err := cfg.ValidateForRole(RoleProbeOnly); err == nil {
		t.Fatal("probe-only accepted a config that also enables the gateway role")
	}
	cfg = probeCandidateConfig(t)
	cfg.Gateway.ProbeNetwork = ""
	if err := cfg.ValidateForRole(RoleProbeOnly); err == nil {
		t.Fatal("probe-only accepted a probe with no network trust domain")
	}
}

// -gateway-status and friends must work on a dedicated gateway's own config,
// which has no storage settings at all.
func TestManagementRoleIgnoresStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleManagement); err != nil {
				t.Fatalf("config management rejected a storage-free config: %v", err)
			}
		})
	}
	// It also accepts a config with no gateway role at all, which is what
	// -gateway-disable leaves behind.
	cfg := gatewayCandidateConfig(t)
	cfg.Gateway.Enabled, cfg.Gateway.ProbeEnabled = false, false
	if err := cfg.ValidateForRole(RoleManagement); err != nil {
		t.Fatalf("config management rejected a node with no gateway role: %v", err)
	}
	// But -gateway-enable must still refuse to save a broken gateway section.
	cfg = gatewayCandidateConfig(t)
	cfg.Gateway.TLS.CertificatePath = ""
	if err := cfg.ValidateForRole(RoleManagement); err == nil {
		t.Fatal("config management saved an unusable gateway section")
	}
}

// The stock configuration -- external_verification on, no probes listed --
// must start. The first gateway on a network cannot have a probe fleet to
// point at, because probes are gateways someone has to stand up first.
func TestStockVerificationWithNoProbeFleetStarts(t *testing.T) {
	cfg := gatewayCandidateConfig(t)
	cfg.Gateway.Verification.Enabled = true
	cfg.Gateway.ProbeURLs = nil
	cfg.Gateway.TrustedProbes = nil
	for _, role := range []Role{RoleGatewayOnly, RoleStorage, RoleManagement} {
		if err := cfg.ValidateForRole(role); err != nil {
			t.Fatalf("%s: stock config with no probe fleet was rejected: %v", role, err)
		}
	}
	if ProbeQuorumConfigured(cfg.Gateway) {
		t.Fatal("an empty probe fleet counted as a configured quorum")
	}
}

// A HALF-configured quorum is a real mistake and must still be refused --
// otherwise a typo that drops two of three probes silently downgrades the node
// from peer-verified to controller-only.
func TestPartiallyConfiguredQuorumIsStillRejected(t *testing.T) {
	cfg := gatewayCandidateConfig(t)
	cfg.Gateway.Verification.MinimumSuccessfulProbes = 3
	cfg.Gateway.ProbeURLs = []string{"https://probe-a.example"}
	err := cfg.ValidateForRole(RoleGatewayOnly)
	if err == nil {
		t.Fatal("a quorum of 3 was satisfied by 1 probe URL")
	}
	if !strings.Contains(err.Error(), "only 1 are configured") {
		t.Fatalf("unhelpful error: %v", err)
	}
	// Trusted probes alone also count as "the operator meant to run a quorum".
	cfg = gatewayCandidateConfig(t)
	cfg.Gateway.ProbeURLs = nil
	cfg.Gateway.TrustedProbes = map[string]string{"node-a": "key"}
	if err := cfg.ValidateForRole(RoleGatewayOnly); err == nil {
		t.Fatal("trusted_probes without probe_urls was accepted as a quorum")
	}
}

// A full quorum still validates, and still counts as configured.
func TestFullyConfiguredQuorumStillValidates(t *testing.T) {
	cfg := gatewayCandidateConfig(t)
	if !ProbeQuorumConfigured(cfg.Gateway) {
		t.Fatal("a fully configured quorum was not recognised")
	}
	if err := cfg.ValidateForRole(RoleGatewayOnly); err != nil {
		t.Fatalf("fully configured quorum rejected: %v", err)
	}
}

func TestUnknownRoleIsRejected(t *testing.T) {
	if err := gatewayCandidateConfig(t).ValidateForRole(Role("bogus")); err == nil {
		t.Fatal("an unknown runtime role was accepted")
	}
}

// The reported bug, end to end: a hand-written gateway.json holds no S3
// credentials, and -gateway-only must start from it.
func TestLoadOrCreateGatewayOnlyAcceptsConfigWithoutStorageSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	raw := []byte(`{
	  "gateway": {
	    "enabled": true,
	    "listen_port": 443,
	    "public_hostname": "gw-node.example.com",
	    "registration_api": "https://syndichan.org/api/v1/gateways",
	    "tls": {"mode": "existing", "certificate_path": "cert.pem", "private_key_path": "key.pem"},
	    "public_addresses": ["198.51.100.10"],
	    "probe_urls": [
	      "https://probe-a.example", "https://probe-b.example", "https://probe-c.example"
	    ]
	  }
	}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, created, err := LoadOrCreate(path, RoleGatewayOnly)
	if err != nil {
		t.Fatalf("gateway-only refused a storage-free gateway config: %v", err)
	}
	if created {
		t.Fatal("existing config reported as newly created")
	}
	if cfg.AccessKey != "" || cfg.SecretKey != "" {
		t.Fatal("loading a gateway config invented S3 credentials")
	}
	// Same file, storage role: the S3 check must still fire.
	if _, _, err := LoadOrCreate(path, RoleStorage); err == nil {
		t.Fatal("storage role accepted a config with no S3 credentials")
	}
}

// A config created by the gateway-only path must round-trip through Save
// without the storage validation rejecting it.
func TestSaveRoundTripsAStorageFreeGatewayConfig(t *testing.T) {
	cfg := gatewayCandidateConfig(t)
	cfg.AccessKey, cfg.SecretKey = "", ""
	cfg.I2PSAM, cfg.I2PHTTPProxy, cfg.UIListen, cfg.S3Listen = "", "", "", ""
	path := filepath.Join(t.TempDir(), "gateway.json")
	if err := Save(path, cfg, RoleGatewayOnly); err != nil {
		t.Fatalf("saving a gateway-only config failed: %v", err)
	}
	if _, _, err := LoadOrCreate(path, RoleGatewayOnly); err != nil {
		t.Fatalf("reloading a gateway-only config failed: %v", err)
	}
	if err := Save(path, cfg, RoleStorage); err == nil {
		t.Fatal("storage role saved a config it could not start from")
	}
}

// The documented copy-paste path: gateway.example.json must carry no storage
// settings and must be startable as a dedicated gateway once its host-specific
// fields are filled in.
func TestShippedGatewayExampleNeedsNoStorageConfiguration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "gateway.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.AccessKey != "" || probe.SecretKey != "" {
		t.Fatal("the gateway example ships S3 credentials a gateway never uses")
	}
	cfg, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.AccessKey, cfg.SecretKey = "", ""
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicAddresses = []string{"198.51.100.10"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}

	// The example DELIBERATELY ships a placeholder ACME contact, so that a
	// gateway refuses to start until its operator supplies a real address
	// rather than silently ending up with no expiry warnings.
	err = cfg.ValidateForRole(RoleGatewayOnly)
	if err == nil || !strings.Contains(err.Error(), "acme_email") {
		t.Fatalf("the example no longer forces the operator to set acme_email: %v", err)
	}

	// With that one field filled in, it must start -- and still need no
	// storage configuration whatsoever.
	cfg.Gateway.TLS.ACMEEmail = "ops@syndichan.org"
	if err := cfg.ValidateForRole(RoleGatewayOnly); err != nil {
		t.Fatalf("the documented gateway example cannot start as a gateway: %v", err)
	}
}

// The shipped placeholder must fail loudly at startup, not four steps later as
// an opaque registry 422.
func TestPlaceholderACMEEmailIsRejected(t *testing.T) {
	acme := func() Config {
		cfg := gatewayCandidateConfig(t)
		cfg.Gateway.TLS.Mode = "acme"
		cfg.Gateway.TLS.ACMEHTTPAddress = "0.0.0.0:80"
		cfg.Gateway.PublicHostname = "gw-node.example.com"
		return cfg
	}
	for _, bad := range []string{
		"operator@example.com", "a@example.org", "a@example.net",
		"a@sub.example", "a@thing.invalid", "a@host.test",
	} {
		cfg := acme()
		cfg.Gateway.TLS.ACMEEmail = bad
		err := cfg.ValidateForRole(RoleGatewayOnly)
		if err == nil {
			t.Fatalf("placeholder ACME email %q was accepted", bad)
		}
		if !strings.Contains(err.Error(), "acme_email") {
			t.Fatalf("unhelpful error for %q: %v", bad, err)
		}
	}
	// A real address, and an intentionally empty one, both pass.
	for _, good := range []string{"ops@syndichan.org", ""} {
		cfg := acme()
		cfg.Gateway.TLS.ACMEEmail = good
		if err := cfg.ValidateForRole(RoleGatewayOnly); err != nil {
			t.Fatalf("ACME email %q rejected: %v", good, err)
		}
	}
	// Only checked for ACME mode; other modes never contact Let's Encrypt.
	cfg := gatewayCandidateConfig(t)
	cfg.Gateway.TLS.ACMEEmail = "operator@example.com"
	if err := cfg.ValidateForRole(RoleGatewayOnly); err != nil {
		t.Fatalf("non-ACME mode was held to the ACME contact rule: %v", err)
	}
}

// An empty ui_listen means "no dashboard", which is a valid posture for a
// public server administered over SSH: the page may only be bound to loopback
// or the operator's own private network, so someone who cannot reach it either
// way should be able to not run it at all.
func TestEmptyDashboardAddressDisablesItRatherThanFailing(t *testing.T) {
	cfg := gatewayCandidateConfig(t)
	cfg.UIListen = ""
	if err := cfg.ValidateForRole(RoleStorage); err != nil {
		t.Fatalf("an empty ui_listen should disable the dashboard, not fail: %v", err)
	}
	// A malformed one is still an error — "off" and "wrong" are different.
	cfg.UIListen = "127.0.0.1"
	if err := cfg.ValidateForRole(RoleStorage); err == nil {
		t.Fatal("a malformed dashboard address was accepted")
	}
}
