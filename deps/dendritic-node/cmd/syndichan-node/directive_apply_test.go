package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/directive"
)

func configPointingAtOrigin() *config.Config {
	cfg := &config.Config{}
	cfg.Gateway.RegistrationAPI = "https://syndichan.org/api/v1/gateways"
	cfg.Gateway.Validator.OriginURL = "https://syndichan.org"
	cfg.Gateway.Content.OriginURL = "https://syndichan.org"
	cfg.NetworkDirective.Sources = []string{
		"https://syndichan.org/.well-known/syndichan/network.json",
	}
	cfg.UIListen = "127.0.0.1:9090"
	cfg.I2PSAM = "127.0.0.1:7656"
	return cfg
}

func applyWithStore(t *testing.T, cfg *config.Config, held *directive.Directive) string {
	t.Helper()
	store, err := directive.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if held != nil {
		if err := store.Adopt(held, "sig", "signer", 1); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	applyDirective(cfg, store, held, log.New(&out, "", 0))
	return out.String()
}

func TestAMoveCarriesEveryOriginURL(t *testing.T) {
	// Adopting a directive and restarting achieves nothing if the config still
	// names the old domain -- the node comes back up and talks to exactly the
	// host that moved.
	cfg := configPointingAtOrigin()
	logs := applyWithStore(t, cfg, &directive.Directive{
		Kind: directive.KindMove, Sequence: 3, OriginDomain: "syndichan.net"})

	for what, got := range map[string]string{
		"registration": cfg.Gateway.RegistrationAPI,
		"validator":    cfg.Gateway.Validator.OriginURL,
		"content":      cfg.Gateway.Content.OriginURL,
		"source":       cfg.NetworkDirective.Sources[0],
	} {
		if !strings.Contains(got, "syndichan.net") {
			t.Fatalf("%s did not follow the move: %s", what, got)
		}
		if strings.Contains(got, "syndichan.org") {
			t.Fatalf("%s still points at the old origin: %s", what, got)
		}
	}
	if !strings.Contains(logs, "->") {
		t.Fatalf("changes were applied silently: %q", logs)
	}
}

func TestLocalAddressesNeverFollowADirective(t *testing.T) {
	// The management page, SAM and the I2P proxy are local. A directive that
	// moved them would point this node's own internals at somebody else's host.
	cfg := configPointingAtOrigin()
	applyWithStore(t, cfg, &directive.Directive{
		Kind: directive.KindMove, Sequence: 3, OriginDomain: "syndichan.net"})

	if cfg.UIListen != "127.0.0.1:9090" || cfg.I2PSAM != "127.0.0.1:7656" {
		t.Fatalf("local addresses moved: ui=%s sam=%s", cfg.UIListen, cfg.I2PSAM)
	}
}

func TestAnOperatorsOwnEndpointIsLeftAlone(t *testing.T) {
	// Someone running their own registration endpoint chose that deliberately.
	// Rewriting it because the origin moved redirects their choice to a host
	// they never named.
	cfg := configPointingAtOrigin()
	cfg.Gateway.RegistrationAPI = "https://my-own.example/api/v1/gateways"
	applyWithStore(t, cfg, &directive.Directive{
		Kind: directive.KindMove, Sequence: 3, OriginDomain: "syndichan.net"})

	if cfg.Gateway.RegistrationAPI != "https://my-own.example/api/v1/gateways" {
		t.Fatalf("hijacked an unrelated endpoint: %s", cfg.Gateway.RegistrationAPI)
	}
	if !strings.Contains(cfg.Gateway.Validator.OriginURL, "syndichan.net") {
		t.Fatal("the origin URLs should still have followed")
	}
}

func TestAFreezeChangesNothing(t *testing.T) {
	// A freeze pins the network where it is. Reading it as a move to nowhere
	// would blank every origin URL on the node.
	cfg := configPointingAtOrigin()
	before := cfg.Gateway.RegistrationAPI
	applyWithStore(t, cfg, &directive.Directive{
		Kind: directive.KindFreeze, Sequence: 4})
	if cfg.Gateway.RegistrationAPI != before {
		t.Fatalf("a freeze moved things: %s", cfg.Gateway.RegistrationAPI)
	}
}

func TestApplyingTwiceIsAStableNoOp(t *testing.T) {
	// This runs on every start. A second pass must not report changes, or the
	// log claims a move is happening on every restart forever.
	cfg := configPointingAtOrigin()
	held := &directive.Directive{Kind: directive.KindMove, Sequence: 3,
		OriginDomain: "syndichan.net"}
	applyWithStore(t, cfg, held)
	after := cfg.Gateway.RegistrationAPI

	logs := applyWithStore(t, cfg, held)
	if cfg.Gateway.RegistrationAPI != after {
		t.Fatalf("second pass changed it again: %s", cfg.Gateway.RegistrationAPI)
	}
	if strings.Contains(logs, "->") {
		t.Fatalf("second pass reported changes: %q", logs)
	}
}

func TestMovingBackIsPossible(t *testing.T) {
	// The ordinary outcome of a registrar dispute being resolved. Once the URLs
	// have been rewritten away from the original, only the remembered
	// install-time origin lets them match again.
	cfg := configPointingAtOrigin()
	store, err := directive.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	logger := log.New(out, "", 0)

	away := &directive.Directive{Kind: directive.KindMove, Sequence: 3,
		OriginDomain: "syndichan.net"}
	if err := store.Adopt(away, "sig", "signer", 1); err != nil {
		t.Fatal(err)
	}
	applyDirective(cfg, store, away, logger)

	back := &directive.Directive{Kind: directive.KindMove, Sequence: 4,
		OriginDomain: "syndichan.org"}
	if err := store.Adopt(back, "sig", "signer", 2); err != nil {
		t.Fatal(err)
	}
	applyDirective(cfg, store, back, logger)

	if !strings.Contains(cfg.Gateway.Validator.OriginURL, "syndichan.org") {
		t.Fatalf("could not move back: %s", cfg.Gateway.Validator.OriginURL)
	}
}

func TestNothingToChangeIsSaidOutLoud(t *testing.T) {
	cfg := &config.Config{}
	cfg.NetworkDirective.Sources = []string{"https://syndichan.org/x.json"}
	logs := applyWithStore(t, cfg, &directive.Directive{
		Kind: directive.KindMove, Sequence: 3, OriginDomain: "syndichan.net"})
	if !strings.Contains(logs, "no URLs changed") {
		t.Fatalf("silent no-op: %q", logs)
	}
}
