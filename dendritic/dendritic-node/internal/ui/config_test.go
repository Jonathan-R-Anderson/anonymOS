package ui

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/config"
)

// The config panels only render when config access is wired, so the base tests
// never execute that template branch. This renders it with a real config and
// checks the sections and current values appear -- catching a bad field
// reference (which html/template surfaces at execution) before it ships.
func TestDashboardRendersConfigPanels(t *testing.T) {
	cfg, err := config.Default()
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	cfg.RunMode = "storage"
	cfg.DCS.Enabled = true
	cfg.DCS.Role.Worker = true
	cfg.DCS.Limits.MaxContainers = 4
	cfg.DCS.Policy.TrustedBrokers = []string{"12D3KooWExampleBroker"}
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicHostname = "node.example"

	s := New(nil, nil, log.New(io.Discard, "", 0)) // nil store + nil node: gateway-only shape
	s.SetConfigAccess(
		func() config.Config { return cfg },
		func(mut func(*config.Config) error) error { return mut(&cfg) },
	)

	rec := httptest.NewRecorder()
	s.dashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"Run mode", "Storage &amp; S3", "Volunteer gateway", "Docker facilitation (DCS)",
		"node.example",          // gateway hostname value rendered
		"12D3KooWExampleBroker", // trusted broker rendered in the textarea
		`name="dcs_api_listen"`, // the bridge API field exists
		`action="/config/dcs"`,  // the DCS form posts to the handler
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}

	// The checkbox states reflect the config.
	if !strings.Contains(body, `name="dcs_worker" value="1" checked`) {
		t.Fatal("dcs worker checkbox should be checked")
	}
}
