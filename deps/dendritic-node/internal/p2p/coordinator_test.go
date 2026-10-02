package p2p

import (
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/config"
)

func restoreCoordinatorEndpoints(t *testing.T) {
	t.Helper()
	heartbeat, lease, revocation, boot := heartbeatEndpoint, leaseURL, revocationURL, bootstrapURL
	t.Cleanup(func() {
		heartbeatEndpoint, leaseURL, revocationURL, bootstrapURL = heartbeat, lease, revocation, boot
	})
}

// The bug this guards: heartbeat_endpoint moved the presence beacon and nothing
// else, so a node on another domain was visible there but kept asking the
// compiled-in domain for leases -- and was never handed any data.
func TestCoordinatorEndpointsAllFollowTheHeartbeatDomain(t *testing.T) {
	restoreCoordinatorEndpoints(t)
	if err := SetCoordinatorEndpoints("https://example.test/api/v1/storage/nodes/heartbeat"); err != nil {
		t.Fatal(err)
	}
	if heartbeatEndpoint != "https://example.test/api/v1/storage/nodes/heartbeat" {
		t.Fatalf("heartbeat = %s", heartbeatEndpoint)
	}
	lease, revocation, boot := CoordinatorEndpoints()
	if lease != "https://example.test/api/v1/storage/leases" {
		t.Fatalf("lease = %s", lease)
	}
	if revocation != "https://example.test/api/v1/storage/revocations" {
		t.Fatalf("revocation = %s", revocation)
	}
	if boot != "https://node.example.test"+config.BootstrapPath {
		t.Fatalf("bootstrap = %s", boot)
	}
}

func TestCoordinatorEndpointsKeepThePortAndUseTheHostForAnAddress(t *testing.T) {
	restoreCoordinatorEndpoints(t)
	if err := SetCoordinatorEndpoints("http://127.0.0.1:8080/hb"); err != nil {
		t.Fatal(err)
	}
	lease, _, boot := CoordinatorEndpoints()
	if lease != "http://127.0.0.1:8080/api/v1/storage/leases" {
		t.Fatalf("lease = %s", lease)
	}
	// There is no node.127.0.0.1 to ask.
	if boot != "http://127.0.0.1:8080"+config.BootstrapPath {
		t.Fatalf("bootstrap = %s", boot)
	}
}

func TestCoordinatorEndpointsUnsetKeepsTheDefaults(t *testing.T) {
	restoreCoordinatorEndpoints(t)
	if err := SetCoordinatorEndpoints(""); err != nil {
		t.Fatal(err)
	}
	lease, revocation, boot := CoordinatorEndpoints()
	if lease != "https://rabbiit.io/api/v1/storage/leases" ||
		revocation != "https://rabbiit.io/api/v1/storage/revocations" ||
		boot != config.BootstrapURL {
		t.Fatalf("defaults moved: %s %s %s", lease, revocation, boot)
	}
}

func TestCoordinatorEndpointsRejectARelativeURL(t *testing.T) {
	restoreCoordinatorEndpoints(t)
	for _, bad := range []string{"rabbiit.io", "/api/v1/storage/nodes/heartbeat", "://x"} {
		if err := SetCoordinatorEndpoints(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if leaseURL != "https://rabbiit.io"+leasePath {
		t.Fatalf("a rejected value still moved leases to %s", leaseURL)
	}
}
