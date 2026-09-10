package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixtures are SIGNED BY PYTHON (backend/services/storage_coordination).
// This is the test that matters: if the two sides build the signed message
// differently, every node rejects every document and the failure appears as
// "bootstrap unavailable" on machines nobody can reach.

type fixture struct {
	Document json.RawMessage `json:"document"`
	Message  string          `json:"message"`
}

func fixtures(t *testing.T) map[string]fixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "fixtures.json"))
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	var out map[string]fixture
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no fixtures")
	}
	return out
}

func TestMessageMatchesPython(t *testing.T) {
	for name, f := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			doc, rawExpires, err := Parse(f.Document)
			if err != nil {
				t.Fatal(err)
			}
			got := string(Message(doc.Peers, doc.CoordinatorPublicKey, rawExpires))
			if got != f.Message {
				t.Fatalf("message mismatch\n go: %q\n py: %q", got, f.Message)
			}
		})
	}
}

func TestPythonSignaturesVerify(t *testing.T) {
	for name, f := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			doc, rawExpires, err := Parse(f.Document)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(doc, rawExpires, doc.CoordinatorPublicKey); err != nil {
				t.Fatalf("a document Python signed did not verify: %v", err)
			}
		})
	}
}

func TestTamperingBreaksVerification(t *testing.T) {
	f := fixtures(t)["three_peers"]
	doc, rawExpires, err := Parse(f.Document)
	if err != nil {
		t.Fatal(err)
	}
	pinned := doc.CoordinatorPublicKey

	t.Run("swapped peer", func(t *testing.T) {
		altered := *doc
		altered.Peers = []string{"/garlic32/evil/p2p/12D3KooWEvil",
			doc.Peers[1], doc.Peers[2]}
		if Verify(&altered, rawExpires, pinned) == nil {
			t.Fatal("a swapped peer verified")
		}
	})
	t.Run("dropped peer", func(t *testing.T) {
		// Steering a joining node toward the few you control. The signed count
		// is what stops a truncated list passing as complete.
		altered := *doc
		altered.Peers = doc.Peers[:1]
		if Verify(&altered, rawExpires, pinned) == nil {
			t.Fatal("a truncated peer list verified")
		}
	})
	t.Run("extended expiry", func(t *testing.T) {
		if Verify(doc, "2099-01-01T00:00:00Z", pinned) == nil {
			t.Fatal("an extended expiry verified")
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		altered := *doc
		altered.Signature = ""
		if !errors.Is(Verify(&altered, rawExpires, pinned), ErrUnsigned) {
			t.Fatal("an unsigned document was not called unsigned")
		}
	})
}

func TestADocumentMustAnnounceThePinnedCoordinator(t *testing.T) {
	// Verifying the signature while letting the document name a DIFFERENT
	// coordinator would leave the node using a key it never checked a
	// signature for -- which is the whole hole this closes.
	f := fixtures(t)["three_peers"]
	doc, rawExpires, _ := Parse(f.Document)
	other := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if !errors.Is(Verify(doc, rawExpires, other), ErrWrongKey) {
		t.Fatal("a document announcing another coordinator was accepted")
	}
}

func TestFingerprintIgnoresWhatLegitimatelyDiffers(t *testing.T) {
	// Each origin call stamps a fresh expiry and signature, so two gateways
	// proxying the same origin seconds apart differ byte-for-byte while saying
	// exactly the same thing. Comparing raw bodies would report disagreement
	// constantly and mean nothing.
	base := &Document{CoordinatorPublicKey: "K", Peers: []string{"a", "b"}}
	sameClaim := &Document{CoordinatorPublicKey: "K", Peers: []string{"b", "a"},
		Signature: "different", ExpiresAt: time.Now()}
	if Fingerprint(base) != Fingerprint(sameClaim) {
		t.Fatal("a reorder was treated as a disagreement")
	}
	for name, other := range map[string]*Document{
		"different key":  {CoordinatorPublicKey: "J", Peers: []string{"a", "b"}},
		"extra peer":     {CoordinatorPublicKey: "K", Peers: []string{"a", "b", "c"}},
		"missing peer":   {CoordinatorPublicKey: "K", Peers: []string{"a"}},
		"different peer": {CoordinatorPublicKey: "K", Peers: []string{"a", "z"}},
	} {
		t.Run(name, func(t *testing.T) {
			if Fingerprint(base) == Fingerprint(other) {
				t.Fatal("a real difference was not noticed")
			}
		})
	}
}

// --- discovery -----------------------------------------------------------

type fakeResolver struct {
	records []*net.SRV
	err     error
}

func (f fakeResolver) LookupSRV(_ context.Context, _, _, _ string) (string, []*net.SRV, error) {
	return "", f.records, f.err
}

func TestDiscoverBuildsHostnameURLs(t *testing.T) {
	// SRV gives HOSTNAMES, which is the point: a gateway holds a certificate
	// for gw-<id>.<domain>, so connecting by bare address would fail TLS.
	resolver := fakeResolver{records: []*net.SRV{
		{Target: "gw-b.syndichan.org.", Port: 443, Priority: 10, Weight: 5},
		{Target: "gw-a.syndichan.org.", Port: 443, Priority: 1, Weight: 1},
		{Target: "gw-c.syndichan.org.", Port: 8443, Priority: 10, Weight: 50},
	}}
	urls := Discover(context.Background(), resolver,
		"_syndichan-bootstrap._tcp.syndichan.org")
	if len(urls) != 3 {
		t.Fatalf("got %v", urls)
	}
	if !strings.HasPrefix(urls[0], "https://gw-a.syndichan.org/") {
		t.Fatalf("priority ignored: %v", urls)
	}
	// Higher weight first within a priority.
	if !strings.HasPrefix(urls[1], "https://gw-c.syndichan.org:8443/") {
		t.Fatalf("weight ignored: %v", urls)
	}
	if !strings.HasSuffix(urls[0], DocumentPath) {
		t.Fatalf("wrong path: %v", urls)
	}
}

func TestDiscoverIsHarmlessWhenDNSSaysNothing(t *testing.T) {
	for _, resolver := range []Resolver{
		fakeResolver{err: fmt.Errorf("nxdomain")},
		fakeResolver{records: nil},
	} {
		if got := Discover(context.Background(), resolver, "_a._tcp.x.org"); got != nil {
			t.Fatalf("got %v", got)
		}
	}
	if got := Discover(context.Background(), fakeResolver{}, ""); got != nil {
		t.Fatalf("empty name gave %v", got)
	}
}

func TestSourcesFallBackToConfiguredURLs(t *testing.T) {
	// DNS being unavailable must not mean no bootstrap at all.
	cfg := Config{SRVName: "_a._tcp.x.org",
		URLs: []string{"https://node.syndichan.org" + DocumentPath}}
	got := Sources(context.Background(), fakeResolver{err: fmt.Errorf("no")}, cfg)
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestSourcesDeduplicate(t *testing.T) {
	resolver := fakeResolver{records: []*net.SRV{
		{Target: "node.syndichan.org.", Port: 443},
	}}
	cfg := Config{SRVName: "_a._tcp.x.org",
		URLs: []string{"https://node.syndichan.org" + DocumentPath}}
	if got := Sources(context.Background(), resolver, cfg); len(got) != 1 {
		t.Fatalf("duplicate source not collapsed: %v", got)
	}
}
