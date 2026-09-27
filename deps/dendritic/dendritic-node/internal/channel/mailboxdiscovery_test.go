package channel

// Discovery must read and only read, and must never turn "I could not look"
// into "nothing is waiting".

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestCoordinator: the route under test never touches the coordinator, but
// NewAPI requires one.
func newTestCoordinator(t *testing.T) *Coordinator {
	t.Helper()
	r := newPayoutRig(t, 1000)
	return NewCoordinator(r.store, r.chain, big.NewInt(1), Address{}, r.me.address(),
		func(raw [32]byte) ([]byte, error) { return r.me.sign(raw), nil })
}

func discoverySigner(t *testing.T) (*MailboxDiscovery, *signer) {
	t.Helper()
	s := newSigner(t)
	d, err := NewMailboxDiscovery(s.address(), func(raw [32]byte) ([]byte, error) {
		return s.sign(raw), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, s
}

// A real mailbox behind a real HTTP server: the encoding of the proof is
// exactly what this is here to catch, and a stub would accept anything.
func servedMailbox(t *testing.T, s *signer) (*Mailbox, *httptest.Server) {
	t.Helper()
	m := newTestMailbox(1000)
	if err := m.Serve(authFor(t, s, testNode, 99999)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(MailboxHandler(m))
	t.Cleanup(srv.Close)
	return m, srv
}

func TestDiscoveryReadsWithoutConsuming(t *testing.T) {
	d, s := discoverySigner(t)
	m, srv := servedMailbox(t, s)
	if err := m.Deliver(s.address(), Envelope{Type: MsgStatePropose, Channel: "cc"}); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 2; i++ {
		frames, err := d.Waiting(context.Background(), srv.URL, testNode)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if len(frames) != 1 || frames[0].Channel != "cc" {
			t.Fatalf("read %d: got %d frames", i, len(frames))
		}
		if m.Pending(s.address()) != 1 {
			t.Fatalf("read %d consumed the queue", i)
		}
	}
}

func TestDiscoveryUsesAFreshChallengeEachRead(t *testing.T) {
	// A captured proof must not answer a later request.
	d, s := discoverySigner(t)
	m, _ := servedMailbox(t, s)
	_ = m

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, body["token"]+"|"+body["sig"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"frames":[]}`))
	}))
	defer srv.Close()

	for i := 0; i < 3; i++ {
		if _, err := d.Waiting(context.Background(), srv.URL, testNode); err != nil {
			t.Fatal(err)
		}
	}
	for i := range seen {
		for j := i + 1; j < len(seen); j++ {
			if seen[i] == seen[j] {
				t.Fatal("the same challenge and proof were reused across reads")
			}
		}
	}
}

func TestDiscoveryNeverCallsCollect(t *testing.T) {
	// The structural guarantee: if this ever hits /collect it drains a real
	// recipient's mailbox at page load.
	d, _ := discoverySigner(t)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"frames":[]}`))
	}))
	defer srv.Close()

	if _, err := d.Waiting(context.Background(), srv.URL, testNode); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.Contains(p, "collect") {
			t.Fatalf("discovery called %s", p)
		}
	}
	if len(paths) != 1 || paths[0] != "/mailbox/v1/peek" {
		t.Fatalf("unexpected calls: %v", paths)
	}
}

func TestDiscoveryRefusalIsNotAnEmptyInbox(t *testing.T) {
	// The exact confusion this whole capability is guarding against: a lapsed
	// authorization must not render as "nobody tipped you".
	d, _ := discoverySigner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"mailbox: not served"}`))
	}))
	defer srv.Close()

	frames, err := d.Waiting(context.Background(), srv.URL, testNode)
	if err == nil {
		t.Fatal("a refusal was reported as a successful read")
	}
	if frames != nil {
		t.Fatal("a refusal returned frames")
	}
	if !strings.Contains(err.Error(), "not served") {
		t.Fatalf("the volunteer's own reason was lost: %v", err)
	}
}

func TestDiscoveryUnreachableIsNotAnEmptyInbox(t *testing.T) {
	d, _ := discoverySigner(t)
	if _, err := d.Waiting(context.Background(), "http://127.0.0.1:1", testNode); err == nil {
		t.Fatal("an unreachable volunteer read as an empty mailbox")
	}
}

func TestDiscoveryRefusesToExistWithoutAuthority(t *testing.T) {
	s := newSigner(t)
	if _, err := NewMailboxDiscovery(s.address(), nil); err == nil {
		t.Fatal("built a discovery client that cannot sign")
	}
	if _, err := NewMailboxDiscovery(Address{}, func([32]byte) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("built a discovery client with no recipient")
	}
}

func TestDiscoveryCannotReadAnotherRecipientsMailbox(t *testing.T) {
	// It signs as itself and the volunteer checks that. Asking for somebody
	// else is not an option this type offers, and forging it fails at the
	// volunteer.
	_, alice := discoverySigner(t)
	m, srv := servedMailbox(t, alice)
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); err != nil {
		t.Fatal(err)
	}

	mallory := newSigner(t)
	bad, err := NewMailboxDiscovery(alice.address(), func(raw [32]byte) ([]byte, error) {
		return mallory.sign(raw), nil // right claim, wrong key
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Waiting(context.Background(), srv.URL, testNode); err == nil {
		t.Fatal("a stranger read alice's mailbox")
	}
	if m.Pending(alice.address()) != 1 {
		t.Fatal("a refused read consumed the queue")
	}
}

// ---- the operator route ------------------------------------------------------

func TestWaitingRouteIsTokenGatedAndNonConsuming(t *testing.T) {
	d, s := discoverySigner(t)
	m, vol := servedMailbox(t, s)
	if err := m.Deliver(s.address(), Envelope{Type: MsgStatePropose, Channel: "dd"}); err != nil {
		t.Fatal(err)
	}

	api, err := NewAPI(newTestCoordinator(t), nil, "operator-token")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.WithMailboxDiscovery(d).Handler())
	defer srv.Close()

	url := srv.URL + "/v1/mailbox/waiting?volunteer=" + vol.URL + "&node_id=" + testNode

	// No token.
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated read got %d", resp.StatusCode)
	}
	if m.Pending(s.address()) != 1 {
		t.Fatal("an unauthenticated request consumed the queue")
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer operator-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorised read got %d", resp.StatusCode)
	}
	var out struct {
		Frames   []Envelope `json:"frames"`
		Consumed bool       `json:"consumed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Frames) != 1 || out.Consumed {
		t.Fatalf("frames=%d consumed=%v", len(out.Frames), out.Consumed)
	}
	if m.Pending(s.address()) != 1 {
		t.Fatal("the route consumed the queue")
	}
}

func TestWaitingRouteSaysSoWhenItCannotLook(t *testing.T) {
	api, err := NewAPI(newTestCoordinator(t), nil, "operator-token")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler()) // no discovery attached
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/mailbox/waiting?volunteer=http://x", nil)
	req.Header.Set("Authorization", "Bearer operator-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("a node that cannot look answered %d, not 501", resp.StatusCode)
	}
}

func TestWaitingRouteReportsAnUnreachableVolunteerAsAFailure(t *testing.T) {
	d, _ := discoverySigner(t)
	api, err := NewAPI(newTestCoordinator(t), nil, "operator-token")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.WithMailboxDiscovery(d).Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet,
		srv.URL+"/v1/mailbox/waiting?volunteer=http://127.0.0.1:1", nil)
	req.Header.Set("Authorization", "Bearer operator-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("an unreachable volunteer answered %d, not 502", resp.StatusCode)
	}
}

func TestWaitingRouteRejectsWrites(t *testing.T) {
	// Discovery is a read. A POST here would be somebody reaching for an
	// acceptance path that must stay on the recipient's explicit action.
	d, _ := discoverySigner(t)
	api, err := NewAPI(newTestCoordinator(t), nil, "operator-token")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.WithMailboxDiscovery(d).Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/mailbox/waiting?volunteer=http://x",
		strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer operator-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST answered %d", resp.StatusCode)
	}
}
