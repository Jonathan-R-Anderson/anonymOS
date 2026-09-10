package heartbeat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type testSigner struct {
	key crypto.PrivKey
	id  peer.ID
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{key: key, id: id}
}

func (s *testSigner) ID() string                    { return s.id.String() }
func (s *testSigner) Sign(m []byte) ([]byte, error) { return s.key.Sign(m) }

type captured struct {
	body      []byte
	userAgent string
	nodeID    string
	signature string
}

func capture(t *testing.T) (*httptest.Server, chan captured) {
	t.Helper()
	seen := make(chan captured, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		seen <- captured{
			body: body, userAgent: r.Header.Get("User-Agent"),
			nodeID:    r.Header.Get("X-Syndichan-Node"),
			signature: r.Header.Get("X-Syndichan-Signature"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, seen
}

// A dedicated gateway reports zero capacity. That is how the frontend tells it
// apart from a storage node, so it must survive the round trip intact.
func TestGatewayHeartbeatReportsZeroCapacity(t *testing.T) {
	server, seen := capture(t)
	signer := newTestSigner(t)
	client := &Client{
		Signer: signer, Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{CapacityBytes: 0, GatewayEnabled: true, GatewayVerified: false}
		},
	}
	client.Send(context.Background())

	item := <-seen
	if item.userAgent != UserAgent {
		t.Fatalf("User-Agent is %q, want %q", item.userAgent, UserAgent)
	}
	if item.nodeID != signer.ID() {
		t.Fatalf("node header is %q, want %q", item.nodeID, signer.ID())
	}
	var payload map[string]any
	if err := json.Unmarshal(item.body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["capacity_bytes"] != float64(0) {
		t.Fatalf("capacity_bytes is %v, want 0", payload["capacity_bytes"])
	}
	if payload["gateway_enabled"] != true {
		t.Fatal("gateway_enabled was not reported")
	}
	if payload["gateway_verified"] != false {
		t.Fatal("an unverified gateway claimed verification")
	}
	if _, present := payload["gateway_registration"]; present {
		t.Fatal("a registration was attached without one being held")
	}
	// The signature must cover the exact bytes the server received.
	signature, err := base64.RawStdEncoding.DecodeString(item.signature)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := signer.key.GetPublic().Verify(item.body, signature)
	if err != nil || !ok {
		t.Fatalf("heartbeat signature does not verify the transmitted body: %v", err)
	}
}

func TestStorageHeartbeatReportsItsCapacity(t *testing.T) {
	server, seen := capture(t)
	client := &Client{
		Signer: newTestSigner(t), Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{CapacityBytes: 20 << 30}
		},
	}
	client.Send(context.Background())

	var payload map[string]any
	if err := json.Unmarshal((<-seen).body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["capacity_bytes"] != float64(20<<30) {
		// int64, because an untyped 20<<30 defaults to `int` and does not fit in
		// one on 32-bit platforms — the linux/arm release target. The comparison
		// above already says float64 and was never affected.
		t.Fatalf("capacity_bytes is %v, want %d", payload["capacity_bytes"], int64(20<<30))
	}
	if payload["gateway_enabled"] != false {
		t.Fatal("a storage node reported a gateway role it does not have")
	}
}

// Every send takes a fresh snapshot, so a gateway that becomes verified is
// reflected in the next beacon rather than at the next restart.
func TestSnapshotIsSampledPerSend(t *testing.T) {
	server, seen := capture(t)
	verified := false
	client := &Client{
		Signer: newTestSigner(t), Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{GatewayEnabled: true, GatewayVerified: verified}
		},
	}
	client.Send(context.Background())
	verified = true
	client.Send(context.Background())

	for index, want := range []bool{false, true} {
		var payload map[string]any
		if err := json.Unmarshal((<-seen).body, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["gateway_verified"] != want {
			t.Fatalf("send %d reported gateway_verified=%v, want %v",
				index, payload["gateway_verified"], want)
		}
	}
}

// A node with no identity must not post an unsigned beacon.
func TestSendWithoutSignerIsANoOp(t *testing.T) {
	server, seen := capture(t)
	client := &Client{Endpoint: server.URL, HTTP: server.Client()}
	client.Send(context.Background())
	select {
	case <-seen:
		t.Fatal("a heartbeat was sent without a signing identity")
	default:
	}
}

// The heartbeat must never be routed through a proxy: its whole purpose is to
// originate from the node's real address.
func TestDirectClientHasNoProxy(t *testing.T) {
	transport, ok := DirectHTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatal("heartbeat transport is not an *http.Transport")
	}
	if transport.Proxy != nil {
		t.Fatal("heartbeat transport would honour a proxy")
	}
}

// A node that has never completed a dispersal pass must send NO placement key at
// all. The coordinator draws an absent block as "not reporting"; a present block
// full of zeros draws as a node with no failures and a fully dispersed corpus.
// That substitution -- an unknown rendered as a number -- is the single most
// common failure shape in this project, and is exactly how a backlog counter
// passed for replication while every node stayed empty.
func TestANodeWithNoObservedPassSendsNoPlacementKey(t *testing.T) {
	server, seen := capture(t)
	client := &Client{
		Signer: newTestSigner(t), Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{CapacityBytes: 20 << 30, Placement: nil}
		},
	}
	client.Send(context.Background())

	item := <-seen
	var payload map[string]any
	if err := json.Unmarshal(item.body, &payload); err != nil {
		t.Fatal(err)
	}
	if _, present := payload["placement"]; present {
		t.Fatalf("an unmeasured node reported placement health anyway: %s", item.body)
	}
}

// And the reason must reach the coordinator, in the signed body. "3 failures" is
// undiagnosable; "3 failures: storage capacity exceeded" is the whole point of
// phase 4.3.
func TestPlacementHealthAndItsRefusalReasonsAreSignedAndSent(t *testing.T) {
	server, seen := capture(t)
	signer := newTestSigner(t)
	outstanding, deferred, unreadable := 2, 1, 0
	client := &Client{
		Signer: signer, Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{
				CapacityBytes: 20 << 30,
				Placement: &Placement{
					Objects: 11640, UnderReplicated: 402, LocalOnly: 7,
					FullyDispersed: 11238, Placed: 6, Failed: 3,
					Attempted: 40, Peers: 9, AgeSeconds: 118,
					RecallsOutstanding: &outstanding,
					RecallsDeferred:    &deferred,
					RecallsUnreadable:  &unreadable,
					Refusals: []Refusal{
						{Peer: "12D3KooWFullDis", Count: 3, Reason: "storage capacity exceeded"},
					},
				},
			}
		},
	}
	client.Send(context.Background())

	item := <-seen
	var payload struct {
		Placement *Placement `json:"placement"`
	}
	if err := json.Unmarshal(item.body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Placement == nil {
		t.Fatalf("the placement block never made it onto the wire: %s", item.body)
	}
	if payload.Placement.UnderReplicated != 402 || payload.Placement.Failed != 3 {
		t.Fatalf("counters did not survive the round trip: %+v", payload.Placement)
	}
	if len(payload.Placement.Refusals) != 1 ||
		payload.Placement.Refusals[0].Reason != "storage capacity exceeded" {
		t.Fatalf("the refusal reason did not survive: %+v", payload.Placement.Refusals)
	}
	if payload.Placement.RecallsOutstanding == nil || *payload.Placement.RecallsOutstanding != 2 {
		t.Fatalf("recall counters did not survive: %+v", payload.Placement)
	}
	// The added fields must not break the one guarantee the coordinator relies
	// on: the signature covers the exact bytes it received.
	signature, err := base64.RawStdEncoding.DecodeString(item.signature)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := signer.key.GetPublic().Verify(item.body, signature)
	if err != nil || !ok {
		t.Fatalf("a heartbeat carrying placement health does not verify: %v", err)
	}
}

// An unreadable recall ledger sends no recall keys rather than zeros: "nothing
// outstanding" and "I could not tell" must not arrive as the same document.
func TestAnUnreadableRecallLedgerSendsNoRecallCounts(t *testing.T) {
	server, seen := capture(t)
	client := &Client{
		Signer: newTestSigner(t), Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{CapacityBytes: 20 << 30, Placement: &Placement{Objects: 5}}
		},
	}
	client.Send(context.Background())

	item := <-seen
	var payload struct {
		Placement map[string]any `json:"placement"`
	}
	if err := json.Unmarshal(item.body, &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"recalls_outstanding", "recalls_deferred", "recalls_unreadable"} {
		if _, present := payload.Placement[key]; present {
			t.Errorf("%s was reported without the ledger being readable: %s", key, item.body)
		}
	}
	if _, present := payload.Placement["objects"]; !present {
		t.Error("the counters that WERE measured went missing with the ones that were not")
	}
}
