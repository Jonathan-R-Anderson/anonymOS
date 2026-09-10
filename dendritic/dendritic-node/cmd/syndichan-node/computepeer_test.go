//go:build linux

package main

// The relay and the receiving adapter.
//
// The relay's whole job is to keep two facts apart: the peer declined, and the
// peer could not be reached. The site charges a job differently for each — a
// decline leaves it QUEUED, unreachability moves on — so a relay that collapsed
// them would silently burn submissions. Most of what follows is that one
// distinction, from both directions.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/p2p"
)

// A real, well-formed peer id. Written out rather than generated because the
// relay must reject an id it cannot decode, and a test that only ever passes
// valid ones would not notice if it stopped checking.
const testPeerID = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"

// fakePeers stands in for the node's libp2p side.
type fakePeers struct {
	status       int
	body         []byte
	err          error
	calls        int
	sawOperation string
	sawPayload   []byte
	destinations map[string]string
	destErr      error
}

func (f *fakePeers) AddPeerDestination(id peer.ID, destination string) error {
	if f.destinations == nil {
		f.destinations = map[string]string{}
	}
	f.destinations[id.String()] = destination
	return f.destErr
}

func (f *fakePeers) SendCompute(_ context.Context, _ peer.ID, operation string, payload []byte) (int, []byte, error) {
	f.calls++
	f.sawOperation = operation
	f.sawPayload = append([]byte(nil), payload...)
	if f.err != nil {
		return 0, nil, f.err
	}
	return f.status, f.body, nil
}

func relayTo(t *testing.T, peers *fakePeers, verb string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	api := &bridgeAPI{peers: peers, logger: log.New(io.Discard, "", 0)}
	rec := httptest.NewRecorder()
	api.handleComputePeer(rec, httptest.NewRequest(
		http.MethodPost, "/compute/peer/"+verb, bytes.NewReader(raw)))
	return rec
}

// The happy path: the peer's own status and body reach the site untouched, and
// the job was forwarded byte for byte rather than reassembled on the way.
func TestTheRelayReturnsThePeersOwnAnswer(t *testing.T) {
	peers := &fakePeers{status: http.StatusOK, body: []byte(`{"ticket":"abc","accepted":true}`)}
	rec := relayTo(t, peers, "submit", map[string]any{
		"peer":        testPeerID,
		"destination": strings.Repeat("a", 52),
		"request":     map[string]any{"job_id": "11", "workload": "embed"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want the peer's own 200: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"ticket":"abc","accepted":true}` {
		t.Fatalf("the peer's answer was rewritten: %s", rec.Body.String())
	}
	if peers.sawOperation != p2p.ComputeSubmit {
		t.Fatalf("the relay sent operation %q", peers.sawOperation)
	}
	var forwarded map[string]any
	if err := json.Unmarshal(peers.sawPayload, &forwarded); err != nil {
		t.Fatal(err)
	}
	if forwarded["job_id"] != "11" || forwarded["workload"] != "embed" {
		t.Fatalf("the job was not forwarded intact: %s", peers.sawPayload)
	}
	// The dialling hint from the peer's own heartbeat was taught to the node.
	if peers.destinations[testPeerID] != strings.Repeat("a", 52) {
		t.Fatalf("the destination was not passed on: %v", peers.destinations)
	}
}

// A REFUSAL is reported as a refusal. The peer said 503 with a reason, and the
// relay must hand that on rather than converting a considered no into an error.
func TestTheRelayReportsARefusalAsTheNodesOwnAnswer(t *testing.T) {
	peers := &fakePeers{
		status: http.StatusServiceUnavailable,
		body:   []byte(`{"admitted":false,"reason":"the machine is warm","retryable":true}`),
	}
	rec := relayTo(t, peers, "admit", map[string]any{
		"peer": testPeerID, "request": map[string]any{"device": "cpu"},
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want the peer's own 503", rec.Code)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["unreachable"] == true {
		t.Fatal("a node that answered was marked unreachable")
	}
	if decoded["reason"] != "the machine is warm" {
		t.Fatalf("the node's reason was lost: %s", rec.Body.String())
	}
	if decoded["retryable"] != true {
		t.Fatalf("a temporary refusal was reported as permanent: %s", rec.Body.String())
	}
}

// UNREACHABILITY is reported as unreachability, and — the part that matters —
// it is marked in the BODY. A status alone cannot carry it: the site reads 5xx
// as "the node declined", so without the marker every failed dial would be
// filed as a volunteer's considered refusal.
func TestTheRelayMarksAnUnreachablePeerInTheBody(t *testing.T) {
	peers := &fakePeers{err: errors.New("all dials failed")}
	rec := relayTo(t, peers, "admit", map[string]any{
		"peer": testPeerID, "request": map[string]any{"device": "cpu"},
	})
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["unreachable"] != true {
		t.Fatalf("a peer that was never reached was not marked unreachable: %s", rec.Body.String())
	}
	if !strings.Contains(decoded["error"].(string), "all dials failed") {
		t.Fatalf("the dial failure was not explained: %s", rec.Body.String())
	}
	if decoded["reason"] != nil || decoded["retryable"] != nil {
		t.Fatalf("unreachability was dressed up as a refusal: %s", rec.Body.String())
	}
}

// An oversized job is refused HERE, before a dial. It will not fit however many
// times it is asked, so it must reach the site as a permanent request error and
// not as unreachability — which the site would retry for ever.
func TestTheRelayRefusesAnOversizedJobWithoutDialling(t *testing.T) {
	peers := &fakePeers{status: http.StatusOK, body: []byte(`{"accepted":true}`)}
	huge := strings.Repeat("x", int(p2p.MaxComputeRequest(p2p.ComputeAdmit))+1)
	rec := relayTo(t, peers, "admit", map[string]any{
		"peer": testPeerID, "request": map[string]any{"device": "cpu", "pad": huge},
	})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413: %s", rec.Code, rec.Body.String())
	}
	if peers.calls != 0 {
		t.Fatal("an oversized job was dialled out anyway")
	}
	if strings.Contains(rec.Body.String(), "unreachable") {
		t.Fatalf("a request that is too big was reported as unreachability: %s", rec.Body.String())
	}
}

// A verb the relay does not define is a 404 here, never an operation name
// forwarded to a peer.
func TestTheRelayRefusesAVerbItDoesNotDefine(t *testing.T) {
	peers := &fakePeers{status: http.StatusOK, body: []byte(`{}`)}
	rec := relayTo(t, peers, "teleport", map[string]any{"peer": testPeerID})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
	if peers.calls != 0 {
		t.Fatal("an undefined verb was sent to a peer")
	}
}

// An unusable peer id is our request being wrong, not a node being down.
func TestTheRelayRefusesAnUndecodablePeer(t *testing.T) {
	peers := &fakePeers{status: http.StatusOK, body: []byte(`{}`)}
	rec := relayTo(t, peers, "admit", map[string]any{"peer": "not-a-peer-id"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "unreachable") {
		t.Fatalf("a malformed request was reported as unreachability: %s", rec.Body.String())
	}
	if peers.calls != 0 {
		t.Fatal("a request naming no valid peer was dialled out")
	}
}

// A bad dialling hint is not fatal: the relay may already be connected to the
// peer, in which case the dial works and the hint never mattered.
func TestABadDestinationHintDoesNotStopTheRelay(t *testing.T) {
	peers := &fakePeers{
		status: http.StatusOK, body: []byte(`{"admitted":true}`),
		destErr: errors.New("invalid I2P base32 destination"),
	}
	rec := relayTo(t, peers, "admit", map[string]any{
		"peer": testPeerID, "destination": "nonsense", "request": map[string]any{"device": "cpu"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if peers.calls != 1 {
		t.Fatal("a bad hint stopped the relay dialling at all")
	}
}

// ---- the receiving half ----

// A peer's frame is served by the SAME handlers the loopback API serves, so the
// closed catalogue table applies to a peer exactly as it does to the site.
// Proven by the property that only that table produces: an unknown workload is
// refused with a 400 and the refusal names no image.
func TestAPeerFrameIsServedByTheSameHandlers(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	handler := api.peerComputeHandler()

	request, err := json.Marshal(map[string]any{
		"job_id": "job-1", "device": "cpu", "workload": "definitely-not-a-workload",
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := handler(context.Background(), peer.ID("peer-a"), p2p.ComputeSubmit, request)
	if status != http.StatusBadRequest {
		t.Fatalf("got %d, want the same 400 the HTTP path gives: %s", status, body)
	}
	for _, leak := range []string{"registry.local", "compute-embed"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("the refusal leaked %q over the peer path: %s", leak, body)
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 0 {
		t.Fatalf("an unknown workload started %d container(s)", len(runtime.specs))
	}
}

// An operation the adapter does not define never reaches a handler.
func TestAnUndefinedOperationNeverReachesAHandler(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	status, body := api.peerComputeHandler()(
		context.Background(), peer.ID("peer-a"), "compute-teleport", []byte(`{}`))
	if status != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", status)
	}
	if !strings.Contains(string(body), "unsupported compute operation") {
		t.Fatalf("the refusal did not say what was refused: %s", body)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 0 {
		t.Fatal("an undefined operation started a container")
	}
}

// One peer cannot collect another's result.
//
// Job ids are the SITE'S OWN small integers. Before compute rode the peer
// protocol the result map was the site's private namespace, because only
// loopback could reach it. Now any peer can submit and poll, and an unscoped map
// would hand whoever asked for "job-7" whatever job-7 produced for somebody
// else — the output of a stranger's job, for the cost of guessing a small
// number.
func TestOnePeerCannotCollectAnotherPeersResult(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	handler := api.peerComputeHandler()
	submitter, stranger := peer.ID("peer-a"), peer.ID("peer-b")

	request, err := json.Marshal(map[string]any{
		"job_id": "job-7", "device": "cpu", "language": "python", "entrypoint": "main.py",
		"files": map[string]string{"main.py": "print(1)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := handler(context.Background(), submitter, p2p.ComputeSubmit, request)
	if status != http.StatusOK {
		t.Fatalf("the job was not accepted (%d): %s", status, body)
	}
	runtime.awaitSpec(t)

	poll, err := json.Marshal(map[string]any{"job_id": "job-7"})
	if err != nil {
		t.Fatal(err)
	}
	// The stranger asks for the same id. The node has never heard of it — from
	// that peer — and says so, rather than handing over the answer.
	strangerStatus, strangerBody := handler(context.Background(), stranger, p2p.ComputeResult, poll)
	if strangerStatus != http.StatusNotFound {
		t.Fatalf("a stranger polling somebody else's job id got %d: %s",
			strangerStatus, strangerBody)
	}
	if strings.Contains(string(strangerBody), "exit_code") {
		t.Fatalf("a stranger was handed another peer's result: %s", strangerBody)
	}

	// The submitter still gets its own result, which is the half that must not
	// have been broken by scoping.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ownStatus, ownBody := handler(context.Background(), submitter, p2p.ComputeResult, poll)
		if ownStatus != http.StatusOK {
			t.Fatalf("the submitter polling its own job got %d: %s", ownStatus, ownBody)
		}
		var decoded map[string]any
		if err := json.Unmarshal(ownBody, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["done"] == true {
			result, _ := decoded["result"].(map[string]any)
			if result["job_id"] != "job-7" {
				t.Fatalf("the result came back under the wrong id: %s", ownBody)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the submitter never got its own result back")
}

// A loopback caller — the site, on the same machine — carries no peer header and
// keeps exactly the behaviour it has always had.
func TestALoopbackCallerIsUnscopedAsBefore(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-8", "device": "cpu", "language": "python", "entrypoint": "main.py",
		"files": map[string]string{"main.py": "print(1)"},
	})
	if rec.Code != http.StatusOK || body["accepted"] != true {
		t.Fatalf("the loopback submit was not accepted (%d): %v", rec.Code, body)
	}
	runtime.awaitSpec(t)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		poll := httptest.NewRecorder()
		api.handleResult(poll, httptest.NewRequest(http.MethodPost, "/compute/result",
			strings.NewReader(`{"job_id":"job-8"}`)))
		var decoded map[string]any
		if err := json.Unmarshal(poll.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["done"] == true {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a loopback caller could not read back its own result")
}
