package channel

// SCPP/1 over HTTP — roadmap P8.
//
// Two halves. First the carrier on its own, against a stub handler: it has to
// stay dumb, and the way to prove that is to show it passes everything through
// and decides nothing. Then the whole thing, with the REAL browser client
// paying a REAL coordinator over a real HTTP server — the only test that would
// catch the two implementations quietly drifting apart.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- the carrier on its own -------------------------------------------------

type stubHandler struct {
	mu    sync.Mutex
	seen  []Envelope
	reply *Envelope
	err   error
	block chan struct{}
}

func (s *stubHandler) Handle(ctx context.Context, env Envelope) (*Envelope, error) {
	s.mu.Lock()
	s.seen = append(s.seen, env)
	s.mu.Unlock()
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.reply, s.err
}

func (s *stubHandler) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func webPeerServer(t *testing.T, h Handler) (*httptest.Server, *WebPeer) {
	t.Helper()
	wp := &WebPeer{Handler: h, Timeout: 2 * time.Second}
	srv := httptest.NewServer(wp.HTTPHandler())
	t.Cleanup(srv.Close)
	return srv, wp
}

func postFrame(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url+"/scpp/v1", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeEnvelope(t *testing.T, resp *http.Response) Envelope {
	t.Helper()
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	return env
}

func TestWebPeerPassesAFrameThroughUntouched(t *testing.T) {
	reply, err := newEnvelope(MsgStateAccept, [32]byte{1}, StateAcceptBody{Nonce: 9})
	if err != nil {
		t.Fatalf("newEnvelope: %v", err)
	}
	stub := &stubHandler{reply: &reply}
	srv, _ := webPeerServer(t, stub)

	out, err := newEnvelope(MsgStateRequest, [32]byte{1}, StateRequestBody{})
	if err != nil {
		t.Fatalf("newEnvelope: %v", err)
	}
	resp := postFrame(t, srv.URL, out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decodeEnvelope(t, resp)
	if got.Type != MsgStateAccept {
		t.Errorf("reply type %q", got.Type)
	}
	if stub.count() != 1 {
		t.Errorf("handler saw %d frames", stub.count())
	}
	if stub.seen[0].Type != MsgStateRequest {
		t.Errorf("handler saw %q, not what was sent", stub.seen[0].Type)
	}
}

// The distinction the whole design rests on: a refusal is a protocol outcome
// the peer must be able to read and act on, not a transport failure.
func TestWebPeerReturnsARejectionAsASuccessfulReply(t *testing.T) {
	reject, err := newEnvelope(MsgStateReject, [32]byte{1},
		StateRejectBody{Code: RejectInsufficient})
	if err != nil {
		t.Fatalf("newEnvelope: %v", err)
	}
	// Note the nil error: this is how the coordinator returns a rejection.
	srv, _ := webPeerServer(t, &stubHandler{reply: &reject})

	out, _ := newEnvelope(MsgStatePropose, [32]byte{1}, StateProposeBody{})
	resp := postFrame(t, srv.URL, out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a rejection came back as HTTP %d; it is an outcome, not an error",
			resp.StatusCode)
	}
	if got := decodeEnvelope(t, resp); got.Type != MsgStateReject {
		t.Errorf("reply type %q", got.Type)
	}
}

func TestWebPeerAnswers204WhenThereIsNothingToSay(t *testing.T) {
	srv, _ := webPeerServer(t, &stubHandler{reply: nil})

	out, _ := newEnvelope(MsgStateAccept, [32]byte{1}, StateAcceptBody{Nonce: 1})
	resp := postFrame(t, srv.URL, out)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", resp.StatusCode)
	}
}

func TestWebPeerReportsAHandlerFailureBothWays(t *testing.T) {
	srv, _ := webPeerServer(t, &stubHandler{err: errors.New("channel is closing")})

	out, _ := newEnvelope(MsgStatePropose, [32]byte{1}, StateProposeBody{})
	resp := postFrame(t, srv.URL, out)

	// The status is for fetch() and every proxy in between; the envelope is for
	// the client's protocol code. Both audiences are addressed.
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status %d, want 422", resp.StatusCode)
	}
	env := decodeEnvelope(t, resp)
	if env.Type != MsgError {
		t.Fatalf("reply type %q, want ERROR", env.Type)
	}
	var body ErrorBody
	if err := json.Unmarshal(env.Body, &body); err != nil {
		t.Fatalf("error body: %v", err)
	}
	if !strings.Contains(body.Detail, "closing") {
		t.Errorf("detail %q lost the cause", body.Detail)
	}
}

func TestWebPeerRefusesGarbage(t *testing.T) {
	srv, _ := webPeerServer(t, &stubHandler{})
	resp, err := http.Post(srv.URL+"/scpp/v1", "application/json",
		strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	if env := decodeEnvelope(t, resp); env.Type != MsgError {
		t.Errorf("reply type %q, want ERROR", env.Type)
	}
}

func TestWebPeerRefusesAnotherProtocolVersion(t *testing.T) {
	stub := &stubHandler{}
	srv, _ := webPeerServer(t, stub)

	resp := postFrame(t, srv.URL, map[string]any{"v": 99, "type": MsgStateRequest})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	if stub.count() != 0 {
		t.Error("a frame from an unknown version reached the handler")
	}
}

func TestWebPeerRefusesAnOversizedFrameBeforeAllocating(t *testing.T) {
	stub := &stubHandler{}
	srv, _ := webPeerServer(t, stub)

	huge := strings.Repeat("a", MaxFrameBytes+1024)
	resp, err := http.Post(srv.URL+"/scpp/v1", "application/json",
		strings.NewReader(fmt.Sprintf(`{"v":1,"type":"HELLO","body":%q}`, huge)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("an oversized frame was accepted")
	}
	if stub.count() != 0 {
		t.Error("an oversized frame reached the handler")
	}
}

// A cross-origin JSON POST always preflights, so a browser that cannot get past
// OPTIONS cannot tip at all.
func TestWebPeerAnswersThePreflight(t *testing.T) {
	srv, _ := webPeerServer(t, &stubHandler{})

	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/scpp/v1", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Origin", "https://syndichan.org")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("allow-origin %q", got)
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Errorf("content-type is not permitted, so the POST cannot carry JSON")
	}
}

// The pairing that turns a public endpoint into a confused deputy. Any origin is
// deliberate; credentials with it would be a hole, and the browser would refuse
// the combination anyway.
func TestWebPeerNeverAllowsCredentials(t *testing.T) {
	srv, _ := webPeerServer(t, &stubHandler{})

	out, _ := newEnvelope(MsgStateRequest, [32]byte{1}, StateRequestBody{})
	resp := postFrame(t, srv.URL, out)
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("allow-credentials is set to %q alongside a wildcard origin", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("cache-control %q: frames about money must not be cached", got)
	}
}

func TestWebPeerRefusesOtherMethods(t *testing.T) {
	srv, _ := webPeerServer(t, &stubHandler{})
	resp, err := http.Get(srv.URL + "/scpp/v1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status %d, want 405", resp.StatusCode)
	}
}

// Shedding beats dying. A node under a stampede must still be able to answer
// the peers it already has.
func TestWebPeerShedsRatherThanQueueingWithoutLimit(t *testing.T) {
	block := make(chan struct{})
	stub := &stubHandler{block: block, reply: nil}
	wp := &WebPeer{Handler: stub, Timeout: 5 * time.Second, Concurrency: 1}
	srv := httptest.NewServer(wp.HTTPHandler())
	defer srv.Close()

	out, _ := newEnvelope(MsgStateRequest, [32]byte{1}, StateRequestBody{})
	raw, _ := json.Marshal(out)

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		resp, err := http.Post(srv.URL+"/scpp/v1", "application/json", strings.NewReader(string(raw)))
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started

	// Wait for the first request to actually occupy the slot.
	deadline := time.Now().Add(2 * time.Second)
	for stub.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	resp, err := http.Post(srv.URL+"/scpp/v1", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error(`no Retry-After: "later" and "never" must be distinguishable`)
	}

	close(block)
	<-done
}

// ---- the whole thing --------------------------------------------------------

// A real browser client, a real HTTP carrier, a real coordinator.
//
// Everything else in this package tests the node against itself, and the
// JavaScript tests test the browser against the contract's vectors. Only this
// puts the two live implementations on opposite ends of one payment, which is
// the arrangement they will actually be in.
func TestABrowserPaysARealNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	script := filepath.Join(root, "browser-test", "pay-node.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("driver missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules", "ethers")); err != nil {
		t.Skip("ethers is not installed in proof-of-facilitation")
	}

	// The browser's key, fixed so the test is reproducible.
	tipperKey := "0x" + strings.Repeat("11", 32)
	const tipperAddr = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"

	tipper := mustAddr(t, tipperAddr)
	recipientKey := newSigner(t)
	recipient := recipientKey.address()
	contract := mustAddr(t, deployedChannelManager)

	// The tipper funds the channel — D3. Which side that lands on depends on the
	// address ordering, not on who is paying.
	deposit := anon(500)
	partyA, partyB := SortParties(tipper, recipient)
	depositA, depositB := new(big.Int), new(big.Int)
	if partyA == tipper {
		depositA = deposit
	} else {
		depositB = deposit
	}

	chain := NewFakeChain()
	id := chain.Add(partyA, partyB, depositA, depositB)
	payee := newWiredNode(t, recipientKey, chain, contract)

	wp := &WebPeer{Handler: payee.coord, Timeout: 5 * time.Second}
	srv := httptest.NewServer(wp.HTTPHandler())
	defer srv.Close()

	amount := anon(25)
	cmd := exec.Command(node, script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SCPP_URL="+srv.URL+"/scpp/v1",
		"TIP_KEY="+tipperKey,
		"RECIPIENT="+recipient.Hex(),
		"MANAGER="+contract.Hex(),
		"CHAIN_ID=1",
		"PARTY_A="+partyA.Hex(),
		"PARTY_B="+partyB.Hex(),
		"DEPOSIT_A="+depositA.String(),
		"DEPOSIT_B="+depositB.String(),
		"AMOUNT="+amount.String(),
	)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driver failed: %v\n%s", err, stderr)
	}

	var result struct {
		Outcome string `json:"outcome"`
		Nonce   uint64 `json:"nonce"`
		Detail  string `json:"detail"`
		Code    string `json:"code"`
		Tipper  string `json:"tipper"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%s", err, out)
	}
	if result.Outcome != "completed" {
		t.Fatalf("the browser reported %q (%s %s)", result.Outcome, result.Code, result.Detail)
	}
	if result.Tipper != tipperAddr {
		t.Fatalf("the driver used key %s, not the one this test funded", result.Tipper)
	}

	// The node's own view. This is the assertion that matters: the payment did
	// not merely round-trip, it moved value in this node's authoritative record.
	balances, err := payee.coord.Balances(id)
	if err != nil {
		t.Fatalf("balances: %v", err)
	}
	if balances.Mine.Cmp(amount) != 0 {
		t.Errorf("recipient holds %s, want %s", balances.Mine, amount)
	}
	if balances.Nonce != 1 {
		t.Errorf("node at nonce %d, want 1", balances.Nonce)
	}
	if balances.Theirs.Cmp(new(big.Int).Sub(deposit, amount)) != 0 {
		t.Errorf("tipper holds %s, want %s", balances.Theirs, new(big.Int).Sub(deposit, amount))
	}
}

// A retry with the same intent must be one payment, across the whole stack.
func TestABrowserRetryPaysOnce(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules", "ethers")); err != nil {
		t.Skip("ethers is not installed in proof-of-facilitation")
	}
	script := filepath.Join(root, "browser-test", "pay-node.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("driver missing: %v", err)
	}

	tipperKey := "0x" + strings.Repeat("11", 32)
	tipper := mustAddr(t, "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A")
	recipientKey := newSigner(t)
	recipient := recipientKey.address()
	contract := mustAddr(t, deployedChannelManager)

	deposit := anon(500)
	partyA, partyB := SortParties(tipper, recipient)
	depositA, depositB := new(big.Int), new(big.Int)
	if partyA == tipper {
		depositA = deposit
	} else {
		depositB = deposit
	}
	chain := NewFakeChain()
	id := chain.Add(partyA, partyB, depositA, depositB)
	payee := newWiredNode(t, recipientKey, chain, contract)

	wp := &WebPeer{Handler: payee.coord, Timeout: 5 * time.Second}
	srv := httptest.NewServer(wp.HTTPHandler())
	defer srv.Close()

	amount := anon(25)
	intentHex := strings.Repeat("ab", 32)

	run := func() string {
		cmd := exec.Command(node, script)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"SCPP_URL="+srv.URL+"/scpp/v1",
			"TIP_KEY="+tipperKey,
			"RECIPIENT="+recipient.Hex(),
			"MANAGER="+contract.Hex(),
			"CHAIN_ID=1",
			"PARTY_A="+partyA.Hex(),
			"PARTY_B="+partyB.Hex(),
			"DEPOSIT_A="+depositA.String(),
			"DEPOSIT_B="+depositB.String(),
			"AMOUNT="+amount.String(),
			"INTENT="+intentHex,
		)
		out, err := cmd.Output()
		if err != nil {
			var stderr string
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = string(ee.Stderr)
			}
			t.Fatalf("driver failed: %v\n%s", err, stderr)
		}
		var result struct {
			Outcome string `json:"outcome"`
			Detail  string `json:"detail"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("driver output is not JSON: %v\n%s", err, out)
		}
		return result.Outcome
	}

	if got := run(); got != "completed" {
		t.Fatalf("first attempt: %s", got)
	}
	// The same intent again — a user pressing the button twice. The value must
	// move once.
	run()

	balances, err := payee.coord.Balances(id)
	if err != nil {
		t.Fatalf("balances: %v", err)
	}
	if balances.Mine.Cmp(amount) != 0 {
		t.Errorf("recipient holds %s after a retry, want %s (paid twice?)",
			balances.Mine, amount)
	}
}
