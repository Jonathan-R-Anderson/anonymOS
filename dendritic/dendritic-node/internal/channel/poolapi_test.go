package channel

// The recipient's pool endpoint, driven over real HTTP — roadmap P15 phase 5.
//
// These run the actual mux, with the actual bearer check, against a real
// coordinator holding real co-signed states. Nothing is stubbed except the
// chain, which the surrounding suite already fakes for every other API test.
//
// What is being protected: the endpoint is the ONE place a pool aggregate is
// allowed to exist as a number, so the tests care about (a) it being reachable
// only by the node's operator, and (b) it reporting what the signatures say
// rather than what a caller asked for.

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// poolAPIFor stands the pool surface up in front of the PAYEE, because the pool
// is the recipient's view. apiFor points its API at the payer.
func poolAPIFor(t *testing.T, deposit int64) (*http.Client, string, *wiredNode, *wiredNode, [32]byte, func()) {
	t.Helper()
	payer, payee, id := wiredPair(t, anon(deposit))

	peerAddr, stopPeer := listening(t, payer.coord)
	api, err := NewAPI(payee.coord, func(_ [32]byte, _ Address) (Peer, error) {
		return NewStreamPeer(peerAddr), nil
	}, testToken)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	return srv.Client(), srv.URL, payer, payee, id, func() {
		srv.Close()
		stopPeer()
	}
}

func TestPoolViewIsReachableOnlyWithTheNodeToken(t *testing.T) {
	c, base, _, _, _, stop := poolAPIFor(t, 500)
	defer stop()

	// The aggregate is the single most sensitive number the node computes. An
	// unauthenticated read would publish every recipient's balance to anyone
	// who could reach the port.
	for _, token := range []string{"", "wrong-token", testToken + "x"} {
		code, _ := do(t, c, http.MethodGet, base+"/v1/pool", nil, token)
		if code != http.StatusUnauthorized {
			t.Fatalf("token %q: got %d, want 401", token, code)
		}
	}

	if code, _ := do(t, c, http.MethodGet, base+"/v1/pool", nil, testToken); code != http.StatusOK {
		t.Fatalf("the operator's own token was refused: %d", code)
	}
}

func TestPoolViewIsReadOnly(t *testing.T) {
	c, base, _, _, _, stop := poolAPIFor(t, 500)
	defer stop()

	// A pool holds no value, so there is nothing here to POST to. A write verb
	// that quietly succeeded would be the first step toward a stored balance.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		code, _ := do(t, c, method, base+"/v1/pool", map[string]any{"withdrawable": "999"}, testToken)
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /v1/pool: got %d, want 405", method, code)
		}
	}
}

func TestPoolViewReportsWhatWasActuallyPaid(t *testing.T) {
	c, base, payer, payee, id, stop := poolAPIFor(t, 500)
	defer stop()

	before := poolOf(t, c, base)
	if before.Withdrawable != "0" {
		t.Fatalf("a channel with no payments should be empty, got %q", before.Withdrawable)
	}

	// A real payment through the real coordinator, not a hand-written state.
	payInto(t, payer, payee, id, 120)

	after := poolOf(t, c, base)
	if after.Withdrawable != anon(120).String() {
		t.Fatalf("withdrawable = %q, want %s", after.Withdrawable, anon(120))
	}
	if after.Contributors != 1 {
		t.Fatalf("contributors = %d, want 1", after.Contributors)
	}
	if after.Members != 1 {
		t.Fatalf("members = %d, want 1", after.Members)
	}
}

func TestPoolViewIsRecomputedNotAccumulated(t *testing.T) {
	c, base, payer, payee, id, stop := poolAPIFor(t, 500)
	defer stop()

	payInto(t, payer, payee, id, 70)
	first := poolOf(t, c, base)

	// Reading twice must not add anything. If the endpoint were accumulating
	// into a stored total rather than summing signed states, this is where it
	// would show — and a recipient would believe they held more than they can
	// withdraw.
	second := poolOf(t, c, base)
	if first.Withdrawable != second.Withdrawable {
		t.Fatalf("reading the pool changed it: %q then %q",
			first.Withdrawable, second.Withdrawable)
	}

	payInto(t, payer, payee, id, 30)
	third := poolOf(t, c, base)
	if third.Withdrawable != anon(100).String() {
		t.Fatalf("withdrawable = %q, want %s after 70+30", third.Withdrawable, anon(100))
	}
}

func TestPoolViewOffersACheckpointCandidateForRealValue(t *testing.T) {
	c, base, payer, payee, id, stop := poolAPIFor(t, 500)
	defer stop()

	if got := poolOf(t, c, base); len(got.Candidates) != 0 {
		t.Fatalf("an empty channel is not worth checkpointing, got %d candidates",
			len(got.Candidates))
	}

	payInto(t, payer, payee, id, 250)

	view := poolOf(t, c, base)
	if len(view.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(view.Candidates))
	}
	cand := view.Candidates[0]
	if cand.Amount != anon(250).String() {
		t.Fatalf("candidate amount = %q, want %s", cand.Amount, anon(250))
	}
	if cand.Channel != poolChannelHex(id) {
		t.Fatalf("candidate names the wrong channel")
	}
	if cand.LocksLive {
		t.Fatal("no locks were created, but the candidate reports live locks")
	}
	// The candidate must describe the same money the aggregate reported.
	if cand.Amount != view.Withdrawable {
		t.Fatalf("candidate %q disagrees with aggregate %q", cand.Amount, view.Withdrawable)
	}
}

func TestPoolViewNeverReportsTheCounterpartysSide(t *testing.T) {
	c, base, payer, payee, id, stop := poolAPIFor(t, 500)
	defer stop()

	payInto(t, payer, payee, id, 100)

	// The payer still holds 400 in this channel. The recipient's pool must
	// report 100 — their own side — and must not expose the payer's balance,
	// which is not theirs to see aggregated.
	raw := rawPool(t, c, base)
	if strings.Contains(raw, anon(400).String()) {
		t.Fatalf("the counterparty's balance leaked into the pool view: %s", raw)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, forbidden := range []string{"theirs", "counterparty", "payer", "peer"} {
		if _, present := body[forbidden]; present {
			t.Fatalf("pool view exposes %q", forbidden)
		}
	}
}

func TestPoolViewOfANodeWithNoChannelsIsZeroNotAnError(t *testing.T) {
	// "Nobody has tipped you yet" is an ordinary state. An error here would
	// look like a broken feature to every new recipient.
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	coord := NewCoordinator(store, NewFakeChain(), big.NewInt(1),
		Address{9}, Address{1}, nil)
	api, err := NewAPI(coord, nil, testToken)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	code, body := do(t, srv.Client(), http.MethodGet, srv.URL+"/v1/pool", nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("empty pool: got %d, want 200", code)
	}
	if body["withdrawable"] != "0" {
		t.Fatalf("withdrawable = %v, want \"0\"", body["withdrawable"])
	}
}

// ---- helpers -----------------------------------------------------------------

type poolBody struct {
	Withdrawable string `json:"withdrawable"`
	InFlight     string `json:"in_flight"`
	Members      int    `json:"members"`
	Contributors int    `json:"contributors"`
	Candidates   []struct {
		Channel   string `json:"channel"`
		Amount    string `json:"amount"`
		LocksLive bool   `json:"locks_live"`
	} `json:"candidates"`
}

func rawPool(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/pool", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/pool: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(raw)
}

func poolOf(t *testing.T, c *http.Client, base string) poolBody {
	t.Helper()
	var out poolBody
	if err := json.Unmarshal([]byte(rawPool(t, c, base)), &out); err != nil {
		t.Fatalf("unmarshal pool: %v", err)
	}
	return out
}

// payInto moves value from payer to payee through the REAL coordinator path, so
// the pool sums states that were produced the way production produces them.
func payInto(t *testing.T, payer, payee *wiredNode, id [32]byte, amount int64) {
	t.Helper()
	paidSeq++
	_, err := payer.coord.Pay(context.Background(), id, intent(paidSeq),
		payTransition(amount), directPeer{t, payee.coord})
	if err != nil {
		t.Fatalf("pay %d: %v", amount, err)
	}
}

// paidSeq keeps intents distinct: AppliedAt makes a repeated intent idempotent,
// so reusing one would silently make the second payment a no-op and the test
// would be asserting against a number that never moved.
var paidSeq byte
