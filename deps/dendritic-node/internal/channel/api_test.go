package channel

// P5-4. The HTTP surface, driven through a real http.Server over TCP, against
// a payee reachable over a real SCPP/1 socket.
//
// The interesting assertions are about what the API will NOT do.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testToken = "a-shared-secret-pending-D2"

// apiFor stands up the whole node: coordinator, SCPP/1 listener for the peer,
// and an HTTP surface in front.
func apiFor(t *testing.T, deposit int64) (client *http.Client, base string, payer, payee *wiredNode, id [32]byte, stop func()) {
	t.Helper()
	payer, payee, id = wiredPair(t, anon(deposit))

	peerAddr, stopPeer := listening(t, payee.coord)

	api, err := NewAPI(payer.coord, func(_ [32]byte, _ Address) (Peer, error) {
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

func do(t *testing.T, c *http.Client, method, url string, body any, token string) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func hexID(id [32]byte) string { return hex.EncodeToString(id[:]) }

// ---- the whole stack through HTTP -------------------------------------------

func TestAPaymentDrivenEntirelyOverHTTP(t *testing.T) {
	c, base, payer, payee, id, stop := apiFor(t, 500)
	defer stop()

	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(id)+"/pay",
		payRequest{Intent: hexID(intent(1)), Amount: anon(25).String()}, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	if body["outcome"] != "completed" {
		t.Fatalf("outcome %v", body["outcome"])
	}

	// Both nodes, through the whole stack: HTTP → coordinator → SCPP/1 → TCP →
	// coordinator → state machine → store.
	for name, n := range map[string]*wiredNode{"payer": payer, "payee": payee} {
		bal, err := n.coord.Balances(id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bal.Nonce != 1 {
			t.Fatalf("%s at nonce %d", name, bal.Nonce)
		}
	}
	if got, _ := payee.coord.Balances(id); got.Mine.Cmp(anon(25)) != 0 {
		t.Fatalf("payee holds %s", got.Mine)
	}
}

// The invariant: a caller states an intent, never a state. There is no endpoint
// that takes balances or a signature, and sending them changes nothing —
// unknown fields are simply not read.
func TestTheAPIWillNotAcceptAState(t *testing.T) {
	c, base, _, payee, id, stop := apiFor(t, 500)
	defer stop()

	// A caller trying to dictate the outcome: balances, nonce, signatures.
	smuggle := map[string]any{
		"intent":    hexID(intent(1)),
		"amount":    anon(25).String(),
		"balance_a": anon(1).String(),
		"balance_b": anon(499).String(),
		"nonce":     99,
		"state":     map[string]any{"balance_a": "1", "balance_b": "499"},
		"sig_a":     hex.EncodeToString(make([]byte, 65)),
	}
	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(id)+"/pay", smuggle, testToken)
	if code != http.StatusOK || body["outcome"] != "completed" {
		t.Fatalf("status %d: %v", code, body)
	}

	// The payment that happened is the one the TRANSITION describes, not the one
	// the smuggled fields asked for.
	bal, _ := payee.coord.Balances(id)
	if bal.Nonce != 1 {
		t.Fatalf("nonce %d — a caller-supplied nonce was honoured", bal.Nonce)
	}
	if bal.Mine.Cmp(anon(25)) != 0 {
		t.Fatalf("payee holds %s — caller-supplied balances were honoured", bal.Mine)
	}
}

func TestAmountsAreDecimalStringsNotNumbers(t *testing.T) {
	c, base, _, payee, id, stop := apiFor(t, 500)
	defer stop()

	// One gold award: 1e20 wei, past what a JSON number survives in a browser.
	gold := anon(100).String()
	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(id)+"/pay",
		payRequest{Intent: hexID(intent(1)), Amount: gold}, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}

	// And it comes back as a string, exactly.
	code, got := do(t, c, http.MethodGet, base+"/v1/channels/"+hexID(id), nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if got["theirs"] != gold {
		t.Fatalf("balance came back as %v (%T), want the string %s", got["theirs"], got["theirs"], gold)
	}
	bal, _ := payee.coord.Balances(id)
	if bal.Mine.Cmp(anon(100)) != 0 {
		t.Fatalf("payee holds %s", bal.Mine)
	}
}

// ---- the three outcomes stay distinct ----------------------------------------

func TestARejectionIsAResultNotAnHTTPError(t *testing.T) {
	c, base, payer, _, id, stop := apiFor(t, 500)
	defer stop()

	// A lock expiring too soon: refused on policy, deliberately.
	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(id)+"/pay",
		payRequest{
			Kind: KindLockAdd, Intent: hexID(intent(1)), Amount: anon(50).String(),
			LockID: hexID([32]byte{31: 1}), Hash: hexID([32]byte{31: 9}),
			Expiry: payer.clock + 10,
		}, testToken)
	if code != http.StatusOK {
		t.Fatalf("a refusal produced status %d: %v", code, body)
	}
	if body["outcome"] != "rejected" {
		t.Fatalf("outcome %v", body["outcome"])
	}
	if body["reason"] == nil {
		t.Fatal("no reason given")
	}
}

// An unfinished exchange is "unknown", not "failed". The payment may have
// happened, and saying otherwise is a guess that costs a double payment.
func TestAnUnfinishedExchangeIsUnknownNotFailed(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))

	// A peer that reads the frame, commits it, then hangs up without replying.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if env, err := ReadFrame(conn); err == nil {
			_, _ = payee.coord.Handle(context.Background(), env)
		}
	}()

	api, err := NewAPI(payer.coord, func(_ [32]byte, _ Address) (Peer, error) {
		return &StreamPeer{
			Dial: func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", ln.Addr().String())
			},
			Timeout: 3 * time.Second,
		}, nil
	}, testToken)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	code, body := do(t, srv.Client(), http.MethodPost,
		srv.URL+"/v1/channels/"+hexID(id)+"/pay",
		payRequest{Intent: hexID(intent(1)), Amount: anon(25).String()}, testToken)

	if code != http.StatusAccepted {
		t.Fatalf("status %d, want 202 Accepted: %v", code, body)
	}
	if body["outcome"] != "unknown" {
		t.Fatalf("outcome %v, want unknown", body["outcome"])
	}

	// The payee did complete it, and the payer knows nothing — which /recover
	// is for.
	if b, _ := payee.coord.Balances(id); b.Nonce != 1 {
		t.Fatal("the payee did not commit")
	}
	if b, _ := payer.coord.Balances(id); b.Nonce != 0 {
		t.Fatal("the payer concluded something from a broken connection")
	}
}

func TestRecoverOverHTTPResolvesAnUnknownOutcome(t *testing.T) {
	c, base, payer, payee, id, stop := apiFor(t, 500)
	defer stop()

	// The payee completes a payment the payer never hears about.
	if err := payer.coord.Adopt(context.Background(), id); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	propose, err := payer.coord.Session().Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := payee.coord.Handle(context.Background(), hop(t, propose)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(id)+"/recover", nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	if body["outcome"] != string(ResyncAdopted) {
		t.Fatalf("outcome %v", body["outcome"])
	}
	if b, _ := payer.coord.Balances(id); b.Nonce != 1 {
		t.Fatal("recovery did not adopt")
	}
}

// ---- idempotence through the API ---------------------------------------------

func TestPostingTheSameIntentTwicePaysOnce(t *testing.T) {
	c, base, _, payee, id, stop := apiFor(t, 500)
	defer stop()
	url := base + "/v1/channels/" + hexID(id) + "/pay"
	req := payRequest{Intent: hexID(intent(1)), Amount: anon(25).String()}

	for i := 0; i < 3; i++ {
		code, body := do(t, c, http.MethodPost, url, req, testToken)
		if code != http.StatusOK || body["outcome"] != "completed" {
			t.Fatalf("attempt %d: status %d %v", i, code, body)
		}
	}
	if got, _ := payee.coord.Balances(id); got.Mine.Cmp(anon(25)) != 0 {
		t.Fatalf("payee holds %s after three identical posts, want 25", got.Mine)
	}
}

// ---- the surface refuses what it should ---------------------------------------

func TestEveryRouteNeedsTheToken(t *testing.T) {
	c, base, _, _, id, stop := apiFor(t, 500)
	defer stop()

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/channels"},
		{http.MethodGet, "/v1/channels/" + hexID(id)},
		{http.MethodPost, "/v1/channels/" + hexID(id) + "/adopt"},
		{http.MethodPost, "/v1/channels/" + hexID(id) + "/pay"},
		{http.MethodPost, "/v1/channels/" + hexID(id) + "/recover"},
	} {
		if code, _ := do(t, c, tc.method, base+tc.path, nil, ""); code != http.StatusUnauthorized {
			t.Fatalf("%s %s answered %d without a token", tc.method, tc.path, code)
		}
		if code, _ := do(t, c, tc.method, base+tc.path, nil, "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("%s %s accepted the wrong token", tc.method, tc.path)
		}
	}
}

func TestTheAPIRefusesToExistWithoutAToken(t *testing.T) {
	payer, _, _ := wiredPair(t, anon(500))
	if _, err := NewAPI(payer.coord, nil, ""); err != ErrNoAPIToken {
		t.Fatalf("got %v, want ErrNoAPIToken", err)
	}
	if _, err := NewAPI(payer.coord, nil, "   "); err != ErrNoAPIToken {
		t.Fatal("whitespace was accepted as a token")
	}
}

func TestMalformedRequestsAreRefusedCleanly(t *testing.T) {
	c, base, _, _, id, stop := apiFor(t, 500)
	defer stop()

	cases := []struct {
		name string
		path string
		body any
		want int
	}{
		{"bad channel id", "/v1/channels/nothex/pay",
			payRequest{Intent: hexID(intent(1)), Amount: "1"}, http.StatusBadRequest},
		{"missing intent", "/v1/channels/" + hexID(id) + "/pay",
			payRequest{Amount: "1"}, http.StatusBadRequest},
		{"amount not decimal", "/v1/channels/" + hexID(id) + "/pay",
			payRequest{Intent: hexID(intent(1)), Amount: "0x19"}, http.StatusBadRequest},
		{"unknown action", "/v1/channels/" + hexID(id) + "/teleport", nil, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, body := do(t, c, http.MethodPost, base+tc.path, tc.body, testToken); code != tc.want {
				t.Fatalf("status %d, want %d: %v", code, tc.want, body)
			}
		})
	}
}

func TestAnUnknownChannelIsANotFound(t *testing.T) {
	c, base, _, _, _, stop := apiFor(t, 500)
	defer stop()
	unknown := hexID([32]byte{0xde, 0xad, 0xbe, 0xef})
	if code, _ := do(t, c, http.MethodGet, base+"/v1/channels/"+unknown, nil, testToken); code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", code)
	}
	if code, _ := do(t, c, http.MethodPost, base+"/v1/channels/"+unknown+"/adopt", nil, testToken); code != http.StatusNotFound {
		t.Fatalf("adopt status %d, want 404", code)
	}
}

func TestPayingMoreThanTheChainBackedDepositIsRefused(t *testing.T) {
	c, base, _, _, id, stop := apiFor(t, 10) // the chain says ten
	defer stop()

	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(id)+"/pay",
		payRequest{Intent: hexID(intent(1)), Amount: anon(100).String()}, testToken)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %v", code, body)
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	c, base, _, _, _, stop := apiFor(t, 500)
	defer stop()
	if code, body := do(t, c, http.MethodGet, base+"/healthz", nil, ""); code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
}

func TestListingChannelsShowsWhatIsTracked(t *testing.T) {
	c, base, payer, _, id, stop := apiFor(t, 500)
	defer stop()

	code, body := do(t, c, http.MethodGet, base+"/v1/channels", nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if list, _ := body["channels"].([]any); len(list) != 0 {
		t.Fatal("channels appeared before adoption")
	}

	if err := payer.coord.Adopt(context.Background(), id); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	code, body = do(t, c, http.MethodGet, base+"/v1/channels", nil, testToken)
	list, _ := body["channels"].([]any)
	if code != http.StatusOK || len(list) != 1 {
		t.Fatalf("status %d, %d channels", code, len(list))
	}
}

// ---- the settlement routes ------------------------------------------------------

// payoutAPI wires a node whose channel can actually be settled.
func payoutAPI(t *testing.T) (*http.Client, string, *payoutRig, func()) {
	t.Helper()
	r := newPayoutRig(t, 1000)
	coord := NewCoordinator(r.store, r.chain, big.NewInt(1), Address{}, r.me.address(),
		func(raw [32]byte) ([]byte, error) { return r.me.sign(raw), nil })
	api, err := NewAPI(coord, func(_ [32]byte, _ Address) (Peer, error) {
		return nil, errors.New("no peer needed")
	}, testToken)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.WithPayout(r.worker).Handler())
	return srv.Client(), srv.URL, r, srv.Close
}

// A caller asks for a close. It does not supply balances, a nonce, a withdrawal
// or a signature — there is no field for any of them.
func TestClosingAChannelOverHTTP(t *testing.T) {
	c, base, r, stop := payoutAPI(t)
	defer stop()
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)

	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(r.id)+"/payout/close", nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	if body["outcome"] != string(OutcomeSubmitted) {
		t.Fatalf("outcome %v", body["outcome"])
	}
	calls := r.writer.Calls()
	if len(calls) != 1 || calls[0].Op != "closeCooperative" {
		t.Fatalf("submitted %+v", calls)
	}
}

func TestSettingAPayoutPolicyOverHTTP(t *testing.T) {
	c, base, r, stop := payoutAPI(t)
	defer stop()

	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(r.id)+"/payout/policy",
		payoutPolicyRequest{Mode: PayoutOnInterval, IntervalSeconds: 3600}, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	if body["mode"] != string(PayoutOnInterval) {
		t.Fatalf("mode %v", body["mode"])
	}

	// A checkpoint the parties agreed to is then submitted on demand.
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(75)}, r.peer)
	r.clock += 4000

	code, body = do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(r.id)+"/payout/run", nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("run status %d: %v", code, body)
	}
	calls := r.writer.Calls()
	if len(calls) != 1 || calls[0].Op != "checkpoint" {
		t.Fatalf("submitted %+v, want a checkpoint", calls)
	}
}

func TestAnInvalidPolicyIsRefused(t *testing.T) {
	c, base, r, stop := payoutAPI(t)
	defer stop()
	for _, tc := range []payoutPolicyRequest{
		{Mode: "hourly-ish"},
		{Mode: PayoutOnInterval}, // no interval given
	} {
		if code, _ := do(t, c, http.MethodPost,
			base+"/v1/channels/"+hexID(r.id)+"/payout/policy", tc, testToken); code != http.StatusBadRequest {
			t.Fatalf("%+v answered %d, want 400", tc, code)
		}
	}
}

// A settlement that cannot complete comes back WITH its outcome, so a caller can
// tell "not due" from "the RPC is down" from "locks outstanding".
func TestAnUnfinishedSettlementReportsItsOutcome(t *testing.T) {
	c, base, r, stop := payoutAPI(t)
	defer stop()

	r.agree(StateTransition{Kind: KindPay, Amount: anon(200)}, r.me)
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: r.clock + 9000,
	}, r.me)

	code, body := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(r.id)+"/payout/close", nil, testToken)
	if code != http.StatusAccepted {
		t.Fatalf("status %d, want 202: %v", code, body)
	}
	if body["outcome"] != string(OutcomeLocksPending) {
		t.Fatalf("outcome %v, want LOCKS_PENDING", body["outcome"])
	}
	if body["error"] == nil {
		t.Fatal("no reason given")
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent with a lock outstanding", n)
	}
}

func TestPayoutStatusIsReadable(t *testing.T) {
	c, base, r, stop := payoutAPI(t)
	defer stop()
	code, body := do(t, c, http.MethodGet, base+"/v1/channels/"+hexID(r.id)+"/payout", nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	if body["phase"] != string(PhaseNone) {
		t.Fatalf("phase %v", body["phase"])
	}
	if body["locked"] != "0" {
		t.Fatalf("locked %v — amounts must be decimal strings", body["locked"])
	}
}

// A node with no settlement worker says so rather than accepting a request it
// will never act on.
func TestSettlementRoutesRefuseWithoutAWorker(t *testing.T) {
	payer, _, id := wiredPair(t, anon(500))
	api, err := NewAPI(payer.coord, nil, testToken)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	for _, path := range []string{"/payout", "/payout/close", "/payout/run"} {
		method := http.MethodPost
		if path == "/payout" {
			method = http.MethodGet
		}
		if code, _ := do(t, srv.Client(), method,
			srv.URL+"/v1/channels/"+hexID(id)+path, nil, testToken); code != http.StatusNotImplemented {
			t.Fatalf("%s answered %d, want 501", path, code)
		}
	}
}

func TestSettlementRoutesNeedTheToken(t *testing.T) {
	c, base, r, stop := payoutAPI(t)
	defer stop()
	for _, path := range []string{"/payout", "/payout/policy", "/payout/close", "/payout/run"} {
		if code, _ := do(t, c, http.MethodPost, base+"/v1/channels/"+hexID(r.id)+path, nil, ""); code != http.StatusUnauthorized {
			t.Fatalf("%s answered %d without a token", path, code)
		}
	}
}
