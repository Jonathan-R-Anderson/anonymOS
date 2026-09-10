package channel

// The mailbox over real HTTP — roadmap P15.
//
// What matters here is that the PUBLIC surface stays public and the OPERATOR
// surface stays absent from it. A tipper has no token; the moment these routes
// demanded one, tipping through a volunteer would be impossible. The moment
// they served the operator API, a web page could spend the node's money.

import (
	"net/http"
	"strings"
	"net/http/httptest"
	"testing"
)

func mailboxServer(t *testing.T, now int64) (*Mailbox, *httptest.Server) {
	t.Helper()
	m := newTestMailbox(now)
	srv := httptest.NewServer(MailboxHandler(m))
	t.Cleanup(srv.Close)
	return m, srv
}

func TestTheMailboxSurfaceNeedsNoOperatorToken(t *testing.T) {
	// THE POINT OF A PUBLIC SURFACE. A contributor is a stranger.
	m, srv := mailboxServer(t, 1000)
	alice := newSigner(t)
	a := authFor(t, alice, testNode, 2000)

	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/authorize",
		map[string]any{
			"recipient": a.Recipient.Hex(), "node_id": a.NodeID,
			"endpoint": a.Endpoint, "expires": a.Expires, "sig": hexOf(a.Sig),
		}, "")
	if code != http.StatusOK {
		t.Fatalf("authorize with no token: got %d, want 200", code)
	}
	if !m.Serves(alice.address()) {
		t.Fatal("the node did not record the authorization")
	}

	code, _ = do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/deliver",
		map[string]any{"recipient": alice.address().Hex(),
			"envelope": Envelope{Type: MsgStatePropose, Channel: "ab"}}, "")
	if code != http.StatusAccepted {
		t.Fatalf("deliver with no token: got %d, want 202", code)
	}
}

func TestTheMailboxSurfaceDoesNotServeTheOperatorAPI(t *testing.T) {
	// If these ever shared a mux, a web page would reach routes that can move
	// the node's money.
	_, srv := mailboxServer(t, 1000)
	for _, path := range []string{"/v1/channels", "/v1/pool", "/v1/pool/checkpoint"} {
		code, _ := do(t, srv.Client(), http.MethodGet, srv.URL+path, nil, testToken)
		if code != http.StatusNotFound {
			t.Fatalf("%s is reachable from the public mailbox surface (%d)", path, code)
		}
	}
}

func TestDeliveringToAnUnservedRecipientIsRefused(t *testing.T) {
	_, srv := mailboxServer(t, 1000)
	stranger := newSigner(t)
	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/deliver",
		map[string]any{"recipient": stranger.address().Hex(),
			"envelope": Envelope{Type: MsgStatePropose}}, "")
	if code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", code)
	}
}

func TestCollectingOverHTTPNeedsTheRecipientsOwnSignature(t *testing.T) {
	m, srv := mailboxServer(t, 1000)
	alice, mallory := newSigner(t), newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); err != nil {
		t.Fatal(err)
	}

	ch := MailboxChallenge(testNode, alice.address(), "tok")

	// Mallory signs the same challenge and asks for Alice's mail.
	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/collect",
		map[string]any{"recipient": alice.address().Hex(), "token": "tok",
			"sig": hexOf(mallory.sign(PersonalDigest(ch)))}, "")
	if code != http.StatusForbidden {
		t.Fatalf("mallory collected alice's mail: %d", code)
	}
	if m.Pending(alice.address()) != 1 {
		t.Fatal("a refused collection consumed the queue")
	}

	code, body := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/collect",
		map[string]any{"recipient": alice.address().Hex(), "token": "tok",
			"sig": hexOf(alice.sign(PersonalDigest(ch)))}, "")
	if code != http.StatusOK {
		t.Fatalf("alice could not collect: %d", code)
	}
	frames, _ := body["frames"].([]any)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
}

func TestAuthorizingForAnotherNodeIsRefusedOverHTTP(t *testing.T) {
	m, srv := mailboxServer(t, 1000)
	alice := newSigner(t)
	a := authFor(t, alice, "someone-else", 2000)
	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/authorize",
		map[string]any{
			"recipient": a.Recipient.Hex(), "node_id": a.NodeID,
			"endpoint": a.Endpoint, "expires": a.Expires, "sig": hexOf(a.Sig),
		}, "")
	if code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", code)
	}
	if m.Serves(alice.address()) {
		t.Fatal("the node adopted a recipient authorized elsewhere")
	}
}

// ---- the browser preflight (P15) --------------------------------------------
//
// A cross-origin JSON POST always triggers OPTIONS first. The mailbox answered
// 405, so no browser ever sent the delivery — the tip failed before a byte left
// the page. Found by loading the real site in Firefox; every server-side test
// passed because curl sends no preflight.

func TestTheMailboxAnswersTheBrowsersPreflight(t *testing.T) {
	_, srv := mailboxServer(t, 1000)

	for _, route := range []string{"authorize", "deliver", "collect", "states", "accepted"} {
		req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/mailbox/v1/"+route, nil)
		// Exactly what tip-channel.js provokes.
		req.Header.Set("Origin", "https://syndichan.example")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type")

		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", route, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s preflight: got %d, want 204 — a browser will not send the POST",
				route, resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("%s: Allow-Origin %q", route, got)
		}
		if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "POST") {
			t.Fatalf("%s: POST is not advertised", route)
		}
		if !strings.Contains(strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers")), "content-type") {
			t.Fatalf("%s: Content-Type is not allowed", route)
		}
		// Never credentials alongside a wildcard origin — the browser refuses
		// that pair anyway, and asking for it would break every tip.
		if resp.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("%s advertises credentials with a wildcard origin", route)
		}
	}
}

func TestThePreflightNeedsNoAuthorizationButThePostStillDoes(t *testing.T) {
	// A preflight carries no body, no signature and no recipient — there is
	// nothing to authorise. The POST is a different matter.
	m, srv := mailboxServer(t, 1000)
	stranger := newSigner(t)

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/mailbox/v1/deliver", nil)
	req.Header.Set("Origin", "https://anywhere.example")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight required authorization: %d", resp.StatusCode)
	}

	// The actual delivery is still refused for a recipient this node does not
	// serve. Answering the preflight authorised nothing.
	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/deliver",
		map[string]any{"recipient": stranger.address().Hex(),
			"envelope": Envelope{Type: MsgStatePropose}}, "")
	if code != http.StatusForbidden {
		t.Fatalf("an unserved recipient was accepted after a preflight: %d", code)
	}
	if m.Pending(stranger.address()) != 0 {
		t.Fatal("a frame was queued for an unserved recipient")
	}
}

func TestTheOperatorAPIGainsNoCORS(t *testing.T) {
	// The mailbox is public by design; the operator API is not, and must not
	// have been loosened by the same change.
	c, base, _, _, _, stop := poolAPIFor(t, 500)
	defer stop()

	for _, path := range []string{"/v1/channels", "/v1/pool", "/v1/pool/checkpoint"} {
		req, _ := http.NewRequest(http.MethodOptions, base+path, nil)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("%s advertises Allow-Origin %q — the operator API must stay "+
				"unreachable from a web page", path, got)
		}
	}
}

// ---- channel parties on the operator API (P15) -------------------------------
//
// The recipient's browser cannot learn a channel's parties any other way: the id
// is keccak(sorted(a,b)) and does not run backwards, and taking them from the
// volunteer would make signature verification circular. So the node reports
// them — as an INPUT to verification, never as proof of payment.

func TestChannelSummaryCarriesTheChainRecordedParties(t *testing.T) {
	c, base, payer, payee, id, stop := poolAPIFor(t, 500)
	defer stop()
	// The payee adopts on the first message, so give it one.
	payInto(t, payer, payee, id, 10)

	code, body := do(t, c, http.MethodGet, base+"/v1/channels/"+hexID(id), nil, testToken)
	if code != http.StatusOK {
		t.Fatalf("get channel: %d", code)
	}
	ch, ok := payee.coord.store.Get(id)
	if !ok {
		t.Fatal("the node does not hold the channel")
	}
	// The addresses must be the ones the chain gave the store, not anything
	// derived from the balances beside them.
	if !strings.EqualFold(str(body["party_a"]), ch.PartyA.Hex()) {
		t.Fatalf("party_a = %v, want %s", body["party_a"], ch.PartyA.Hex())
	}
	if !strings.EqualFold(str(body["party_b"]), ch.PartyB.Hex()) {
		t.Fatalf("party_b = %v, want %s", body["party_b"], ch.PartyB.Hex())
	}
	if str(body["party_a"]) == str(body["party_b"]) {
		t.Fatal("both parties are the same address")
	}
}

func TestPartiesDidNotDisplaceTheBalances(t *testing.T) {
	// Mine/Theirs are AMOUNTS. Adding two address fields beside them must not
	// have turned either into an identity.
	c, base, payer, payee, id, stop := poolAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 60)

	_, body := do(t, c, http.MethodGet, base+"/v1/channels/"+hexID(id), nil, testToken)
	if body["mine"] != anon(60).String() {
		t.Fatalf("mine = %v, want the balance %s", body["mine"], anon(60))
	}
	for _, k := range []string{"mine", "theirs", "locked"} {
		if strings.HasPrefix(str(body[k]), "0x") {
			t.Fatalf("%s looks like an address, not an amount: %v", k, body[k])
		}
	}
	for _, k := range []string{"party_a", "party_b"} {
		if !strings.HasPrefix(str(body[k]), "0x") {
			t.Fatalf("%s is not an address: %v", k, body[k])
		}
	}
}

func TestThePartiesStayBehindTheOperatorGate(t *testing.T) {
	// Adding them must not have made the route reachable without a token, and
	// must not have added CORS — this is the operator surface, not the mailbox.
	c, base, _, _, id, stop := poolAPIFor(t, 500)
	defer stop()

	for _, token := range []string{"", "wrong"} {
		code, body := do(t, c, http.MethodGet, base+"/v1/channels/"+hexID(id), nil, token)
		if code != http.StatusUnauthorized {
			t.Fatalf("token %q: got %d, want 401", token, code)
		}
		if _, leaked := body["party_a"]; leaked {
			t.Fatal("an unauthorized response carried the channel parties")
		}
	}

	req, _ := http.NewRequest(http.MethodOptions, base+"/v1/channels/"+hexID(id), nil)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("the operator API advertises Allow-Origin %q", got)
	}
}
