package ui

// P7. The recipient's panel.
//
// Driven against a fake Receiving, because the point of the interface is that
// the dashboard can be exercised without a payment node — and because a test
// that needs a chain to check a redirect is testing the wrong thing.

import (
	"fmt"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type fakeReceiving struct {
	channels []ReceivingChannel
	listErr  error

	policyCalls []string
	settleCalls []string
	closeCalls  []string
	outcome     string
	actionErr   error
	policyErr   error

	// P15 collection.
	tips        []WaitingTip
	tipsErr     error
	tipCalls    []string
	tipOutcome  string
	tipErr      error
	publishOut  string
	publishErr  error
	publishCall []string
}

func (f *fakeReceiving) WaitingTips(context.Context) ([]WaitingTip, error) {
	return f.tips, f.tipsErr
}

func (f *fakeReceiving) AcceptTip(_ context.Context, id string, nonce uint64) (string, error) {
	f.tipCalls = append(f.tipCalls, fmt.Sprintf("%s/%d", id, nonce))
	return f.tipOutcome, f.tipErr
}

func (f *fakeReceiving) PublishTip(_ context.Context, id string, nonce uint64) (string, error) {
	f.publishCall = append(f.publishCall, fmt.Sprintf("%s/%d", id, nonce))
	return f.publishOut, f.publishErr
}

func (f *fakeReceiving) Channels(context.Context) ([]ReceivingChannel, error) {
	return f.channels, f.listErr
}

func (f *fakeReceiving) SetPolicy(_ context.Context, id, mode string, interval int64) error {
	f.policyCalls = append(f.policyCalls, id+"/"+mode)
	return f.policyErr
}

func (f *fakeReceiving) SettleNow(_ context.Context, id string) (string, error) {
	f.settleCalls = append(f.settleCalls, id)
	return f.outcome, f.actionErr
}

func (f *fakeReceiving) Close(_ context.Context, id string) (string, error) {
	f.closeCalls = append(f.closeCalls, id)
	return f.outcome, f.actionErr
}

func receivingServer(t *testing.T, rec Receiving) *Server {
	t.Helper()
	s := New(nil, nil, nil)
	if rec != nil {
		s.SetReceiving(rec)
	}
	return s
}

func post(t *testing.T, s *Server, path string, form url.Values, accept string) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("csrf", s.csrf)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1:9090"
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func getJSON(t *testing.T, s *Server, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// ---- the panel shows what the node believes ----------------------------------

func TestTheReceivingListIsServed(t *testing.T) {
	rec := &fakeReceiving{channels: []ReceivingChannel{{
		ID: "aa", Mine: "425000000000000000000", Theirs: "75000000000000000000",
		Locked: "0", Nonce: 12, Mode: "interval", Phase: "none",
	}}}
	code, body := getJSON(t, receivingServer(t, rec), "/api/receiving")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	list, _ := body["channels"].([]any)
	if len(list) != 1 {
		t.Fatalf("%d channels", len(list))
	}
	row := list[0].(map[string]any)
	// Amounts stay strings: 425 ANON is 4.25e20 and a JSON number would round.
	if row["mine"] != "425000000000000000000" {
		t.Fatalf("mine came back as %v (%T)", row["mine"], row["mine"])
	}
}

func TestAnEmptyListIsAnEmptyArray(t *testing.T) {
	code, body := getJSON(t, receivingServer(t, &fakeReceiving{}), "/api/receiving")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	list, ok := body["channels"].([]any)
	if !ok || len(list) != 0 {
		t.Fatalf("channels came back as %#v, want an empty array", body["channels"])
	}
}

// A node that does not receive says so, rather than showing an empty panel that
// reads as "nobody has tipped you".
func TestANodeThatDoesNotReceiveSaysSo(t *testing.T) {
	s := receivingServer(t, nil)
	if code, _ := getJSON(t, s, "/api/receiving"); code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501", code)
	}
	for _, path := range []string{"/receiving/policy", "/receiving/settle", "/receiving/close"} {
		if w := post(t, s, path, url.Values{"channel": {"aa"}}, ""); w.Code != http.StatusNotImplemented {
			t.Fatalf("%s answered %d, want 501", path, w.Code)
		}
	}
}

func TestAnUnreadablePanelIsNotAnEmptyOne(t *testing.T) {
	rec := &fakeReceiving{listErr: errors.New("rpc down")}
	if code, _ := getJSON(t, receivingServer(t, rec), "/api/receiving"); code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", code)
	}
}

// ---- operations ---------------------------------------------------------------

func TestSettingAPolicyReachesTheNode(t *testing.T) {
	rec := &fakeReceiving{}
	s := receivingServer(t, rec)
	w := post(t, s, "/receiving/policy",
		url.Values{"channel": {"abc"}, "mode": {"interval"}, "interval_seconds": {"3600"}}, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect", w.Code)
	}
	if len(rec.policyCalls) != 1 || rec.policyCalls[0] != "abc/interval" {
		t.Fatalf("calls %v", rec.policyCalls)
	}
}

func TestANonsenseIntervalIsRefused(t *testing.T) {
	rec := &fakeReceiving{}
	s := receivingServer(t, rec)
	for _, v := range []string{"0", "-60", "soon"} {
		w := post(t, s, "/receiving/policy",
			url.Values{"channel": {"abc"}, "mode": {"interval"}, "interval_seconds": {v}}, "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("interval %q answered %d, want 400", v, w.Code)
		}
	}
	if len(rec.policyCalls) != 0 {
		t.Fatal("a bad interval reached the payment node")
	}
}

func TestSettleAndCloseReachTheNode(t *testing.T) {
	rec := &fakeReceiving{outcome: "SUBMITTED"}
	s := receivingServer(t, rec)

	if w := post(t, s, "/receiving/settle", url.Values{"channel": {"abc"}}, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("settle answered %d", w.Code)
	}
	if w := post(t, s, "/receiving/close", url.Values{"channel": {"abc"}}, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("close answered %d", w.Code)
	}
	if len(rec.settleCalls) != 1 || len(rec.closeCalls) != 1 {
		t.Fatalf("settle %v close %v", rec.settleCalls, rec.closeCalls)
	}
}

// A settlement that could not finish reports its OUTCOME, not just a failure —
// "not due" and "the RPC is down" call for different responses.
func TestAnUnfinishedSettlementCarriesItsOutcome(t *testing.T) {
	rec := &fakeReceiving{outcome: "LOCKS_PENDING", actionErr: errors.New("locks are still outstanding")}
	w := post(t, receivingServer(t, rec), "/receiving/settle",
		url.Values{"channel": {"abc"}}, "application/json")

	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["outcome"] != "LOCKS_PENDING" {
		t.Fatalf("outcome %v", body["outcome"])
	}
	if body["error"] == nil {
		t.Fatal("no reason given")
	}
}

// ---- the panel cannot become a second way to move money -----------------------

// Every mutating route is CSRF-checked, like the rest of the dashboard. Without
// this a page on another site could settle somebody's channel by posting a form.
func TestEveryReceivingActionChecksCSRF(t *testing.T) {
	rec := &fakeReceiving{}
	s := receivingServer(t, rec)

	for _, path := range []string{"/receiving/policy", "/receiving/settle", "/receiving/close"} {
		req := httptest.NewRequest(http.MethodPost, path,
			strings.NewReader("channel=abc&mode=on_close")) // no csrf
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "127.0.0.1:9090"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code == http.StatusSeeOther || w.Code == http.StatusOK {
			t.Fatalf("%s accepted a request with no CSRF token (%d)", path, w.Code)
		}
	}
	if len(rec.policyCalls)+len(rec.settleCalls)+len(rec.closeCalls) != 0 {
		t.Fatal("a CSRF-less request reached the payment node")
	}
}

// The panel takes a channel id and a policy. There is no route that accepts a
// balance, a nonce, a withdrawal amount or a signature — the same invariant the
// payment API holds, at the other end of the system.
func TestThePanelOffersNoWayToNameAState(t *testing.T) {
	rec := &fakeReceiving{outcome: "SUBMITTED"}
	s := receivingServer(t, rec)

	// Everything a caller might hope to dictate, posted at once.
	form := url.Values{
		"channel":   {"abc"},
		"balance_a": {"1"},
		"balance_b": {"999"},
		"nonce":     {"4242"},
		"withdraw":  {"999"},
		"sig_a":     {strings.Repeat("00", 65)},
	}
	if w := post(t, s, "/receiving/settle", form, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("status %d", w.Code)
	}
	// The node was asked to settle a channel, and told nothing else. The extra
	// fields are not parameters of any method on the interface.
	if len(rec.settleCalls) != 1 || rec.settleCalls[0] != "abc" {
		t.Fatalf("calls %v", rec.settleCalls)
	}
}

// ---- the rendered page --------------------------------------------------------

func TestThePanelRendersChannelsAndWarnsAboutConflicts(t *testing.T) {
	rec := &fakeReceiving{channels: []ReceivingChannel{
		{ID: "aa", Mine: "425", Theirs: "75", Locked: "50", Nonce: 12, Mode: "interval", Phase: "submitted"},
		{ID: "bb", Mine: "1", Theirs: "2", Locked: "0", Nonce: 3, Conflicted: true},
	}}
	s := receivingServer(t, rec)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	page := w.Body.String()
	for _, want := range []string{"Receiving tips", "425", "Settle now", "Close channel"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page does not mention %q", want)
		}
	}
	// A stopped channel says so, and does not offer buttons that cannot work.
	if !strings.Contains(page, "This channel is stopped") {
		t.Fatal("a conflicted channel was rendered as if it were healthy")
	}
}

func TestThePanelIsAbsentWithoutAPaymentNode(t *testing.T) {
	s := receivingServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "Receiving tips") {
		t.Fatal("a node that cannot receive showed a receiving panel")
	}
}

// ---- pending HTLCs in the panel (P7-c) -------------------------------------------

func TestPendingLocksAreShownWithTheirStatus(t *testing.T) {
	rec := &fakeReceiving{channels: []ReceivingChannel{{
		ID: "aa", Mine: "425", Incoming: "100", Outgoing: "75", Total: "525", Nonce: 12,
		Locks: []PendingLock{
			{ID: "abc123", Direction: "incoming", Amount: "100", Status: "claimable", ExpiresIn: 240},
			{ID: "def456", Direction: "outgoing", Amount: "75", Status: "offered", ExpiresIn: 900},
		},
	}}}
	s := receivingServer(t, rec)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	page := w.Body.String()

	for _, want := range []string{
		"Payments in flight", "abc123", "claimable", "def456", "offered",
		"Available", "Incoming, in flight", "Total exposure",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page does not show %q", want)
		}
	}
}

// The panel reports exposure as three separate figures. Collapsing them would
// tell a recipient they hold money that may never arrive.
func TestExposureIsNotCollapsedIntoOneBalance(t *testing.T) {
	rec := &fakeReceiving{channels: []ReceivingChannel{{
		ID: "aa", Mine: "425", Incoming: "100", Outgoing: "0", Total: "525",
	}}}
	code, body := getJSON(t, receivingServer(t, rec), "/api/receiving")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	row := body["channels"].([]any)[0].(map[string]any)
	if row["mine"] != "425" || row["incoming"] != "100" || row["total"] != "525" {
		t.Fatalf("exposure came back as %v", row)
	}
}

// An expired lock says so rather than showing a negative countdown.
func TestAnExpiredLockReadsAsExpired(t *testing.T) {
	rec := &fakeReceiving{channels: []ReceivingChannel{{
		ID: "aa", Mine: "0", Incoming: "0", Total: "0",
		Locks: []PendingLock{{ID: "old", Direction: "outgoing", Amount: "50",
			Status: "refundable", ExpiresIn: -120}},
	}}}
	s := receivingServer(t, rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	page := w.Body.String()
	if !strings.Contains(page, "expired") || !strings.Contains(page, "refundable") {
		t.Fatal("an expired lock was not shown as expired and refundable")
	}
	if strings.Contains(page, "-120s") {
		t.Fatal("a negative countdown was rendered")
	}
}

// The panel is observational: it offers no route that would construct a
// settlement or a refund. Those are co-signed transitions owned by the
// coordinator, and a form that could build one would be a second way to move
// money.
func TestThePanelOffersNoLockActions(t *testing.T) {
	rec := &fakeReceiving{channels: []ReceivingChannel{{
		ID: "aa", Locks: []PendingLock{{ID: "abc", Direction: "incoming",
			Amount: "100", Status: "claimable", ExpiresIn: 60}},
	}}}
	s := receivingServer(t, rec)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	page := w.Body.String()

	for _, forbidden := range []string{
		"/receiving/settle-lock", "/receiving/claim", "/receiving/refund",
		"LOCK_SETTLE", "LOCK_REFUND", "preimage",
	} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("the panel exposes %q, which would let a form move money", forbidden)
		}
	}
	// And no such routes exist.
	for _, path := range []string{"/receiving/claim", "/receiving/refund", "/receiving/settle-lock"} {
		if w := post(t, s, path, url.Values{"channel": {"aa"}}, ""); w.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d, want 404", path, w.Code)
		}
	}
}
