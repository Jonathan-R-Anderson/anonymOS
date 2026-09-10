package ui

// The node-served collection console, assembled — roadmap P15.5.
//
// These drive the REAL Server, the REAL template and the REAL routes. The
// lesson that produced them is that seven P15 defects survived component tests
// and died the moment a browser loaded the actual page: a handler that works
// and a page that never reaches it are indistinguishable from below.

import (
	"context"
	"errors"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

const tipChannel = "ade3bbc0ce2367a812a9d03ab3646393114a01c944778b893fdd12c2ec6e9587"

func waitingFake() *fakeReceiving {
	return &fakeReceiving{
		tips: []WaitingTip{{
			Channel: tipChannel, Nonce: 1, Amount: "5",
			From: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", State: TipWaiting,
		}},
	}
}

// render returns the dashboard exactly as the node serves it.
func render(t *testing.T, s *Server, target string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.dashboard(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard returned %d", rec.Code)
	}
	return rec.Body.String()
}

func TestConsoleShowsAWaitingTipWithReviewAndAccept(t *testing.T) {
	f := waitingFake()
	body := render(t, receivingServer(t, f), "/")

	for _, want := range []string{
		"Tip waiting for acceptance",  // it is WAITING, not received
		"No funds have been accepted", // and the page says so outright
		"Review this tip",             // (1) the review control exists
		"5 ANON",                      // the amount, in ANON not wei
		tipChannel,                    // the channel, so the state is auditable
		`action="/tips/accept"`,       // (3) the accept control exists
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the console page never mentions %q", want)
		}
	}
	// Wording that would claim the money had arrived.
	for _, forbidden := range []string{"received", "you have been paid", "balance increased"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("a waiting tip is described as %q", forbidden)
		}
	}
}

func TestRenderingTheConsoleNeverConsumesTheTip(t *testing.T) {
	// (2) Review must not consume. The console reads through WaitingTips, which
	// is Peek; it must never reach for a consuming collect, and re-rendering
	// must keep showing the same tip.
	f := waitingFake()
	s := receivingServer(t, f)
	for i := 0; i < 3; i++ {
		if !strings.Contains(render(t, s, "/"), tipChannel) {
			t.Fatalf("render %d lost the waiting tip", i+1)
		}
	}
	if len(f.tipCalls) != 0 || len(f.publishCall) != 0 {
		t.Fatalf("merely displaying the page acted on the tip: accept=%v publish=%v",
			f.tipCalls, f.publishCall)
	}
}

func TestAcceptReachesTheReceivingInterfaceWithTheChosenUpdate(t *testing.T) {
	// (4) The click must reach the node, carrying WHICH state was agreed to.
	f := waitingFake()
	f.tipOutcome = TipAccepted
	s := receivingServer(t, f)

	form := url.Values{"csrf": {s.csrf}, "channel": {tipChannel}, "nonce": {"1"}}
	rec := post(t, s, "/tips/accept", form, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("accept returned %d", rec.Code)
	}
	if len(f.tipCalls) != 1 || f.tipCalls[0] != tipChannel+"/1" {
		t.Fatalf("the node was asked for %v", f.tipCalls)
	}
	// (10) It goes back to the dashboard, which re-reads the node.
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/?tip=accepted") {
		t.Fatalf("redirected to %q", loc)
	}
}

func TestAcceptWithoutTheUpdateNumberIsRefused(t *testing.T) {
	// A volunteer may hold several states for one channel. Accepting "whichever
	// was listed first" would let the volunteer choose which one is agreed to.
	f := waitingFake()
	s := receivingServer(t, f)
	rec := post(t, s, "/tips/accept", url.Values{"csrf": {s.csrf}, "channel": {tipChannel}}, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an accept with no update number returned %d", rec.Code)
	}
	if len(f.tipCalls) != 0 {
		t.Fatal("it reached the node anyway")
	}
}

// postRaw sends the form EXACTLY as given. The shared post() helper rewrites
// the CSRF field to the correct value, which is convenient everywhere else and
// makes it impossible to test the guard itself.
func postRaw(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1:9090"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestAcceptIsCSRFGated(t *testing.T) {
	f := waitingFake()
	s := receivingServer(t, f)
	rec := postRaw(t, s, "/tips/accept",
		url.Values{"csrf": {"wrong"}, "channel": {tipChannel}, "nonce": {"1"}})
	if rec.Code == http.StatusSeeOther {
		t.Fatal("a forged cross-site post accepted a tip")
	}
	if len(f.tipCalls) != 0 {
		t.Fatal("a forged post reached the node")
	}
}

func TestAcceptedUnpublishedIsNotAFailure(t *testing.T) {
	// (9) Publication is discovery. Its failure must never read as a failed
	// payment, and must never invite the recipient to accept again.
	f := waitingFake()
	f.publishOut = TipUnpublished
	f.publishErr = context.DeadlineExceeded
	s := receivingServer(t, f)

	form := url.Values{"csrf": {s.csrf}, "channel": {tipChannel}, "nonce": {"1"}}
	rec := post(t, s, "/tips/publish", form, "application/json")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("publish failure returned %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["outcome"] != TipUnpublished {
		t.Fatalf("outcome was %v", out["outcome"])
	}

	page := render(t, s, "/?tip="+TipUnpublished)
	low := strings.ToLower(page)
	if !strings.Contains(low, "accepted") {
		t.Fatal("the page does not say the tip is still accepted")
	}
	for _, wrong := range []string{"accept it again", "failed", "was not accepted"} {
		if strings.Contains(low, wrong) {
			t.Errorf("an unpublished-but-accepted tip is described as %q", wrong)
		}
	}
}

func TestCouldNotLookIsNotAnEmptyMailbox(t *testing.T) {
	// (12) The distinction the whole capability exists for.
	f := &fakeReceiving{tipsErr: context.DeadlineExceeded}
	page := render(t, receivingServer(t, f), "/")
	if strings.Contains(page, "No tips waiting") {
		t.Fatal("a failed look rendered as an empty mailbox")
	}
	if !strings.Contains(page, "not the same as having none") {
		t.Fatal("the page does not distinguish 'could not check' from 'none'")
	}

	// And the JSON surface says so with a status, not an empty list.
	s := receivingServer(t, f)
	rec := httptest.NewRecorder()
	s.serveTips(rec, httptest.NewRequest(http.MethodGet, "/api/tips", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("/api/tips answered %d for a failed look", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"tips":[]`) {
		t.Fatal("a failed look returned an empty tip list")
	}
}

// tipsSection is the collection panel alone, so a check about it is not
// answered by the rest of the dashboard.
func tipsSection(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, `<section id="tips">`)
	if i < 0 {
		t.Fatal("the console rendered no tips panel")
	}
	j := strings.Index(page[i:], "</section>")
	if j < 0 {
		t.Fatal("the tips panel is unterminated")
	}
	return page[i : i+j]
}

func TestConsolePageRunsNoPaymentCodeAndNoOperatorAPI(t *testing.T) {
	// (5)(6)(7) The browser is presentation and control. It holds no wallet, it
	// never reaches the operator API, and there is no bearer token on the page.
	//
	// Scanned for actual API USE rather than for words: the page legitimately
	// contains the sentence "There is no wallet prompt", and a test that failed
	// on the word "wallet" would be reading prose.
	page := render(t, receivingServer(t, waitingFake()), "/")

	for _, api := range []string{
		"window.ethereum", "ethereum.request", "eth_requestAccounts",
		"eth_sendTransaction", "personal_sign", "eth_signTypedData",
		"privateKey", "localStorage", "sessionStorage", "indexedDB",
	} {
		if strings.Contains(page, api) {
			t.Errorf("the node console page uses %s", api)
		}
	}
	if regexp.MustCompile(`["'(\s]/v1/`).MatchString(page) {
		t.Error("the console page reaches the operator API")
	}
	if regexp.MustCompile(`(?i)bearer\s+\S`).MatchString(page) {
		t.Error("a bearer token appears in the console page")
	}
}

func TestConsoleDoesNotDoArithmeticOnAnybodysMoney(t *testing.T) {
	// (11) The node is authoritative for every figure. A page that added a tip
	// to a total would be showing a number no signature supports.
	// Scoped to the tips panel. The dashboard's network graph does its own
	// arithmetic on its own numbers, and scanning the whole page would fail on
	// that forever while saying nothing about anybody's money.
	section := tipsSection(t, render(t, receivingServer(t, waitingFake()), "/"))
	for _, pattern := range []string{`\+=`, `-=`, `parseFloat`, `parseInt`, `Number\(`, `<script`} {
		if regexp.MustCompile(pattern).MatchString(section) {
			t.Errorf("the tips panel computes amounts (%s)", pattern)
		}
	}
}

func TestEveryOutcomeGetsItsOwnWording(t *testing.T) {
	// A boolean here would be the received/accepted/withdrawn collapse.
	seen := map[string]string{}
	for _, outcome := range []string{
		TipAccepted, TipUnpublished, TipPublished, TipRefused, TipConflict, TipUnreachable,
	} {
		page := render(t, receivingServer(t, waitingFake()), "/?tip="+outcome)
		i := strings.Index(page, `id="tip-outcome"`)
		if i < 0 {
			t.Fatalf("%s rendered no outcome banner", outcome)
		}
		text := page[i:min(i+700, len(page))]
		for other, prev := range seen {
			if prev == text {
				t.Errorf("%s and %s are worded identically", outcome, other)
			}
		}
		seen[outcome] = text
	}
}

func TestTheConsoleSaysWhenItIsNotSetUpToCollect(t *testing.T) {
	// "Not configured" is not "nobody tipped you".
	f := &fakeReceiving{tipsErr: errNoCollector}
	page := render(t, receivingServer(t, f), "/")
	if strings.Contains(page, "No tips waiting") {
		t.Fatal("an unconfigured node claims nobody has tipped it")
	}
	if !strings.Contains(page, "channels.volunteer") {
		t.Fatal("the page does not say what is missing")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestAnAlreadyAcceptedTipIsNotOfferedAgain(t *testing.T) {
	// A volunteer's queue is a cache and nothing removes the proposal from it
	// when the recipient accepts — peek does not consume, and the contributor
	// may still be collecting the co-signed reply. The console must therefore
	// take its answer from the node's stored state, not from the queue.
	//
	// This is a real defect that reached a running node: after a successful
	// acceptance the panel kept offering the same tip as though it were still
	// waiting, inviting the recipient to accept the same money twice.
	f := waitingFake()
	f.tips[0].State = TipAccepted
	page := tipsSection(t, render(t, receivingServer(t, f), "/"))

	if strings.Contains(page, `action="/tips/accept"`) {
		t.Error("an accepted tip is still offered for acceptance")
	}
	if strings.Contains(page, "Tip waiting for acceptance") {
		t.Error("an accepted tip is still described as waiting")
	}
	if !strings.Contains(page, "Tip accepted") {
		t.Error("the panel does not say the tip was accepted")
	}
	// Publishing stays available: an accepted tip may still be unpublished, and
	// republishing is harmless.
	if !strings.Contains(page, `action="/tips/publish"`) {
		t.Error("an accepted tip cannot be published")
	}
}

func TestASupersededTipIsNotReportedAsARefusal(t *testing.T) {
	// Re-accepting a tip that a later state already includes must not read as
	// "your node declined this". Observed on a real node: the coordinator
	// answers a stale proposal with its own current state to resync the peer,
	// and that leaked to the operator as: unexpected answer "STATE_RESPONSE".
	f := waitingFake()
	f.tipOutcome = TipSuperseded
	f.tipErr = errors.New("your node already holds a newer state for this channel")
	s := receivingServer(t, f)

	rec := post(t, s, "/tips/accept",
		url.Values{"csrf": {s.csrf}, "channel": {tipChannel}, "nonce": {"4"}}, "application/json")
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["outcome"] != TipSuperseded {
		t.Fatalf("outcome was %v", out["outcome"])
	}

	page := strings.ToLower(render(t, s, "/?tip="+TipSuperseded))
	if !strings.Contains(page, "already included") {
		t.Error("the page does not say the tip is already counted")
	}
	for _, wrong := range []string{"declined", "state_response", "unexpected answer"} {
		if strings.Contains(page, wrong) {
			t.Errorf("a superseded tip is described as %q", wrong)
		}
	}
}
