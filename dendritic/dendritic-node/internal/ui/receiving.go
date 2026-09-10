package ui

// The recipient's control panel — roadmap P7.
//
// WHY THIS TALKS TO AN INTERFACE AND NOT TO internal/channel
// ----------------------------------------------------------
// A dashboard is a view. It shows what the payment node believes and forwards
// what an operator asks for; it does not compute balances, decide what is
// settleable, or know that a state has a nonce. Everything below is expressed
// in strings and enums that a template can render, and the one file that
// understands channels is receiving_adapter.go.
//
// That boundary is not decoration. The whole payment stack was built so that
// exactly one component turns a request into money, and a dashboard reaching
// past this interface into a Store would be a second one — arriving through the
// least-reviewed door in the system.
//
// AMOUNTS ARE STRINGS ALL THE WAY THROUGH
// ---------------------------------------
// Decimal strings, never numbers, for the reason the rest of the stack uses
// them: one gold award is 1e20 wei and this page is read by a browser.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ReceivingChannel is one channel, as an operator needs to see it.
type ReceivingChannel struct {
	ID     string `json:"id"`
	Peer   string `json:"peer"`
	Mine   string `json:"mine"`
	Theirs string `json:"theirs"`
	// Locked is value committed to payments in flight. Shown separately from
	// Mine because it is not spendable and an operator who reads it as
	// available will be surprised at settlement.
	Locked     string `json:"locked"`
	Nonce      uint64 `json:"nonce"`
	Conflicted bool   `json:"conflicted"`

	// Exposure, kept apart on purpose. Available is settled and spendable;
	// Incoming may never arrive; Outgoing is this node's own money at risk.
	// Adding them would tell a recipient they hold money they might not get.
	Incoming string        `json:"incoming"`
	Outgoing string        `json:"outgoing"`
	Total    string        `json:"total"`
	Locks    []PendingLock `json:"locks,omitempty"`

	// Settlement, as the local record has it.
	Mode      string `json:"mode"`
	Phase     string `json:"phase"`
	TxHash    string `json:"tx_hash,omitempty"`
	DueAt     int64  `json:"due_at,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// PendingLock is one conditional payment, as an operator reads it.
//
// Observational. There is deliberately nothing here that would let a page
// construct a settlement or a refund: those are co-signed state transitions and
// they belong to the coordinator. A UI that could build one would be a second
// way to move money, arriving through a form.
type PendingLock struct {
	ID string `json:"id"`
	// Direction is "incoming" (offered to this node) or "outgoing" (offered by
	// it). The same lock reads differently from each end.
	Direction string `json:"direction"`
	Amount    string `json:"amount"`
	// Status is waiting | claimable | lapsed | offered | refundable | settling.
	Status string `json:"status"`
	Expiry int64  `json:"expiry"`
	// ExpiresIn is seconds remaining, negative once past. Computed by the node,
	// whose clock is the one that decides.
	ExpiresIn int64 `json:"expires_in"`
}

// Receiving is everything the panel needs from the payment node.
//
// Deliberately narrow. There is no method here that hands back a state, a
// signature or a nonce to act on — an operator sets a policy and asks for
// settlement, and what that means is decided below.
type Receiving interface {
	// Channels lists what this node is receiving on.
	Channels(ctx context.Context) ([]ReceivingChannel, error)
	// SetPolicy records when the recipient wants value on chain.
	SetPolicy(ctx context.Context, id, mode string, intervalSeconds int64) error
	// SettleNow advances one channel's settlement and reports what happened.
	SettleNow(ctx context.Context, id string) (outcome string, err error)
	// Close asks for the money now and ends the channel.
	Close(ctx context.Context, id string) (outcome string, err error)

	// ---- mailbox collection (P15) -----------------------------------------
	//
	// Here rather than in the browser because acceptance needs the recipient's
	// channel key, and that key lives in this node so somebody can be tipped
	// while their browser is closed. A page that could accept would be a page
	// with custody.

	// WaitingTips lists mailbox proposals held for this node WITHOUT consuming
	// them. An error means "could not look" and NEVER "nothing is waiting" —
	// a recipient shown an empty list because their authorization lapsed would
	// conclude nobody had tipped them.
	WaitingTips(ctx context.Context) ([]WaitingTip, error)
	// AcceptTip verifies and countersigns one waiting proposal, through the
	// node's ordinary acceptance path. Returns one of TipAccepted, TipRefused,
	// TipConflict or TipUnreachable.
	AcceptTip(ctx context.Context, channel string, nonce uint64) (outcome string, err error)
	// PublishTip caches the co-signed state at the volunteer so the contributor
	// can find it. DISCOVERY ONLY: it moves no value, and failing it does not
	// undo an acceptance.
	PublishTip(ctx context.Context, channel string, nonce uint64) (outcome string, err error)
}

// The outcomes of a collection step, kept apart because they call for different
// responses. A boolean here would be the "received"/"accepted"/"withdrawn"
// collapse this whole feature exists to avoid.
const (
	// TipWaiting: a contributor signed and a volunteer is holding it. NOBODY
	// has agreed to anything and no value has moved.
	TipWaiting = "waiting"
	// TipAccepted: both parties signed and the node stored it. It is now part
	// of the recipient's withdrawable pool.
	TipAccepted = "accepted"
	// TipUnpublished: accepted, but not yet cached at the volunteer. NOT a
	// failed payment — the acceptance is real and must never be retried.
	TipUnpublished = "accepted_unpublished"
	// TipPublished: the co-signed state is discoverable by the contributor.
	TipPublished = "published"
	// TipRefused: the node declined. Its reason travels with it.
	TipRefused = "refused"
	// TipConflict: two different states at one update number. I4 — refuse,
	// never choose.
	TipConflict = "conflict"
	// TipSuperseded: a LATER state is already stored, so this proposal is
	// history. Not a refusal and not a loss — the value it carried is in the
	// newer state the node already holds.
	TipSuperseded = "superseded"
	// TipUnreachable: the volunteer or the node could not be reached. Nothing
	// is known, and specifically it is NOT "no tips".
	TipUnreachable = "unreachable"
)

// WaitingTip is one mailbox proposal, as the console displays it.
//
// Everything here is for reading. The browser cannot assemble a payment from
// these fields and is not meant to: they exist so a recipient can see what they
// are agreeing to before they agree to it.
type WaitingTip struct {
	Channel string `json:"channel"`
	Nonce   uint64 `json:"nonce"`
	// Amount is what this state would add, in ANON.
	Amount string `json:"amount"`
	// From is the contributor, DERIVED FROM THE CHAIN by the node. Never taken
	// from the frame: a volunteer that could name the parties could name itself.
	From string `json:"from"`
	// State is one of the constants above.
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// SetReceiving attaches a payment node to the dashboard. Without one the
// receiving routes answer 501 — a node that cannot receive should say so rather
// than show an empty panel that looks like "no tips yet".
//
// Called during wiring, before the server starts, exactly like the other
// setters here. This type deliberately has no lock: everything on it is set
// once at startup, and adding one for this field alone would suggest the rest
// are safe to change while serving, which they are not.
func (s *Server) SetReceiving(r Receiving) { s.receiving = r }

func (s *Server) requireReceiving(w http.ResponseWriter) (Receiving, bool) {
	rec := s.receiving
	if rec == nil {
		writeReceivingJSON(w, http.StatusNotImplemented,
			map[string]string{"error": "this node is not configured to receive payments"})
		return nil, false
	}
	return rec, true
}

func writeReceivingJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// serveReceiving lists the channels, for the panel and for anything scripting
// against it.
func (s *Server) serveReceiving(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	channels, err := rec.Channels(r.Context())
	if err != nil {
		writeReceivingJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if channels == nil {
		channels = []ReceivingChannel{}
	}
	writeReceivingJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

// setReceivingPolicy records how often the recipient wants settling.
//
// Form-encoded rather than JSON because it is posted by the dashboard's own
// form. Guarded by the CSRF token, but NOT by "is there a config file" — a node
// with no config can still be owed money.
func (s *Server) setReceivingPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.checkToken(w, r) {
		return
	}
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.FormValue("channel"))
	mode := strings.TrimSpace(r.FormValue("mode"))

	var interval int64
	if raw := strings.TrimSpace(r.FormValue("interval_seconds")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			http.Error(w, "interval must be a positive number of seconds", http.StatusBadRequest)
			return
		}
		interval = parsed
	}
	if err := rec.SetPolicy(r.Context(), id, mode, interval); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// settleReceiving is "Settle Now".
func (s *Server) settleReceiving(w http.ResponseWriter, r *http.Request) {
	s.receivingAction(w, r, func(rec Receiving, id string) (string, error) {
		return rec.SettleNow(r.Context(), id)
	})
}

// closeReceiving is "Close Channel".
func (s *Server) closeReceiving(w http.ResponseWriter, r *http.Request) {
	s.receivingAction(w, r, func(rec Receiving, id string) (string, error) {
		return rec.Close(r.Context(), id)
	})
}

// receivingAction runs one settlement operation and reports its OUTCOME.
//
// The outcome travels even when the operation could not finish, for the same
// reason the payment API separates its three results: "not due", "there are
// locks outstanding" and "the RPC is down" call for different responses, and
// collapsing them into a red box tells an operator nothing.
func (s *Server) receivingAction(w http.ResponseWriter, r *http.Request,
	run func(Receiving, string) (string, error)) {

	if !s.checkToken(w, r) {
		return
	}
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.FormValue("channel"))
	outcome, err := run(rec, id)

	// A browser form gets a redirect; a script asking for JSON gets the detail.
	if wantsJSON(r) {
		body := map[string]any{"outcome": outcome}
		code := http.StatusOK
		if err != nil {
			body["error"] = err.Error()
			code = http.StatusAccepted
		}
		writeReceivingJSON(w, code, body)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// ---- mailbox collection (P15) ------------------------------------------------
//
// Server-rendered, like every other panel here. The browser posts a form and is
// redirected; it holds no state and runs no protocol. That is deliberate — the
// node is the state machine, and a page that decided anything about a payment
// would be a second one that could disagree with it.

// serveTips lists what is waiting, for the panel and for anything scripting
// against it.
func (s *Server) serveTips(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	tips, err := rec.WaitingTips(r.Context())
	if err != nil {
		// 502 with the reason, NOT 200 with an empty list. "I could not look"
		// and "I looked and there was nothing" are different answers, and only
		// one of them means nobody tipped you.
		writeReceivingJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if tips == nil {
		tips = []WaitingTip{}
	}
	writeReceivingJSON(w, http.StatusOK, map[string]any{"tips": tips})
}

// acceptTip countersigns one waiting proposal.
func (s *Server) acceptTip(w http.ResponseWriter, r *http.Request) {
	s.tipAction(w, r, func(rec Receiving, id string, nonce uint64) (string, error) {
		return rec.AcceptTip(r.Context(), id, nonce)
	})
}

// publishTip makes an accepted state findable by the contributor.
func (s *Server) publishTip(w http.ResponseWriter, r *http.Request) {
	s.tipAction(w, r, func(rec Receiving, id string, nonce uint64) (string, error) {
		return rec.PublishTip(r.Context(), id, nonce)
	})
}

// tipAction runs one collection step and carries its OUTCOME back.
//
// Modelled on receivingAction above and for the same reason: the outcome
// travels even when the step failed, because "the node refused", "two states
// were signed at one update number" and "the mailbox could not be reached" call
// for different responses from the recipient.
func (s *Server) tipAction(w http.ResponseWriter, r *http.Request,
	run func(Receiving, string, uint64) (string, error)) {

	if !s.checkToken(w, r) {
		return
	}
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.FormValue("channel"))
	// The update number travels with the channel because a volunteer may hold
	// several states for one channel and the recipient agreed to a particular
	// one. Accepting "whichever is listed first" would let the volunteer choose.
	nonce, err := strconv.ParseUint(strings.TrimSpace(r.FormValue("nonce")), 10, 64)
	if err != nil {
		http.Error(w, "which tip? the update number is missing", http.StatusBadRequest)
		return
	}
	outcome, runErr := run(rec, id, nonce)

	if wantsJSON(r) {
		body := map[string]any{"outcome": outcome}
		code := http.StatusOK
		if runErr != nil {
			body["error"] = runErr.Error()
			// 202, like receivingAction: the step ran and reported a result
			// that is not success. A 500 would suggest the node broke.
			code = http.StatusAccepted
		}
		writeReceivingJSON(w, code, body)
		return
	}
	// The outcome rides in the URL so the page can say what happened. It is a
	// label, not a claim about money — the panel re-reads the node either way.
	dest := "/?tip=" + url.QueryEscape(outcome)
	if runErr != nil {
		dest += "&detail=" + url.QueryEscape(runErr.Error())
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
