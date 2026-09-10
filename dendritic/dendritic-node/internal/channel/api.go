package channel

// The payment node's HTTP surface — roadmap P5-4.
//
// THIS FILE SHOULD BE BORING
// --------------------------
// It translates:
//
//	HTTP request → coordinator operation → coordinator result → HTTP response
//
// and does nothing else. It does not calculate balances, validate signatures,
// build state representations, touch the store, decide whether a payment is
// legal, read collateral from anybody, or implement any lock behaviour. Every
// one of those has an owner already, and a second one here would be a payment
// implementation that nobody remembers writing.
//
// A CALLER STATES AN INTENT, NEVER A STATE
// ----------------------------------------
// There is deliberately no endpoint that accepts a channel state, a balance or
// a signature. A caller cannot say:
//
//	"the new balance is 475/25, please store it"
//
// only:
//
//	"pay 25 on channel X, and here is the intent id so a retry is not a second
//	 payment"
//
// The coordinator then reads the current state, builds the deterministic
// transition, and runs SCPP/1. If a browser could hand over a state, the browser
// would be a second state machine — one that runs on a stranger's computer.
//
// THREE OUTCOMES, KEPT DISTINCT
// -----------------------------
//	completed   a fully signed state is committed here
//	rejected    the peer deliberately said no, with a reason
//	unknown     the exchange did not finish; the payment MAY have happened
//
// The third is not an error to be smoothed over. It is the honest answer when a
// connection dies mid-payment, and the response says so rather than guessing —
// the caller resolves it with /recover, which asks the peer.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

var ErrNoAPIToken = errors.New("api: refusing to serve without a token")

// PeerResolver says how to reach the other end of a channel.
//
// The node's own configuration, never the request body. A caller naming its own
// peer address could not steal — the counterparty still has to sign — but it
// could be pointed somewhere that quietly fails, and routing is the node's
// business anyway.
type PeerResolver func(id [32]byte, counterparty Address) (Peer, error)

// API is the HTTP surface.
type API struct {
	coord  *Coordinator
	payout *PayoutWorker
	// discovery is optional; nil means the waiting-tips route answers 501.
	discovery *MailboxDiscovery
	peers  PeerResolver

	// token is required. An unauthenticated payment API is not a smaller
	// version of a secure one.
	//
	// A single shared token is a PLACEHOLDER. Roadmap D2 — how the website
	// authenticates to the node — is undecided, and this is the least that can
	// be shipped without pretending it is answered. The read/write split the
	// roadmap calls for is not here either: today every route needs the same
	// token.
	token string
}

// NewAPI wires the surface. It refuses to exist without a token.
func NewAPI(coord *Coordinator, peers PeerResolver, token string) (*API, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrNoAPIToken
	}
	return &API{coord: coord, peers: peers, token: token}, nil
}

// WithPayout enables the settlement routes. Without a worker they answer 501:
// a node that cannot pay gas should say so rather than accept a request it will
// silently never act on.
func (a *API) WithPayout(w *PayoutWorker) *API { a.payout = w; return a }

// WithMailboxDiscovery enables the waiting-tips route.
//
// Without it the route answers 501 rather than "nothing waiting": a node that
// cannot look must not report an empty mailbox, because the recipient would
// read that as nobody having tipped them.
func (a *API) WithMailboxDiscovery(d *MailboxDiscovery) *API { a.discovery = d; return a }

// Handler returns the routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.health)
	mux.HandleFunc("/v1/channels", a.authed(a.listChannels))
	mux.HandleFunc("/v1/channels/", a.authed(a.channelRoutes))
	// The recipient's own pooled-tipping view (P15). Same token, same loopback
	// surface — a pool is not a new trust domain, so it does not get a new one.
	mux.HandleFunc("/v1/pool", a.authed(a.pool))
	// Withdrawing pooled value. Same token; a checkpoint is a financial
	// operation and gets no weaker a gate than reading the balance.
	mux.HandleFunc("/v1/pool/checkpoint", a.authed(a.poolCheckpoint))
	// "Is anything waiting for me at my volunteer?" — read-only, and the only
	// reason it lives on the node rather than in the page is that only the
	// recipient's key can authorise the read (see mailboxdiscovery.go).
	mux.HandleFunc("/v1/mailbox/waiting", a.authed(a.mailboxWaiting))
	return mux
}

// ---- plumbing ---------------------------------------------------------------

func (a *API) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		// Length-independent comparison is not worth pretending at here: the
		// token is a shared secret over loopback, and D2 will replace it.
		if got == "" || got != a.token {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrChannelNotOnChain), errors.Is(err, ErrChannelNotAdopted), errors.Is(err, ErrNoSuchChannel):
		code = http.StatusNotFound
	case errors.Is(err, ErrNotAParticipant):
		code = http.StatusForbidden
	case errors.Is(err, ErrConflicted):
		code = http.StatusConflict
	case errors.Is(err, ErrInsufficient), errors.Is(err, ErrAmountNotPositive),
		errors.Is(err, ErrNotAParty), errors.Is(err, ErrUnknownKind),
		errors.Is(err, ErrNoSuchLock), errors.Is(err, ErrLockExists),
		errors.Is(err, ErrPreimageBad), errors.Is(err, ErrLocksRemain),
		// A withdrawal the state does not support is the caller being wrong,
		// not the node being broken. Reported as 500 until the devnet run
		// showed a correctly-refused replay arriving as a server error — which
		// would push an operator to investigate an outage that never happened.
		errors.Is(err, ErrCheckpointNotEligible), errors.Is(err, ErrCheckpointTooLarge):
		code = http.StatusUnprocessableEntity
	case errors.Is(err, ErrChainUnreachable):
		code = http.StatusBadGateway
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- reads -------------------------------------------------------------------

type channelSummary struct {
	ID string `json:"id"`
	// The channel's parties, as the chain recorded them. An input the
	// operator's browser needs to verify signatures on a volunteer-carried
	// state; it does not make this API an authority on payment.
	PartyA     string `json:"party_a"`
	PartyB     string `json:"party_b"`
	Mine       string `json:"mine"`
	Theirs     string `json:"theirs"`
	Locked     string `json:"locked"`
	Nonce      uint64 `json:"nonce"`
	Conflicted bool   `json:"conflicted"`
}

func (a *API) listChannels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	out := []channelSummary{}
	for _, id := range a.coord.Channels() {
		bal, err := a.coord.Balances(id)
		if err != nil {
			continue
		}
		out = append(out, summarise(bal))
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": out})
}

// summarise renders what the coordinator already computed. Note it does no
// arithmetic — amounts are stringified, not derived.
func summarise(b Balances) channelSummary {
	return channelSummary{
		ID:         hex.EncodeToString(b.ChannelID[:]),
		PartyA:     b.PartyA.Hex(),
		PartyB:     b.PartyB.Hex(),
		Mine:       decString(b.Mine),
		Theirs:     decString(b.Theirs),
		Locked:     decString(b.Locked),
		Nonce:      b.Nonce,
		Conflicted: b.Conflicted,
	}
}

// ---- routes under /v1/channels/{id}/… ---------------------------------------

func (a *API) channelRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/channels/")
	parts := strings.SplitN(strings.Trim(rest, "/"), "/", 2)
	id, err := parseBytes32(parts[0])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "channel id must be 32 hex bytes"})
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "":
		a.getChannel(w, r, id)
	case "adopt":
		a.adopt(w, r, id)
	case "pay":
		a.pay(w, r, id)
	case "recover":
		a.recover(w, r, id)
	case "payout":
		a.payoutStatus(w, r, id)
	case "payout/policy":
		a.payoutPolicy(w, r, id)
	case "payout/close":
		a.payoutClose(w, r, id)
	case "payout/run":
		a.payoutRun(w, r, id)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such action"})
	}
}

func (a *API) getChannel(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	bal, err := a.coord.Balances(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summarise(bal))
}

func (a *API) adopt(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	if err := a.coord.Adopt(r.Context(), id); err != nil {
		writeErr(w, err)
		return
	}
	bal, err := a.coord.Balances(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summarise(bal))
}

// ---- payment -----------------------------------------------------------------

// payRequest is what a caller may say. Note what is absent: no balances, no
// nonce, no state, no signature. An intent and an amount.
type payRequest struct {
	// Intent makes a retry a retry. 32 hex bytes, chosen by the caller and
	// reused verbatim on every attempt at the SAME payment.
	Intent string `json:"intent"`
	// Kind defaults to PAY.
	Kind TransitionKind `json:"kind,omitempty"`
	// Amount in wei, as a DECIMAL STRING. A JSON number cannot carry 1e20
	// through a browser, and 100 ANON is 1e20.
	Amount string `json:"amount,omitempty"`

	// Lock fields, for the conditional kinds.
	LockID   string `json:"lock_id,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Expiry   int64  `json:"expiry,omitempty"`
	Preimage string `json:"preimage,omitempty"`
}

type payResponse struct {
	// Outcome is completed | rejected | unknown. Three states, kept apart on
	// purpose: "unknown" is not a failure, it is an unfinished exchange, and it
	// is answered by /recover rather than by retrying blindly.
	Outcome string     `json:"outcome"`
	Nonce   uint64     `json:"nonce,omitempty"`
	Route   string     `json:"route,omitempty"`
	Reason  RejectCode `json:"reason,omitempty"`
	Detail  string     `json:"detail,omitempty"`
	// Retryable is only meaningful when rejected.
	Retryable bool `json:"retryable,omitempty"`
}

func (a *API) pay(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req payRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed body"})
		return
	}
	intent, err := parseBytes32(req.Intent)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "intent must be 32 hex bytes"})
		return
	}
	tr, err := buildTransition(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	peer, err := a.peerFor(r, id)
	if err != nil {
		writeErr(w, err)
		return
	}

	result, err := a.coord.Pay(r.Context(), id, intent, tr, peer)
	if err != nil {
		// The distinction that matters. A coordinator error here means the
		// exchange did not complete — the peer may well have committed the
		// payment. Saying "failed" would be a guess.
		if isUnknownOutcome(err) {
			writeJSON(w, http.StatusAccepted, payResponse{
				Outcome: "unknown",
				Detail:  err.Error(),
			})
			return
		}
		writeErr(w, err)
		return
	}
	if result.Rejected != "" {
		writeJSON(w, http.StatusOK, payResponse{
			Outcome: "rejected", Reason: result.Rejected,
			Detail: result.Detail, Retryable: result.Retryable(),
		})
		return
	}
	if !result.Done {
		writeJSON(w, http.StatusAccepted, payResponse{Outcome: "unknown"})
		return
	}
	writeJSON(w, http.StatusOK, payResponse{
		Outcome: "completed", Nonce: result.Nonce, Route: result.Route,
	})
}

// buildTransition turns a request into a transition. The nearest this file comes
// to constructing anything, and deliberately mechanical: no defaults invented,
// no amounts computed, no expiry chosen on the caller's behalf.
func buildTransition(req payRequest) (StateTransition, error) {
	kind := req.Kind
	if kind == "" {
		kind = KindPay
	}
	tr := StateTransition{Kind: kind, Expiry: req.Expiry}

	if req.Amount != "" {
		amount, ok := new(big.Int).SetString(req.Amount, 10)
		if !ok {
			return tr, fmt.Errorf("amount must be a decimal string in wei")
		}
		tr.Amount = amount
	}
	for _, f := range []struct {
		s    string
		dst  *[32]byte
		name string
	}{
		{req.LockID, &tr.LockID, "lock_id"},
		{req.Hash, &tr.Hash, "hash"},
		{req.Preimage, &tr.Preimage, "preimage"},
	} {
		if f.s == "" {
			continue
		}
		v, err := parseBytes32(f.s)
		if err != nil {
			return tr, fmt.Errorf("%s must be 32 hex bytes", f.name)
		}
		*f.dst = v
	}
	return tr, nil
}

// isUnknownOutcome reports whether an error leaves the payment undecided.
//
// Anything from the transport does: the message may have been received, acted
// on and committed by the peer before the connection failed. Errors raised
// before the message went out do not, but distinguishing those precisely is not
// worth being clever about — treating a local refusal as "unknown" costs one
// resync, while treating a lost reply as "failed" costs a double payment.
func isUnknownOutcome(err error) bool {
	return strings.Contains(err.Error(), "transport:")
}

func (a *API) recover(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	peer, err := a.peerFor(r, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	outcome, err := a.coord.Recover(r.Context(), id, peer)
	if err != nil {
		writeErr(w, err)
		return
	}
	bal, balErr := a.coord.Balances(id)
	body := map[string]any{"outcome": string(outcome)}
	if balErr == nil {
		body["channel"] = summarise(bal)
	}
	writeJSON(w, http.StatusOK, body)
}

func (a *API) peerFor(r *http.Request, id [32]byte) (Peer, error) {
	if a.peers == nil {
		return nil, errors.New("api: no peer resolver configured")
	}
	ch, ok := a.coord.Channel(id)
	if !ok {
		// Adopt so the counterparty is known from the chain rather than guessed.
		if err := a.coord.Adopt(r.Context(), id); err != nil {
			return nil, err
		}
		ch, ok = a.coord.Channel(id)
		if !ok {
			return nil, ErrChannelNotAdopted
		}
	}
	counterparty := ch.PartyA
	if counterparty == a.coord.self {
		counterparty = ch.PartyB
	}
	return a.peers(id, counterparty)
}

// ---- settlement ----------------------------------------------------------------
//
// As thin as the payment routes, and for the same reason. A caller asks for
// "checkpoint this channel" or "close this channel"; it does not supply
// balances, a nonce, withdrawal amounts, signatures or calldata. Those are
// consequences of the current signed state and the recipient's policy, and
// letting a caller name them would put the state machine back on the far side
// of an HTTP request.

func (a *API) requirePayout(w http.ResponseWriter) bool {
	if a.payout == nil {
		writeJSON(w, http.StatusNotImplemented,
			map[string]string{"error": "this node has no settlement worker configured"})
		return false
	}
	return true
}

func (a *API) payoutStatus(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	if !a.requirePayout(w) {
		return
	}
	status, err := a.payout.Status(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type payoutPolicyRequest struct {
	Mode PayoutMode `json:"mode"`
	// IntervalSeconds applies to interval mode.
	IntervalSeconds int64 `json:"interval_seconds,omitempty"`
}

func (a *API) payoutPolicy(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	if !a.requirePayout(w) {
		return
	}
	var req payoutPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed body"})
		return
	}
	switch req.Mode {
	case PayoutOnClose:
	case PayoutOnInterval:
		if req.IntervalSeconds <= 0 {
			writeJSON(w, http.StatusBadRequest,
				map[string]string{"error": "interval mode needs a positive interval_seconds"})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest,
			map[string]string{"error": "mode must be on_close or interval"})
		return
	}
	if err := a.payout.SetPolicy(id, PayoutPolicy{
		Mode: req.Mode, IntervalSeconds: req.IntervalSeconds,
	}); err != nil {
		writeErr(w, err)
		return
	}
	status, err := a.payout.Status(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// payoutClose asks for the money now, whatever the schedule says.
func (a *API) payoutClose(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	if !a.requirePayout(w) {
		return
	}
	if err := a.payout.RequestClose(id); err != nil {
		writeErr(w, err)
		return
	}
	a.runPayout(w, r, id)
}

// payoutRun advances a channel's settlement one step. What the scheduled worker
// does, exposed so an operator can push it.
func (a *API) payoutRun(w http.ResponseWriter, r *http.Request, id [32]byte) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	if !a.requirePayout(w) {
		return
	}
	a.runPayout(w, r, id)
}

func (a *API) runPayout(w http.ResponseWriter, r *http.Request, id [32]byte) {
	outcome, err := a.payout.Settle(r.Context(), id)
	status, statusErr := a.payout.Status(id)

	body := map[string]any{"outcome": string(outcome)}
	if statusErr == nil {
		body["payout"] = status
	}
	if err != nil {
		// A settlement that could not complete is reported WITH its outcome, so
		// a caller can tell "not due" from "the RPC is down" from "there are
		// locks outstanding" — three situations with three different answers.
		body["error"] = err.Error()
		writeJSON(w, http.StatusAccepted, body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// mailboxWaiting reports what a volunteer is holding, without consuming it.
//
// GET-shaped on purpose: it changes nothing. The volunteer endpoint comes in
// the query because a recipient may move between volunteers and the node should
// not need restarting to follow them.
func (a *API) mailboxWaiting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	if a.discovery == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "this node has no mailbox discovery configured"})
		return
	}
	q := r.URL.Query()
	endpoint := strings.TrimSpace(q.Get("volunteer"))
	if endpoint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "volunteer required"})
		return
	}
	frames, err := a.discovery.Waiting(r.Context(), endpoint, q.Get("node_id"))
	if err != nil {
		// 502, not 200-with-nothing. The caller must be able to tell "I could
		// not look" from "I looked and it was empty".
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if frames == nil {
		frames = []Envelope{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recipient": a.discovery.Self.Hex(),
		"frames":    frames,
		// Said explicitly so no caller has to infer it from the route name.
		"consumed": false,
	})
}
