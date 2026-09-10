package channel

// The mailbox's public HTTP surface — roadmap P15.
//
// SAME AUDIENCE AS /scpp/v1, SAME RULE. Strangers reach these routes: a
// contributor dropping a frame for somebody it cannot reach directly, and a
// recipient collecting their own mail from their own browser. Neither has an
// operator token and neither must ever be given one.
//
// So authorization here is the same shape webpeer.go uses — a SIGNATURE inside
// the request:
//
//	POST /mailbox/v1/authorize   the recipient's signed appointment of this node
//	POST /mailbox/v1/deliver     anyone may drop a frame for a served recipient
//	POST /mailbox/v1/collect     the recipient proves who they are and takes it
//
// The operator API in api.go is a different surface with a different gate, and
// nothing here may be mounted on it.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type mailboxAuthorizeRequest struct {
	Recipient string `json:"recipient"`
	NodeID    string `json:"node_id"`
	Endpoint  string `json:"endpoint"`
	Expires   int64  `json:"expires"`
	Sig       string `json:"sig"`
}

type mailboxDeliverRequest struct {
	Recipient string   `json:"recipient"`
	Envelope  Envelope `json:"envelope"`
}

type mailboxCollectRequest struct {
	Recipient string `json:"recipient"`
	Token     string `json:"token"`
	Sig       string `json:"sig"`
}

// MailboxHandler serves the public mailbox routes.
func MailboxHandler(m *Mailbox) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mailbox/v1/authorize", public(func(w http.ResponseWriter, r *http.Request) {
		var req mailboxAuthorizeRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		sig, err := ParseAuthorizationSig(req.Sig)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auth := MailboxAuthorization{
			Recipient: recipient, NodeID: req.NodeID, Endpoint: req.Endpoint,
			Expires: req.Expires, Sig: sig,
		}
		if err := m.Serve(auth); err != nil {
			// 403 for every refusal. A caller learns that it was refused and
			// not which recipients this node already serves.
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"node_id": m.NodeID, "serving": true})
	}))

	mux.HandleFunc("/mailbox/v1/deliver", public(func(w http.ResponseWriter, r *http.Request) {
		var req mailboxDeliverRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		// The frame is NOT inspected. A mailbox that parsed payments would be a
		// mailbox that could get them wrong.
		if err := m.Deliver(recipient, req.Envelope); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		// "Queued" is deliberately not "delivered" and certainly not "paid".
		// Nothing has happened to any channel: a proposal is waiting for a
		// recipient who has not seen it yet.
		writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
	}))

	mux.HandleFunc("/mailbox/v1/collect", public(func(w http.ResponseWriter, r *http.Request) {
		var req mailboxCollectRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		sig, err := ParseAuthorizationSig(req.Sig)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		frames, err := m.Collect(recipient, MailboxChallenge(m.NodeID, recipient, req.Token), sig)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if frames == nil {
			frames = []Envelope{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"frames": frames})
	}))

	// The recipient's own node asking WHETHER anything is waiting.
	//
	// Same proof as /collect and deliberately NOT the same effect: collect
	// empties the queue, so a console that used it to render "a tip is waiting"
	// would consume the proposal at page load, before the recipient had read it.
	// /states cannot serve this — it authorises the CONTRIBUTOR and derives the
	// channel from caller+recipient, which for a recipient asking about itself
	// derives a channel that does not exist.
	mux.HandleFunc("/mailbox/v1/peek", public(func(w http.ResponseWriter, r *http.Request) {
		var req mailboxCollectRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		sig, err := ParseAuthorizationSig(req.Sig)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		frames, err := m.Peek(recipient, MailboxChallenge(m.NodeID, recipient, req.Token), sig)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if frames == nil {
			frames = []Envelope{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"frames": frames})
	}))

	// A contributor rebuilding its own chain. Same public surface, same
	// signature-in-the-request rule: the caller proves which address it is, and
	// the channel id is DERIVED from that address and the recipient rather than
	// taken on the caller's word.
	mux.HandleFunc("/mailbox/v1/states", public(func(w http.ResponseWriter, r *http.Request) {
		var req mailboxStatesRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		caller, err := ParseAddress(req.Caller)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad caller"})
			return
		}
		sig, err := ParseAuthorizationSig(req.Sig)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		frames, err := m.StatesFor(recipient, caller, req.Channel,
			MailboxChallenge(m.NodeID, caller, req.Token), sig)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if frames == nil {
			frames = []Envelope{}
		}
		// NO "highest" FIELD, deliberately. Naming a winner here would make the
		// volunteer choose which economic state matters, and choosing is the one
		// thing it must not do. It returns candidates; the caller verifies every
		// signature itself and selects.
		writeJSON(w, http.StatusOK, map[string]any{"frames": frames})
	}))

	// The recipient publishing what it ACCEPTED, so the contributor can find out.
	//
	// Case A's missing half. Without it a contributor knows only that a
	// volunteer took its frame, never that the recipient countersigned — so it
	// has no base for the next tip. The co-signed state IS the evidence; there
	// is no separate payment record and nothing here to reconcile.
	mux.HandleFunc("/mailbox/v1/accepted", public(func(w http.ResponseWriter, r *http.Request) {
		var req mailboxAcceptedRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		sig, err := ParseAuthorizationSig(req.Sig)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// Only the recipient may publish, and only for itself. Not because the
		// state would be dangerous otherwise — a contributor verifies every
		// signature before using one — but because an open write here would let
		// anyone fill a volunteer's disk with states it will never serve.
		if err := m.PublishAccepted(recipient, req.Channel, req.Envelope,
			MailboxChallenge(m.NodeID, recipient, req.Token), sig); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"retained": true})
	}))

	return mux
}

type mailboxAcceptedRequest struct {
	Recipient string   `json:"recipient"`
	Channel   string   `json:"channel"`
	Token     string   `json:"token"`
	Sig       string   `json:"sig"`
	Envelope  Envelope `json:"envelope"`
}

type mailboxStatesRequest struct {
	Recipient string `json:"recipient"`
	Caller    string `json:"caller"`
	Channel   string `json:"channel"`
	Token     string `json:"token"`
	Sig       string `json:"sig"`
}

// public marks a mailbox route as browser-facing.
//
// THE SAME AUDIENCE AS /scpp/v1, SO THE SAME POLICY — cors() from webpeer.go,
// reused rather than restated, because two copies of a cross-origin policy is
// one of them drifting later.
//
// A mailbox exists to be reached by strangers' browsers. tip-channel.js posts
// JSON cross-origin, which always triggers an OPTIONS preflight, and a surface
// that answers 405 to that preflight is a surface no browser can ever reach:
// the POST is never sent. Observed in a real Firefox run, where the tip failed
// before a single byte of the delivery left the page.
//
// This is NOT the operator API loosening. That one is loopback-bound and
// token-gated and gets none of this. Here the load-bearing defence is the
// signature inside the message — cors never restricted sending, only reading —
// and mailbox authorization is still checked on the POST itself.
func public(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		if r.Method == http.MethodOptions {
			// Answered BEFORE any authorization: a preflight carries no body,
			// no signature and no recipient, so there is nothing to authorise
			// and a browser cannot proceed without an answer.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(into); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return false
	}
	return true
}

// MailboxCollectToken is what a recipient signs alongside their address.
//
// Supplied by the caller and bound into the challenge so a signature made for
// one collection cannot be replayed forever. A node that wanted stronger replay
// protection would issue the token itself; this is the minimum that stops a
// captured signature being reusable against another node, because the node id
// is in the challenge too.
func MailboxCollectToken(s string) string { return strings.TrimSpace(s) }
