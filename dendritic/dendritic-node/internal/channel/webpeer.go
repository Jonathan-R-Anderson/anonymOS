package channel

// SCPP/1 over HTTP, so a browser can be a peer — roadmap P8.
//
// WHY THIS EXISTS
// ---------------
// A tipper IS a channel party. It holds a key, it signs states, and it needs to
// exchange STATE_REQUEST/STATE_PROPOSE with the recipient's node like any other
// peer. What it cannot do is open a TCP socket, because it is a web page.
//
// So this is a carrier, not a second protocol. Same envelopes, same message
// types, same reject codes, same Handler — one request carries one frame and
// the reply carries whatever the coordinator produced. Everything transport.go
// says about staying dumb applies here word for word:
//
//	the carrier never inspects a message, never decides what it means,
//	and never turns "the HTTP request succeeded" into "the payment happened"
//
// A second protocol for browsers would be a second place for the state machine
// to be subtly different, and money would find the difference.
//
// WHY IT IS NOT AUTHENTICATED
// ---------------------------
// The operator API in api.go is bearer-token authed because it acts on the
// operator's behalf: it can move this node's money and change its payout
// policy. This endpoint is the opposite — it is how STRANGERS talk to this
// node, and a tipper has no operator token and must never be given one.
//
// What authorises a message here is the signature inside it. A party who cannot
// sign for a channel cannot change it, so there is nothing a bearer token would
// add and a great deal it would wrongly imply. Mounting this on the authed mux
// would be a serious mistake in both directions: tippers locked out, and a
// token handed to a web page.
//
// The honest cost: unlike a TCP listener that can sit behind a firewall or an
// onion address, this is reachable from any page in any visitor's browser, and
// CORS does not change that (it never restricted sending, only reading). So the
// bound below is a real defence and not decoration — but the load-bearing one
// remains that every state-changing message needs a signature, and every claim
// about deposits is settled against the chain rather than the sender.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// DefaultWebPeerConcurrency bounds frames in flight from browsers.
//
// Sized as a guard against a stampede rather than a throughput target: a real
// tipper sends two or three frames to make a payment, so a node with genuine
// traffic never approaches this and a node under load sheds instead of dying.
const DefaultWebPeerConcurrency = 64

// WebPeer serves SCPP/1 to browsers over HTTP.
type WebPeer struct {
	// Handler is the coordinator. Same interface the TCP server dispatches to,
	// deliberately: if these two ever pointed at different things, a browser and
	// a node would be talking to different state machines.
	Handler Handler
	// Timeout bounds one exchange.
	Timeout time.Duration
	// Concurrency caps frames in flight. Zero means DefaultWebPeerConcurrency.
	Concurrency int
	// OnError, if set, is told about failures. Nothing here logs on its own —
	// see transport.go for why a library that writes on a hostile peer's
	// schedule is a library that can be made to fill a disk.
	OnError func(error)

	once  sync.Once
	slots chan struct{}
}

// Handler returns the HTTP surface: POST for a frame, OPTIONS for the preflight
// that a cross-origin JSON POST always triggers.
func (wp *WebPeer) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/scpp/v1", wp.exchange)
	return mux
}

func (wp *WebPeer) init() {
	wp.once.Do(func() {
		n := wp.Concurrency
		if n <= 0 {
			n = DefaultWebPeerConcurrency
		}
		wp.slots = make(chan struct{}, n)
	})
}

// cors permits any origin and NO credentials.
//
// Both halves matter. Any origin, because a tipper arrives from whatever site
// embedded the tip button and this node cannot enumerate them. No credentials,
// because the pair "allow any origin" and "allow credentials" is the classic
// way to turn a public endpoint into a confused deputy — and the browser
// forbids that combination anyway, so asking for it would break every tip.
//
// Echoing back the request's Origin is deliberately NOT done: it looks stricter
// and is not, since any page can send any Origin it likes. It would only make
// the policy harder to read.
func cors(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", "600")
	// Nothing here is cacheable: every frame is a distinct point in a
	// conversation about money.
	h.Set("Cache-Control", "no-store")
}

func (wp *WebPeer) exchange(w http.ResponseWriter, r *http.Request) {
	wp.init()
	cors(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if wp.Handler == nil {
		wp.fail(w, http.StatusServiceUnavailable, errors.New("scpp: no handler"))
		return
	}

	select {
	case wp.slots <- struct{}{}:
		defer func() { <-wp.slots }()
	default:
		// Shedding is the honest answer, and 503 with Retry-After says
		// "later, not never" — which for a tipper is true.
		w.Header().Set("Retry-After", "1")
		wp.fail(w, http.StatusServiceUnavailable, errors.New("scpp: too many exchanges in flight"))
		return
	}

	// The same cap the framed transport applies, for the same reason: a frame
	// is bounded, so a peer cannot ask this node to buffer without limit.
	body := http.MaxBytesReader(w, r.Body, MaxFrameBytes)
	var env Envelope
	if err := json.NewDecoder(body).Decode(&env); err != nil {
		wp.fail(w, http.StatusBadRequest, err)
		return
	}
	if env.V != ProtocolVersion {
		wp.fail(w, http.StatusBadRequest, ErrBadVersion)
		return
	}

	timeout := wp.Timeout
	if timeout <= 0 {
		timeout = DefaultExchangeTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	reply, err := wp.Handler.Handle(ctx, env)
	if err != nil {
		// NOTE, as in transport.go: a rejection is NOT an error. STATE_REJECT
		// arrives here as a reply with a nil error, and goes back as a 200,
		// because a refusal is a protocol outcome the peer must be able to read
		// and act on. Reaching this branch means the frame could not be
		// processed at all.
		wp.fail(w, http.StatusUnprocessableEntity, err)
		return
	}
	if reply == nil {
		// Messages that need no answer. 204 rather than an empty 200 so a
		// client cannot mistake "nothing to say" for a truncated reply.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeEnvelope(w, http.StatusOK, *reply)
}

// fail answers with an ERROR envelope AND a non-2xx status.
//
// Both, because the two audiences differ: fetch() and every proxy in between
// read the status, and the client's protocol code reads the envelope. Sending
// only one leaves whichever reader it was not addressed to guessing.
func (wp *WebPeer) fail(w http.ResponseWriter, code int, cause error) {
	if wp.OnError != nil {
		wp.OnError(cause)
	}
	env, err := newEnvelope(MsgError, [32]byte{}, ErrorBody{Detail: cause.Error()})
	if err != nil {
		http.Error(w, "scpp: error", code)
		return
	}
	writeEnvelope(w, code, env)
}

func writeEnvelope(w http.ResponseWriter, code int, env Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(env)
}
