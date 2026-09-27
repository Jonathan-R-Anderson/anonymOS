package channel

// Payment history — roadmap P7-d.
//
// AN AUDIT LAYER, NEVER A SOURCE OF PAYMENT TRUTH
// -----------------------------------------------
//	history        observes
//	   │
//	   ▼
//	payment engine
//	   │
//	   ▼
//	signed state / chain      ← the authority
//
// Never the other way. "History says completed, therefore the payment
// completed" is the inversion this must not permit. Nothing in this file is
// consulted to decide whether value moved; Channel.Accept and the chain do
// that, and these records only describe what they did.
//
// So a balance is never computed from history, and history never holds a copy
// of one. It answers WHAT HAPPENED TO THIS PAYMENT, not what the channel is
// worth — those drift apart the moment a record is missed, and only one of them
// is allowed to be authoritative.
//
// UNKNOWN IS AN OUTCOME, NOT A FAILURE
// ------------------------------------
// An interrupted exchange leaves a payment that may or may not have happened.
// Every other layer here refuses to guess past that, and so does this one:
// PayUnknown is recorded as itself, and — the point of the phase —
//
//	a record MUST be able to move from unknown to completed or rejected
//	once recovery establishes what really happened.
//
// A history that permanently enshrined whatever the first attempt believed
// would be worse than no history, because it would be confidently wrong.
//
// EACH NODE RECORDS ONLY WHAT IT KNOWS
// ------------------------------------
// A recipient at the end of a routed payment learns that value arrived under a
// hash it could open. It does not learn who sent it, and this does not invent
// an origin for it. blinded.go and onion.go exist so a hop cannot name the
// endpoints; a history that reconstructed one would quietly undo that.

import (
	"encoding/hex"
	"time"
)

// PayStatus is where a payment got to.
type PayStatus string

const (
	// PayInitiated: proposed and signed by this node, not yet answered.
	PayInitiated PayStatus = "initiated"
	// PayInFlight: a conditional payment is live — the lock exists and nobody
	// has resolved it.
	PayInFlight PayStatus = "in_flight"
	// PayCompleted: a fully signed state carries it. The only status that means
	// the money moved.
	PayCompleted PayStatus = "completed"
	// PayRefunded: a lock came back to whoever put it up.
	PayRefunded PayStatus = "refunded"
	// PayRejected: the counterparty deliberately refused it.
	PayRejected PayStatus = "rejected"
	// PayUnknown: the exchange did not finish. It MAY have happened, and
	// recovery is what settles that — see the file header.
	PayUnknown PayStatus = "unknown"
)

// PayRoute distinguishes a direct tip from one that travelled.
type PayRoute string

const (
	RouteDirect PayRoute = "direct"
	RouteRouted PayRoute = "routed"
)

// PaymentRecord is one payment, as this node saw it.
//
// Note what is absent: any balance. A record says what moved, not what the
// channel is worth afterwards — the second is the state's job and duplicating
// it here would create a number that can disagree with the money.
type PaymentRecord struct {
	// Intent is the payment's identity, and the record's. Retrying an intent
	// updates this record rather than adding another, which is the same
	// idempotence the payment path has.
	Intent [32]byte `json:"intent"`
	// Kind is the transition that carried it.
	Kind TransitionKind `json:"kind"`
	// Route is direct or routed. A lock whose hash this node did not choose
	// arrived from somewhere else, which is what makes it routed.
	Route PayRoute `json:"route"`
	// Incoming is true when value came toward this node.
	Incoming bool      `json:"incoming"`
	Amount   string    `json:"amount"`
	Status   PayStatus `json:"status"`
	// LockID ties a conditional payment to the lock it created.
	LockID [32]byte `json:"lock_id,omitempty"`
	// Nonce is the state that carried it, once one did.
	Nonce      uint64 `json:"nonce,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	ResolvedAt int64  `json:"resolved_at,omitempty"`
	// Detail is a human-readable reason, for rejections and unknowns. Never
	// parsed.
	Detail string `json:"detail,omitempty"`
}

// Resolved reports whether this payment has stopped moving.
//
// Unknown is deliberately NOT resolved: it is the one status that is expected
// to change later.
func (r PaymentRecord) Resolved() bool {
	switch r.Status {
	case PayCompleted, PayRefunded, PayRejected:
		return true
	}
	return false
}

// IntentHex renders the identity for a UI or a log.
func (r PaymentRecord) IntentHex() string { return hex.EncodeToString(r.Intent[:]) }

// historyCap bounds what one channel keeps.
//
// The channel record is rewritten on every payment, so an unbounded log would
// make each tip cost more to write than the one before it. Unlike the applied-
// intent set this CAN be trimmed — nothing depends on old entries for
// correctness — which makes the cap a policy choice rather than a hazard.
// Longer retention belongs in a separate archive, not in the money record.
const historyCap = 256

// NotePayment records or UPDATES a payment by intent.
//
// Updating rather than appending is what lets unknown become completed. A
// second record for one intent would leave a reader with two answers and no
// rule for choosing.
func (c *Channel) NotePayment(rec PaymentRecord) {
	for i := range c.History {
		if c.History[i].Intent != rec.Intent {
			continue
		}
		existing := c.History[i]
		// A resolved record is final. Later noise — a retried proposal, a
		// duplicate acknowledgement — must not reopen a payment that already
		// completed.
		if existing.Resolved() {
			return
		}
		rec.CreatedAt = existing.CreatedAt
		if rec.Amount == "" || rec.Amount == "0" {
			rec.Amount = existing.Amount
		}
		if rec.Route == "" {
			rec.Route = existing.Route
		}
		c.History[i] = rec
		return
	}
	c.History = append(c.History, rec)
	if len(c.History) > historyCap {
		c.History = c.History[len(c.History)-historyCap:]
	}
}

// PaymentAt returns the record for an intent.
func (c *Channel) PaymentAt(intent [32]byte) (PaymentRecord, bool) {
	for _, r := range c.History {
		if r.Intent == intent {
			return r, true
		}
	}
	return PaymentRecord{}, false
}

// recordFor builds a record from a transition, in the direction this node saw
// it.
func recordFor(intent [32]byte, tr StateTransition, incoming bool, status PayStatus, now int64) PaymentRecord {
	rec := PaymentRecord{
		Intent: intent, Kind: tr.Kind, Incoming: incoming,
		Status: status, CreatedAt: now, LockID: tr.LockID,
		Route: RouteDirect,
	}
	if tr.Amount != nil {
		rec.Amount = decString(tr.Amount)
	}
	// A conditional payment is the shape a routed one takes. A plain PAY never
	// travelled; a lock may have, and this node cannot tell from its own end —
	// which is exactly the information a hop is not supposed to have.
	switch tr.Kind {
	case KindLockAdd, KindLockSettle, KindLockRefund:
		rec.Route = RouteRouted
	}
	return rec
}

// History returns a channel's payment log, oldest first.
func (c *Coordinator) History(id [32]byte) ([]PaymentRecord, error) {
	ch, ok := c.store.Get(id)
	if !ok {
		return nil, ErrChannelNotAdopted
	}
	return append([]PaymentRecord(nil), ch.History...), nil
}

func nowOr(fn func() int64) int64 {
	if fn != nil {
		return fn()
	}
	return time.Now().Unix()
}

// outcomeRecord is the record for a transition that has fully landed.
//
// The status depends on what the transition MEANS, not on the fact that it was
// accepted: adding a lock is not a completed payment, it is one in flight, and
// calling it completed would tell an operator money arrived that has not.
func outcomeRecord(intent [32]byte, tr StateTransition, incoming bool, nonce uint64, now int64) PaymentRecord {
	status := PayCompleted
	switch tr.Kind {
	case KindLockAdd:
		status = PayInFlight
	case KindLockRefund:
		status = PayRefunded
	}
	rec := recordFor(intent, tr, incoming, status, now)
	rec.Nonce = nonce
	if status != PayInFlight {
		rec.ResolvedAt = now
	}
	return rec
}
