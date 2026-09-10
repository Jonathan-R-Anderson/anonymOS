package channel

// A forwarding router: one hop of a three-hop payment.
//
// This is where the onion stops being a data structure and becomes routing.
//
// WHAT A ROUTER IS ALLOWED TO REMEMBER
// ------------------------------------
// The roadmap's retention policy is not advice, it is the thing that decides
// whether the onion accomplished anything. A router that logged its decrypted
// hop instruction alongside a timestamp has reconstructed, for its own hop,
// exactly what the encryption exists to prevent — and three such logs joined
// are the whole path.
//
// So this type is built so the forbidden data has nowhere to live:
//
//	discarded immediately   the decrypted instruction, the shared secret,
//	                        the full onion packet after forwarding
//	kept until settled      the outgoing lock, the replay guard
//	kept long-term          aggregate counts only — never per-payment records
//
// Retention is enforced by what the struct HOLDS, not by remembering to delete.
// A `forwarded map[...]HopInstruction` would be a correct-looking cache and a
// complete breach; there is deliberately no such field.
//
// WHY A ROUTER REFUSES RATHER THAN GUESSES
// ----------------------------------------
// Every check here fails the payment. That is the safe direction: a forwarded
// payment this node cannot later claim upstream is money it has lost, and no
// fee is worth a maybe.

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrReplayed        = errors.New("channel: this hop has already forwarded that payment")
	ErrExpiredHop      = errors.New("channel: hop expiry has passed")
	ErrExpiryTooTight  = errors.New("channel: insufficient timelock margin to forward safely")
	ErrFeeUnacceptable = errors.New("channel: offered fee is below this router's minimum")
	ErrNoLiquidity     = errors.New("channel: insufficient outbound liquidity for this hop")
	ErrTooManyInFlight = errors.New("channel: too many payments already in flight")
)

// RouterPolicy is the operator's configuration, mirroring RouterConfig.
type RouterPolicy struct {
	// MinTimelockMargin is the safety gap this router demands between the
	// incoming expiry and its own outgoing one. It is the room to claim
	// upstream after paying downstream, and the setting that actually loses
	// money when set too low.
	MinTimelockMargin time.Duration
	MaxInFlight       int
	MaxHTLCValue      Amount
	BaseFee           Amount
	// PrivateOnly refuses payments that are not privately routed, so an
	// operator who does not want to know who pays whom can arrange to be unable
	// to find out.
	PrivateOnly bool
}

// InFlight is a lock this router has taken on, and the only per-payment record
// it keeps. Note what is absent: no next hop, no predecessor, no amount beyond
// the commitment, no instruction.
type InFlight struct {
	// ReplayGuard identifies the payment TO THIS HOP only. It is per-hop and
	// per-payment by construction, so it cannot be correlated with the same
	// payment at another router.
	ReplayGuard [32]byte
	// OutgoingCommitment is what this router must satisfy to be paid.
	OutgoingCommitment Commitment
	Expiry             time.Time
}

// Router forwards one hop.
type Router struct {
	policy RouterPolicy
	key    *Key

	mu sync.Mutex
	// inFlight is keyed by replay guard: the double-forward check and the
	// outstanding-lock record are the same set, because they answer the same
	// question.
	inFlight map[[32]byte]InFlight
	// seen is the replay guard of every payment ever forwarded. Kept because a
	// payment that settled must not be forwardable again, and dropping it when
	// the lock resolves would make replay possible one second later.
	seen map[[32]byte]bool

	// Aggregate counters. The only long-lived record, and deliberately not
	// per-payment: "3,412 forwarded" says what an operator needs and identifies
	// nobody.
	Forwarded uint64
	Refused   uint64
}

func NewRouter(policy RouterPolicy, key *Key) *Router {
	if policy.MinTimelockMargin <= 0 {
		policy.MinTimelockMargin = 10 * time.Minute
	}
	if policy.MaxInFlight <= 0 {
		policy.MaxInFlight = 20
	}
	return &Router{
		policy: policy, key: key,
		inFlight: map[[32]byte]InFlight{}, seen: map[[32]byte]bool{},
	}
}

// Forward peels this router's layer and decides whether to carry the payment.
//
// Returns the packet to send onward. The decrypted instruction is NOT returned:
// a caller that received it could log it, and this function exists partly so
// there is no honest reason to.
func (r *Router) Forward(packet *Packet, shared [32]byte, outboundAvailable Amount, now time.Time) (*Packet, InFlight, error) {
	hop, err := packet.Peel(shared)
	if err != nil {
		r.count(false)
		return nil, InFlight{}, err
	}

	// Replay first: cheapest, and the only check that must consult state.
	r.mu.Lock()
	if r.seen[hop.ReplayGuard] {
		r.mu.Unlock()
		r.count(false)
		return nil, InFlight{}, ErrReplayed
	}
	if len(r.inFlight) >= r.policy.MaxInFlight {
		r.mu.Unlock()
		r.count(false)
		// The jamming defence. Without it a peer opens many small locks it
		// never settles and this router's liquidity is stuck until they expire.
		return nil, InFlight{}, ErrTooManyInFlight
	}
	r.mu.Unlock()

	outgoing := time.Unix(int64(hop.OutgoingExpiry), 0)
	if !outgoing.After(now) {
		r.count(false)
		return nil, InFlight{}, ErrExpiredHop
	}
	// The incoming expiry must exceed the outgoing by the margin. Forwarding
	// without it risks paying downstream and finding the upstream lock has
	// already expired — the one routing failure that actually loses money.
	incoming := time.Unix(int64(packet.Expiry), 0)
	if incoming.Sub(outgoing) < r.policy.MinTimelockMargin {
		r.count(false)
		return nil, InFlight{}, ErrExpiryTooTight
	}

	if r.policy.MaxHTLCValue > 0 && outboundAvailable < r.policy.MaxHTLCValue &&
		outboundAvailable <= 0 {
		r.count(false)
		return nil, InFlight{}, ErrNoLiquidity
	}
	if outboundAvailable <= 0 {
		r.count(false)
		return nil, InFlight{}, ErrNoLiquidity
	}

	lock := InFlight{
		ReplayGuard:        hop.ReplayGuard,
		OutgoingCommitment: hop.OutgoingCommitment,
		Expiry:             outgoing,
	}

	r.mu.Lock()
	r.inFlight[hop.ReplayGuard] = lock
	r.seen[hop.ReplayGuard] = true
	r.mu.Unlock()
	r.count(true)

	// The onward packet is the same size as what arrived — the blob is carried
	// forward unchanged in length, so this router's position cannot be inferred
	// downstream from what it emitted.
	onward := &Packet{
		EphemeralPublicKey: packet.EphemeralPublicKey,
		Slots:              packet.Slots,
		PaymentCommitment:  packet.PaymentCommitment,
		ProofReference:     packet.ProofReference,
		Expiry:             hop.OutgoingExpiry,
	}
	// `hop` goes out of scope here and is never stored. That is the retention
	// policy, expressed as the absence of an assignment.
	return onward, lock, nil
}

// Resolve clears a lock once the payment settled or expired.
//
// The lock is dropped; the replay guard is NOT. A settled payment must stay
// unforwardable, and forgetting it when the lock clears would open a replay
// window one second wide.
func (r *Router) Resolve(guard [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inFlight, guard)
}

// Outstanding reports locks still held.
func (r *Router) Outstanding() []InFlight {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]InFlight, 0, len(r.inFlight))
	for _, f := range r.inFlight {
		out = append(out, f)
	}
	return out
}

// ExpireStale drops locks past their deadline, returning how many.
//
// A router that never expired locks would fill MaxInFlight permanently the
// first time a downstream hop went silent.
func (r *Router) ExpireStale(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for guard, f := range r.inFlight {
		if !f.Expiry.After(now) {
			delete(r.inFlight, guard)
			n++
		}
	}
	return n
}

func (r *Router) count(ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		r.Forwarded++
	} else {
		r.Refused++
	}
}
