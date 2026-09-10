package channel

// Multi-hop routing — roadmap P7-b.
//
// A hub forwards value it can never keep. That is the whole property, and it is
// what the HTLCs were integrated from the beginning for:
//
//	           ONE SECRET, TWO LOCKS
//	                   │
//	       ┌───────────┴───────────┐
//	       ▼                       ▼
//	  upstream lock           downstream lock
//	   A owes Hub              Hub owes B
//
// A's money moves only if the Hub can produce the secret. The Hub can only
// produce the secret because B revealed it to take the downstream payment. So
// the Hub is paid upstream exactly when it has paid downstream, and neither
// half can happen alone.
//
// WHAT THIS FILE IS NOT
// ---------------------
// It is not hub.go, which is still in this package and still wrong for this:
// that keeps its own map of reader and recipient balances in int64 and moves
// value between them. A hub with its own ledger is a custodian — it holds A's
// money and decides later whether B gets it. Nothing here holds anything. Every
// movement is a co-signed V2 state on an ordinary bilateral channel, and the
// forwarding is only ever an ORDERING of those.
//
// THE TWO WAYS A HUB LOSES MONEY, AND WHY NEITHER CAN HAPPEN
// ----------------------------------------------------------
//	paid downstream, cannot claim upstream
//	    the secret is persisted before the downstream settle is signed
//	    (see preimages.go), and the upstream lock outlives the downstream
//	    one by a margin this file enforces.
//
//	paid upstream, not paid downstream
//	    impossible by construction: the upstream claim REQUIRES the secret,
//	    and the secret only exists downstream once B has taken the money.

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	ErrNoMargin        = errors.New("routing: not enough time left on the incoming lock to forward safely")
	ErrNoSuchIncoming  = errors.New("routing: no such lock on the incoming channel")
	ErrSecretUnknown   = errors.New("routing: this node does not know the secret for that lock")
	ErrNotTheForwarder = errors.New("routing: this node is not the payee of that incoming lock")
)

// DefaultHopMargin is how much longer an incoming lock must live than the
// outgoing one this node creates against it.
//
// It is a SAFETY margin, not a courtesy. Between B settling downstream and this
// node claiming upstream there is a message, a signature, possibly a reconnect,
// and possibly a force close with a challenge window. If the incoming lock
// expires inside that gap the node has paid and cannot collect.
const DefaultHopMargin = 2 * time.Hour

// refundSkewMargin is how far past an expiry this node waits before proposing a
// refund. The counterparty applies its own clock skew allowance in the opposite
// direction — deliberately, so a fast clock cannot reclaim a lock somebody could
// still settle — and proposing inside that window just collects refusals.
const refundSkewMargin = 120

// Forwarder is a hub's routing logic over the channels it already has.
type Forwarder struct {
	coord *Coordinator
	vault *PreimageVault
	self  Address
	// metrics is aggregate-only: a routed payment happened, not whose.
	metrics *Metrics

	now    func() int64
	margin int64
}

// NewForwarder wires one. The vault is required: a node that cannot durably
// remember a secret must not forward, because forwarding is being owed upstream
// on a secret learned downstream.
func NewForwarder(coord *Coordinator, vault *PreimageVault, self Address) *Forwarder {
	return &Forwarder{
		coord: coord, vault: vault, self: self,
		now:    func() int64 { return time.Now().Unix() },
		margin: int64(DefaultHopMargin / time.Second),
	}
}

// SetMetrics attaches an aggregate collector.
func (f *Forwarder) SetMetrics(m *Metrics) { f.metrics = m }

// SetClock replaces the clock and the hop margin.
func (f *Forwarder) SetClock(now func() int64, marginSeconds int64) {
	f.now, f.margin = now, marginSeconds
}

// Incoming describes a lock this node has been offered.
type Incoming struct {
	Channel [32]byte
	Lock    HTLC
}

// Pending lists locks where this node is the PAYEE — value offered to it, not
// yet resolved. These are the ones a hub may forward, and the ones a leaf
// simply settles.
func (f *Forwarder) Pending() []Incoming {
	out := []Incoming{}
	for _, id := range f.coord.Channels() {
		ch, ok := f.coord.Channel(id)
		if !ok {
			continue
		}
		for _, lock := range ch.Latest.State.Pending {
			payer := ch.Party(lock.PayerIsA)
			if payer == f.self {
				continue // this node put it up; it is outgoing
			}
			out = append(out, Incoming{Channel: id, Lock: lock})
		}
	}
	return out
}

// Forward offers a matching lock downstream against one held upstream.
//
// The amounts are equal here: a routing fee is D3 and unanswered, and when it
// exists it appears as a difference between the two, which the state model
// already expresses. Taking one before it is decided would be inventing policy.
//
// The expiry is where the safety lives. The outgoing lock must expire EARLIER
// than the incoming one by the margin, so that when B settles downstream there
// is still time to claim upstream. The contract cannot check this — it sees one
// channel at a time — so it is checked here or nowhere.
func (f *Forwarder) Forward(ctx context.Context, in Incoming, outChannel [32]byte,
	intent [32]byte, peer Peer) (PaymentResult, error) {

	upstream, ok := f.coord.Channel(in.Channel)
	if !ok {
		return PaymentResult{}, ErrChannelNotAdopted
	}
	// Only forward against a lock somebody offered THIS node. Forwarding
	// against one it put up itself would be paying twice for nothing.
	if upstream.Party(in.Lock.PayerIsA) == f.self {
		return PaymentResult{}, ErrNotTheForwarder
	}
	if i := findLock(upstream.Latest.State.Pending, in.Lock.ID); i < 0 {
		return PaymentResult{}, ErrNoSuchIncoming
	}

	outExpiry := in.Lock.Expiry - f.margin
	if outExpiry <= f.now() {
		// Either the incoming lock is nearly expired or the margin does not
		// fit. Forwarding now would create a downstream obligation this node
		// might not be able to recover upstream.
		return PaymentResult{}, fmt.Errorf(
			"%w: incoming expires in %ds, margin is %ds",
			ErrNoMargin, in.Lock.Expiry-f.now(), f.margin)
	}

	// A forward is one routed payment. The channels, the lock and the hash are
	// all in scope here and none is passed: the metric is that routing was used.
	f.metrics.RoutedPayment()

	return f.coord.Pay(ctx, outChannel, intent, StateTransition{
		Kind:   KindLockAdd,
		Amount: new(big.Int).Set(orZero(in.Lock.Amount)),
		// The SAME hash. That is the entire mechanism: one secret unlocks both
		// halves, so the two payments stand or fall together.
		LockID: in.Lock.ID,
		Hash:   in.Lock.Hash,
		Expiry: outExpiry,
	}, peer)
}

// ClaimUpstream settles a lock this node is owed, using a secret it has learned.
//
// Called after the downstream settlement revealed the preimage — which is also
// when the vault got it, because HandlePropose stores it before signing.
//
// Refuses without the secret rather than proposing something the peer would
// reject: a settle nobody can verify is a wasted round trip and a confusing log
// line, and the honest answer is that this node cannot claim yet.
func (f *Forwarder) ClaimUpstream(ctx context.Context, in Incoming,
	intent [32]byte, peer Peer) (PaymentResult, error) {

	preimage, known := f.vault.Lookup(in.Lock.Hash)
	if !known {
		return PaymentResult{}, ErrSecretUnknown
	}
	return f.coord.Pay(ctx, in.Channel, intent, StateTransition{
		Kind:     KindLockSettle,
		LockID:   in.Lock.ID,
		Preimage: preimage,
	}, peer)
}

// claimUpstreamIntent identifies ONE LOCK INSTANCE for idempotency purposes.
//
// Named and separate so the property can be tested directly: two locks that
// merely share an id must derive different intents, while the same lock derives
// the same intent across a restart. See the comment at its call site in
// SweepClaimable for the theft that a lock-id-only key allowed.
func claimUpstreamIntent(in Incoming) [32]byte {
	return derive("syndichan/routing/claim-upstream/v2",
		in.Channel[:], in.Lock.ID[:], in.Lock.Hash[:],
		orZero(in.Lock.Amount).Bytes(), u64(uint64(in.Lock.Expiry)))
}

// SweepClaimable settles every incoming lock this node can now open.
//
// What a hub runs after a downstream settlement, and again on startup: a node
// that crashed between learning a secret and claiming upstream comes back, finds
// the secret in the vault and the lock still pending, and finishes the job. The
// vault is what makes that possible; without it the money would simply be gone.
func (f *Forwarder) SweepClaimable(ctx context.Context, peer func([32]byte) (Peer, error)) []error {
	var problems []error
	for _, in := range f.Pending() {
		if _, known := f.vault.Lookup(in.Lock.Hash); !known {
			continue
		}
		p, err := peer(in.Channel)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		// The intent identifies THIS LOCK INSTANCE, not merely its id.
		//
		// It was keccak("claim-upstream", Lock.ID) — and the goal was right: a
		// retry after a crash must produce the same intent so it cannot claim
		// twice. But a lock ID is only unique among PENDING locks. Channel.Accept
		// builds its duplicate check over st.Pending (state.go:691), so once a
		// lock settles or refunds its id leaves the state and is free again.
		//
		// That turned the crash-idempotency key into a theft:
		//
		//	1. payment 1 uses lock id L, resolves. AppliedAt(intent_L) is recorded.
		//	2. payment 2 reuses L upstream. Accept permits it — L is not pending.
		//	3. the hub forwards, pays downstream, learns the preimage.
		//	4. the sweep recomputes intent_L. Coordinator.Pay finds it already
		//	   applied and returns Done WITHOUT claiming anything.
		//	5. res.Done is true, so the sweep reports no problem.
		//
		// The hub paid downstream, never claimed upstream, and believed it had.
		// Verified as a working exploit before this change.
		//
		// Binding the channel, hash, amount and expiry keeps the crash property —
		// every input is read back off the pending lock, so a restart derives the
		// same bytes — while making two instances that merely share an id derive
		// different ones.
		intent := claimUpstreamIntent(in)
		res, err := f.ClaimUpstream(ctx, in, intent, p)
		if err != nil {
			problems = append(problems, fmt.Errorf("claiming %x: %w", in.Lock.ID[:4], err))
			continue
		}
		// A REJECTION IS NOT SUCCESS. Coordinator.Pay returns a refusal as a
		// result with a nil error, deliberately — "the peer said no" and "the
		// network broke" are different. A sweep that only looked at err would
		// report a claim it never made, and the money would quietly expire.
		if !res.Done {
			problems = append(problems, fmt.Errorf("claiming %x: refused: %s %s",
				in.Lock.ID[:4], res.Rejected, res.Detail))
		}
	}
	return problems
}

// RefundExpired returns locks this node put up that nobody claimed.
//
// The other half of the guarantee: if a forwarded payment never completes, the
// value comes back rather than sitting locked forever. Each hop refunds its own
// outgoing lock once the expiry passes, which cascades backwards to the payer
// because their lock always expires later than the one they funded.
func (f *Forwarder) RefundExpired(ctx context.Context, peer func([32]byte) (Peer, error)) []error {
	var problems []error
	now := f.now()

	for _, id := range f.coord.Channels() {
		ch, ok := f.coord.Channel(id)
		if !ok {
			continue
		}
		for _, lock := range ch.Latest.State.Pending {
			if ch.Party(lock.PayerIsA) != f.self {
				continue // not this node's money to reclaim
			}
			// The peer applies its own skew tolerance before agreeing a lock has
			// expired, and skew works against the refunder — so a lock that is
			// only just past its expiry here will still be refused there.
			// Waiting is correct: the alternative is a rejected proposal every
			// pass until the margin catches up.
			if lock.Expiry > now-refundSkewMargin {
				continue
			}
			// A lock this node can open is claimable, not refundable: taking it
			// back when the payee could still settle would be reclaiming a
			// payment that has, in effect, happened.
			if _, known := f.vault.Lookup(lock.Hash); known {
				continue
			}
			p, err := peer(id)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			var intent [32]byte
			copy(intent[:], keccak([]byte("refund-expired"), lock.ID[:]))
			res, err := f.coord.Pay(ctx, id, intent, StateTransition{
				Kind: KindLockRefund, LockID: lock.ID,
			}, p)
			if err != nil {
				problems = append(problems, fmt.Errorf("refunding %x: %w", lock.ID[:4], err))
				continue
			}
			// Same as above: a peer that says LOCK_NOT_EXPIRED has not refunded
			// anything, and treating that as done would leave the value locked
			// while the caller believed it was back.
			if !res.Done {
				problems = append(problems, fmt.Errorf("refunding %x: refused: %s %s",
					lock.ID[:4], res.Rejected, res.Detail))
			}
		}
	}
	return problems
}
