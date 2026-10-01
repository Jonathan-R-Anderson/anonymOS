package channel

// Defending a channel whose owner is not watching — roadmap P10.
//
// THE ASYMMETRY THIS EXISTS FOR
// -----------------------------
// A recipient's node is online; it can watch its own channels. A tipper is a
// person who opened a browser tab:
//
//	make one tip  ->  close the tab  ->  leave for six months
//
// Nobody in that sequence is watching the chain. But `closeUnilateral` lets
// either party put a state on chain and start a clock, and if a STALE state
// wins that clock the difference is simply taken. A payment system whose safety
// depends on the payer staying awake is not a payment system.
//
// So somebody else has to be able to defend the channel. The contract makes
// that possible by NOT restricting `challenge` to the parties — it checks the
// signatures, not the sender — which means a watchtower needs no key of the
// party it defends and can never move their money anywhere except where they
// already signed it.
//
// WHAT IT CAN AND CANNOT DO
// -------------------------
//	can:     submit a state both parties already signed
//	cannot:  create a state, alter one, or pay itself
//
// The worst a hostile watchtower can do is nothing at all — which is exactly
// what happens if there is no watchtower, so delegating to one is never worse
// than not having one. That is the property that makes this safe to hand out.
//
// WHY IT POLLS THE CHAIN RATHER THAN WATCHING EVENTS
// -------------------------------------------------
// An event is a notification; the mapping is the fact. A watchtower that had
// been down for an hour, or whose log subscription silently dropped, would have
// no way to discover a close it had missed — and "silently dropped" is the
// normal failure mode of a websocket subscription. Polling costs one eth_call
// per channel per interval and cannot miss a close that is still open.
//
// It also means detection latency is a NUMBER THIS FILE CHOOSES rather than a
// property of somebody's RPC provider, which matters because that number goes
// into challengePeriod.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrNoBetterState is returned when this watchtower has nothing that beats what
// is on chain. Not a failure: it is the ordinary answer for an honest close.
var ErrNoBetterState = errors.New("watchtower: no better state to submit")

// ErrTooLate is returned when the challenge window has already closed.
//
// Distinct from every other failure on purpose. Everything else is worth
// retrying and this is not, and a watchtower that kept retrying past the
// deadline would bury the one event an operator most needs to see.
var ErrTooLate = errors.New("watchtower: the challenge window has closed")

// DisputeSender broadcasts a challenge.
//
// Narrower than ChainWriter deliberately: a watchtower must not be able to open,
// deposit, checkpoint or close. It submits states that already exist.
type DisputeSender interface {
	Challenge(ctx context.Context, contract Address, signed SignedState) (string, error)
}

// WatchOutcome is what one pass over one channel did.
type WatchOutcome string

const (
	// WatchQuiet: the channel is not closing. The overwhelmingly common answer.
	WatchQuiet WatchOutcome = "quiet"
	// WatchHonest: closing, and the state on chain is the best one known. The
	// system working, not a problem.
	WatchHonest WatchOutcome = "honest"
	// WatchChallenged: a stale close was beaten.
	WatchChallenged WatchOutcome = "challenged"
	// WatchFailed: a stale close was found and NOT beaten. The one outcome that
	// must reach a human.
	WatchFailed WatchOutcome = "failed"
	// WatchSettled: already past the window, nothing to do.
	WatchSettled WatchOutcome = "settled"
)

// Watch is one channel's result from one pass.
type Watch struct {
	Channel [32]byte
	Outcome WatchOutcome
	// OnChainNonce and BestNonce are what made the decision. Recorded because
	// "why did you not challenge" is the question an incident asks first.
	OnChainNonce uint64
	BestNonce    uint64
	// Deadline is the challengeEnds this pass saw, and Remaining is how long was
	// left when it looked. Remaining going negative across a fleet is the signal
	// that challengePeriod is too short.
	Deadline  int64
	Remaining int64
	TxHash    string
	Err       error
}

// ChannelSource is where a watchtower gets the states it defends with.
//
// An interface because there are two kinds of holder and they must not become
// one type: a node's own Store, written by a participant, and a Vault, written
// by strangers and verifying everything. The watchtower needs the same two
// methods from both and no more — which is also a useful limit on it, since
// these are the only two operations that cannot alter anything.
type ChannelSource interface {
	IDs() [][32]byte
	Get(id [32]byte) (*Channel, bool)
}

// Watchtower defends channels it holds states for.
type Watchtower struct {
	Store    ChannelSource
	Chain    ChainReader
	Sender   DisputeSender
	Contract Address

	// Metrics is aggregate-only. A Watch carries the channel id and the tx hash;
	// NEITHER is passed to the collector. The measured facts are "a channel was
	// examined" and "a recovery was attempted", which is what the workload
	// question needs and all it needs.
	Metrics *Metrics

	// Interval is how often Run sweeps. This is DETECTION LATENCY, and it is
	// the first term in the challengePeriod budget — see doc/watchtower.md.
	Interval time.Duration
	// Margin is how close to the deadline this will still try. Inside it, the
	// transaction is unlikely to confirm in time and a failed attempt is worse
	// than a recorded, alarming refusal.
	Margin time.Duration

	// Now is injectable so a test can control a deadline. A watchtower whose
	// clock cannot be moved cannot be tested against the thing it exists for.
	Now func() time.Time

	// OnResult, if set, is told about every pass. This is how the measurement
	// harness collects timings without the watchtower knowing it is measured.
	OnResult func(Watch)

	mu      sync.Mutex
	stopped bool
}

const (
	// DefaultWatchInterval is the sweep period.
	//
	// Thirty seconds is a deliberate trade: it costs one eth_call per channel
	// per half minute, and it bounds detection latency at 30s rather than at
	// "however long until somebody notices". The number is small enough to be
	// a rounding error in a challenge period measured in hours.
	DefaultWatchInterval = 30 * time.Second

)

// DefaultWatchMargin is how much runway a challenge is given.
//
// Below this the attempt is abandoned and reported rather than sent. A
// transaction broadcast two minutes before a deadline it needs an hour to meet
// spends gas to lose, and — worse — writes "challenge sent" into a log somebody
// later reads as "we were fine".
//
// DERIVED, not chosen. It is exactly the part of the challengePeriod budget
// still ahead of a watchtower that has only just noticed: local work, inclusion,
// repricing, RPC failover and reorg depth. Picking a round number here instead
// would let the two drift, and the direction they drift is a watchtower
// confidently attempting challenges that cannot arrive in time.
var DefaultWatchMargin = WatchMarginFor(MainnetChallengeBudget().Recommend())

func (w *Watchtower) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watchtower) interval() time.Duration {
	if w.Interval > 0 {
		return w.Interval
	}
	return DefaultWatchInterval
}

func (w *Watchtower) margin() time.Duration {
	if w.Margin > 0 {
		return w.Margin
	}
	return DefaultWatchMargin
}

// Sweep checks every tracked channel once.
//
// Returns a result per channel rather than an error, because one unreachable
// channel must not stop the other forty from being defended — and the pass that
// found nothing is as much a fact as the pass that acted.
func (w *Watchtower) Sweep(ctx context.Context) []Watch {
	if w.Store == nil {
		return nil
	}
	out := []Watch{}
	for _, id := range w.Store.IDs() {
		// One observation per channel examined. `id` is right here and is not
		// passed: the aggregate is how MUCH was watched, never what.
		w.Metrics.WatchtowerObservation()
		result := w.Check(ctx, id)
		if w.OnResult != nil {
			w.OnResult(result)
		}
		out = append(out, result)
	}
	return out
}

// Check examines one channel and challenges it if it must.
func (w *Watchtower) Check(ctx context.Context, id [32]byte) Watch {
	result := Watch{Channel: id}

	ch, ok := w.Store.Get(id)
	if !ok {
		result.Outcome = WatchQuiet
		return result
	}
	if ch.Latest.Complete() {
		result.BestNonce = ch.Latest.State.Nonce
	}

	// The chain, not the peer. Everything this decides rests on what the
	// contract currently believes, and asking anybody else would be asking the
	// party who might be attacking.
	onChain, err := w.Chain.ReadChannel(ctx, w.Contract, id)
	if err != nil {
		result.Outcome = WatchFailed
		result.Err = fmt.Errorf("watchtower: reading the chain: %w", err)
		return result
	}

	result.OnChainNonce = onChain.Nonce
	result.Deadline = onChain.ChallengeEnds

	if onChain.Status != StatusClosing {
		if onChain.Status == StatusSettled {
			result.Outcome = WatchSettled
			return result
		}
		result.Outcome = WatchQuiet
		return result
	}

	now := w.now()
	result.Remaining = onChain.ChallengeEnds - now.Unix()

	// STRICTLY greater, matching the contract. A state at the same nonce is not
	// better, and submitting it would revert.
	if !ch.Latest.Complete() || ch.Latest.State.Nonce <= onChain.Nonce {
		// The close is honest, or at least not one this node can improve on.
		result.Outcome = WatchHonest
		return result
	}

	if result.Remaining <= 0 {
		result.Outcome = WatchFailed
		result.Err = ErrTooLate
		return result
	}
	if time.Duration(result.Remaining)*time.Second < w.margin() {
		// Too close to make it. Refused loudly rather than attempted quietly:
		// a broadcast that cannot confirm in time still writes "challenge sent"
		// into a log somebody will later read as "we were fine".
		result.Outcome = WatchFailed
		result.Err = fmt.Errorf(
			"watchtower: %ds left is inside the %s margin; not attempting",
			result.Remaining, w.margin())
		return result
	}

	if w.Sender == nil {
		result.Outcome = WatchFailed
		result.Err = errors.New("watchtower: a stale close needs challenging and there is no sender")
		return result
	}

	txHash, err := w.Sender.Challenge(ctx, w.Contract, ch.Latest)
	if err != nil {
		result.Outcome = WatchFailed
		result.Err = fmt.Errorf("watchtower: submitting the challenge: %w", err)
		return result
	}
	// A recovery happened. txHash is in hand and stays in the Watch, which is an
	// operator-facing result; the collector gets the fact, not the transaction.
	w.Metrics.WatchtowerRecovery()
	result.Outcome = WatchChallenged
	result.TxHash = txHash
	return result
}

// Run sweeps until the context ends.
func (w *Watchtower) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval())
	defer ticker.Stop()

	// Sweep immediately: a watchtower that started after a close and waited a
	// full interval before looking has spent its first interval blind, which is
	// the interval most likely to matter after a restart.
	w.Sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.mu.Lock()
			stopped := w.stopped
			w.mu.Unlock()
			if stopped {
				return nil
			}
			w.Sweep(ctx)
		}
	}
}

// Stop ends a Run after the current sweep.
func (w *Watchtower) Stop() {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
}

// ChallengeSender is the production DisputeSender, over an RPC writer.
type ChallengeSender struct{ Writer *RPCChainWriter }

// Challenge builds and broadcasts the transaction.
func (c ChallengeSender) Challenge(ctx context.Context, contract Address, signed SignedState) (string, error) {
	data, err := ChallengeCalldata(signed)
	if err != nil {
		return "", err
	}
	return c.Writer.send(ctx, contract, data)
}
