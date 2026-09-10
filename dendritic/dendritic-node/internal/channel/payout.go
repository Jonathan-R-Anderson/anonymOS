package channel

// Payout — roadmap P6 settlement. Turning accumulated off-chain value into on-chain
// value.
//
// THE SAME TRUST MODEL AS COLLATERAL
// ----------------------------------
// P5-1 fixed where a deposit comes from: the chain, never a peer. This applies
// the identical rule to settlement. Whether a channel is settled, and at what
// state, is a question for AxonChannels — never for a local record of what
// this node believes it broadcast.
//
// That is not tidiness. It is the only thing that makes the worst case
// answerable: a node that died between broadcasting and recording genuinely
// cannot know what it did, but it can always ask.
//
//	broadcast → CRASH → restart → read the contract
//	                                 Settled  → done
//	                                 Open     → it did not land
//	                                 Closing  → a close is in its window
//
// So the Settlement record below is for humans and dashboards. The worker never
// decides anything from it that the chain could be asked about instead.
//
// SUBMITTED IS NOT CONFIRMED
// --------------------------
// The same distinction the transport layer makes, one layer down:
//
//	TCP write succeeded    ≠  payment completed
//	transaction broadcast  ≠  settlement completed
//
// Collapsing them is how a worker reports a settlement because it managed to
// send something. They are separate phases here and the worker moves between
// them only on a chain read.
//
// LOCKS FIRST
// -----------
// AxonChannels.settle reverts with LocksOutstanding while any lock is
// unresolved, and cannot simply hand them back: a lock whose expiry has not
// arrived may still be claimed with the preimage, and refunding it early would
// steal a payment that is legitimately in flight. So the worker resolves locks
// before it settles, and refuses rather than forcing.

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	ErrNothingToPayOut = errors.New("payout: channel has no fully signed state to settle")
	ErrLocksUnresolved = errors.New("payout: locks are still outstanding")
	ErrPayoutConflict  = errors.New("payout: channel is stopped after a conflict")
)

// PayoutMode is when the recipient wants value on chain.
type PayoutMode string

const (
	// PayoutOnClose leaves the channel off-chain until the recipient closes it.
	// The cheapest option and the default: no gas until the money is wanted.
	PayoutOnClose PayoutMode = "on_close"
	// PayoutOnInterval marks a channel due once its interval has elapsed.
	//
	// ⚠ READ settlement_notes.md — SEE ALSO the roadmap. Against the CURRENT
	// contract, settling means CLOSING: AxonChannels has no partial
	// withdrawal, so every settlement path ends at Status.Payoutd and pays out.
	// "Settle hourly" therefore means "close hourly", which costs a close plus
	// a fresh open and deposit each time. This mode is implemented so the
	// policy machinery is real, and the operation it triggers is a cooperative
	// close. Whether that is what an operator wants is a decision recorded in
	// the roadmap, not one this file makes.
	PayoutOnInterval PayoutMode = "interval"
)

// PayoutPolicy is the recipient's choice. Theirs because they pay the gas.
type PayoutPolicy struct {
	Mode PayoutMode `json:"mode"`
	// IntervalSeconds applies to PayoutOnInterval.
	IntervalSeconds int64 `json:"interval_seconds,omitempty"`
}

// DefaultPayoutPolicy is on-close: no gas spent until somebody asks for it.
func DefaultPayoutPolicy() PayoutPolicy {
	return PayoutPolicy{Mode: PayoutOnClose}
}

// PayoutPhase is how far a settlement has got.
//
//	none → submitted → confirmed
//	             ↘ failed (retryable)
type PayoutPhase string

const (
	PhaseNone      PayoutPhase = "none"
	PhaseSubmitted PayoutPhase = "submitted"
	PhaseConfirmed PayoutPhase = "confirmed"
	PhaseFailed    PayoutPhase = "failed"
)

// PayoutRecord is the local record. Not authoritative — see the file header.
type PayoutRecord struct {
	Policy PayoutPolicy `json:"policy"`
	Phase  PayoutPhase  `json:"phase"`
	// TxHash is what was broadcast, if anything. Kept for humans following a
	// transaction; the worker does not conclude anything from its presence.
	TxHash string `json:"tx_hash,omitempty"`
	// Nonce is the state that was submitted, so a later reader can tell WHICH
	// state went on chain.
	Nonce         uint64 `json:"nonce,omitempty"`
	SubmittedAt   int64  `json:"submitted_at,omitempty"`
	ConfirmedAt   int64  `json:"confirmed_at,omitempty"`
	LastAttemptAt int64  `json:"last_attempt_at,omitempty"`
	Attempts      int    `json:"attempts,omitempty"`
	// LastError is the most recent failure, for a dashboard. Never parsed.
	LastError string `json:"last_error,omitempty"`
	// DueAt is when an interval policy next wants this channel settled.
	DueAt int64 `json:"due_at,omitempty"`
}

// ---- the chain, in the writing direction ------------------------------------

// ChainWriter submits transactions.
//
// Sharply separate from ChainReader, and not merged with it, because they are
// different capabilities with different failure modes and different
// requirements: reading needs an RPC endpoint, writing needs a key that can pay
// gas. A component that only needs to look at the chain should not be handed
// the ability to spend from it.
//
// The settlement worker talks to this and never constructs a transaction
// itself, so it can be tested without pretending to be on chain.
type ChainWriter interface {
	// Approve authorises a spender to move `amount` of the token on this node's
	// behalf. Sent to the TOKEN contract, not to AxonChannels — funding a
	// channel is two transactions against two contracts, because openChannel
	// calls safeTransferFrom and ERC-20 moves nothing without an allowance.
	Approve(ctx context.Context, token, spender Address, amount *big.Int) (string, error)
	// OpenChannel opens a channel with partner and funds it in one transaction.
	OpenChannel(ctx context.Context, contract Address, partner Address, deposit *big.Int) (string, error)
	// Deposit tops up a channel that already exists.
	Deposit(ctx context.Context, contract Address, id [32]byte, amount *big.Int) (string, error)
	// Checkpoint submits a co-signed state that takes value out WITHOUT closing.
	// The channel stays open and keeps its nonce line.
	Checkpoint(ctx context.Context, contract Address, ch *Channel) (string, error)
	// CloseCooperative submits a fully signed, lock-free state. Returns the
	// transaction hash.
	//
	// A returned hash means BROADCAST, not settled. The worker learns the
	// difference by reading the chain.
	CloseCooperative(ctx context.Context, contract Address, ch *Channel) (string, error)
	// ClaimLock resolves a lock with its preimage.
	ClaimLock(ctx context.Context, contract Address, id [32]byte,
		locks []HTLC, index int, preimage [32]byte) (string, error)
	// ExpireLock returns an expired lock to whoever put it up.
	ExpireLock(ctx context.Context, contract Address, id [32]byte,
		locks []HTLC, index int) (string, error)
}

// ---- outcomes ----------------------------------------------------------------

// PayoutOutcome is what one pass did about one channel.
type PayoutOutcome string

const (
	OutcomeNotDue         PayoutOutcome = "NOT_DUE"
	OutcomeNothingToDo    PayoutOutcome = "NOTHING_TO_SETTLE"
	OutcomeSubmitted      PayoutOutcome = "SUBMITTED"
	OutcomeConfirmed      PayoutOutcome = "CONFIRMED"
	OutcomeAlreadyOnChain PayoutOutcome = "ALREADY_SETTLED_ON_CHAIN"
	OutcomeAwaitingWindow PayoutOutcome = "AWAITING_CHALLENGE_WINDOW"
	OutcomeLocksPending   PayoutOutcome = "LOCKS_PENDING"
	OutcomeFailed         PayoutOutcome = "FAILED"
	OutcomeStopped        PayoutOutcome = "STOPPED_BY_CONFLICT"
)

// PayoutWorker turns signed states into on-chain value.
type PayoutWorker struct {
	store    *Store
	chain    ChainReader
	writer   ChainWriter
	contract Address
	now      func() int64
}

// NewPayoutWorker wires one.
func NewPayoutWorker(store *Store, chain ChainReader, writer ChainWriter, contract Address) *PayoutWorker {
	return &PayoutWorker{
		store: store, chain: chain, writer: writer, contract: contract,
		now: func() int64 { return time.Now().Unix() },
	}
}

// SetClock replaces the clock. For tests, and for anywhere an operator needs
// settlement timing to follow something other than wall clock.
func (w *PayoutWorker) SetClock(now func() int64) { w.now = now }

// SetPolicy records the recipient's choice.
func (w *PayoutWorker) SetPolicy(id [32]byte, policy PayoutPolicy) error {
	return w.store.Update(id, func(c *Channel) error {
		if c.Payout == nil {
			c.Payout = &PayoutRecord{Phase: PhaseNone}
		}
		c.Payout.Policy = policy
		if policy.Mode == PayoutOnInterval && policy.IntervalSeconds > 0 {
			c.Payout.DueAt = w.now() + policy.IntervalSeconds
		} else {
			c.Payout.DueAt = 0
		}
		return nil
	})
}

// RequestClose marks a channel for settlement now, whatever its policy.
//
// The explicit-close path. An interval policy is a schedule; this is a person
// saying they want their money.
func (w *PayoutWorker) RequestClose(id [32]byte) error {
	return w.store.Update(id, func(c *Channel) error {
		if c.Payout == nil {
			c.Payout = &PayoutRecord{Policy: DefaultPayoutPolicy(), Phase: PhaseNone}
		}
		c.Payout.DueAt = 1 // any time in the past; due immediately
		return nil
	})
}

// Pass runs one round over every tracked channel.
//
// A failure on one channel never stops the others: settlement is per-channel
// and an unreachable RPC for one is not a reason to leave the rest unsettled.
func (w *PayoutWorker) Pass(ctx context.Context) map[[32]byte]PayoutOutcome {
	out := map[[32]byte]PayoutOutcome{}
	for _, id := range w.store.IDs() {
		outcome, err := w.Settle(ctx, id)
		if err != nil {
			out[id] = PayoutOutcome(string(OutcomeFailed) + ": " + err.Error())
			continue
		}
		out[id] = outcome
	}
	return out
}

// Settle advances one channel, asking the chain what is true before doing
// anything.
//
// THE ORDER MATTERS AND IS THE POINT: the chain is read FIRST, every time, even
// when the local record says the phase is none. A node that crashed after
// broadcasting has a local record saying nothing happened and a chain that says
// otherwise, and the chain is right.
func (w *PayoutWorker) Settle(ctx context.Context, id [32]byte) (PayoutOutcome, error) {
	ch, ok := w.store.Get(id)
	if !ok {
		return "", ErrNoSuchChannel
	}
	if ch.Conflict != nil {
		// A conflicted channel needs a force close with the best state held,
		// which is a decision for an operator rather than a scheduled worker.
		return OutcomeStopped, nil
	}

	occ, err := w.chain.ReadChannel(ctx, w.contract, id)
	if err != nil {
		return "", err
	}

	switch occ.Status {
	case StatusSettled:
		// It landed — whether this node remembers sending it or not.
		if err := w.mark(id, func(s *PayoutRecord) {
			s.Phase = PhaseConfirmed
			if s.ConfirmedAt == 0 {
				s.ConfirmedAt = w.now()
			}
			s.LastError = ""
		}); err != nil {
			return "", err
		}
		if ch.Payout != nil && ch.Payout.Phase == PhaseConfirmed {
			return OutcomeAlreadyOnChain, nil
		}
		return OutcomeConfirmed, nil

	case StatusClosing:
		// A unilateral close is in its challenge window. Nothing to submit;
		// this is the watchtower's territory (P10a) and settle() is only
		// callable once the window ends and locks are resolved.
		if err := w.mark(id, func(s *PayoutRecord) { s.Phase = PhaseSubmitted }); err != nil {
			return "", err
		}
		return OutcomeAwaitingWindow, nil

	case StatusOpen:
		// Nothing has landed. Whether this node broadcast something earlier is
		// not the question — it clearly did not take effect.
		return w.trySubmit(ctx, id)
	}
	return "", fmt.Errorf("payout: unexpected on-chain status %d", occ.Status)
}

func (w *PayoutWorker) trySubmit(ctx context.Context, id [32]byte) (PayoutOutcome, error) {
	ch, ok := w.store.Get(id)
	if !ok {
		return "", ErrNoSuchChannel
	}
	if !w.due(ch) {
		return OutcomeNotDue, nil
	}
	if !ch.Latest.Complete() {
		// Nothing was ever agreed. The deposits are already where they belong,
		// and closing would spend gas to move nothing.
		return OutcomeNothingToDo, nil
	}
	// Which operation depends on the policy, and they are genuinely different:
	// a checkpoint draws value down and leaves the channel open, a close ends
	// it. Both submit a state both parties signed.
	drawing := hasWithdrawal(ch.Latest.State)
	if drawing && ch.Payout != nil && ch.Payout.Policy.Mode == PayoutOnInterval {
		txHash, err := w.writer.Checkpoint(ctx, w.contract, ch)
		return w.afterSubmit(id, ch, txHash, err)
	}

	// Closing needs the locks resolved: closeCooperative refuses a state with a
	// non-zero root, and they cannot be force-returned without stealing a
	// payment that may still be claimable.
	if len(ch.Latest.State.Pending) > 0 {
		return OutcomeLocksPending, ErrLocksUnresolved
	}
	if drawing {
		// A state that takes value out is not a state that closes: the close
		// paths sign zero withdrawals, so this would revert on chain.
		return OutcomeFailed, errors.New("payout: the latest state is a checkpoint; it cannot be used to close")
	}

	txHash, err := w.writer.CloseCooperative(ctx, w.contract, ch)
	return w.afterSubmit(id, ch, txHash, err)
}

// hasWithdrawal reports whether a state takes value out of the channel.
func hasWithdrawal(s State) bool {
	return orZero(s.WithdrawA).Sign() > 0 || orZero(s.WithdrawB).Sign() > 0
}

// afterSubmit records a broadcast, or its failure.
func (w *PayoutWorker) afterSubmit(id [32]byte, ch *Channel, txHash string, err error) (PayoutOutcome, error) {
	if err != nil {
		_ = w.mark(id, func(s *PayoutRecord) {
			s.Phase = PhaseFailed
			s.Attempts++
			s.LastAttemptAt = w.now()
			s.LastError = err.Error()
		})
		return OutcomeFailed, err
	}

	// SUBMITTED, not confirmed. A hash is a broadcast; the next pass reads the
	// chain to find out what became of it.
	if err := w.mark(id, func(s *PayoutRecord) {
		s.Phase = PhaseSubmitted
		s.TxHash = txHash
		s.Nonce = ch.Latest.State.Nonce
		s.SubmittedAt = w.now()
		s.LastAttemptAt = w.now()
		s.Attempts++
		s.LastError = ""
	}); err != nil {
		// The transaction is already out. Failing to record it is exactly the
		// case the chain-first rule covers: the next pass reads the chain and
		// catches up, so this is reported rather than treated as lost.
		return OutcomeSubmitted, fmt.Errorf("payout: broadcast %s but could not record it: %w", txHash, err)
	}
	return OutcomeSubmitted, nil
}

// due reports whether policy wants this channel settled now.
func (w *PayoutWorker) due(ch *Channel) bool {
	if ch.Payout == nil {
		return false
	}
	switch ch.Payout.Policy.Mode {
	case PayoutOnInterval:
		return ch.Payout.DueAt > 0 && w.now() >= ch.Payout.DueAt
	default:
		// On-close: only when somebody asked, which RequestClose records by
		// setting a due time in the past.
		return ch.Payout.DueAt > 0 && w.now() >= ch.Payout.DueAt
	}
}

func (w *PayoutWorker) mark(id [32]byte, fn func(*PayoutRecord)) error {
	return w.store.Update(id, func(c *Channel) error {
		if c.Payout == nil {
			c.Payout = &PayoutRecord{Policy: DefaultPayoutPolicy(), Phase: PhaseNone}
		}
		fn(c.Payout)
		return nil
	})
}

// ---- locks ------------------------------------------------------------------

// ResolveLocks claims what it has preimages for and refunds what has expired,
// so a channel can reach a settleable state.
//
// preimages maps a lock's hash to its secret — whatever the node learned while
// forwarding. A lock it cannot open and that has not expired is simply left:
// it is still somebody's live claim.
func (w *PayoutWorker) ResolveLocks(ctx context.Context, id [32]byte,
	preimages map[[32]byte][32]byte) (claimed, refunded int, err error) {

	ch, ok := w.store.Get(id)
	if !ok {
		return 0, 0, ErrNoSuchChannel
	}
	locks := ch.Latest.State.Pending
	now := w.now()

	for i, lock := range locks {
		// KNOWING THE SECRET IS NOT ENOUGH — THE LOCK MUST STILL BE LIVE.
		//
		//	AxonChannels.claimLock: if (block.timestamp >= lock.expiry) revert LockHasExpired();
		//
		// This branch used to fire on `known` alone and then `continue`, so an
		// expired lock whose secret was known went to claimLock, REVERTED on
		// chain, and never reached the expireLock branch below. The value was
		// then neither claimed nor reclaimed — and because the error returns
		// immediately, every REMAINING lock in the channel went unresolved too.
		//
		// The expiry test is the same one the off-chain settle rule now applies
		// (session.go checkTiming): past expiry a lock is refund-only, because
		// that is all the chain will honour.
		if secret, known := preimages[lock.Hash]; known && lock.Matches(secret) && lock.Expiry > now {
			if _, err := w.writer.ClaimLock(ctx, w.contract, id, locks, i, secret); err != nil {
				return claimed, refunded, err
			}
			claimed++
			continue
		}
		if lock.Expiry <= now {
			if _, err := w.writer.ExpireLock(ctx, w.contract, id, locks, i); err != nil {
				return claimed, refunded, err
			}
			refunded++
		}
	}
	return claimed, refunded, nil
}

// ---- reporting ---------------------------------------------------------------

// PayoutStatus is what a dashboard shows. Derived, never authoritative.
type PayoutStatus struct {
	ChannelID string      `json:"channel_id"`
	Mode      PayoutMode  `json:"mode"`
	Phase     PayoutPhase `json:"phase"`
	TxHash    string      `json:"tx_hash,omitempty"`
	Nonce     uint64      `json:"nonce,omitempty"`
	DueAt     int64       `json:"due_at,omitempty"`
	Attempts  int         `json:"attempts,omitempty"`
	LastError string      `json:"last_error,omitempty"`
	Locked    string      `json:"locked"`
}

// Status reports one channel's settlement position from the local record.
//
// Explicitly the LOCAL view, for humans. Anything acting on it should read the
// chain instead — which is what Settle does on every pass.
func (w *PayoutWorker) Status(id [32]byte) (PayoutStatus, error) {
	ch, ok := w.store.Get(id)
	if !ok {
		return PayoutStatus{}, ErrNoSuchChannel
	}
	out := PayoutStatus{
		ChannelID: fmt.Sprintf("%x", ch.ID),
		Phase:     PhaseNone,
		Mode:      PayoutOnClose,
		Locked:    decString(ch.Latest.State.lockedTotal()),
	}
	if s := ch.Payout; s != nil {
		out.Mode, out.Phase = s.Policy.Mode, s.Phase
		out.TxHash, out.Nonce = s.TxHash, s.Nonce
		out.DueAt, out.Attempts, out.LastError = s.DueAt, s.Attempts, s.LastError
	}
	return out, nil
}
