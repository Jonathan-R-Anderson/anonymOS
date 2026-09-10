package channel

// Transitions: the deterministic rule that turns a payment intent into the next
// state. SCPP/1 §4.2 and §5 — doc/channel-payment-protocol.md.
//
// WHY A TRANSITION IS A THING AND NOT JUST "THE NEXT STATE"
// --------------------------------------------------------
// Channel.Accept answers "is this state legal". That is not enough to accept a
// payment, because a legal state is not necessarily THE state the payment asked
// for. A payer could propose a perfectly conserved, perfectly signed state that
// moves a different amount than the one being discussed, and every check in
// Accept would pass.
//
// So a proposal carries the transition that produced it, and the payee recomputes:
//
//	Apply(stored latest, transition) == the state I was sent ?
//
// Byte-identical, not "equivalent". That single comparison is what makes a
// proposal unambiguous rather than merely valid.
//
// WHY THIS FUNCTION MUST BE PURE
// ------------------------------
// It is also what makes retries safe (§5). The same base state and the same
// transition must produce the same bytes on every machine, every time — so no
// clock, no randomness, no map iteration order, and lock ids chosen by the payer
// rather than generated here.
//
// The one thing it deliberately does NOT check is whether an expiry is in the
// future. See Channel.Accept's note: freshness is policy, decided by the layer
// that has a clock, because a validation that consults one would let two nodes
// with a little skew disagree about the same signed state.

import (
	"errors"
	"fmt"
	"math/big"
)

// TransitionKind names what a proposal is doing. The wire values are fixed by
// SCPP/1 §3.4 and must not be renamed.
type TransitionKind string

const (
	// KindPay is an ordinary tip: value moves from the payer to the payee.
	KindPay TransitionKind = "PAY"
	// KindLockAdd offers a conditional payment. The amount leaves the payer's
	// balance and enters NEITHER balance until the lock resolves.
	KindLockAdd TransitionKind = "LOCK_ADD"
	// KindLockSettle claims a lock with its preimage. Proposed by the party who
	// learned the secret, which is the lock's payee — so unlike PAY, the
	// proposer is the one who GAINS.
	KindLockSettle TransitionKind = "LOCK_SETTLE"
	// KindLockRefund returns an expired lock to whoever put it up.
	KindLockRefund TransitionKind = "LOCK_REFUND"
	// KindClose fixes a final state for a cooperative close. No value moves and
	// no locks may remain — the contract's closeCooperative refuses a state
	// with a non-zero root.
	KindClose TransitionKind = "CLOSE"
	// KindCheckpoint takes value OUT of the channel without closing it. The
	// amount leaves the proposer's balance and enters neither — it goes to the
	// chain, which pays it to them and reduces the collateral.
	//
	// A checkpoint is co-signed like any other state, which is the point: a
	// withdrawal nobody agreed to is not expressible, and the contract verifies
	// the amounts against the same signatures.
	KindCheckpoint TransitionKind = "CHECKPOINT"
)

var (
	ErrUnknownKind       = errors.New("channel: unknown transition kind")
	ErrNoSuchLock        = errors.New("channel: no such lock in the current state")
	ErrLockExists        = errors.New("channel: a lock with that id is already pending")
	ErrPreimageBad       = errors.New("channel: preimage does not open that lock")
	ErrLocksRemain       = errors.New("channel: cannot close with locks outstanding")
	ErrAmountNotPositive = errors.New("channel: amount must be positive")
	ErrNotAParty         = errors.New("channel: proposer is not a party to this channel")
)

// StateTransition is what a STATE_PROPOSE says it is doing.
type StateTransition struct {
	Kind TransitionKind `json:"kind"`

	// Amount is used by PAY and LOCK_ADD.
	Amount *big.Int `json:"amount,omitempty"`

	// LockID names the lock for LOCK_ADD, LOCK_SETTLE and LOCK_REFUND. Chosen
	// by the payer rather than derived here, so that Apply stays pure and a
	// retry produces the same bytes.
	LockID [32]byte `json:"lock_id,omitempty"`

	// Hash and Expiry describe a new lock (LOCK_ADD).
	Hash   [32]byte `json:"hash,omitempty"`
	Expiry int64    `json:"expiry,omitempty"`

	// Preimage settles one (LOCK_SETTLE).
	Preimage [32]byte `json:"preimage,omitempty"`
}

// Apply produces the state that follows ch's latest under this transition.
//
// proposer is the party sending the proposal. It decides direction: for PAY and
// LOCK_ADD the proposer must be the one losing value, which is check 8 of §4.2
// and is enforced here rather than left to the caller.
//
// Returns the next state. It does NOT sign, persist, or validate the result
// against the channel — Channel.Accept does that, and doing it twice in two
// places is how two implementations of one rule drift apart.
func (t StateTransition) Apply(ch *Channel, proposer Address) (State, error) {
	if ch == nil {
		return State{}, ErrNoSuchChannel
	}
	prev := ch.Latest.State

	// Withdrawals are deliberately NOT carried forward. They belong to the one
	// state that took value out; the next state starts from the balances that
	// checkpoint left behind, with nothing leaving. Copying them would submit
	// the same withdrawal again at a higher nonce.
	next := State{
		Channel:  ch.ID,
		Nonce:    prev.Nonce + 1,
		BalanceA: new(big.Int).Set(orZero(prev.BalanceA)),
		BalanceB: new(big.Int).Set(orZero(prev.BalanceB)),
		Pending:  clonePending(prev.Pending),
	}

	// The very first state of a channel: balances start from the deposits,
	// because there is no previous state to carry forward.
	if prev.Nonce == 0 && !ch.Latest.Complete() {
		next.BalanceA = new(big.Int).Set(orZero(ch.DepositA))
		next.BalanceB = new(big.Int).Set(orZero(ch.DepositB))
	}

	// Checked explicitly, because IsA answers "is this party A" and a stranger
	// is not party A — so without this a non-party would be silently treated as
	// party B and could propose states that pay themselves out of B's balance.
	if proposer != ch.PartyA && proposer != ch.PartyB {
		return State{}, ErrNotAParty
	}
	proposerIsA := ch.IsA(proposer)

	switch t.Kind {
	case KindPay:
		// The proposer pays. This is check 8 of §4.2, and it is enforced by
		// construction rather than by a test: a proposal that paid its own
		// sender would have to come from Apply taking from the other side,
		// which it never does, so Matches rejects it.
		if err := requirePositive(t.Amount); err != nil {
			return State{}, err
		}
		if err := move(&next, proposerIsA, t.Amount); err != nil {
			return State{}, err
		}

	case KindLockAdd:
		if err := requirePositive(t.Amount); err != nil {
			return State{}, err
		}
		if t.Expiry <= 0 {
			return State{}, ErrHTLCExpiryPast
		}
		if findLock(next.Pending, t.LockID) >= 0 {
			return State{}, ErrLockExists
		}
		// Out of the proposer's balance and into neither: while a lock is live
		// the payer can no longer spend it and the payee cannot yet.
		if err := take(&next, proposerIsA, t.Amount); err != nil {
			return State{}, err
		}
		next.Pending = insertLock(next.Pending, HTLC{
			ID: t.LockID, Hash: t.Hash,
			Amount: new(big.Int).Set(t.Amount),
			Expiry: t.Expiry, PayerIsA: proposerIsA,
		})

	case KindLockSettle:
		i := findLock(next.Pending, t.LockID)
		if i < 0 {
			return State{}, ErrNoSuchLock
		}
		lock := next.Pending[i]
		if !lock.Matches(t.Preimage) {
			return State{}, ErrPreimageBad
		}
		// To the party who is NOT the lock's payer. Note this is the only kind
		// where the proposer is normally the one who gains: they proposed it
		// because they learned the secret.
		give(&next, !lock.PayerIsA, lock.Amount)
		next.Pending = removeAt(next.Pending, i)

	case KindLockRefund:
		i := findLock(next.Pending, t.LockID)
		if i < 0 {
			return State{}, ErrNoSuchLock
		}
		lock := next.Pending[i]
		// Back to whoever put it up. Whether the expiry has actually passed is
		// checked by the protocol layer, which owns the clock.
		give(&next, lock.PayerIsA, lock.Amount)
		next.Pending = removeAt(next.Pending, i)

	case KindCheckpoint:
		if err := requirePositive(t.Amount); err != nil {
			return State{}, err
		}
		// Out of the proposer's balance and out of the channel entirely. Not
		// into the other party's balance — this value is leaving, and the
		// contract pays it to whoever the withdrawal is recorded against.
		if err := take(&next, proposerIsA, t.Amount); err != nil {
			return State{}, err
		}
		if proposerIsA {
			next.WithdrawA = new(big.Int).Set(t.Amount)
		} else {
			next.WithdrawB = new(big.Int).Set(t.Amount)
		}

	case KindClose:
		if len(next.Pending) > 0 {
			return State{}, ErrLocksRemain
		}

	default:
		return State{}, fmt.Errorf("%w: %q", ErrUnknownKind, t.Kind)
	}

	// THE ONE PLACE THE OPERATION DOMAIN IS DECIDED.
	//
	// Set unconditionally rather than only for the two kinds that differ,
	// because `next` is built by copying from the previous state and an
	// inherited domain would make a payment hash as whatever the last state
	// happened to be. Assigning every time makes the wrong value unreachable
	// rather than merely unlikely.
	next.Op = opForKind(t.Kind)
	return next, nil
}

// opForKind maps a transition to the digest domain it must be signed under.
//
// Only two kinds leave the ordinary domain, and they are exactly the two the
// contract treats as more than an agreed balance: a checkpoint moves value out,
// and a cooperative close settles immediately with no challenge window. Every
// other kind — pay, and the three lock operations — produces a state whose only
// authority is "this is what we agree the balances are", which is also what a
// watchtower submits to challenge or to exit.
func opForKind(kind TransitionKind) uint8 {
	switch kind {
	case KindCheckpoint:
		return OpCheckpoint
	case KindClose:
		return OpCoopClose
	default:
		return OpState
	}
}

// Matches reports whether state is exactly what this transition produces from
// ch's latest — check 7 of §4.2.
//
// Compared field by field rather than by digest. A digest comparison would be
// shorter and would answer a subtly different question: it folds the lock set
// into one hash, so a mismatch says only "something differs" at the moment a
// human most needs to know what.
func (t StateTransition) Matches(ch *Channel, proposer Address, state State) error {
	want, err := t.Apply(ch, proposer)
	if err != nil {
		return err
	}
	return want.Equal(state)
}

// Equal reports whether two states are the same state, with a reason when they
// are not.
func (s State) Equal(other State) error {
	if s.Channel != other.Channel {
		return fmt.Errorf("channel differs")
	}
	if s.Nonce != other.Nonce {
		return fmt.Errorf("nonce %d != %d", s.Nonce, other.Nonce)
	}
	if orZero(s.BalanceA).Cmp(orZero(other.BalanceA)) != 0 {
		return fmt.Errorf("balanceA %s != %s", orZero(s.BalanceA), orZero(other.BalanceA))
	}
	if orZero(s.BalanceB).Cmp(orZero(other.BalanceB)) != 0 {
		return fmt.Errorf("balanceB %s != %s", orZero(s.BalanceB), orZero(other.BalanceB))
	}
	if orZero(s.WithdrawA).Cmp(orZero(other.WithdrawA)) != 0 {
		return fmt.Errorf("withdrawA %s != %s", orZero(s.WithdrawA), orZero(other.WithdrawA))
	}
	if orZero(s.WithdrawB).Cmp(orZero(other.WithdrawB)) != 0 {
		return fmt.Errorf("withdrawB %s != %s", orZero(s.WithdrawB), orZero(other.WithdrawB))
	}
	if len(s.Pending) != len(other.Pending) {
		return fmt.Errorf("lock count %d != %d", len(s.Pending), len(other.Pending))
	}
	// Both sides are kept in canonical id order, so position comparison is
	// meaningful and does not need a sort here.
	for i := range s.Pending {
		a, b := s.Pending[i], other.Pending[i]
		if a.ID != b.ID {
			return fmt.Errorf("lock %d: id differs", i)
		}
		if a.Hash != b.Hash {
			return fmt.Errorf("lock %x: hash differs", a.ID[:4])
		}
		if orZero(a.Amount).Cmp(orZero(b.Amount)) != 0 {
			return fmt.Errorf("lock %x: amount %s != %s", a.ID[:4], orZero(a.Amount), orZero(b.Amount))
		}
		if a.Expiry != b.Expiry {
			return fmt.Errorf("lock %x: expiry %d != %d", a.ID[:4], a.Expiry, b.Expiry)
		}
		if a.PayerIsA != b.PayerIsA {
			return fmt.Errorf("lock %x: payer differs", a.ID[:4])
		}
	}
	return nil
}

// ---- balance helpers -------------------------------------------------------

func requirePositive(n *big.Int) error {
	if n == nil || n.Sign() <= 0 {
		return ErrAmountNotPositive
	}
	return nil
}

// take removes value from one side without giving it to the other.
func take(s *State, fromA bool, amount *big.Int) error {
	from := s.BalanceB
	if fromA {
		from = s.BalanceA
	}
	if from.Cmp(amount) < 0 {
		return ErrInsufficient
	}
	from.Sub(from, amount)
	return nil
}

func give(s *State, toA bool, amount *big.Int) {
	if toA {
		s.BalanceA.Add(s.BalanceA, amount)
	} else {
		s.BalanceB.Add(s.BalanceB, amount)
	}
}

func move(s *State, fromA bool, amount *big.Int) error {
	if err := take(s, fromA, amount); err != nil {
		return err
	}
	give(s, !fromA, amount)
	return nil
}

// ---- lock-set helpers ------------------------------------------------------

func clonePending(in []HTLC) []HTLC {
	if len(in) == 0 {
		return nil
	}
	out := make([]HTLC, len(in))
	for i, h := range in {
		out[i] = h
		out[i].Amount = new(big.Int).Set(orZero(h.Amount))
	}
	return out
}

func findLock(locks []HTLC, id [32]byte) int {
	for i, h := range locks {
		if h.ID == id {
			return i
		}
	}
	return -1
}

// insertLock keeps the set in canonical id order, which is the order the
// contract requires and HTLCRoot assumes. Appending and sorting later would
// work; inserting means the slice is never briefly in a state that would hash
// differently.
func insertLock(locks []HTLC, add HTLC) []HTLC {
	at := len(locks)
	for i, h := range locks {
		if lessID(add.ID, h.ID) {
			at = i
			break
		}
	}
	out := make([]HTLC, 0, len(locks)+1)
	out = append(out, locks[:at]...)
	out = append(out, add)
	out = append(out, locks[at:]...)
	return out
}

func removeAt(locks []HTLC, i int) []HTLC {
	out := make([]HTLC, 0, len(locks)-1)
	out = append(out, locks[:i]...)
	out = append(out, locks[i+1:]...)
	if len(out) == 0 {
		return nil
	}
	return out
}

func lessID(a, b [32]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
