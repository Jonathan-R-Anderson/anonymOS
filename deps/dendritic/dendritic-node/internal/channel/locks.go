package channel

// What a conditional payment looks like to an operator — roadmap P7-c.
//
// WHY THIS IS HERE AND NOT IN THE DASHBOARD
// -----------------------------------------
// Deciding whether a lock is claimable means knowing whether this node holds
// the secret, whether the expiry has passed, and which side put the value up.
// That is payment reasoning, and a dashboard that worked it out for itself
// would be a second opinion about money — the thing this architecture keeps
// refusing to grow.
//
// So the status is computed once, here, and the panel renders what it is told.
//
// THE DISTINCTION THAT MATTERS TO A HUMAN
// ---------------------------------------
// A recipient reading one number cannot tell "I have been paid" from "somebody
// might pay me". Locked value is neither:
//
//	available      settled, spendable, nobody can take it back
//	incoming       offered to this node, conditional on a secret
//	outgoing       offered BY this node, its own money at risk
//
// Adding them into one balance would tell a streamer they have money they may
// never receive, and hide money of their own that is currently at risk.

import (
	"math/big"
	"time"
)

// LockStatus is where a conditional payment has got to.
type LockStatus string

const (
	// LockWaiting: offered to this node, and the secret is not known yet. The
	// ordinary state of a payment in flight.
	LockWaiting LockStatus = "waiting"
	// LockClaimable: offered to this node AND this node holds the secret. Value
	// that can be taken now — and should be, before the expiry.
	LockClaimable LockStatus = "claimable"
	// LockLapsed: offered to this node and expired without the secret. The
	// payer may take it back; this node has lost its chance at it.
	LockLapsed LockStatus = "lapsed"
	// LockOffered: put up BY this node and still live. Its own value, held
	// against a secret somebody else may produce.
	LockOffered LockStatus = "offered"
	// LockRefundable: put up by this node, expired, and nobody produced the
	// secret. Recoverable now.
	LockRefundable LockStatus = "refundable"
	// LockSettling: put up by this node, and this node has learned the secret —
	// so the payee can take it and almost certainly will. Not this node's money
	// any more in any meaningful sense.
	LockSettling LockStatus = "settling"
)

// LockView is one conditional payment, described rather than acted on.
//
// Deliberately carries no way to resolve itself. Settling and refunding are
// co-signed state transitions owned by the coordinator; a view that handed out
// the means to construct one would be inviting a caller to route around the
// state machine.
type LockView struct {
	Channel  [32]byte
	ID       [32]byte
	Amount   string
	Expiry   int64
	Incoming bool
	Status   LockStatus
	// ExpiresIn is seconds remaining, negative once past. Precomputed because
	// the alternative is every reader applying its own clock to a number whose
	// meaning depends on this node's.
	ExpiresIn int64
}

// Exposure is how a channel's value divides for somebody looking at it.
type Exposure struct {
	// Available is settled and spendable. Locks are NOT in here.
	Available string
	// Incoming is offered to this node, conditional. May never arrive.
	Incoming string
	// Outgoing is offered by this node, conditional. Its own money at risk.
	Outgoing string
	// Total is Available + Incoming: the most this node could end up holding.
	// Not a balance, and named so nobody reads it as one.
	Total string
}

// SetPreimageVault lets the coordinator answer "can this be claimed".
//
// Optional: without it every incoming lock reads as waiting, which is the
// honest answer for a node that cannot remember secrets — it genuinely cannot
// claim anything.
func (c *Coordinator) SetPreimageVault(v *PreimageVault) { c.vault = v }

// Locks describes every conditional payment on a channel.
func (c *Coordinator) Locks(id [32]byte) ([]LockView, error) {
	ch, ok := c.store.Get(id)
	if !ok {
		return nil, ErrChannelNotAdopted
	}
	now := c.clock()
	out := []LockView{}
	for _, lock := range ch.Latest.State.Pending {
		payer := ch.Party(lock.PayerIsA)
		incoming := payer != c.self

		known := false
		if c.vault != nil {
			_, known = c.vault.Lookup(lock.Hash)
		}
		out = append(out, LockView{
			Channel: id, ID: lock.ID,
			Amount: decString(lock.Amount), Expiry: lock.Expiry,
			Incoming: incoming, ExpiresIn: lock.Expiry - now,
			Status: lockStatus(incoming, known, lock.Expiry <= now),
		})
	}
	return out, nil
}

// lockStatus is the whole decision, in one place.
//
// Note that "expired" means different things by direction, which is the reason
// this is a function rather than a field: an expired lock offered TO this node
// is a loss, and the same lock offered BY it is a recovery.
func lockStatus(incoming, secretKnown, expired bool) LockStatus {
	if incoming {
		switch {
		case expired:
			// LAPSED EVEN WITH THE SECRET. This used to return LockClaimable on
			// `secretKnown` alone, reasoning that "the peer may still co-sign".
			// It no longer will: a settlement at or after expiry is refused off
			// chain (session.go checkTiming) because claimLock reverts on chain
			// (ChannelManagerV2.sol:439).
			//
			// Order matters here. Reporting an expired lock as claimable tells an
			// operator to wait for value that cannot arrive, which is worse than
			// telling them it is gone — the honest answer is that the window
			// closed, whatever they hold.
			return LockLapsed
		case secretKnown:
			return LockClaimable
		default:
			return LockWaiting
		}
	}
	switch {
	case secretKnown:
		return LockSettling
	case expired:
		return LockRefundable
	default:
		return LockOffered
	}
}

// Exposure divides a channel's value into what is settled and what is not.
func (c *Coordinator) Exposure(id [32]byte) (Exposure, error) {
	ch, ok := c.store.Get(id)
	if !ok {
		return Exposure{}, ErrChannelNotAdopted
	}
	available := ch.BalanceOf(c.self)
	in, outward := lockTotals(ch, c.self)

	total := new(big.Int).Add(available, in)
	return Exposure{
		Available: decString(available),
		Incoming:  decString(in),
		Outgoing:  decString(outward),
		Total:     decString(total),
	}, nil
}

// lockTotals splits pending value by direction.
func lockTotals(ch *Channel, self Address) (incoming, outgoing *big.Int) {
	incoming, outgoing = new(big.Int), new(big.Int)
	for _, lock := range ch.Latest.State.Pending {
		if ch.Party(lock.PayerIsA) == self {
			outgoing.Add(outgoing, orZero(lock.Amount))
		} else {
			incoming.Add(incoming, orZero(lock.Amount))
		}
	}
	return
}

// clock is the coordinator's view of time. Injectable for the same reason the
// session's is: an expiry test that cannot control the clock cannot run.
func (c *Coordinator) clock() int64 {
	if c.now != nil {
		return c.now()
	}
	return time.Now().Unix()
}

// SetClock replaces the coordinator's clock.
func (c *Coordinator) SetClock(now func() int64) { c.now = now }
