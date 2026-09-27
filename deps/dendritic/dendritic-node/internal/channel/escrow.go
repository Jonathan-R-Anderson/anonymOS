package channel

// Escrow, and disclosing one payment without disclosing the rest.
//
// THE PROBLEM WITH DISPUTES IN A PRIVATE SYSTEM
// ---------------------------------------------
// A buyer who never received what they paid for has to prove what they paid.
// The obvious way is to hand the arbiter the key that opens their payment
// commitments — which opens ALL of them. Winning one dispute would publish
// every purchase they ever made, so nobody would ever dispute, and an escrow
// nobody dares use is not an escrow.
//
// SELECTIVE DISCLOSURE
// --------------------
// Each payment's opening secret is derived one-way from a master secret and the
// payment's own index:
//
//	opening(i) = H(domain ‖ master ‖ i)
//
// Revealing opening(i) proves payment i and reveals nothing about the master or
// about opening(j) for any other j — a hash cannot be run backwards. So a buyer
// discloses exactly one purchase, and the arbiter learns exactly one.
//
// The property to hold onto: the buyer never hands over the master. If a
// protocol ever asks them to, that protocol has thrown away selective
// disclosure while appearing to keep it.
//
// WHY THE ARBITER IS NOT THE OPERATOR
// -----------------------------------
// Escrow needs someone to decide. If that is the site operator, the operator
// adjudicates disputes over payments to their own marketplace — which is the
// same conflict as witnessing your own storage claims. The arbiter is a
// parameter here, and the roadmap says it should be the DAO.

import (
	"errors"
	"sync"
	"time"
)

const domainEscrowOpen = "syndichan/escrow/opening/v1"

var (
	ErrEscrowUnknown = errors.New("escrow: no such escrow")
	ErrEscrowSettled = errors.New("escrow: already settled")
	ErrEscrowLive    = errors.New("escrow: still within the delivery window")
	ErrNotTheArbiter = errors.New("escrow: only the arbiter may resolve a dispute")
	ErrDisclosureBad = errors.New("escrow: disclosure does not open the commitment")
)

// EscrowState is where an escrow has got to.
type EscrowState uint8

const (
	EscrowOpen     EscrowState = iota
	EscrowReleased             // buyer confirmed, or the window passed
	EscrowRefunded             // seller failed to deliver
	EscrowDisputed
)

// Escrow holds value until delivery is confirmed or the window closes.
type Escrow struct {
	ID     [32]byte
	Buyer  NodeID
	Seller NodeID
	Amount Amount
	// Commitment binds this escrow to a payment WITHOUT naming it, the same way
	// a receipt link does.
	Commitment [32]byte
	// Deadline is when the buyer's silence becomes consent. Escrow that never
	// expired would let a buyer strand a seller's payment indefinitely by
	// simply not answering.
	Deadline time.Time
	State    EscrowState
}

// OpeningFor derives the disclosure secret for one payment.
//
// One-way and per-index: revealing this proves payment i and says nothing about
// the master or about any sibling.
func OpeningFor(master [32]byte, index uint64) [32]byte {
	return derive(domainEscrowOpen, master[:], uint64Bytes(index))
}

// Disclosure is what a buyer hands an arbiter. Note what is absent: the master
// secret, and any reference to other payments.
type Disclosure struct {
	Index   uint64
	Opening [32]byte
	Amount  Amount
	Channel ChannelID
	Nonce   uint64
}

// Verify checks a disclosure against a public commitment.
//
// The arbiter runs this. It confirms the buyer paid what they claim, for the
// escrow they claim, and gives the arbiter no way to check any other payment.
func (d Disclosure) Verify(commitment [32]byte) error {
	if CommitPayment(d.Channel, d.Nonce, d.Amount, d.Opening) != commitment {
		return ErrDisclosureBad
	}
	return nil
}

// EscrowBook holds live escrows.
type EscrowBook struct {
	arbiter NodeID
	mu      sync.Mutex
	items   map[[32]byte]*Escrow
}

func NewEscrowBook(arbiter NodeID) *EscrowBook {
	return &EscrowBook{arbiter: arbiter, items: map[[32]byte]*Escrow{}}
}

// Open records an escrow.
func (b *EscrowBook) Open(e Escrow) error {
	if e.Amount <= 0 || e.Buyer == "" || e.Seller == "" {
		return ErrEscrowUnknown
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e.State = EscrowOpen
	b.items[e.ID] = &e
	return nil
}

// Confirm releases to the seller — the buyer got what they paid for.
func (b *EscrowBook) Confirm(id [32]byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.items[id]
	if !ok {
		return ErrEscrowUnknown
	}
	if e.State != EscrowOpen {
		return ErrEscrowSettled
	}
	e.State = EscrowReleased
	return nil
}

// Expire releases to the seller once the window closes.
//
// Silence becomes consent, deliberately. The alternative — refunding on
// silence — lets any buyer take delivery and then simply stop answering, which
// makes selling impossible.
func (b *EscrowBook) Expire(id [32]byte, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.items[id]
	if !ok {
		return ErrEscrowUnknown
	}
	if e.State != EscrowOpen {
		return ErrEscrowSettled
	}
	if now.Before(e.Deadline) {
		return ErrEscrowLive
	}
	e.State = EscrowReleased
	return nil
}

// Dispute freezes an escrow pending arbitration.
func (b *EscrowBook) Dispute(id [32]byte, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.items[id]
	if !ok {
		return ErrEscrowUnknown
	}
	if e.State != EscrowOpen {
		return ErrEscrowSettled
	}
	// A dispute after the window has closed is too late: the seller has already
	// been paid, and reopening settled payments indefinitely is its own attack.
	if !now.Before(e.Deadline) {
		return ErrEscrowSettled
	}
	e.State = EscrowDisputed
	return nil
}

// Resolve settles a disputed escrow. Only the arbiter may call it, and only
// with a disclosure that actually opens the escrow's commitment.
func (b *EscrowBook) Resolve(id [32]byte, by NodeID, d Disclosure, refund bool) error {
	if by != b.arbiter {
		return ErrNotTheArbiter
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.items[id]
	if !ok {
		return ErrEscrowUnknown
	}
	if e.State != EscrowDisputed {
		return ErrEscrowSettled
	}
	// The arbiter must be shown the payment before ruling on it. Without this
	// they could rule on a dispute about a payment that never happened.
	if err := d.Verify(e.Commitment); err != nil {
		return err
	}
	if refund {
		e.State = EscrowRefunded
	} else {
		e.State = EscrowReleased
	}
	return nil
}

// State reports an escrow's current state.
func (b *EscrowBook) State(id [32]byte) (EscrowState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.items[id]
	if !ok {
		return 0, ErrEscrowUnknown
	}
	return e.State, nil
}
