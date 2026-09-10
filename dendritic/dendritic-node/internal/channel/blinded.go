package channel

// Blinded recipient paths.
//
// WHAT THIS STOPS
// ---------------
// Without it, a streamer's payment destination IS their channel topology: every
// person who tips them learns which node they run and who their peers are. Once
// that is public it cannot be withdrawn, and it is the kind of thing a viewer
// collects passively just by paying.
//
// So the recipient never publishes a destination. They publish an INVOICE that
// points at an introduction node, carrying instructions only that node can read.
// The exit router learns "deliver to this blinded endpoint"; it does not learn
// who the endpoint belongs to.
//
// ONE IDENTIFIER PER ROLE, ALWAYS
// -------------------------------
// The likeliest way this gets broken in practice is not a cryptographic
// mistake. It is someone reusing the streaming session id as the invoice id
// "because it is already there" — at which point every tip to that stream is
// linkable to every other, and the blinding was decoration. The roles are
// therefore separate types with separate derivations, so joining two of them is
// a visible act rather than a convenient one.
//
//	public profile      permanent, everyone sees it
//	session id          one broadcast
//	invoice id          ONE payment
//	blinded endpoint    one invoice, seen by the exit router
//	settlement key      rotatable, never leaves the recipient's node
//	withdrawal address  rotatable, seen only by the chain

import (
	"crypto/rand"
	"errors"
	"io"
	"time"
)

const (
	domainInvoice   = "syndichan/invoice/id/v1"
	domainEndpoint  = "syndichan/invoice/endpoint/v1"
	domainInvCommit = "syndichan/invoice/commit/v1"
)

var (
	ErrInvoiceExpired   = errors.New("channel: invoice has expired")
	ErrInvoiceReused    = errors.New("channel: invoice has already been paid")
	ErrAmountOutOfRange = errors.New("channel: amount is outside the invoice's accepted range")
	ErrInvoiceMalformed = errors.New("channel: invoice is malformed")
)

// BlindedInvoice is what a payer receives. It names nobody.
type BlindedInvoice struct {
	// InvoiceID is single-use. Never derived from the session or the profile —
	// see the file comment.
	InvoiceID [32]byte

	// IntroductionNode is an exit-router candidate the recipient is reachable
	// through. The payer learns this node exists, not who is behind it.
	IntroductionNode NodeID

	// BlindedEndpoint is what the exit router is told to deliver to. Opaque to
	// the payer AND to the exit router; only the introduction node can resolve
	// it, and only for this invoice.
	BlindedEndpoint [32]byte

	// FinalHopCiphertext holds routing instructions readable only by the
	// introduction node.
	FinalHopCiphertext []byte

	// RecipientEphemeralKey is per-invoice. A long-term key here would be an
	// identifier printed on every invoice the recipient ever issues.
	RecipientEphemeralKey [32]byte

	// Commitment binds the invoice's terms so neither side can change them
	// afterwards without the other noticing.
	Commitment [32]byte

	IssuedAt  uint64
	ExpiresAt uint64

	// MinAmount/MaxAmount are a RANGE, not an exact figure. An invoice pinning
	// one amount tells anyone who sees it exactly what was paid; a range lets
	// the payer's actual amount stay inside a set.
	MinAmount Amount
	MaxAmount Amount

	// Streaming, when set, allows repeated payment against this invoice up to
	// MaxAmount — the session case, where one invoice covers many vouchers.
	Streaming bool
}

// InvoiceRequest is what a recipient supplies to issue one.
type InvoiceRequest struct {
	// SettlementKey never leaves the recipient's node and is not in the
	// invoice. It is an input to the derivations, not a field.
	SettlementKey    [32]byte
	IntroductionNode NodeID
	MinAmount        Amount
	MaxAmount        Amount
	TTL              time.Duration
	Streaming        bool
}

// NewInvoice issues a single-use blinded invoice.
//
// Every identifier is freshly derived from random entropy, so two invoices from
// the same recipient share no field. That is the property the whole design
// rests on: if any field were stable, it would be the recipient's identifier
// under another name.
func NewInvoice(req InvoiceRequest, now time.Time) (*BlindedInvoice, error) {
	if req.IntroductionNode == "" {
		return nil, ErrInvoiceMalformed
	}
	if req.MaxAmount <= 0 || req.MinAmount < 0 || req.MinAmount > req.MaxAmount {
		return nil, ErrInvoiceMalformed
	}
	if req.TTL <= 0 {
		return nil, ErrInvoiceMalformed
	}

	var entropy [32]byte
	if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
		return nil, err
	}
	var ephemeral [32]byte
	if _, err := io.ReadFull(rand.Reader, ephemeral[:]); err != nil {
		return nil, err
	}

	invoiceID := derive(domainInvoice, entropy[:], req.SettlementKey[:])
	endpoint := derive(domainEndpoint, req.SettlementKey[:], entropy[:], []byte(req.IntroductionNode))

	inv := &BlindedInvoice{
		InvoiceID:             invoiceID,
		IntroductionNode:      req.IntroductionNode,
		BlindedEndpoint:       endpoint,
		RecipientEphemeralKey: ephemeral,
		IssuedAt:              uint64(now.Unix()),
		ExpiresAt:             uint64(now.Add(req.TTL).Unix()),
		MinAmount:             req.MinAmount,
		MaxAmount:             req.MaxAmount,
		Streaming:             req.Streaming,
	}
	inv.Commitment = inv.commit()
	return inv, nil
}

// commit binds the invoice's terms.
//
// Covers the amount range and expiry, so a recipient cannot later claim a
// different range was agreed, and a payer cannot pay outside it and argue the
// invoice said otherwise.
func (i *BlindedInvoice) commit() [32]byte {
	return derive(domainInvCommit,
		i.InvoiceID[:], i.BlindedEndpoint[:],
		amountBytes(i.MinAmount), amountBytes(i.MaxAmount),
		uint64Bytes(i.ExpiresAt),
	)
}

func amountBytes(a Amount) []byte { return uint64Bytes(uint64(a)) }

func uint64Bytes(v uint64) []byte {
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}

// Validate checks an invoice before a payer commits to it.
func (i *BlindedInvoice) Validate(now time.Time) error {
	if i == nil || i.IntroductionNode == "" {
		return ErrInvoiceMalformed
	}
	if i.ExpiresAt <= i.IssuedAt {
		return ErrInvoiceMalformed
	}
	if i.MaxAmount <= 0 || i.MinAmount > i.MaxAmount {
		return ErrInvoiceMalformed
	}
	// The commitment must match, or the terms were altered in transit — the one
	// check that makes the range meaningful rather than advisory.
	if i.Commitment != i.commit() {
		return ErrInvoiceMalformed
	}
	if uint64(now.Unix()) >= i.ExpiresAt {
		return ErrInvoiceExpired
	}
	return nil
}

// AcceptsAmount reports whether a payment falls inside the invoice's range.
func (i *BlindedInvoice) AcceptsAmount(a Amount) error {
	if a < i.MinAmount || a > i.MaxAmount {
		return ErrAmountOutOfRange
	}
	return nil
}

// ExitView is everything the exit router is permitted to learn.
//
// A concrete type rather than a convention, so "what does the exit see" has one
// answer that can be read and audited. Anything absent here is a leak if it
// ever reaches that hop.
type ExitView struct {
	BlindedEndpoint [32]byte
	// FinalHopCiphertext is forwarded, not read: the exit cannot decrypt it.
	FinalHopCiphertext []byte
	Expiry             uint64
}

// ViewForExit strips an invoice down to what the exit router may see.
//
// Note what is dropped: the invoice id, the amount range, the commitment and
// the recipient's ephemeral key. An exit router that learned the range would
// know roughly what was paid, and an exit that learned the invoice id could
// link every payment against it.
func (i *BlindedInvoice) ViewForExit() ExitView {
	return ExitView{
		BlindedEndpoint:    i.BlindedEndpoint,
		FinalHopCiphertext: i.FinalHopCiphertext,
		Expiry:             i.ExpiresAt,
	}
}

// InvoiceLedger tracks which invoices have been paid.
//
// Single-use is enforced here rather than trusted: an invoice that could be
// paid twice is one a router can replay for its own benefit. Streaming invoices
// are the deliberate exception and are marked as such.
type InvoiceLedger struct {
	paid map[[32]byte]bool
}

func NewInvoiceLedger() *InvoiceLedger {
	return &InvoiceLedger{paid: map[[32]byte]bool{}}
}

// Claim marks an invoice paid, refusing a second claim on a single-use one.
func (l *InvoiceLedger) Claim(i *BlindedInvoice) error {
	if l.paid[i.InvoiceID] && !i.Streaming {
		return ErrInvoiceReused
	}
	l.paid[i.InvoiceID] = true
	return nil
}
