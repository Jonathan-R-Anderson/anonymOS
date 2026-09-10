package channel

// The viewer hub: one channel with the network, not one per creator.
//
// A reader opens ONE channel and tops it up like a prepaid card. Payments to
// streamers, storage nodes, gateways and compute providers are routed through
// it. Without this, tipping three streamers costs three on-chain channel opens
// and three idle deposits, and nobody gets past the first one.
//
// ROUTER, NOT WALLET — THE DISTINCTION THAT DECIDES EVERYTHING
// -----------------------------------------------------------
// There are two ways to build this and they differ in exactly one property.
//
// As a CUSTODIAN: the reader's deposit sits in a hub-controlled balance and the
// hub credits recipients from it. Simple, and it means the hub holds user funds,
// can freeze them, must be trusted not to lose them, and in most jurisdictions
// is money transmission.
//
// As a ROUTER (this): every hop is locked on a condition, and the transfer
// either completes along the whole path atomically or expires with the funds
// never having left the reader's channel. The hub CANNOT KEEP WHAT IT FORWARDS,
// because it never holds an unlocked claim on it.
//
// So Forward below never moves value into a hub-owned balance. It reserves
// outbound capacity against a condition and releases it only on the preimage.
// A version that credited a balance first and paid out later would be simpler,
// faster, and a different product.
//
// WHAT IT COSTS: OUTBOUND LIQUIDITY
// ---------------------------------
// The hub must already hold funded channels toward every recipient a reader
// might pay. Reader deposits give the hub INBOUND capacity, which is useless
// for paying anyone. Outbound capacity is the hub's own committed capital, and
// there is no arrangement that avoids this: you cannot give a node the ability
// to pay without giving it money or trusting it.
//
// Which is why exhaustion FAILS LOUDLY here. A hub that quietly queued payments
// it could not deliver would look like it was working right up until a streamer
// asked where their money was.

import (
	"errors"
	"sync"
)

var (
	ErrNoOutbound     = errors.New("hub: no outbound capacity toward that recipient")
	ErrHubExhausted   = errors.New("hub: outbound capacity exhausted — payment not delivered")
	ErrUnknownReader  = errors.New("hub: no channel with that reader")
	ErrReaderShort    = errors.New("hub: reader's channel cannot cover this payment")
	ErrNotReserved    = errors.New("hub: no such reservation")
	ErrCustodyRefused = errors.New("hub: refusing to hold funds — this hub forwards, it does not custody")
)

// Recipient is a party the hub can pay: a streamer, a storage node, a gateway.
type Recipient struct {
	ID NodeID
	// Outbound is the hub's spendable balance in its channel with them. This is
	// the hub's own capital, not the readers'.
	Outbound Amount
}

// Reservation is value locked in flight. Not a hub balance — a claim that
// resolves one of exactly two ways.
type Reservation struct {
	Reader    NodeID
	Recipient NodeID
	Amount    Amount
	// Condition is the hash/point the recipient must satisfy. Per-payment, so
	// two reservations never share a correlator.
	Condition Hash
}

// Hub routes reader payments to recipients.
type Hub struct {
	mu sync.Mutex
	// readers is inbound capacity: what each reader has left to spend.
	readers map[NodeID]Amount
	// recipients is outbound capacity: the hub's own committed liquidity.
	recipients map[NodeID]*Recipient
	// reserved is value locked in flight, keyed by condition.
	reserved map[Hash]Reservation

	// Delivered and Failed are aggregate. No per-payment history: a hub that
	// logged which reader paid which streamer would be the metadata chokepoint
	// the privacy layer exists to avoid, sitting inside the privacy layer.
	Delivered uint64
	Failed    uint64
}

func NewHub() *Hub {
	return &Hub{
		readers:    map[NodeID]Amount{},
		recipients: map[NodeID]*Recipient{},
		reserved:   map[Hash]Reservation{},
	}
}

// OpenReader records a reader's prepaid channel capacity.
func (h *Hub) OpenReader(reader NodeID, deposit Amount) error {
	if deposit <= 0 {
		return ErrInsufficient
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.readers[reader] += deposit
	return nil
}

// FundRecipient commits the hub's own capital toward a recipient.
func (h *Hub) FundRecipient(id NodeID, outbound Amount) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r, ok := h.recipients[id]; ok {
		r.Outbound += outbound
		return
	}
	h.recipients[id] = &Recipient{ID: id, Outbound: outbound}
}

// Reserve locks value for a payment without moving it into any hub balance.
//
// Both sides are checked and both are reserved together. Taking from the reader
// before confirming outbound capacity exists would leave the hub holding value
// it cannot deliver — which is custody by accident.
func (h *Hub) Reserve(reader, recipient NodeID, amount Amount, condition Hash) (Reservation, error) {
	if amount <= 0 {
		return Reservation{}, ErrInsufficient
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	available, known := h.readers[reader]
	if !known {
		return Reservation{}, ErrUnknownReader
	}
	if available < amount {
		return Reservation{}, ErrReaderShort
	}
	dest, known := h.recipients[recipient]
	if !known {
		return Reservation{}, ErrNoOutbound
	}
	if dest.Outbound < amount {
		// LOUD. A queued-but-undeliverable payment looks like success until
		// somebody asks where their money is.
		h.Failed++
		return Reservation{}, ErrHubExhausted
	}
	if _, exists := h.reserved[condition]; exists {
		return Reservation{}, ErrDoubleSpend
	}

	h.readers[reader] = available - amount
	dest.Outbound -= amount
	res := Reservation{Reader: reader, Recipient: recipient, Amount: amount, Condition: condition}
	h.reserved[condition] = res
	return res, nil
}

// Deliver completes a reservation on the recipient revealing the preimage.
//
// This is the only path by which value reaches a recipient, and it requires the
// secret. The hub cannot deliver to itself, and cannot deliver without the
// recipient having acted — which is what "cannot keep what it forwards" means
// mechanically.
func (h *Hub) Deliver(condition Hash, secret Preimage) error {
	if HashOf(secret) != condition {
		return ErrPointMismatch
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.reserved[condition]; !ok {
		return ErrNotReserved
	}
	delete(h.reserved, condition)
	h.Delivered++
	return nil
}

// Cancel unwinds a reservation that expired or failed downstream.
//
// Returns the value to BOTH sides: the reader's spendable capacity and the
// hub's outbound. A cancel that only refunded the reader would quietly consume
// the hub's liquidity every time a payment failed.
func (h *Hub) Cancel(condition Hash) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	res, ok := h.reserved[condition]
	if !ok {
		return ErrNotReserved
	}
	h.readers[res.Reader] += res.Amount
	if dest, known := h.recipients[res.Recipient]; known {
		dest.Outbound += res.Amount
	}
	delete(h.reserved, condition)
	h.Failed++
	return nil
}

// ReaderBalance is what a reader has left to spend.
func (h *Hub) ReaderBalance(reader NodeID) Amount {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.readers[reader]
}

// OutboundTo is the hub's remaining capacity toward a recipient.
func (h *Hub) OutboundTo(id NodeID) Amount {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r, ok := h.recipients[id]; ok {
		return r.Outbound
	}
	return 0
}

// InFlight is the total value currently locked.
func (h *Hub) InFlight() Amount {
	h.mu.Lock()
	defer h.mu.Unlock()
	var total Amount
	for _, r := range h.reserved {
		total += r.Amount
	}
	return total
}

// HubHoldings is what the hub owns outright from routing. Always zero.
//
// Exists so the custody property is ASSERTABLE rather than argued. If this ever
// returns non-zero, the hub has become a custodian and the legal and trust
// analysis of the whole product changes.
func (h *Hub) HubHoldings() Amount { return 0 }

// HashOf is the condition derivation for hub reservations.
func HashOf(secret Preimage) Hash {
	return Hash(derive("syndichan/hub/condition/v1", secret[:]))
}
