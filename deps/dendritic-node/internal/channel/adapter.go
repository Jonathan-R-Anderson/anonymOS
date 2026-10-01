// Package channel is the seam between accounting and whichever payment-channel
// implementation is underneath.
//
// THE POINT OF THIS PACKAGE IS THAT IT IS SMALL
// ---------------------------------------------
// Every real channel protocol — Raiden, Nitro, Connext — has a large surface,
// and binding to any of it directly is how a project ends up unable to leave.
// The roadmap's central finding is that Raiden looks unmaintained, so the
// backend choice must stay reversible; that is only true if the interface above
// it is narrower than all of them and leaks none of their types.
//
// So: nothing above this package may import a backend's types, and nothing in
// this package may grow a method because one backend happens to offer it. A
// wider interface would leak that backend's model upward and quietly make it
// the only one that fits.
//
// WHY CAPABILITIES ARE REPORTED RATHER THAN ASSUMED
// -------------------------------------------------
// Backends differ in ways that change what the application may honestly offer.
// A backend without HTLCs cannot do service reservations or the viewer hub
// safely; one without adaptor signatures cannot do private routing without a
// globally correlating payment hash. Those are not performance differences,
// they are differences in what is TRUE about a payment.
//
// The rule this package enforces is therefore: the software must REFUSE to
// claim a property its backend does not support, never degrade quietly. It is
// the same rule the compute layer already follows for the `gpu` capability —
// claimed only when the mechanism works, because the alternative routes exactly
// the work that needs the property to something that cannot provide it.
package channel

import (
	"context"
	"errors"
	"time"
)

// NodeID is a counterparty's network identity. Deliberately not an Ethereum
// address: the payout address must be rotatable without changing who a peer is.
type NodeID string

// ChannelID identifies an open channel to the backend. Opaque — its contents
// are the backend's business, and code above must never parse it.
type ChannelID string

// LockID identifies a conditional lock (an HTLC or a point-locked transfer).
type LockID string

// Amount is in the token's smallest unit. An integer type, never a float:
// binary floating point cannot represent most decimal token amounts exactly,
// and a rounding error in a settlement path is money that vanishes.
type Amount int64

// Hash is a 32-byte digest — a payment hash, or a point commitment.
type Hash [32]byte

// Preimage unlocks a conditional transfer.
type Preimage [32]byte

// Balance is a local view of a channel. NEVER authoritative against a peer:
// only the latest counter-signed proof is, and code that treats this as truth
// will eventually overdraw.
type Balance struct {
	Outbound Amount // what this node can still send
	Inbound  Amount // what it can still receive
	// Locked is value committed to in-flight transfers. Excluded from Outbound
	// rather than subtracted by the caller — forgetting to subtract it is how a
	// node signs a balance proof it cannot honour.
	Locked Amount
	// Nonce is the sequence of the latest counter-signed state. Monotonic; a
	// lower nonce arriving is either a replay or a bug, never a valid update.
	Nonce uint64
}

// BalanceProof is a counterparty's signed acknowledgement of a transfer.
//
// MUST be persisted durably before a payment is treated as successful. A lost
// balance proof is lost money — the counterparty holds a state this node cannot
// prove, and there is no recovery from that except their goodwill.
type BalanceProof struct {
	Channel   ChannelID
	Nonce     uint64
	Signature []byte
	// Opaque is the backend's own state encoding. Carried but never
	// interpreted here, so a backend can evolve its format without this
	// package changing.
	Opaque []byte
}

// ChainID identifies the settlement chain. Present because the mainnet-versus-
// L2 decision is unresolved (roadmap Phase 0) and code must be able to ask
// rather than assume.
type ChainID uint64

// Capabilities is what a backend can actually do.
type Capabilities struct {
	// MediatedTransfers: can route through intermediaries at all.
	MediatedTransfers bool
	// HTLC: conditional locks. Required for Reserve/Claim, for prepaid
	// allocation, and for the viewer hub to forward without custody.
	HTLC bool
	// AdaptorSignatures: per-hop re-randomised points. Without these, private
	// routing must fall back to one payment hash shared by every hop — which
	// is a global correlation value, so ConfidentialRecipient cannot be true.
	AdaptorSignatures bool
	// Watchtower: third-party dispute monitoring.
	Watchtower bool
	Chain      ChainID

	Privacy PrivacyCapabilities
}

// PrivacyCapabilities is what the backend can honestly claim about privacy.
//
// Every field here is a promise to a user. The Validate method below exists
// because several of them are not independent, and a struct that permits an
// impossible combination will eventually be handed one.
type PrivacyCapabilities struct {
	OnionRouting          bool
	BlindedPaths          bool
	ConfidentialAmounts   bool
	ConfidentialRecipient bool
	PrivateNotes          bool
	ZeroKnowledgeProofs   bool
	AtomicMultipath       bool
	PrivateStreaming      bool
}

var (
	// ErrUnsupported is returned by a backend asked for something it cannot do.
	// Distinct from a failure: the operation did not fail, it was never
	// available, and a caller must not retry it.
	ErrUnsupported = errors.New("channel: the configured backend does not support this")
	// ErrNoBackend means no channel backend is configured at all.
	ErrNoBackend = errors.New("channel: no backend configured")
	// ErrInconsistentCapabilities means a backend claimed a combination that
	// cannot be true. Treated as a configuration error and refused at startup
	// rather than discovered mid-payment.
	ErrInconsistentCapabilities = errors.New("channel: backend claims inconsistent capabilities")
)

// Validate rejects capability sets that cannot be true together.
//
// Checked at startup, because the failure mode otherwise is a user being
// promised confidential recipients by a backend that puts one correlating hash
// on every hop — a privacy claim that is false, made by software that believed
// it. Better to refuse to start.
func (c Capabilities) Validate() error {
	p := c.Privacy
	switch {
	case p.BlindedPaths && !p.OnionRouting:
		// A blinded path is expressed as onion layers. Without onion routing
		// there is nothing to blind.
		return ErrInconsistentCapabilities
	case p.ConfidentialRecipient && !p.OnionRouting:
		return ErrInconsistentCapabilities
	case p.ConfidentialRecipient && !c.AdaptorSignatures:
		// The important one. With a single shared payment hash, every hop sees
		// the same correlator and any two colluding routers link the payment.
		// A backend without adaptor signatures may still route — it may not
		// claim the recipient is confidential while doing so.
		return ErrInconsistentCapabilities
	case p.ConfidentialAmounts && !p.PrivateNotes:
		// Amounts are hidden by commitments carried in notes. Without notes
		// there is nothing holding a hidden amount.
		return ErrInconsistentCapabilities
	case p.PrivateNotes && !p.ZeroKnowledgeProofs:
		// A note without a proof is an unverifiable claim on value.
		return ErrInconsistentCapabilities
	case p.AtomicMultipath && !c.HTLC && !c.AdaptorSignatures:
		// Atomic recombination needs some conditional lock. Neither means
		// fragments could settle independently, which is not multipath — it is
		// several partial payments.
		return ErrInconsistentCapabilities
	case p.OnionRouting && !c.MediatedTransfers:
		return ErrInconsistentCapabilities
	}
	return nil
}

// Adapter is the whole surface the accounting layer may use.
type Adapter interface {
	// Open funds a channel with a counterparty. Blocking and expensive — an
	// on-chain transaction.
	Open(ctx context.Context, peer NodeID, deposit Amount) (ChannelID, error)

	// Pay moves value irrevocably within an open channel. The returned proof
	// MUST be persisted before Pay is treated as successful.
	Pay(ctx context.Context, ch ChannelID, amount Amount, ref string) (BalanceProof, error)

	// Reserve locks value against a future claim. Requires HTLC.
	Reserve(ctx context.Context, ch ChannelID, amount Amount, secret Hash,
		expiry time.Time) (LockID, error)

	// Claim unlocks a reservation; Release returns it to the payer. Exactly one
	// must happen before expiry, and expiry is enforced on-chain rather than by
	// agreement — a counterparty who stops answering must not be able to strand
	// the value.
	Claim(ctx context.Context, lock LockID, secret Preimage) error
	Release(ctx context.Context, lock LockID) error

	// Balance is the local view. See the type's warning.
	Balance(ch ChannelID) (Balance, error)

	// Close settles. Cooperative when the peer agrees; otherwise this starts
	// the challenge period and the watchtower takes over.
	Close(ctx context.Context, ch ChannelID, cooperative bool) error

	// Capabilities reports what this backend can actually do.
	Capabilities() Capabilities
}

// Null is a backend that refuses everything, honestly.
//
// The default. A node with no channel backend configured must behave as though
// channels do not exist — not crash, and not silently succeed. Every method
// returns ErrNoBackend, and Capabilities reports nothing supported, so the
// capability checks above naturally prevent any privacy claim.
//
// It exists so the rest of the system can be built and tested against the
// interface before a backend is chosen, which is exactly what roadmap Phase 0
// asks for: the seam first, the decision second.
type Null struct{}

func (Null) Open(context.Context, NodeID, Amount) (ChannelID, error) {
	return "", ErrNoBackend
}
func (Null) Pay(context.Context, ChannelID, Amount, string) (BalanceProof, error) {
	return BalanceProof{}, ErrNoBackend
}
func (Null) Reserve(context.Context, ChannelID, Amount, Hash, time.Time) (LockID, error) {
	return "", ErrNoBackend
}
func (Null) Claim(context.Context, LockID, Preimage) error { return ErrNoBackend }
func (Null) Release(context.Context, LockID) error         { return ErrNoBackend }
func (Null) Balance(ChannelID) (Balance, error)            { return Balance{}, ErrNoBackend }
func (Null) Close(context.Context, ChannelID, bool) error  { return ErrNoBackend }
func (Null) Capabilities() Capabilities                    { return Capabilities{} }

// compile-time assertion that Null satisfies the interface.
var _ Adapter = Null{}

// MayClaim reports whether the application is permitted to tell a user that a
// given privacy property holds.
//
// The single chokepoint for honest claims. UI copy, API responses and receipts
// all ask this rather than reading the capability struct directly, so there is
// one place to audit and one place a mistake can live.
func MayClaim(c Capabilities, property string) bool {
	if err := c.Validate(); err != nil {
		// An inconsistent backend may claim nothing at all. Refusing the whole
		// set rather than the offending field is deliberate: if the capability
		// report is wrong about one thing, it is not evidence for anything.
		return false
	}
	p := c.Privacy
	switch property {
	case "onion_routing":
		return p.OnionRouting
	case "blinded_paths":
		return p.BlindedPaths
	case "confidential_amounts":
		return p.ConfidentialAmounts
	case "confidential_recipient":
		return p.ConfidentialRecipient
	case "private_notes":
		return p.PrivateNotes
	case "zero_knowledge":
		return p.ZeroKnowledgeProofs
	case "atomic_multipath":
		return p.AtomicMultipath
	case "private_streaming":
		return p.PrivateStreaming
	default:
		// An unknown property is not claimable. Defaulting to true for
		// unrecognised names is how a typo becomes a false promise.
		return false
	}
}
