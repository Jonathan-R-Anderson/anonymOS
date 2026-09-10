package channel

// The proving-system boundary.
//
// WHY THIS EXISTS BEFORE A PROOF SYSTEM IS CHOSEN
// -----------------------------------------------
// The roadmap's production recommendation turns on maintainability rather than
// proof size: Groth16 needs a fresh trusted-setup ceremony for every circuit
// change, and a team that must run a ceremony to ship a bug fix will ship the
// bug fix without one. That argues for a universal or setup-free system in
// production and a fast one for the proof of concept — two different systems,
// which only works if nothing above this interface knows which is underneath.
//
// So the rule matches the channel adapter's: no proving library's types cross
// this boundary, and the interface stays narrower than any of them.
//
// WHAT A PROOF HERE ACTUALLY ASSERTS
// ----------------------------------
// Not "this payment is valid" in the abstract. Specifically: the inputs exist
// and are unspent, the payer controls them, value is conserved across inputs,
// outputs and fees, nothing has expired, and the routing allocation matches the
// onion the hops will see — while revealing none of the payer, recipient,
// amount or purpose. Anything a verifier must check that is NOT in that list
// has to be checked outside the circuit, and this file's job is to make the
// division explicit rather than assumed.

import (
	"context"
	"errors"
)

// Commitment hides a value while binding to it. Pedersen, so commitments add:
// the circuit proves inputs balance outputs by summing them without opening any.
type Commitment [32]byte

// Nullifier is the public tag published when a note is spent.
//
// Derived from the note's seed AND the spending key, so an observer holding the
// note cannot compute it in advance and watch for the spend. Publishing it is
// what makes double-spending detectable; it reveals nothing about which note it
// came from.
type Nullifier [32]byte

// Proof is opaque bytes. Deliberately not a struct: its shape is the proving
// system's business, and a typed field here would be a Groth16 detail that
// Halo2 has to pretend to have.
type Proof []byte

// PublicInputs are the values a verifier sees.
//
// This list IS the privacy boundary. Anything added here becomes visible to
// every verifier forever, so a field belongs here only when a verifier cannot
// do its job without it — which is a much higher bar than "it would be
// convenient".
type PublicInputs struct {
	// NoteTreeRoot anchors membership: which tree the inputs were proven in.
	NoteTreeRoot [32]byte
	// Nullifiers published by this spend. The double-spend check is against a
	// public set, so these cannot be hidden.
	Nullifiers []Nullifier
	// OutputCommitments are inserted into the tree, so they must be visible to
	// be inserted.
	OutputCommitments []Commitment
	// FeeCommitment lets a hop verify it is paid without learning the total.
	FeeCommitment Commitment
	// RouteCommitment binds this proof to one onion. Without it, a captured
	// proof could be replayed down an attacker-chosen path.
	RouteCommitment [32]byte
	// AssetCommitment prevents mixing assets within a proof.
	AssetCommitment Commitment
	// ExpiresAt is checkable without opening a note.
	ExpiresAt uint64
	// VerifyingKeyID says which circuit version this proof is for. A proof
	// verified against the wrong circuit is not a weaker check, it is a
	// meaningless one.
	VerifyingKeyID  string
	ProtocolVersion uint16
}

// Witness is everything the payer knows and nobody else may learn.
//
// NEVER transmitted. The roadmap states this as a rule with teeth: a service
// that generates proofs on a user's behalf receives the witness, which is every
// private value in the payment. If browser proving is too slow the answer is a
// smaller circuit, not a prover that sees everything.
type Witness struct {
	InputValues    []uint64
	InputBlindings [][32]byte
	InputSeeds     [][32]byte
	MerklePaths    [][][32]byte
	SpendingKey    [32]byte

	OutputValues    []uint64
	OutputBlindings [][32]byte
	RecipientKeys   [][32]byte

	RouteSecrets   [][32]byte
	ContextOpening [32]byte
}

// Transition is one private state change, for aggregation.
type Transition struct {
	Inputs  PublicInputs
	Proof   Proof
	Channel ChannelID
}

// AggregateProof stands for many transitions at once — the mechanism that makes
// per-second streaming affordable, since one proof per epoch beats one per
// voucher by orders of magnitude.
type AggregateProof []byte

// ProofCapabilities is what a proving backend can actually do.
//
// Same rule as channel capabilities: reported, never assumed, and the caller
// must refuse the feature rather than degrade quietly.
type ProofCapabilities struct {
	// Recursion / Aggregation: can many transitions collapse into one proof.
	// Without it, private streaming costs one proof per voucher, which is the
	// difference between viable and not.
	Aggregation bool
	// TrustedSetup: whether a ceremony is required. Reported because it decides
	// how a circuit upgrade is shipped, which is an operational property, not a
	// cryptographic detail.
	TrustedSetup bool
	// OnChainVerifier: whether a verifier contract exists for the chain in use.
	// Disputes need one; ordinary payments do not.
	OnChainVerifier bool
	// BrowserProving: whether a viewer can generate a proof client-side. False
	// means either a slower path or a prover that sees the witness — and the
	// second is not acceptable, so false means the feature is off.
	BrowserProving bool
	System         string // "groth16", "plonk", "halo2", …
}

var (
	// ErrNoProver means no proving backend is configured.
	ErrNoProver = errors.New("channel: no proof backend configured")
	// ErrWitnessWouldLeave guards the rule above.
	ErrWitnessWouldLeave = errors.New("channel: refusing to send a witness off-device")
)

// ProofAdapter is the whole proving surface.
type ProofAdapter interface {
	// ProvePrivateTransfer runs locally. An implementation that ships the
	// witness anywhere is a bug, not a deployment choice.
	ProvePrivateTransfer(ctx context.Context, w Witness) (Proof, PublicInputs, error)

	VerifyPrivateTransfer(ctx context.Context, p Proof, in PublicInputs) error

	// ProveAggregate collapses many transitions into one proof. Returns
	// ErrUnsupported when the backend cannot, so the caller disables streaming
	// rather than falling back to one proof per voucher without noticing.
	ProveAggregate(ctx context.Context, transitions []Transition) (AggregateProof, error)

	Capabilities() ProofCapabilities
}

// NullProver is the default: no proving backend.
//
// Refuses everything, claims nothing. Lets the note and routing layers be built
// and tested against the interface before the proving system is chosen — which
// is exactly the ordering Phase 0 asks for.
type NullProver struct{}

func (NullProver) ProvePrivateTransfer(context.Context, Witness) (Proof, PublicInputs, error) {
	return nil, PublicInputs{}, ErrNoProver
}
func (NullProver) VerifyPrivateTransfer(context.Context, Proof, PublicInputs) error {
	return ErrNoProver
}
func (NullProver) ProveAggregate(context.Context, []Transition) (AggregateProof, error) {
	return nil, ErrNoProver
}
func (NullProver) Capabilities() ProofCapabilities { return ProofCapabilities{} }

var _ ProofAdapter = NullProver{}

// SupportsPrivatePayments reports whether a channel backend and a prover
// together can actually carry a private payment.
//
// Both halves are required and they are configured independently, so the
// combination is the thing to check. A node with a private-capable channel
// backend and no prover would otherwise advertise privacy it cannot produce.
func SupportsPrivatePayments(c Capabilities, p ProofCapabilities) bool {
	if err := c.Validate(); err != nil {
		return false
	}
	if !c.Privacy.PrivateNotes || !c.Privacy.ZeroKnowledgeProofs {
		return false
	}
	// A prover that cannot prove in a browser cannot serve viewers without
	// taking their witness, and taking the witness is refused outright — so
	// for this application that combination is simply not private payments.
	return p.System != "" && p.BrowserProving
}

// SupportsPrivateStreaming additionally requires aggregation.
//
// Separate from SupportsPrivatePayments because a backend can honestly do
// one-off private tips and not continuous ones: without aggregation a stream
// costs one proof per voucher, and at a voucher every few seconds that is not a
// slower feature, it is a different one.
func SupportsPrivateStreaming(c Capabilities, p ProofCapabilities) bool {
	return SupportsPrivatePayments(c, p) && p.Aggregation && c.Privacy.PrivateStreaming
}
