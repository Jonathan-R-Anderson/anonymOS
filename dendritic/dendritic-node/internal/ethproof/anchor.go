package ethproof

// The trust anchor, and the gap where it is not yet closed — roadmap P12-5.
//
// THE FINDING THAT SHAPES THIS FILE
// ---------------------------------
// P12-2 and P12-3 reduced the trust to one thing: the header. A record proves
// its value is consistent with SOME header. What makes a header Ethereum
// mainnet's is a separate question, and post-merge the answer is uncomfortable:
//
//	difficulty   0x0
//	nonce        0x0000000000000000
//
// There is no proof-of-work in an execution header any more. Fabricating a
// self-consistent chain of headers — correct parentHash linkage, plausible
// timestamps, whatever state roots the attacker likes, with storage proofs that
// verify perfectly against them — costs nothing but hashing.
//
// So EVERY execution-layer check is worthless against a lying provider:
//
//	parentHash chains    free to fabricate
//	stateRoot            free to fabricate, and proofs under it will verify
//	timestamps, gas      weak, and free to fabricate
//
// The only thing that makes a header canonical is signatures from the beacon
// chain's validators. There is no partial credit here and no cheap
// approximation, which is why this file contains a GATE rather than a
// half-measure: a partial verifier would be indistinguishable from a real one
// at the moment it mattered.
//
// WHAT WOULD CLOSE IT
// -------------------
//	BLS12-381 aggregate verification   sync committee signatures, 512 keys
//	SSZ merkleisation                  hash_tree_root + generalized indices
//	light client protocol              bootstrap, updates, period transitions
//	a checkpoint from OUTSIDE          see below
//
// That is a light client. It is a substantial piece of work and a substantial
// new cryptographic dependency in a module that deliberately has few — see
// doc/trust-anchor.md for the scoping.
//
// WHY THE ANCHOR CANNOT COME FROM THE PROVIDER
// --------------------------------------------
// Taking the anchor from the endpoint being verified moves the trust boundary
// without shrinking it:
//
//	before   provider -> channel value
//	after    provider -> "trusted" header -> channel value
//
// So SetAnchor refuses an anchor whose source shares a provider with the RPC it
// will be used to check. That refusal is the only security this file actually
// provides today, and it is worth having because the mistake is so natural.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoTrustAnchor is returned when header verification is attempted without an
// anchor. It is not a transient failure and must not be retried past.
var ErrNoTrustAnchor = errors.New(
	"ethproof: no trust anchor — a header cannot be established as Ethereum mainnet's")

// ErrAnchorNotIndependent is returned when the anchor comes from the same place
// as the data it is meant to check.
var ErrAnchorNotIndependent = errors.New(
	"ethproof: the anchor and the RPC share a provider, which is not independence")

// AnchorKind is how a header's canonicality was established.
type AnchorKind string

const (
	// AnchorNone: nothing. The provider is believed. This is where the system
	// is today, and naming it is the point — an unnamed trust assumption is one
	// nobody audits.
	AnchorNone AnchorKind = "none"
	// AnchorOperator: a human checked a block hash against block explorers and
	// pinned it. Real, and only as good as that human and that moment; it does
	// not extend forward on its own.
	AnchorOperator AnchorKind = "operator-pinned"
	// AnchorSyncCommittee: BLS-verified beacon headers. The real answer, and
	// not yet implemented — see doc/trust-anchor.md.
	AnchorSyncCommittee AnchorKind = "sync-committee"
)

// Anchor is what a deployment is relying on to believe a header.
type Anchor struct {
	Kind AnchorKind
	// Source is where it came from — a URL, a checkpoint provider, or a note
	// naming the human who pinned it. Compared against the RPC endpoint so the
	// obvious circularity is caught.
	Source string
	// BlockNumber and BlockHash are the pinned point, for an operator anchor.
	BlockNumber uint64
	BlockHash   string
	// Note records how it was established, for whoever audits this later.
	Note string
}

// Trustworthy reports whether this anchor actually establishes canonicality.
//
// Only the sync-committee anchor does. An operator pin is a real but narrow
// claim about one block at one moment, and it says nothing about the header a
// watchtower is looking at six months later — so it is honest input to a risk
// decision and not a substitute for verification.
func (a Anchor) Trustworthy() bool { return a.Kind == AnchorSyncCommittee }

// HeaderVerifier decides whether a header is Ethereum mainnet's.
//
// Today it decides "no, and here is why", which is the correct answer for a
// system that cannot yet tell. It exists now so that P12-6 can be written
// against the interface that will eventually hold a light client, and so the
// gap is a value in the program rather than a paragraph in a document.
type HeaderVerifier struct {
	ChainID  uint64
	Endpoint string
	anchor   Anchor
	// client is the native light client, once attached. Nil until P12-5.8 wires
	// one in, and VerifyHeader refuses while it is nil — there is no degraded
	// mode that accepts a provider's word instead.
	client *LightClient
}

// SetAnchor records what this deployment is relying on.
//
// Refuses an anchor that shares a provider with the endpoint it will be used to
// check. That is the whole point: an anchor fetched from the RPC being verified
// is not an anchor, it is the same claim told twice.
func (v *HeaderVerifier) SetAnchor(a Anchor) error {
	if a.Kind == "" {
		return errors.New("ethproof: an anchor must state its kind")
	}
	if a.Kind != AnchorNone && strings.TrimSpace(a.Source) == "" {
		return errors.New("ethproof: an anchor must say where it came from")
	}
	if a.Kind != AnchorNone && sameProvider(a.Source, v.Endpoint) {
		return fmt.Errorf("%w: both are %q", ErrAnchorNotIndependent, providerOf(a.Source))
	}
	v.anchor = a
	return nil
}

// Anchor returns what is currently relied on.
func (v *HeaderVerifier) Anchor() Anchor { return v.anchor }

// VerifyHeader reports whether a header can be established as canonical.
//
// Returns ErrNoTrustAnchor until a sync-committee anchor exists. It deliberately
// does NOT fall back to checking parentHash linkage or timestamps and calling
// that good enough: post-merge those cost nothing to fabricate, so a verifier
// that accepted them would report success on a wholly invented chain.
//
// Failing closed here is what keeps the gap visible. A watchtower wired to this
// will refuse to act on unanchored headers, which is an outage — and an outage
// is the correct behaviour for a system that cannot tell whether it is looking
// at Ethereum.
func (v *HeaderVerifier) VerifyHeader(h BlockHeader) error {
	if !v.anchor.Trustworthy() {
		return fmt.Errorf("%w (anchor is %q; see doc/trust-anchor.md)",
			ErrNoTrustAnchor, v.anchor.Kind)
	}
	if v.client == nil {
		// A trustworthy anchor with nothing to verify against. Refused rather
		// than treated as permission: the anchor says what we would trust, the
		// client is what does the trusting.
		return fmt.Errorf("%w: anchor is set but no light client is attached", ErrNoTrustAnchor)
	}
	return v.client.VerifyExecutionHeader(h)
}

// ChainAt reports whether two headers are linked parent-to-child.
//
// A CONSISTENCY CHECK, NOT A SECURITY CHECK. Post-merge, linkage is free to
// fabricate, so this catches an honest provider serving a chain gap and catches
// nothing at all from a dishonest one. Named and documented so it cannot be
// mistaken for the verification above.
func ChainAt(parent, child BlockHeader) bool {
	if parent.Hash == "" || child.ParentHash == "" {
		return false
	}
	if !strings.EqualFold(strip0x(parent.Hash), strip0x(child.ParentHash)) {
		return false
	}
	return child.BlockNumber() == parent.BlockNumber()+1
}

// sameProvider is the heuristic from chainprobe: two hosts under one
// registrable domain fail together and are not independent.
func sameProvider(a, b string) bool {
	pa, pb := providerOf(a), providerOf(b)
	return pa != "" && pa == pb
}

// providerOf reduces a URL or a note to the operator it names.
//
// Non-URL sources — "checked against three block explorers by hand" — reduce to
// themselves and will not collide with an endpoint's hostname, which is the
// behaviour an operator anchor needs.
func providerOf(source string) string {
	u, err := url.Parse(source)
	if err != nil || u.Hostname() == "" {
		return strings.ToLower(strings.TrimSpace(source))
	}
	labels := strings.Split(strings.ToLower(u.Hostname()), ".")
	if len(labels) < 2 {
		return labels[0]
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
