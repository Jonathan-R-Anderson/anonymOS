package peer

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// P12b — operator diversity, the fourth rung of the §7.5 ladder (PAR-17).
//
// §7.2 states the gap in its own words: "ASN diversity is not operator
// diversity". A large cloud provider spans many ASes, so a path that satisfies
// distinct-/24 AND distinct-ASN can still be three machines with one owner, one
// billing relationship and one subpoena. Prefix and ASN are properties of the
// address; operator is a property of the person, and only the second one is
// what the threat model actually cares about.
//
// The owner comes from the bonded on-chain registry through the light client.
// It is not a field a relay fills in. A self-declared owner would be a claim,
// and the whole rung would then measure how honestly relays fill in a form.

// OperatorID is the owner's address from NodeRegistry.Node.owner.
type OperatorID [20]byte

// OperatorUnknown is the zero owner: no chain answer.
//
// Like ASNUnknown it is a distinct concept from "the owner whose address is
// zero", and it must never be treated as a value two relays can share. Two
// unknown operators are not known to be the same operator, and collapsing them
// would under-count diversity in the flattering direction (T12b.4).
var OperatorUnknown OperatorID

// IsUnknown reports whether no owner was determined.
func (o OperatorID) IsUnknown() bool { return o == OperatorUnknown }

func (o OperatorID) String() string {
	if o.IsUnknown() {
		return "unknown"
	}
	return "0x" + hex.EncodeToString(o[:])
}

// OperatorSource is the provenance of an operator annotation. There are exactly
// two values, and that is the design: an owner is either proven against the
// chain or it is unknown. There is no "the relay told us" state for it to
// occupy, because such a state would be indistinguishable from the proven one
// everywhere downstream.
type OperatorSource uint8

const (
	// OperatorSourceNone means no verified answer. See OperatorUnknown.
	OperatorSourceNone OperatorSource = iota
	// OperatorSourceChain means read from the bonded registry and verified.
	OperatorSourceChain
)

func (s OperatorSource) String() string {
	if s == OperatorSourceChain {
		return "chain"
	}
	return "none"
}

var (
	// ErrOperatorMismatch is T12b.3: a relay declared an owner that the chain
	// does not agree with.
	//
	// The relay is REFUSED rather than silently corrected to the chain's answer.
	// A disagreement is evidence that something is wrong — a stale descriptor, a
	// transfer in flight, or an attempt to look like somebody else — and none of
	// those are conditions to route through while quietly overriding the claim.
	ErrOperatorMismatch = errors.New("axon/peer: declared operator disagrees with the chain")
)

// OperatorResolver answers the owner of a node from the bonded registry.
//
// It is an interface so that the light client, which is P10's dependency and
// not built into this package, can be supplied by the caller. A nil resolver is
// legitimate and means every operator is unknown — which is what a node with no
// chain access has, and it must degrade to "unknown", never to "same".
type OperatorResolver interface {
	// Operator returns the verified owner. ok is false when the registry has no
	// entry; err is for a resolver that could not answer at all, which is a
	// different condition from an answer of "not registered".
	Operator(nodeID string) (OperatorID, bool, error)
}

// ResolveOperator determines a node's operator, refusing a declaration that
// disagrees with the chain.
//
// declared is what the relay's descriptor claimed, if anything. It is used for
// EXACTLY ONE PURPOSE — detecting the disagreement in T12b.3 — and never as a
// fallback when the chain is silent. A declaration the chain cannot confirm is
// worth nothing, and treating it as a weak signal would let an adversary set
// this node's operator ladder by writing descriptors.
func ResolveOperator(nodeID string, declared *OperatorID, r OperatorResolver) (OperatorID, OperatorSource, error) {
	if r == nil {
		return OperatorUnknown, OperatorSourceNone, nil
	}
	owner, ok, err := r.Operator(nodeID)
	if err != nil {
		// A chain outage makes every operator unknown at once, which is P12b's
		// named failure mode: the ladder silently loses a rung and paths that
		// would have been refused become admissible. The caller learns via the
		// error and the report; nothing here substitutes a guess.
		return OperatorUnknown, OperatorSourceNone, err
	}
	if !ok || owner.IsUnknown() {
		return OperatorUnknown, OperatorSourceNone, nil
	}
	if declared != nil && *declared != owner {
		return OperatorUnknown, OperatorSourceNone,
			fmt.Errorf("%w: %s declares %s, chain says %s",
				ErrOperatorMismatch, nodeID, declared.String(), owner.String())
	}
	return owner, OperatorSourceChain, nil
}

// DomainKeys renders an annotation's failure domains as opaque strings, one per
// domain that is actually KNOWN.
//
// It exists so that a consumer which must not import an address library — the
// storage placement planner, which is deliberately pure — can still enforce the
// same ladder. Unknown domains produce no key at all rather than a placeholder
// one, which preserves the rule that two unknowns are never equal: they simply
// have nothing to collide on.
func DomainKeys(a Annotation) []string {
	keys := make([]string, 0, 3)
	if a.Prefix.IsValid() {
		keys = append(keys, "p:"+a.Prefix.String())
	}
	if a.ASN != ASNUnknown {
		keys = append(keys, fmt.Sprintf("a:%d", a.ASN))
	}
	if !a.Operator.IsUnknown() && a.OperatorSource == OperatorSourceChain {
		keys = append(keys, "o:"+a.Operator.String())
	}
	return keys
}
