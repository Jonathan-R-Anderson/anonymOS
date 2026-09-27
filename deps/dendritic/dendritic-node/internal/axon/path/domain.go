package path

import (
	"net/netip"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// UnknownOperatorPolicy decides what an unverifiable owner means for the
// operator rung.
//
// TWO ROADMAP SECTIONS DISAGREE HERE AND BOTH ARE RIGHT ABOUT SOMETHING.
//
// §8.7's table: "All unlabelled relays count as one operator, so at most one
// per path." Its reasoning is exact for the input it assumes — a SELF-DECLARED
// operator label. If the label is optional and free, omitting it buys
// diversity, so an adversary omits it on every relay and takes all three hops.
// Collapsing the unlabelled into one operator removes that reward.
//
// P12b's card: "UnknownOperatorPolicy — never treated as equal. Identical to
// ASNUnknown's rule: two unknowns are not known to be the same." Its reasoning
// is exact for ITS input — an owner read from the BONDED ON-CHAIN REGISTRY.
// There is nothing to omit; a relay is registered or it is not.
//
// THE RULING. The two texts are answering different questions because they are
// reading different fields, and the resolution follows from WHY an owner is
// unknown:
//
//	unregistered      the relay has no bond, so §8.7's own SelectPath filter
//	                  ("bond >= BondFloor(role)") should have excluded it before
//	                  the operator rung was ever consulted. This is not the
//	                  operator rung's problem to solve.
//	chain unreachable a transient condition affecting EVERY relay at once.
//	                  Collapsing all of them into one operator stops path
//	                  building entirely for the duration of an outage, which
//	                  converts a chain problem into a total loss of service.
//
// So the default is Distinct, matching P12b, and Collapse is available for a
// deployment that wants §8.7's stricter reading. The exposure the default
// carries is REAL and it is reported rather than argued away: until the bond
// floor is enforced, an adversary can hold unregistered relays and they will be
// mutually distinct. PathReport.OperatorUnavailable is how a caller sees it.
type UnknownOperatorPolicy uint8

const (
	// UnknownOperatorsDistinct is P12b's rule and the default.
	UnknownOperatorsDistinct UnknownOperatorPolicy = iota
	// UnknownOperatorsCollapse is §8.7's rule: every relay with no verified
	// owner is treated as the same operator, so at most one may appear in a
	// path. It cannot build a path at all on a network where nothing is
	// registered, which is the cost of the stricter reading.
	UnknownOperatorsCollapse
)

func (p UnknownOperatorPolicy) String() string {
	if p == UnknownOperatorsCollapse {
		return "collapse"
	}
	return "distinct"
}

// pathPrefix is the coarse failure-domain prefix used for PATHS: /16 for IPv4
// and /32 for IPv6, per §8.7.
//
// It is computed here rather than stored on the Annotation because the
// annotation's Prefix is §7.5's replication width and both are needed — the
// same relay is a /24 to the placement planner and a /16 to the path selector,
// and collapsing them into one stored field is what made these read as one
// number in the first place.
func pathPrefix(a peer.Annotation) (netip.Prefix, bool) {
	if !a.Addr.IsValid() {
		return netip.Prefix{}, false
	}
	bits := params.PathPrefixBitsV4
	if a.Addr.Is6() {
		bits = params.PathPrefixBitsV6
	}
	p, err := a.Addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// samePathDomain is the path-level diversity predicate.
//
// It differs from peer.SameDomain in exactly two places, and both are §8.7's:
// the prefix is coarser, and the unknown-operator rule is a policy. Everything
// else defers to peer.SameDomain so there is one definition of "same AS".
func samePathDomain(a, b peer.Annotation, d peer.Domain, unknownOps UnknownOperatorPolicy) bool {
	switch d {
	case peer.DomainPrefix:
		pa, oka := pathPrefix(a)
		pb, okb := pathPrefix(b)
		if !oka || !okb {
			return false
		}
		return pa == pb
	case peer.DomainOperator:
		aUnknown := a.Operator.IsUnknown() || a.OperatorSource != peer.OperatorSourceChain
		bUnknown := b.Operator.IsUnknown() || b.OperatorSource != peer.OperatorSourceChain
		if aUnknown && bUnknown {
			return unknownOps == UnknownOperatorsCollapse
		}
		if aUnknown || bUnknown {
			return false
		}
		return a.Operator == b.Operator
	default:
		return peer.SameDomain(a, b, d)
	}
}
