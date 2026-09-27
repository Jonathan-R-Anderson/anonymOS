package path

import (
	"errors"
	"sort"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// Relay is one selectable relay: where it sits in the address space, what it
// claims, and what it bonded.
//
// The annotation is P3's and is produced from an address this node observed. It
// is not a field the relay fills in — §1.4's finding is that under the old
// transport no node ever saw a peer's IP, so every diversity claim in the
// roadmap rested on inputs that did not exist. These are those inputs.
type Relay struct {
	NodeID string
	Ann    peer.Annotation
	// Weight is the bonded self-report. Used only under WeightPolicy.UseClaims.
	Weight Weight
}

// DiversityConstraint is which failure domains no two hops may share.
//
// It is deliberately a separate type from peer.DiversityConstraint: that one
// constrains a SAMPLE from the peerbook, this one constrains a PATH, and the
// two differ in what a violation costs. A sample that repeats a /24 is a weaker
// sample; a path that repeats a /24 is two hops one seizure can read.
type DiversityConstraint struct {
	// Domains every pair of hops must differ in.
	Domains []peer.Domain
	// Exclude is node ids that may not appear, e.g. relays already in another
	// leg of the same tunnel.
	Exclude map[string]bool
	// UnknownOperators decides whether relays with no verified owner are
	// mutually distinct (the default, P12b) or one operator (§8.7). See
	// UnknownOperatorPolicy for why both readings exist.
	UnknownOperators UnknownOperatorPolicy
}

// Default is the standard constraint: the full §7.5 ladder — distinct prefix,
// distinct AS, and distinct OPERATOR (P12b).
//
// Including the operator rung by default is safe on a network where nobody's
// owner is known, because two unknown operators are never equal: the constraint
// then admits everything and PathReport.OperatorUnavailable says so. What it is
// NOT safe to do is leave the rung out and let a caller believe the ladder was
// applied in full. §7.2: "ASN diversity is not operator diversity."
func Default() DiversityConstraint {
	return DiversityConstraint{Domains: []peer.Domain{
		peer.DomainPrefix, peer.DomainASN, peer.DomainOperator,
	}}
}

var (
	// ErrNoPath means no path satisfying the constraints exists in the
	// candidate set. It is returned INSTEAD of a shorter or less diverse path:
	// a caller that asked for 3 mutually diverse hops and receives 2, or 3 in
	// one AS, has a weaker anonymity property than it believes it has.
	ErrNoPath = errors.New("axon/path: no path satisfies the diversity constraints")
	// ErrBadRequest is a malformed request: non-positive length, or a length
	// above MaxHops.
	ErrBadRequest = errors.New("axon/path: invalid path request")
	// ErrNoProfiles means the policy asked for profile weighting and did not
	// supply a profile store. Failing is deliberate: silently falling back to
	// uniform would make a misconfiguration invisible.
	ErrNoProfiles = errors.New("axon/path: profile weighting requested without a profile store")
)

// Relaxation records one constraint that had to be dropped to find a path.
type Relaxation struct {
	// Hop is the position, 0-based, at which the full constraint set admitted
	// nothing.
	Hop int
	// Dropped is the domain that was given up.
	Dropped peer.Domain
}

// PathReport is what selection could actually enforce.
//
// Returning it alongside the path — rather than only an error — is the whole
// answer to §56.2's failure mode: a diversity mechanism built on an
// unobservable property reports success and delivers nothing. Every way this
// selector can fall short of the request is a counted field here.
type PathReport struct {
	Requested int
	Returned  int
	// Candidates is the size of the pool the path was drawn from, after
	// exclusions and after failing-tier relays were dropped.
	Candidates int
	// DistinctPrefixes and DistinctASNs describe that pool's real diversity,
	// which is the number a partition shows up in.
	DistinctPrefixes int
	DistinctASNs     int
	// ASNUnavailable counts candidates whose ASN could not be determined, so a
	// DomainASN constraint could not be applied to them. On an IPv4 network
	// this is most of them; see peer.Annotate.
	ASNUnavailable int
	// OperatorUnavailable is the same count for the operator rung (T12b.2). It
	// is reported, never silently substituted: a path drawn from a pool of
	// entirely unknown operators satisfied distinct-operator vacuously, and a
	// caller that cannot see this figure will read that as a guarantee.
	OperatorUnavailable int
	// DistinctOperators is how many verified owners the pool covered. A pool of
	// 60 relays and 2 owners is two operators wearing sixty hats.
	DistinctOperators int
	// Relaxations is empty unless the policy allowed relaxation AND no path
	// existed under the full constraint set (E12.2).
	Relaxations []Relaxation
	// Source is the evidence that decided the weighting.
	Source WeightSource
	// PartitionWarning is T12.5: this view is too small or too concentrated to
	// be the whole network.
	PartitionWarning bool
	// PartitionReason says which floor tripped, for a log that has to be
	// actionable rather than merely alarming.
	PartitionReason string
}

// Relaxed reports whether any constraint was given up.
func (r PathReport) Relaxed() bool { return len(r.Relaxations) > 0 }

// poolStats measures the candidate pool's real diversity.
func poolStats(cands []Relay) (prefixes, asns, asnUnknown, operators, opUnknown int) {
	pset := map[string]struct{}{}
	aset := map[uint32]struct{}{}
	oset := map[peer.OperatorID]struct{}{}
	for _, c := range cands {
		pset[c.Ann.Prefix.String()] = struct{}{}
		if c.Ann.ASN == peer.ASNUnknown {
			asnUnknown++
		} else {
			aset[c.Ann.ASN] = struct{}{}
		}
		if c.Ann.Operator.IsUnknown() || c.Ann.OperatorSource != peer.OperatorSourceChain {
			opUnknown++
		} else {
			oset[c.Ann.Operator] = struct{}{}
		}
	}
	return len(pset), len(aset), asnUnknown, len(oset), opUnknown
}

// detectPartition is T12.5.
//
// There is no consensus to compare against — that is R14 — so the only thing a
// client can check is whether the view it was given is plausible as a whole
// network. Two floors, and the second is the one that matters:
//
//	a pool smaller than PathMinCandidates offers no real choice;
//	a pool concentrated in fewer than PathMinDistinctPrefixes failure domains
//	is not a network, whatever its node count.
//
// Two clients handed disjoint descriptor sets by a partitioning adversary each
// see a small, concentrated pool and each warn, which is what T12.5 asks for.
// A CAREFUL partition — two large, diverse, disjoint halves of a real network —
// trips neither floor and is not detected. That limit is stated in §23's P12
// card and this function does not close it.
func detectPartition(cands []Relay, prefixes int) (bool, string) {
	if len(cands) < params.PathMinCandidates {
		return true, "candidate pool below the floor"
	}
	if prefixes < params.PathMinDistinctPrefixes {
		return true, "candidates concentrated in too few failure domains"
	}
	return false, ""
}

// sortRelays orders candidates by node id.
//
// Determinism BEFORE the draw, randomness IN it. A sampler whose input order
// comes from a Go map iteration is unreproducible, so a bias in it cannot be
// measured — and E12.3 is precisely a measurement of the draw's distribution.
func sortRelays(rs []Relay) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].NodeID < rs[j].NodeID })
}
