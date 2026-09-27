package sybil

import (
	"errors"
	"fmt"
	"sort"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// SelectionPoint is a place where an adversary's identities could accumulate.
//
// There are exactly four and they are enumerated here rather than left implicit,
// because T14.3's requirement is that the caps hold at every one of them
// SIMULTANEOUSLY. A cap enforced at three of four is not a weaker cap; it is no
// cap, since the adversary uses the fourth.
type SelectionPoint uint8

const (
	// PointPath is a circuit's hops (§8.7).
	PointPath SelectionPoint = iota
	// PointBucket is a DHT routing-table bucket (§7.2).
	PointBucket
	// PointReplicaSet is the holders of one chunk (§7.5, §10).
	PointReplicaSet
	// PointGuardSet is a client's sampled guard set (§8.5).
	PointGuardSet
)

func (p SelectionPoint) String() string {
	switch p {
	case PointBucket:
		return "dht-bucket"
	case PointReplicaSet:
		return "replica-set"
	case PointGuardSet:
		return "guard-set"
	default:
		return "path"
	}
}

// AllPoints is every selection point. Iterating it is what makes "at every
// selection point" a loop rather than a promise.
var AllPoints = []SelectionPoint{PointPath, PointBucket, PointReplicaSet, PointGuardSet}

// Caps is the per-point occupancy limit for one failure domain.
type Caps struct {
	PerPrefix int
	PerASN    int
	// PerOperator is P12b's fourth rung. Zero means the rung is not applied,
	// which on a network with no registered owners is the honest state and is
	// reported rather than assumed away.
	PerOperator int
}

// CapsFor returns the composed policy for a selection point.
//
// ONE FUNCTION IS THE POINT. Before P14 these numbers lived in four packages —
// dht's bucket admission, path's diversity constraint, placement's holder rule,
// tunnel's guard sampler — and four copies of a policy drift. The drift is not
// hypothetical: §8.7 said /16 for paths while §7.5 said /24 for replication, and
// the code had read them as one number until P12 separated them.
func CapsFor(p SelectionPoint) Caps {
	switch p {
	case PointBucket:
		return Caps{
			PerPrefix:   params.MaxPerPrefixPerBucket,
			PerASN:      params.MaxPerASNPerBucket,
			PerOperator: 1,
		}
	case PointReplicaSet:
		return Caps{
			PerPrefix:   params.MaxPerPrefixPerReplicaSet,
			PerASN:      1,
			PerOperator: 1,
		}
	case PointGuardSet:
		// A guard set is sampled from the population and persists for months,
		// so it is the point where accumulation is most expensive to undo. It
		// takes the strictest cap of all four.
		return Caps{PerPrefix: 1, PerASN: 1, PerOperator: 1}
	default:
		return Caps{
			PerPrefix:   params.MaxPerPrefixPerPath,
			PerASN:      params.MaxPerASNPerPath,
			PerOperator: 1,
		}
	}
}

// ErrCapExceeded is returned by Check when an occupancy limit is breached.
var ErrCapExceeded = errors.New("axon/sybil: failure-domain cap exceeded")

// Occupancy is how many members of a set fall in each failure domain.
type Occupancy struct {
	Prefix   map[string]int
	ASN      map[uint32]int
	Operator map[peer.OperatorID]int
	// UnknownASN and UnknownOperator are members the corresponding rung could
	// not be applied to. They are counted because a set that satisfies every cap
	// on a population whose domains are all unknown has satisfied nothing, and
	// the caller must be able to tell that case from a real one.
	UnknownASN      int
	UnknownOperator int
}

// MeasureOccupancy counts a candidate set's occupancy.
//
// It takes annotations rather than an interface so that every caller — path,
// dht, placement, tunnel — measures the same thing from the same input. A
// per-package accessor would be four chances to read a different field.
func MeasureOccupancy(anns []peer.Annotation) Occupancy {
	o := Occupancy{
		Prefix:   map[string]int{},
		ASN:      map[uint32]int{},
		Operator: map[peer.OperatorID]int{},
	}
	for _, a := range anns {
		if a.Prefix.IsValid() {
			o.Prefix[a.Prefix.String()]++
		}
		if a.ASN == peer.ASNUnknown {
			o.UnknownASN++
		} else {
			o.ASN[a.ASN]++
		}
		if a.Operator.IsUnknown() || a.OperatorSource != peer.OperatorSourceChain {
			o.UnknownOperator++
		} else {
			o.Operator[a.Operator]++
		}
	}
	return o
}

// Check reports whether an occupancy satisfies a point's caps.
//
// The returned error names the domain and the count, because "cap exceeded" with
// no subject is unactionable in a log and a caller will stop reading it.
func Check(o Occupancy, p SelectionPoint) error {
	c := CapsFor(p)
	// Deterministic reporting order: a map iteration would name a different
	// offending domain on each run for the same violation.
	prefixes := make([]string, 0, len(o.Prefix))
	for k := range o.Prefix {
		prefixes = append(prefixes, k)
	}
	sort.Strings(prefixes)
	for _, k := range prefixes {
		if o.Prefix[k] > c.PerPrefix {
			return fmt.Errorf("%w: %s holds %d members of prefix %s, cap %d",
				ErrCapExceeded, p, o.Prefix[k], k, c.PerPrefix)
		}
	}
	asns := make([]uint32, 0, len(o.ASN))
	for k := range o.ASN {
		asns = append(asns, k)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	for _, k := range asns {
		if o.ASN[k] > c.PerASN {
			return fmt.Errorf("%w: %s holds %d members of AS %d, cap %d",
				ErrCapExceeded, p, o.ASN[k], k, c.PerASN)
		}
	}
	if c.PerOperator > 0 {
		ops := make([]peer.OperatorID, 0, len(o.Operator))
		for k := range o.Operator {
			ops = append(ops, k)
		}
		sort.Slice(ops, func(i, j int) bool { return ops[i].String() < ops[j].String() })
		for _, k := range ops {
			if o.Operator[k] > c.PerOperator {
				return fmt.Errorf("%w: %s holds %d members owned by %s, cap %d",
					ErrCapExceeded, p, o.Operator[k], k, c.PerOperator)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Storage admission (T14.4, E14.2)
// ---------------------------------------------------------------------------

// StoreRequest is a request to place one shard on this node.
type StoreRequest struct {
	// Writer is the identity asking to store.
	Writer string
	// Bond is the writer's PROVEN bond. A zero VerifiedAt means unproven, and
	// AdmitStore refuses it -- there is no anonymous-writer path here.
	Bond BondRef
	// Bytes is the shard size.
	Bytes int64
	// FreeBytes is what this node currently has.
	FreeBytes int64
}

var (
	// ErrNoCapacity means the node is full. It is a first-class outcome, not an
	// error condition: §10 says an unplaced shard is a visible deficit and a
	// doubled-up one is a false durability claim.
	ErrNoCapacity = errors.New("axon/sybil: insufficient free capacity")
	// ErrWriterUnbonded means the writer produced no proven bond.
	ErrWriterUnbonded = errors.New("axon/sybil: writer has no proven bond")
)

// AdmitStore decides a shard write from BOND AND LOCAL POLICY ONLY.
//
// WHAT THIS REPLACES. `internal/p2p/node.go`'s validateLease requires an Ed25519
// signature from a coordinator key on every shard write. That signature is the
// last centralised control point in the storage path: stop the coordinator and
// every write in the network stops with it. E14.2 exists to retire it.
//
// WHAT IT DOES NOT YET DO, STATED PLAINLY. E14.2 is NOT CLAIMED. This function
// is the mechanism and it is tested, but nothing calls it in production, and it
// could not usefully be called yet: StakeVault is written and DEPLOYED NOWHERE,
// so VerifyBond has no chain to prove against and every writer would present an
// unprovable bond and be refused. Switching the production path to this before
// the contracts are deployed would replace a working centralised gate with a
// closed one. The sequencing is the deployment, not the code.
func AdmitStore(req StoreRequest) error {
	if req.Bond.VerifiedAt == 0 || req.Bond.Amount == nil || req.Bond.Amount.Sign() == 0 {
		return ErrWriterUnbonded
	}
	if _, err := Admit(req.Bond, RoleStorage); err != nil {
		return err
	}
	if req.Bytes <= 0 {
		return fmt.Errorf("axon/sybil: shard size %d is not a size", req.Bytes)
	}
	if req.FreeBytes < req.Bytes {
		return fmt.Errorf("%w: %d free, %d needed", ErrNoCapacity, req.FreeBytes, req.Bytes)
	}
	return nil
}
