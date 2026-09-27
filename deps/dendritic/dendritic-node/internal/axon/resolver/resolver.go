// Package resolver turns a name into records, from a locally verified snapshot,
// with a declared freshness bound, and WITHOUT the chain on the request path (R7).
//
// THE PIPELINE, in order, and the chain is never in it:
//
//	cache -> DHT DomainRecord -> local verified snapshot -> (slow path) light client
//
// THERE IS NO DNS FALLBACK, by design. §13 puts it plainly: a fallback is a
// downgrade attack with a friendly name. A resolver that answers from DNS when
// the overlay is unreachable has replaced a verified answer with an unverified
// one at exactly the moment an adversary would want it to.
//
// EVERY ANSWER CARRIES ITS MODE AND ITS STALENESS. A caller that does not read
// them is choosing to be downgraded, and the API makes that choice explicit.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

// Mode is how an answer was obtained. §13.3 makes it a field in every answer.
type Mode uint8

const (
	// ModeFull used the light client and eth_getProof. Trusts the initial
	// checkpoint and the BLS assumption; trusts NO RPC.
	ModeFull Mode = iota + 1
	// ModeSnapshotWarm used a root THIS CLIENT verified against the chain at a
	// known time. Staleness is exactly now - T0. The mode R7 describes.
	ModeSnapshotWarm
	// ModeSnapshotCold used a root accepted on a PUBLISHER SIGNATURE, because
	// this client has never had chain access.
	//
	// KEPT SEPARATE FROM WARM ON PURPOSE. §13.3: conflating them would be
	// dishonest. Cold trusts a third party; warm trusts a chain observation the
	// client made itself. Reporting both as "SNAPSHOT" would let a client that
	// has never seen the chain believe it had.
	ModeSnapshotCold
	// ModeDelegated asked a remote resolver, which is UNTRUSTED and learns every
	// name asked. The evidence it returns is checked against an independent root.
	ModeDelegated
)

func (m Mode) String() string {
	switch m {
	case ModeFull:
		return "FULL"
	case ModeSnapshotWarm:
		return "SNAPSHOT-WARM"
	case ModeSnapshotCold:
		return "SNAPSHOT-COLD"
	case ModeDelegated:
		return "DELEGATED"
	default:
		return "UNSET"
	}
}

// TrustsChainObservation reports whether the mode rests on something this client
// verified against the chain itself. SNAPSHOT-COLD does not.
func (m Mode) TrustsChainObservation() bool {
	return m == ModeFull || m == ModeSnapshotWarm
}

// Flags carry what a caller must know beyond the records.
type Flags uint8

const (
	// FlagNegative marks an authenticated proof of absence.
	FlagNegative Flags = 1 << iota
	// FlagPendingPossible marks a negative answer that may be wrong because the
	// name could have been registered after the evidence was taken.
	FlagPendingPossible
	// FlagRevoked marks an identity refused for revocation.
	FlagRevoked
)

// MaxFreshness is the hard refusal bound (§13.3).
//
// Shortening it reintroduces the chain dependency R7 removed; lengthening it
// serves a revoked or transferred name for longer. Neither direction is free.
const MaxFreshness = 24 * time.Hour

var (
	ErrNotAuthenticated = errors.New("axon/resolver: evidence is not authenticated")
	ErrTooStale         = errors.New("axon/resolver: evidence is older than the freshness bound")
	ErrRevoked          = errors.New("axon/resolver: DomainIdentity is revoked")
	ErrNoSource         = errors.New("axon/resolver: no source could answer")
	ErrNotRegistrable   = errors.New("axon/resolver: only a registrable name resolves on chain")
)

// Answer is a resolution result.
//
// E10.3: NO ADDRESS APPEARS IN THIS TYPE OR ANYTHING IT REACHES. The resolver
// runs above L4, where an address is a deanonymisation surface rather than a
// routing input. TestE103 audits it by reflection so a later field fails the build.
type Answer struct {
	Name           name.Name
	DomainIdentity [32]byte
	// Records is opaque here; §11.6 owns its schema.
	Records        []byte
	Mode           Mode
	AsOf           time.Time
	FreshnessBound time.Duration
	Flags          Flags

	now time.Time
}

// StalenessSeconds is how old the evidence is, or -1 when there is none.
//
// A METHOD rather than a field, so it cannot be recorded once and read later as
// though still true. S6: an answer without a staleness figure is a failure.
func (a *Answer) StalenessSeconds() int64 {
	if a.AsOf.IsZero() {
		return -1
	}
	return int64(a.now.Sub(a.AsOf) / time.Second)
}

func (a *Answer) Negative() bool        { return a.Flags&FlagNegative != 0 }
func (a *Answer) PendingPossible() bool { return a.Flags&FlagPendingPossible != 0 }

// Snapshot is a registry snapshot this client holds.
type Snapshot struct {
	Root [32]byte
	// VerifiedAt is when THIS CLIENT checked the root against the chain. Zero
	// means it never did -- which is what makes an answer COLD.
	VerifiedAt time.Time
	// PublishedAt is the publisher's claimed time, used only for COLD.
	PublishedAt time.Time
	BlockNumber uint64
}

// Mode reports which sub-case this snapshot is.
func (s Snapshot) Mode() Mode {
	if !s.VerifiedAt.IsZero() {
		return ModeSnapshotWarm
	}
	return ModeSnapshotCold
}

// SnapshotSource supplies snapshots and proofs against them.
type SnapshotSource interface {
	Current() (Snapshot, bool)
	// Prove returns the identity and records for a zone, or a proof of ABSENCE.
	// A source that can produce neither must error rather than return a bare miss.
	Prove(zoneID [32]byte) (identity [32]byte, records []byte, present bool, err error)
}

// DHTSource fetches a DomainRecord over a circuit (R4b).
type DHTSource interface {
	Fetch(ctx context.Context, zoneID [32]byte) (identity [32]byte, records []byte, err error)
}

// ChainSource is the slow path, never on the request path.
type ChainSource interface {
	// Authenticated reports whether a verified header chain is held. An RPC that
	// answers is not the same as a chain that verifies.
	Authenticated() bool
	Resolve(ctx context.Context, nameHash [32]byte) (identity [32]byte, records []byte, err error)
}

// RevocationSource reports revoked identities.
type RevocationSource interface{ Revoked(identity [32]byte) bool }

// Resolver runs the pipeline.
type Resolver struct {
	Snapshots  SnapshotSource
	DHT        DHTSource
	Chain      ChainSource
	Revocation RevocationSource
	Now        func() time.Time
	Freshness  time.Duration

	mu    sync.Mutex
	cache map[[32]byte]*Answer
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) bound() time.Duration {
	if r.Freshness > 0 && r.Freshness < MaxFreshness {
		return r.Freshness
	}
	return MaxFreshness
}

// Resolve answers a name.
//
// Order is cache, DHT, snapshot, then the chain as a SLOW PATH ONLY. The chain
// is last because R7 requires resolution to work with no RPC reachable; a
// pipeline that tried the chain first would be merely slow when it worked and
// broken when it did not.
func (r *Resolver) Resolve(ctx context.Context, n name.Name) (*Answer, error) {
	zone := n.ZoneID()
	now := r.now()

	// 1. Cache. Revocation is re-checked on the way OUT, so a key revoked after
	//    caching cannot be served from it (T10.3).
	if a := r.cached(zone, now); a != nil {
		if r.Revocation != nil && r.Revocation.Revoked(a.DomainIdentity) {
			r.purge(zone)
		} else {
			return a, nil
		}
	}

	snap, haveSnap := r.snapshot()

	// 2. DHT, over a circuit.
	if r.DHT != nil {
		if id, rec, err := r.DHT.Fetch(ctx, zone); err == nil {
			// A DHT record is self-authenticating under its DomainIdentity, but
			// the IDENTITY still has to come from somewhere trusted -- so mode
			// and staleness follow the snapshot that vouches for it, never the
			// record's own freshness.
			m, asOf := ModeDelegated, time.Time{}
			if haveSnap {
				m, asOf = snap.Mode(), r.asOf(snap)
			}
			a, err := r.finish(n, id, rec, m, asOf, now, 0)
			if err != nil {
				return nil, err
			}
			r.store(zone, a)
			return a, nil
		}
	}

	// 3. Local verified snapshot -- the path that must work with the chain
	//    unreachable (T10.1, E10.1).
	if haveSnap {
		asOf := r.asOf(snap)
		if !asOf.IsZero() {
			if age := now.Sub(asOf); age > r.bound() {
				return nil, fmt.Errorf("%w: %s > %s", ErrTooStale,
					age.Truncate(time.Second), r.bound())
			}
		}
		id, rec, present, err := r.Snapshots.Prove(zone)
		if err != nil {
			return nil, err
		}
		if !present {
			// T10.5: an authenticated PROOF OF ABSENCE, not a missing record.
			// T10.4: and it may be wrong if the name is newer than the evidence,
			// which the flag says out loud rather than implying certainty.
			return &Answer{
				Name: n, Mode: snap.Mode(), AsOf: asOf, now: now,
				FreshnessBound: r.bound(),
				Flags:          FlagNegative | FlagPendingPossible,
			}, nil
		}
		a, err := r.finish(n, id, rec, snap.Mode(), asOf, now, 0)
		if err != nil {
			return nil, err
		}
		r.store(zone, a)
		return a, nil
	}

	// 4. Slow path, only when nothing local could answer.
	if r.Chain != nil {
		if !r.Chain.Authenticated() {
			return nil, ErrNotAuthenticated // T10.2
		}
		if !n.IsRegistrable() {
			return nil, ErrNotRegistrable
		}
		nh, err := n.NameHash()
		if err != nil {
			return nil, err
		}
		id, rec, err := r.Chain.Resolve(ctx, nh)
		if err != nil {
			return nil, err
		}
		a, err := r.finish(n, id, rec, ModeFull, now, now, 0)
		if err != nil {
			return nil, err
		}
		r.store(zone, a)
		return a, nil
	}

	return nil, ErrNoSource
}

func (r *Resolver) finish(n name.Name, id [32]byte, rec []byte, m Mode,
	asOf, now time.Time, extra Flags) (*Answer, error) {
	if r.Revocation != nil && r.Revocation.Revoked(id) {
		return nil, fmt.Errorf("%w: %x", ErrRevoked, id[:4])
	}
	return &Answer{
		Name: n, DomainIdentity: id, Records: rec, Mode: m,
		AsOf: asOf, now: now, FreshnessBound: r.bound(), Flags: extra,
	}, nil
}

func (r *Resolver) snapshot() (Snapshot, bool) {
	if r.Snapshots == nil {
		return Snapshot{}, false
	}
	return r.Snapshots.Current()
}

// asOf is when the snapshot's evidence was known good.
//
// For WARM that is when this client verified it. For COLD there is no such
// moment at all -- which is exactly why the two modes are reported separately
// and why a COLD answer's staleness is -1 rather than a comforting number.
func (r *Resolver) asOf(s Snapshot) time.Time { return s.VerifiedAt }

func (r *Resolver) cached(zone [32]byte, now time.Time) *Answer {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.cache[zone]
	if !ok {
		return nil
	}
	if !a.AsOf.IsZero() && now.Sub(a.AsOf) > r.bound() {
		delete(r.cache, zone)
		return nil
	}
	c := *a
	c.now = now
	return &c
}

func (r *Resolver) store(zone [32]byte, a *Answer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = map[[32]byte]*Answer{}
	}
	c := *a
	r.cache[zone] = &c
}

// purge drops every cached artefact for a zone. T10.3 requires a revoked
// identity to leave nothing behind, not merely that the next lookup misses.
func (r *Resolver) purge(zone [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, zone)
}

// CacheLen is the number of cached answers.
func (r *Resolver) CacheLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}
