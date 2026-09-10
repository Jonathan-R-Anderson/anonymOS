package path

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"sort"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
	"github.com/syndichan/maniwani/storage-client/internal/axon/profile"
)

// Selector draws paths from a candidate set.
//
// The candidate source is a function rather than a stored slice so that the
// pool is re-read on every selection. A cached pool would freeze a view, and a
// frozen view is a partition this node performed on itself.
type Selector struct {
	// Candidates returns the currently known relays.
	Candidates func() []Relay
	// Rand returns a uniform float in [0,1). Nil means crypto/rand.
	//
	// It is injectable ONLY so that E12.3 can drive the sampler with a
	// reproducible stream and compare the resulting distribution against an
	// exact model. Production has no seed to reuse: T12.6 requires that two
	// selections from one view differ.
	Rand func() float64
}

func (s *Selector) rnd() float64 {
	if s.Rand != nil {
		return s.Rand()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not a condition to degrade gracefully through.
		// A path drawn from a broken entropy source is worse than no path.
		panic("axon/path: crypto/rand unavailable: " + err.Error())
	}
	// 53 bits, the exact-integer range of a float64.
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(1<<53)
}

// SelectPath draws n relays satisfying the constraint, weighted by the policy.
//
// It differs from §23's stated signature by returning a PathReport as well.
// That is deliberate: the stated signature can only say "here is a path" or
// "there is no path", and the interesting outcomes are in between — a path that
// met its constraints on a pool of 12 relays in 4 /24s is a different object
// from the same path on a pool of 600, and a caller that cannot tell them apart
// will treat them the same.
func (s *Selector) SelectPath(ctx context.Context, n int, c DiversityConstraint, pol WeightPolicy) ([]Relay, PathReport, error) {
	rep := PathReport{Requested: n}
	if n <= 0 || n > params.MaxHops {
		return nil, rep, ErrBadRequest
	}
	if pol.UseProfile && pol.Profiles == nil {
		return nil, rep, ErrNoProfiles
	}
	if err := ctx.Err(); err != nil {
		return nil, rep, err
	}

	// One view per selection. See weightOf.
	var view profile.View
	if pol.UseProfile {
		view = pol.Profiles.View()
	}

	cands := s.admissible(c, pol, view)
	sortRelays(cands)
	rep.Candidates = len(cands)
	rep.DistinctPrefixes, rep.DistinctASNs, rep.ASNUnavailable,
		rep.DistinctOperators, rep.OperatorUnavailable = poolStats(cands)
	rep.PartitionWarning, rep.PartitionReason = detectPartition(cands, rep.DistinctPrefixes)

	// The claim scale is the pool's median effective capacity. A median rather
	// than a mean because one relay claiming an absurd figure would otherwise
	// drag the scale up and push every honest relay toward the floor -- which
	// is the same lie having an effect by a different route.
	claimScale := 0.0
	if pol.UseClaims {
		claimScale = medianClaim(cands)
	}

	path, src, failedAt, ok := s.draw(ctx, n, cands, c, pol, view, claimScale)
	if !ok && pol.AllowRelaxation {
		// Relaxation drops DomainASN and keeps DomainPrefix.
		//
		// The order is derived, not preferred. A /24 sits inside an AS, so two
		// relays sharing a /24 almost always share an AS: dropping the prefix
		// constraint while keeping ASN changes nearly nothing, and dropping ASN
		// while keeping prefix is the only relaxation that actually widens the
		// admissible set. There is exactly one meaningful step here, which is
		// why there is no relaxation ladder.
		relaxed := DiversityConstraint{Exclude: c.Exclude}
		dropped := false
		for _, d := range c.Domains {
			if d == peer.DomainASN {
				dropped = true
				continue
			}
			relaxed.Domains = append(relaxed.Domains, d)
		}
		if dropped {
			if p2, src2, _, ok2 := s.draw(ctx, n, cands, relaxed, pol, view, claimScale); ok2 {
				// The recorded hop is where the FULL constraint set ran out,
				// not where the relaxed draw happened to place a relay. That is
				// the actionable number: it says how far into the path the pool
				// stopped offering alternatives.
				rep.Relaxations = append(rep.Relaxations,
					Relaxation{Hop: failedAt, Dropped: peer.DomainASN})
				path, src, ok = p2, src2, ok2
			}
		}
	}
	rep.Source = src
	if !ok {
		rep.Returned = 0
		return nil, rep, ErrNoPath
	}
	rep.Returned = len(path)
	return path, rep, nil
}

// admissible filters the pool down to relays that may appear at all.
//
// Failing-tier relays are removed HERE rather than given a zero weight. A zero
// weight is an exclusion the report cannot see: rep.Candidates would count a
// relay that could never be drawn, and the pool would look healthier than it is.
func (s *Selector) admissible(c DiversityConstraint, pol WeightPolicy, view profile.View) []Relay {
	if s.Candidates == nil {
		return nil
	}
	all := s.Candidates()
	out := make([]Relay, 0, len(all))
	for _, r := range all {
		if r.NodeID == "" || !r.Ann.Addr.IsValid() {
			continue
		}
		if c.Exclude[r.NodeID] {
			continue
		}
		if pol.UseProfile && view.Tier(r.NodeID) == profile.TierFailing {
			continue
		}
		out = append(out, r)
	}
	return out
}

// draw builds one path, hop by hop, re-filtering after every choice.
//
// Rule 1 lives in this loop: the admissible set is computed from the diversity
// constraint FIRST, and weights are consulted only to choose within it. There
// is no code path by which a weight reaches a relay the constraint excluded.
// It returns the hop at which it gave up, so the caller can report WHERE the
// pool ran out rather than merely that it did.
func (s *Selector) draw(ctx context.Context, n int, cands []Relay, c DiversityConstraint, pol WeightPolicy, view profile.View, claimScale float64) (chosen []Relay, src WeightSource, failedAt int, ok bool) {
	chosen = make([]Relay, 0, n)
	src = SourceUniform
	for hop := 0; hop < n; hop++ {
		if ctx.Err() != nil {
			return nil, src, hop, false
		}
		pool := make([]Relay, 0, len(cands))
		weights := make([]float64, 0, len(cands))
		total := 0.0
		for _, cand := range cands {
			if used(chosen, cand.NodeID) || conflicts(cand, chosen, c) {
				continue
			}
			w, ws := weightOf(cand, pol, view, claimScale)
			if w <= 0 || math.IsNaN(w) {
				continue
			}
			// The reported source is the strongest evidence used anywhere in
			// the path. A path weighted by profiles for two hops and uniformly
			// for the third was not a uniform draw and must not report as one.
			if ws > src {
				src = ws
			}
			pool = append(pool, cand)
			weights = append(weights, w)
			total += w
		}
		if len(pool) == 0 {
			return nil, src, hop, false
		}
		chosen = append(chosen, pool[pick(weights, total, s.rnd())])
	}
	return chosen, src, n, true
}

// pick is weighted reservoir-free selection: one uniform draw, one scan.
func pick(weights []float64, total, u float64) int {
	target := u * total
	acc := 0.0
	for i, w := range weights {
		acc += w
		if target < acc {
			return i
		}
	}
	// Floating-point accumulation can leave target just past the end.
	return len(weights) - 1
}

func used(chosen []Relay, id string) bool {
	for _, r := range chosen {
		if r.NodeID == id {
			return true
		}
	}
	return false
}

// conflicts is the diversity predicate: does this relay share a constrained
// domain with any already-chosen hop.
func conflicts(cand Relay, chosen []Relay, c DiversityConstraint) bool {
	for _, prev := range chosen {
		for _, d := range c.Domains {
			if samePathDomain(cand.Ann, prev.Ann, d, c.UnknownOperators) {
				return true
			}
		}
	}
	return false
}

// medianClaim is the pool's median effective (bond-capped) capacity.
func medianClaim(cands []Relay) float64 {
	vals := make([]float64, 0, len(cands))
	for _, c := range cands {
		if v := c.Weight.Value(); v > 0 {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	return vals[len(vals)/2]
}
