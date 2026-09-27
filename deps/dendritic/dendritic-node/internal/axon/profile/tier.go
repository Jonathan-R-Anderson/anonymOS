package profile

import (
	"sort"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// snapshot is one consistent decayed view of every peer plus the tier
// assignment derived from it.
//
// Tiering is a POPULATION operation, not a per-peer one — "top 10 %" has no
// meaning for a peer in isolation — so it is computed here in one pass and
// never cached. Caching it would reintroduce exactly the staleness T12a.5
// forbids: the cache would hold a tier computed at some earlier instant, and
// decay-on-read would then be decay-on-read-of-a-frozen-number.
type snapshot struct {
	byID map[string]Profile
}

// View is one decayed, tiered snapshot of the whole store, taken at an instant.
//
// It exists for a performance reason with a correctness consequence. Tiering is
// a population operation, so every single-peer Tier() call recomputes the whole
// store — and a path selector asks about every candidate at every hop, which
// makes selection quadratic in the population. A caller that needs many answers
// about one instant takes one View and asks it.
//
// A View MUST NOT BE STORED. It is decayed as of the moment it was taken, and
// holding one across time is precisely the frozen tier T12a.5 forbids. The
// type carries no method to refresh itself, so the only way to get a current
// answer is to take a new one.
type View struct {
	at   time.Time
	byID map[string]Profile
}

// View takes a snapshot at the current time.
func (p *Profiles) View() View {
	now := p.now()
	return View{at: now, byID: p.snapshot(now).byID}
}

// At is when the view was taken, so a caller can assert it is using a fresh one.
func (v View) At() time.Time { return v.at }

// Get returns one peer's decayed profile from the view.
func (v View) Get(nodeID string) (Profile, bool) {
	pr, ok := v.byID[nodeID]
	return pr, ok
}

// Tier is the peer's tier as of the view.
func (v View) Tier(nodeID string) Tier {
	pr, ok := v.byID[nodeID]
	if !ok {
		return TierUntiered
	}
	return pr.Tier
}

// Weight is the peer's selection weight as of the view. It is the same function
// as Profiles.Weight and shares its meaning; see there.
func (v View) Weight(nodeID string) float64 { return weightForTier(v.Tier(nodeID)) }

func (p *Profiles) snapshot(now time.Time) snapshot {
	p.mu.RLock()
	profs := make([]Profile, 0, len(p.m))
	total := 0.0
	for _, e := range p.m {
		pr := Profile{
			NodeID:        e.nodeID,
			LastSeen:      e.lastSeen,
			FailureStreak: e.failureStreak,
			FailingSince:  e.failingSince,
			Tier:          TierUntiered,
		}
		pr.Speed, _ = e.speed.mean(now)
		pr.Capacity, _ = e.capacity.mean(now)
		pr.Reliability, _ = e.reliability.mean(now)
		if s := e.samples.decayTo(now); s.weight > 0 {
			pr.Samples = s.weight
		}
		total += pr.Samples
		profs = append(profs, pr)
	}
	p.mu.RUnlock()

	// Deterministic order first, so every percentile boundary and every tie is
	// resolved the same way on every call.
	sort.Slice(profs, func(i, j int) bool { return profs[i].NodeID < profs[j].NodeID })

	assignTiers(profs, total, now)

	byID := make(map[string]Profile, len(profs))
	for _, pr := range profs {
		byID[pr.NodeID] = pr
	}
	return snapshot{byID: byID}
}

// assignTiers implements P12a's four tiers over one decayed population.
//
// The order is deliberate and each step depends on the one before it:
//
//	FAILING          consecutive failures, absolute, checked first so that a
//	                 peer that is refusing everything cannot be "fast"
//	(gate)           the whole store below ProfileMinSamples -> everyone stays
//	                 untiered, which is E12a.3
//	HIGH CAPACITY    top 25 % by accepted-build ratio among peers with enough
//	                 samples
//	FAST             top 10 % by speed AMONG HIGH CAPACITY -- I2P's nesting.
//	                 Speed alone would promote a peer that answers one probe
//	                 quickly and refuses every build.
func assignTiers(profs []Profile, totalSamples float64, now time.Time) {
	// FAILING, and re-admission.
	//
	// Exclusion is temporary on purpose. An adversary who can cause three
	// failures -- by, say, being the middle hop that drops them -- would
	// otherwise remove a peer from this node's view permanently, which is a
	// cheap way to shrink somebody's candidate set one relay at a time.
	eligible := make([]int, 0, len(profs))
	for i := range profs {
		pr := &profs[i]
		failing := pr.FailureStreak >= params.ProfileFailingStreak &&
			!pr.FailingSince.IsZero() &&
			now.Sub(pr.FailingSince) < params.ProfileRepromoteInterval
		if failing {
			pr.Tier = TierFailing
			continue
		}
		if pr.Samples >= params.ProfileMinSamples {
			eligible = append(eligible, i)
		}
	}

	// The store-wide gate. A node that has barely observed anything must not
	// act on the little it has, even if one peer happens to clear the per-peer
	// floor -- with two peers observed, "top 25 %" is a statement about a
	// population of two.
	if totalSamples < params.ProfileMinSamples || len(eligible) == 0 {
		return
	}

	for _, i := range eligible {
		profs[i].Tier = TierStandard
	}

	// HIGH CAPACITY: top 25 % by accepted-build ratio.
	byCapacity := append([]int(nil), eligible...)
	sort.SliceStable(byCapacity, func(a, b int) bool {
		x, y := profs[byCapacity[a]], profs[byCapacity[b]]
		if x.Capacity != y.Capacity {
			return x.Capacity > y.Capacity
		}
		return x.NodeID < y.NodeID // ties broken deterministically, never by map order
	})
	hc := byCapacity[:topN(len(byCapacity), params.TierHighCapacityFraction)]
	for _, i := range hc {
		profs[i].Tier = TierHighCapacity
	}

	// FAST: top 10 % by speed among the high-capacity set.
	bySpeed := append([]int(nil), hc...)
	sort.SliceStable(bySpeed, func(a, b int) bool {
		x, y := profs[bySpeed[a]], profs[bySpeed[b]]
		if x.Speed != y.Speed {
			return x.Speed > y.Speed // Speed is 1/RTT, so higher is faster
		}
		return x.NodeID < y.NodeID
	})
	for _, i := range bySpeed[:topN(len(bySpeed), params.TierFastFraction)] {
		profs[i].Tier = TierFast
	}
}

// topN is how many peers a fraction admits, rounded UP and floored at one.
//
// Rounding up matters on a small network, which is the network this actually
// runs on: 10 % of 9 peers rounds down to zero, and a tier that is empty
// whenever the network is small is a tier that never exists here. The floor of
// one is bounded above by the same fraction as the population grows, so it does
// not distort a large network.
func topN(n int, fraction float64) int {
	if n <= 0 {
		return 0
	}
	k := int(float64(n)*fraction + 0.999999)
	if k < 1 {
		k = 1
	}
	if k > n {
		k = n
	}
	return k
}
