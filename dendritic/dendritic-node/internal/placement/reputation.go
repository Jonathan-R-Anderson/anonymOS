package placement

import "sort"

// G11 — reputation-aware host selection (§95).
//
// R-92.2 IS THE ENTIRE CONSTRAINT: reputation may REORDER the diversity-
// admissible set and may never WIDEN it. Every guarantee this package makes is a
// property of the domain gate in Plan, and a host that shares a failure domain
// with an existing holder is inadmissible at ANY reputation. There is no score
// that buys past it.
//
// So reputation enters at exactly one point -- the ORDER candidates are tried in
// -- and the gate that follows is untouched. This is not a stylistic choice.
// The obvious implementation, scoring candidates and taking the top n, silently
// becomes "a well-regarded datacentre gets all nine shards", which is the exact
// failure this package was written to fix.
//
// REPUTATION IS NEVER AN ADMISSION TEST. Not a floor, not a threshold, not a
// minimum. Two reasons, and the second is the one that bites:
//
//   - It cannot narrow either. A floor makes dispersal FAIL on a network where
//     nobody has a history yet -- the R-87.1 shape again, arriving at the
//     storage layer: strictness that reads as "the network stores nothing and
//     nobody can tell why".
//   - It would starve new hosts permanently. A host with no history can never
//     earn one if it is never selected, so the ranking would freeze the current
//     membership in place and no operator could ever join. A reputation system
//     that cannot onboard is a cartel with extra steps.
//
// UNKNOWN IS THE NEUTRAL PRIOR, NOT LAST. Sorting unknown hosts to the back is
// the same starvation by a quieter route. G5's Laplace prior is reused for the
// same reason it exists there: no history is not a bad history.
//
// The scores are LOCAL (R-88.1). This node's reducer over attestations it has
// chosen to believe -- never a network-wide figure, because there is no
// measurement authority (R14) and a global host score would be one.

// NeutralReputation is what a host with no observed history is worth.
//
// 0.5, matching G5's Laplace prior: it sits between the best and worst observed
// hosts, so a new operator is tried ahead of hosts that have actually failed and
// behind hosts that have actually delivered. Any other value is a policy about
// newcomers disguised as a default.
const NeutralReputation = 0.5

// HostScore is this node's LOCAL opinion of one host.
type HostScore struct {
	// Reputation in [0,1], from this node's own reducer over attestations it
	// believes. Ignored unless Observed.
	Reputation float64
	// Observed distinguishes "scored 0" from "never seen". They are different
	// facts and collapsing them is how a new host becomes indistinguishable
	// from one that has failed every retrieval.
	Observed bool
}

// Value is the score used for ordering, with the neutral prior applied.
func (h HostScore) Value() float64 {
	if !h.Observed {
		return NeutralReputation
	}
	if h.Reputation < 0 {
		return 0
	}
	if h.Reputation > 1 {
		return 1
	}
	return h.Reputation
}

// ScoreFunc is how a caller supplies local reputation. A nil ScoreFunc, or one
// returning an unobserved score, means every host ranks at the neutral prior and
// the ordering falls back to Plan's -- which is the state a fresh node is in.
type ScoreFunc func(peerID string) HostScore

// RankByReputation orders candidates by local reputation, then by free space.
//
// IT RETURNS THE SAME SET IT WAS GIVEN. Not a filtered one, not a truncated one
// -- a permutation, and RankIsPermutation asserts it. Any candidate this drops
// is a candidate the domain gate never gets to consider, which is how a ranking
// function quietly turns into an admission test.
//
// Reputation is the PRIMARY key and free space the secondary, so a host with
// room is preferred among equals rather than instead of them. Scores are bucketed
// to one decimal place first: raw float comparison would make a 0.71 host
// strictly beat a 0.70 one, which is a precision the underlying attestation
// counts do not have, and it would make the order thrash on noise. Within a
// bucket the existing emptiest-first rule decides, which is the behaviour a node
// with no reputation data at all keeps.
func RankByReputation(candidates []Candidate, score ScoreFunc) []Candidate {
	out := append([]Candidate(nil), candidates...)
	if score == nil {
		return out
	}
	bucket := make(map[string]int, len(out))
	for _, c := range out {
		bucket[c.PeerID] = int(score(c.PeerID).Value()*10 + 0.5)
	}
	sort.SliceStable(out, func(i, j int) bool {
		bi, bj := bucket[out[i].PeerID], bucket[out[j].PeerID]
		if bi != bj {
			return bi > bj
		}
		if out[i].FreeBytes != out[j].FreeBytes {
			return out[i].FreeBytes > out[j].FreeBytes
		}
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

// PlanWithReputation is Plan, with candidates tried in reputation order.
//
// THE DIVERSITY GATE IS planOrdered's, UNCHANGED. This function does not
// reimplement it, weaken it, or add an exception for well-regarded hosts -- it
// reorders the slice and hands it to the same gate Plan uses. That is what makes
// R-92.2 checkable rather than aspirational: there is no second copy of the
// constraint to drift.
//
// It calls planOrdered and NOT Plan. Plan applies its own emptiest-first sort,
// which silently overrides any order the caller supplies whenever FreeBytes
// differs -- the first version of this function did exactly that and was a
// no-op, while still passing every test that compared SETS of selected hosts.
// R-92.2's "reputation may reorder" is only checkable if the reordering
// survives to the gate.
func PlanWithReputation(shards []Shard, candidates []Candidate, wantHolders int, score ScoreFunc) []Assignment {
	return planOrdered(shards, RankByReputation(candidates, score), wantHolders)
}

// RankIsPermutation reports whether ranked contains exactly the same peers as
// original.
//
// It is exported because it is the property, not an implementation detail: a
// caller that builds its own ordering can assert the same thing. R-92.2's
// "never widen" fails in both directions -- a ranking that ADDS a peer smuggles
// in a host the caller never offered, and one that DROPS a peer has become an
// admission test.
func RankIsPermutation(original, ranked []Candidate) bool {
	if len(original) != len(ranked) {
		return false
	}
	count := make(map[string]int, len(original))
	for _, c := range original {
		count[c.PeerID]++
	}
	for _, c := range ranked {
		count[c.PeerID]--
		if count[c.PeerID] < 0 {
			return false
		}
	}
	return true
}
