// Package placement decides WHICH node each shard of a chunk goes to.
//
// THE PROBLEM THIS FIXES
// ----------------------
// Erasure coding buys nothing unless the shards it produces end up in different
// failure domains. The node split every 1 MiB chunk into 6 data + 3 parity
// shards and then wrote all nine to its own disk; the later "distribute" pass
// handed them out with `peers[shardNumber % len(peers)]`, which only yields nine
// distinct holders by accident when nine or more peers happen to be connected.
// With five peers, peers 0..3 each received two shards of every chunk, so a
// single node loss consumed two of the three parity shards and two losses
// destroyed the object. The arithmetic looked like 6+3 and behaved like 6+1.
//
// WHAT THIS PACKAGE GUARANTEES
// ----------------------------
// Plan never assigns two shards of the SAME chunk to the same peer, and never
// assigns a shard to a peer already known to hold a shard of that chunk. If
// there are fewer usable peers than unplaced shards it returns FEWER
// assignments rather than doubling up: an unplaced shard is a visible deficit
// the repair loop can retire later, whereas a doubled-up shard is a durability
// claim that is quietly false.
//
// It is deliberately pure — no libp2p, no store, no I/O — because the property
// that matters ("no two shards of a chunk share a host") is a property of the
// assignment, and it should be testable without standing up a network.
package placement

import "sort"

// Candidate is a peer that could take a shard. FreeBytes comes from the DHT
// capacity record when one is available and is zero for a peer we only know is
// connected; zero sorts last but is still usable, so a young network with no
// capacity records yet still disperses.
type Candidate struct {
	PeerID    string
	FreeBytes int64
	// Capacity is the total the peer says it will accept, from the same record.
	// Zero means the record is absent, NOT that the peer has no room -- levelling
	// needs the difference, because Capacity-FreeBytes is the only measured
	// occupancy figure a peer publishes about itself and "unknown" must never be
	// read as "empty". Plan itself ignores it.
	Capacity int64
	// Domains are this peer's failure domains as opaque keys -- /24 or /48,
	// ASN, and on-chain operator -- from peer.DomainKeys. Plan will not place
	// two shards of one chunk on peers that share ANY key (T12.2).
	//
	// THEY ARE OPAQUE STRINGS ON PURPOSE. This package is pure by design: no
	// libp2p, no store, no I/O, because "no two shards of a chunk share a
	// failure domain" is a property of the assignment and must be testable
	// without standing up a network. Taking a netip.Prefix or an ASN here would
	// drag an address library in and lose that.
	//
	// An UNKNOWN domain contributes NO KEY, so two peers whose ASN nobody could
	// determine share nothing and are treated as distinct. That is the same
	// conservative rule as peer.ASNUnknown, and inverting it -- rendering the
	// unknown as a key like "a:0" -- would silently collapse every unannotated
	// peer into one domain and refuse to disperse at all.
	//
	// Empty is legitimate and means "no domain constraint for this peer", which
	// is what every caller supplies until P3's annotations are wired through.
	// The guarantee then degrades to distinct-PEER, exactly as before, and
	// §1.4's finding is that this is where the storage layer has always been.
	Domains []string
}

// Shard is one erasure shard of one chunk, as the planner sees it.
type Shard struct {
	// ID is the content address (sha256 hex) of the shard bytes.
	ID string
	// Index is the shard's position in the Reed-Solomon set: 0..DataShards-1 are
	// data, the rest parity. Needed because reconstruction is index-sensitive.
	Index int
	// Size in bytes, used for the capacity filter.
	Size int64
	// Holders are peers already confirmed to hold this shard.
	Holders []string
}

// Assignment binds one shard to one peer.
type Assignment struct {
	ShardID    string
	ShardIndex int
	Peer       string
}

// Plan assigns unplaced shards of a single chunk to distinct peers.
//
// wantHolders is how many distinct remote holders each shard should have; in
// practice 1, because the redundancy comes from the erasure code, not from
// copying each shard. A shard already at wantHolders is skipped.
//
// Candidates are tried emptiest-first so writes spread toward the nodes with
// room instead of repeatedly filling whichever peer answered first.
func Plan(shards []Shard, candidates []Candidate, wantHolders int) []Assignment {
	ranked := append([]Candidate(nil), candidates...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].FreeBytes != ranked[j].FreeBytes {
			return ranked[i].FreeBytes > ranked[j].FreeBytes
		}
		// Deterministic tie-break so two nodes planning the same chunk from the
		// same inputs agree, and so tests are not flaky.
		return ranked[i].PeerID < ranked[j].PeerID
	})
	return planOrdered(shards, ranked, wantHolders)
}

// planOrdered is the placement gate. It tries candidates IN THE ORDER GIVEN and
// applies the domain constraint; it does not reorder them.
//
// The split exists so that every caller which wants a different preference order
// -- Plan's emptiest-first, G11's reputation ranking (§95) -- shares ONE copy of
// the constraint. The alternative, a caller that pre-sorts and then calls Plan,
// does not work and is worth recording: Plan's own sort silently overrides the
// caller's order whenever FreeBytes differs, so the ranking becomes a no-op that
// every set-based test still passes. R-92.2's "reputation may reorder" is only
// checkable if the reordering actually survives to the gate.
func planOrdered(shards []Shard, ranked []Candidate, wantHolders int) []Assignment {
	candidates := ranked
	if wantHolders < 1 {
		wantHolders = 1
	}
	// Every peer that already holds ANY shard of this chunk is excluded from
	// taking another one. This is the whole point of the package: co-location
	// inside one chunk is what turns three tolerable losses into one.
	occupied := make(map[string]bool)
	for _, shard := range shards {
		for _, holder := range shard.Holders {
			occupied[holder] = true
		}
	}

	// Failure domains already spoken for by an existing holder.
	//
	// Existing holders are looked up in the candidate list, because that is the
	// only place their annotations are: a Holder is a peer id and nothing more.
	// A holder that is not among the candidates contributes no domains, and the
	// resulting placement is then weaker than it looks -- so that case is worth
	// knowing about, and DomainsUnavailable reports it.
	byPeer := make(map[string][]string, len(candidates))
	for _, c := range candidates {
		byPeer[c.PeerID] = c.Domains
	}
	takenDomain := make(map[string]bool)
	for holder := range occupied {
		for _, k := range byPeer[holder] {
			takenDomain[k] = true
		}
	}

	// Shards furthest from the target are served first, so a chunk with one
	// unplaced shard and eight placed ones does not lose its last slot to a
	// shard that is already covered.
	order := make([]int, 0, len(shards))
	for i := range shards {
		if len(shards[i].Holders) < wantHolders {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		return len(shards[order[a]].Holders) < len(shards[order[b]].Holders)
	})

	var out []Assignment
	for _, index := range order {
		shard := shards[index]
		need := wantHolders - len(shard.Holders)
		for need > 0 {
			picked := ""
			pickedDomains := []string(nil)
			for _, candidate := range ranked {
				if occupied[candidate.PeerID] {
					continue
				}
				if candidate.FreeBytes > 0 && candidate.FreeBytes < shard.Size {
					continue
				}
				if sharesDomain(candidate.Domains, takenDomain) {
					continue
				}
				picked, pickedDomains = candidate.PeerID, candidate.Domains
				break
			}
			if picked == "" {
				// Out of distinct peers. Leave the shard unplaced rather than
				// stacking it on a peer that already holds a sibling.
				break
			}
			occupied[picked] = true
			for _, k := range pickedDomains {
				takenDomain[k] = true
			}
			out = append(out, Assignment{ShardID: shard.ID, ShardIndex: shard.Index, Peer: picked})
			need--
		}
	}
	return out
}

// sharesDomain reports whether any of this peer's domains is already taken.
//
// A peer with NO domain keys never shares one, so an unannotated candidate is
// always admissible. That is the deliberate direction: the constraint tightens
// as annotations arrive and never blocks dispersal because they have not.
func sharesDomain(domains []string, taken map[string]bool) bool {
	for _, k := range domains {
		if taken[k] {
			return true
		}
	}
	return false
}

// DomainsUnavailable counts candidates carrying no failure-domain keys.
//
// It is the storage layer's ConstraintReport, and it exists for §56.2's reason:
// a placement that satisfied distinct-domain because nobody had a domain is not
// a placement that survives a datacentre. A caller that logs only "9 shards
// placed" cannot tell that case from a real one.
func DomainsUnavailable(candidates []Candidate) int {
	n := 0
	for _, c := range candidates {
		if len(c.Domains) == 0 {
			n++
		}
	}
	return n
}

// DistinctHolders counts the peers holding at least one shard of the chunk.
// This is the number that actually bounds survivability: a chunk whose nine
// shards sit on three peers survives one loss, not three, however many shards
// were "placed".
func DistinctHolders(shards []Shard) int {
	seen := make(map[string]bool)
	for _, shard := range shards {
		for _, holder := range shard.Holders {
			seen[holder] = true
		}
	}
	return len(seen)
}

// WithoutCrowdedHolders returns the chunk as the planner should see it when
// some peer holds more than one of its shards: the SURPLUS placements -- the
// second and later shards one peer ended up with -- are shown as unplaced, so
// Plan gives those indexes a holder on a machine that holds nothing of the
// chunk.
//
// WHY THIS IS NEEDED AT ALL
// -------------------------
// Plan refuses to create co-location, but it cannot undo it, and rows written
// before that refusal existed (or by two placement rounds racing, or by two
// objects sharing a content-addressed shard) can arrive already crowded. Every
// shard has a holder, so an ordinary plan finds nothing to do: the object would
// sit in the queue forever, correctly counted as under-replicated and never
// getting any better. This is the one move that improves it.
//
// Nothing is forgotten. The crowded peer stays a holder in the ledger and keeps
// serving reads; what changes is that the index stops depending on it alone.
//
// A shard is only surplus against a DIFFERENT shard: a chunk of uniform bytes
// produces several indexes with the same content address, and a peer holding
// those bytes once holds all of them. Re-sending the same shard id to another
// peer would be paying for a copy that buys nothing.
func WithoutCrowdedHolders(shards []Shard) []Shard {
	out := make([]Shard, len(shards))
	credited := make(map[string]string, len(shards))
	for i, shard := range shards {
		out[i] = shard
		out[i].Holders = append([]string(nil), shard.Holders...)
		if len(shard.Holders) == 0 {
			continue
		}
		surplus := true
		for _, holder := range shard.Holders {
			if by, taken := credited[holder]; !taken || by == shard.ID {
				credited[holder] = shard.ID
				surplus = false
			}
		}
		if surplus {
			out[i].Holders = nil
		}
	}
	return out
}

// maxEnumeratedHolders / maxEnumeratedSubsets bound the exact survivability
// search. A chunk has dataShards+parityShards shards and one holder each, so
// the real numbers are nine and eighty-four; the caps only exist so a ledger
// row that somehow accumulated hundreds of holders cannot turn a queue scan
// into a combinatorial explosion.
const (
	maxEnumeratedHolders = 63
	maxEnumeratedSubsets = 50_000
)

// SurvivingIndexes reports how many distinct shard indexes would still be held
// off this node after the WORST `losses` holders vanished at the same moment.
//
// THIS IS THE NUMBER THE FEATURE EXISTS TO PROTECT, and it is not the number of
// placed indexes. An index survives exactly as long as one of ITS holders does,
// so nine indexes on one peer survive zero losses while nine indexes on nine
// peers survive three and still leave six -- which is a decode. Counting placed
// indexes cannot tell those two apart; counting holders per index can.
//
// It is exact while the search is small (nine shards means a handful of holders
// and at most a few thousand subsets) and deliberately PESSIMISTIC beyond that:
// the fallback assumes the largest holders share no index, which can only
// understate survivability. Understating costs a pass some extra work;
// overstating retires an object that is one disk away from gone.
func SurvivingIndexes(shards []Shard, losses int) int {
	covered := RemoteIndexCount(shards)
	if losses <= 0 || covered == 0 {
		return covered
	}

	// holderOf maps each still-covered index to the set of peers holding it.
	holderIndex := make(map[string]int)
	perIndex := make(map[int][]string)
	for _, shard := range shards {
		for _, holder := range shard.Holders {
			if _, known := holderIndex[holder]; !known {
				holderIndex[holder] = len(holderIndex)
			}
			perIndex[shard.Index] = append(perIndex[shard.Index], holder)
		}
	}
	if losses >= len(holderIndex) {
		// Every holder gone. Nothing is remotely available, whatever was placed.
		return 0
	}

	combinations := choose(len(holderIndex), losses)
	if len(holderIndex) > maxEnumeratedHolders || combinations > maxEnumeratedSubsets {
		return covered - worstCaseHolderLoad(shards, losses, covered)
	}

	// Each index becomes a bitmask of the holders that keep it alive; a set of
	// dead holders kills the index only when the mask is a subset of it.
	masks := make([]uint64, 0, len(perIndex))
	for _, holders := range perIndex {
		var mask uint64
		for _, holder := range holders {
			mask |= 1 << uint(holderIndex[holder])
		}
		masks = append(masks, mask)
	}
	worst := covered
	forEachSubset(len(holderIndex), losses, func(dead uint64) bool {
		alive := 0
		for _, mask := range masks {
			if mask&^dead != 0 {
				alive++
			}
		}
		if alive < worst {
			worst = alive
		}
		return worst > 0
	})
	return worst
}

// SurvivesHolderLosses reports whether the chunk is still rebuildable WITHOUT
// this node after `losses` of its holders drop out.
func SurvivesHolderLosses(shards []Shard, dataShards, losses int) bool {
	if dataShards < 1 {
		dataShards = 1
	}
	return SurvivingIndexes(shards, losses) >= dataShards
}

// worstCaseHolderLoad is the pessimistic fallback: the indexes carried by the
// `losses` busiest holders, as if none of those indexes were held anywhere else.
func worstCaseHolderLoad(shards []Shard, losses, covered int) int {
	load := make(map[string]map[int]bool)
	for _, shard := range shards {
		for _, holder := range shard.Holders {
			if load[holder] == nil {
				load[holder] = make(map[int]bool)
			}
			load[holder][shard.Index] = true
		}
	}
	counts := make([]int, 0, len(load))
	for _, indexes := range load {
		counts = append(counts, len(indexes))
	}
	sort.Sort(sort.Reverse(sort.IntSlice(counts)))
	lost := 0
	for i := 0; i < losses && i < len(counts); i++ {
		lost += counts[i]
	}
	if lost > covered {
		lost = covered
	}
	return lost
}

// forEachSubset calls visit with every bitmask of exactly `pick` of `total`
// holders, stopping early when visit returns false.
func forEachSubset(total, pick int, visit func(uint64) bool) {
	var walk func(start, remaining int, mask uint64) bool
	walk = func(start, remaining int, mask uint64) bool {
		if remaining == 0 {
			return visit(mask)
		}
		for i := start; i <= total-remaining; i++ {
			if !walk(i+1, remaining-1, mask|1<<uint(i)) {
				return false
			}
		}
		return true
	}
	walk(0, pick, 0)
}

// choose is n-choose-k, saturating rather than overflowing: the caller only
// wants to know whether the search is small enough to run.
func choose(n, k int) int {
	if k < 0 || k > n {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	result := 1
	for i := 1; i <= k; i++ {
		result = result * (n - k + i) / i
		if result > maxEnumeratedSubsets {
			return maxEnumeratedSubsets + 1
		}
	}
	return result
}

// RemotelyRecoverable reports whether the shards held off this node are enough
// to rebuild the chunk WITHOUT the local copies — the only definition of
// redundancy that survives losing this node.
//
// It counts distinct shard INDEXES, not holders and not shards: Reed-Solomon
// needs dataShards distinct positions, and two copies of index 4 rebuild
// nothing that one copy does not.
func RemotelyRecoverable(shards []Shard, dataShards int) bool {
	return RemoteIndexCount(shards) >= dataShards
}

// RemoteIndexCount is the number of distinct shard indexes held by at least one
// remote peer.
func RemoteIndexCount(shards []Shard) int {
	seen := make(map[int]bool)
	for _, shard := range shards {
		if len(shard.Holders) > 0 {
			seen[shard.Index] = true
		}
	}
	return len(seen)
}
