package placement

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func cand(id string, free int64, domains ...string) Candidate {
	return Candidate{PeerID: id, FreeBytes: free, Domains: domains}
}

func chunk(n int) []Shard {
	s := make([]Shard, n)
	for i := range s {
		s[i] = Shard{ID: fmt.Sprintf("shard%d", i), Index: i, Size: 1}
	}
	return s
}

func peersIn(as []Assignment) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Peer)
	}
	sort.Strings(out)
	return out
}

// TestReputationNeverWidensTheAdmissibleSet is R-92.2, the whole point of G11.
//
// A well-regarded host that shares a failure domain with an existing holder is
// INADMISSIBLE, at any reputation. There is no score that buys past the gate.
func TestReputationNeverWidensTheAdmissibleSet(t *testing.T) {
	// Three hosts, two of them in one datacentre. The one with the perfect
	// record is a co-tenant.
	cands := []Candidate{
		cand("star", 1000, "o:acme"), // maximum reputation, shares with "twin"
		cand("twin", 1000, "o:acme"), //
		cand("lone", 10, "o:other"),  // no reputation at all, distinct domain
	}
	score := func(id string) HostScore {
		switch id {
		case "star":
			return HostScore{Reputation: 1.0, Observed: true}
		case "twin":
			return HostScore{Reputation: 0.9, Observed: true}
		}
		return HostScore{} // "lone" is unknown
	}

	got := PlanWithReputation(chunk(3), cands, 1, score)
	seen := map[string]bool{}
	domains := map[string]bool{}
	for _, a := range got {
		if seen[a.Peer] {
			t.Fatalf("%s took two shards of one chunk", a.Peer)
		}
		seen[a.Peer] = true
		for _, c := range cands {
			if c.PeerID != a.Peer {
				continue
			}
			for _, d := range c.Domains {
				if domains[d] {
					t.Fatalf("R-92.2 violated: reputation admitted %s into failure "+
						"domain %s, which was already taken; a score bought past the gate",
						a.Peer, d)
				}
				domains[d] = true
			}
		}
	}
	// The reputable co-tenant does NOT get a second slot; the unknown host in a
	// distinct domain does.
	if len(got) != 2 {
		t.Fatalf("placed %d shards across 2 distinct domains, want 2", len(got))
	}
	if !seen["lone"] {
		t.Fatal("the only diversity-admissible host was passed over because it had " +
			"no reputation; reputation acted as an admission test")
	}
}

// TestReputationOnlyReorders compares the SETS, not the orders.
//
// For any reputation assignment, the peers that can be selected are exactly the
// peers selectable without reputation. If this ever differs, reputation has
// stopped being an ordering.
func TestReputationOnlyReorders(t *testing.T) {
	cands := []Candidate{
		cand("a", 500, "p:198.51.100.0/24"),
		cand("b", 400, "p:203.0.113.0/24"),
		cand("c", 300, "p:192.0.2.0/24"),
		cand("d", 200, "p:198.18.0.0/24"),
	}
	base := peersIn(Plan(chunk(4), cands, 1))

	// Every assignment of reputations, including inverted and degenerate ones.
	for _, sc := range []ScoreFunc{
		nil,
		func(string) HostScore { return HostScore{} },
		func(string) HostScore { return HostScore{Reputation: 1, Observed: true} },
		func(id string) HostScore { return HostScore{Reputation: float64(id[0]-'a') / 3, Observed: true} },
		func(id string) HostScore { return HostScore{Reputation: 1 - float64(id[0]-'a')/3, Observed: true} },
		func(id string) HostScore {
			if id == "d" {
				return HostScore{Reputation: 1, Observed: true}
			}
			return HostScore{Reputation: 0, Observed: true}
		},
	} {
		got := peersIn(PlanWithReputation(chunk(4), cands, 1, sc))
		if len(got) != len(base) {
			t.Fatalf("reputation changed how many hosts were selected: %d vs %d",
				len(got), len(base))
		}
		for i := range got {
			if got[i] != base[i] {
				t.Fatalf("reputation changed WHICH hosts were selectable: %v vs %v",
					got, base)
			}
		}
	}
}

// TestReputationDoesReorder guards against the opposite failure: a "safe"
// implementation that ignores reputation entirely and passes every other test.
func TestReputationDoesReorder(t *testing.T) {
	cands := []Candidate{
		cand("a", 900, "p:198.51.100.0/24"),
		cand("b", 800, "p:203.0.113.0/24"),
		cand("c", 700, "p:192.0.2.0/24"),
	}
	// Only one shard, so exactly one host is chosen: the ranking decides which.
	byFreeSpace := Plan([]Shard{{ID: "s", Index: 0, Size: 1}}, cands, 1)
	if len(byFreeSpace) != 1 || byFreeSpace[0].Peer != "a" {
		t.Fatalf("baseline picked %v, expected the emptiest host", byFreeSpace)
	}
	score := func(id string) HostScore {
		if id == "c" {
			return HostScore{Reputation: 1, Observed: true}
		}
		return HostScore{Reputation: 0, Observed: true}
	}
	got := PlanWithReputation([]Shard{{ID: "s", Index: 0, Size: 1}}, cands, 1, score)
	if len(got) != 1 || got[0].Peer != "c" {
		t.Fatalf("reputation had no effect on selection: picked %v, wanted the "+
			"best-regarded host", got)
	}
}

// TestNewHostsAreNotStarved is the onboarding property.
//
// A host with no history can never earn one if it is never selected. A ranking
// that sorts unknown hosts last freezes the current membership in place, and a
// reputation system that cannot onboard is a cartel with extra steps.
func TestNewHostsAreNotStarved(t *testing.T) {
	if NeutralReputation <= 0 {
		t.Fatal("an unobserved host ranks at the bottom; no new operator can ever " +
			"be selected, so none can ever earn a history")
	}
	fresh := HostScore{}
	failing := HostScore{Reputation: 0.1, Observed: true}
	proven := HostScore{Reputation: 0.95, Observed: true}
	if fresh.Value() <= failing.Value() {
		t.Fatalf("a host with no history (%v) ranks at or below one that has actually "+
			"failed (%v); no history is not a bad history", fresh.Value(), failing.Value())
	}
	if fresh.Value() >= proven.Value() {
		t.Fatalf("a host with no history (%v) ranks at or above one that has actually "+
			"delivered (%v)", fresh.Value(), proven.Value())
	}

	// End to end: a brand-new host still wins a slot against a mediocre one.
	cands := []Candidate{
		cand("incumbent", 1000, "p:198.51.100.0/24"),
		cand("newcomer", 1000, "p:203.0.113.0/24"),
	}
	score := func(id string) HostScore {
		if id == "incumbent" {
			return HostScore{Reputation: 0.2, Observed: true}
		}
		return HostScore{} // never seen
	}
	got := PlanWithReputation([]Shard{{ID: "s", Index: 0, Size: 1}}, cands, 1, score)
	if len(got) != 1 || got[0].Peer != "newcomer" {
		t.Fatalf("a new host lost to a host with a demonstrably poor record: %v", got)
	}
}

// TestRankIsAlwaysAPermutation is R-92.2 at the ranking layer.
func TestRankIsAlwaysAPermutation(t *testing.T) {
	var cands []Candidate
	for i := 0; i < 40; i++ {
		cands = append(cands, cand(fmt.Sprintf("n%02d", i), int64(i*100),
			fmt.Sprintf("p:10.%d.0.0/24", i)))
	}
	for _, sc := range []ScoreFunc{
		nil,
		func(string) HostScore { return HostScore{} },
		func(id string) HostScore { return HostScore{Reputation: float64(len(id)%7) / 6, Observed: true} },
		// Degenerate scores that a naive comparator would mishandle.
		func(string) HostScore { return HostScore{Reputation: -5, Observed: true} },
		func(string) HostScore { return HostScore{Reputation: 1e9, Observed: true} },
	} {
		ranked := RankByReputation(cands, sc)
		if !RankIsPermutation(cands, ranked) {
			t.Fatalf("ranking is not a permutation: %d in, %d out; a ranking that "+
				"drops a peer has become an admission test",
				len(cands), len(ranked))
		}
	}
	// Out-of-range scores must clamp rather than produce an inconsistent
	// comparator, which would make sort panic or silently corrupt the slice.
	if v := (HostScore{Reputation: -5, Observed: true}).Value(); v != 0 {
		t.Fatalf("a negative reputation produced %v, not a clamped 0", v)
	}
	if v := (HostScore{Reputation: 1e9, Observed: true}).Value(); v != 1 {
		t.Fatalf("an out-of-range reputation produced %v, not a clamped 1", v)
	}
}

// TestReputationCannotEmptyTheCandidateSet is the R-87.1 shape at the storage
// layer: a floor would make dispersal fail on a network where nobody has a
// history yet.
func TestReputationCannotEmptyTheCandidateSet(t *testing.T) {
	cands := []Candidate{
		cand("a", 100, "p:198.51.100.0/24"),
		cand("b", 100, "p:203.0.113.0/24"),
		cand("c", 100, "p:192.0.2.0/24"),
	}
	// Everybody is terrible. They are still the only hosts there are.
	awful := func(string) HostScore { return HostScore{Reputation: 0, Observed: true} }
	got := PlanWithReputation(chunk(3), cands, 1, awful)
	if len(got) != 3 {
		t.Fatalf("uniformly zero reputation placed %d of 3 shards; a reputation "+
			"floor turned into a refusal to store anything", len(got))
	}
	// And a network where nothing has ever been observed disperses identically.
	unseen := PlanWithReputation(chunk(3), cands, 1, func(string) HostScore { return HostScore{} })
	if len(unseen) != 3 {
		t.Fatalf("an unobserved network placed %d of 3 shards", len(unseen))
	}
}

// TestNoSecondCopyOfTheDiversityGate keeps R-92.2 checkable.
//
// The gate lives in Plan. If this file grows its own domain logic there are two
// copies of the constraint, they drift, and "reputation never widens" stops
// being something one can read off the code.
func TestNoSecondCopyOfTheDiversityGate(t *testing.T) {
	src, err := os.ReadFile("reputation.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	// Match IDENTIFIERS, not prose: the file's comments necessarily discuss
	// domains and the gate, and an audit that fails on its own justification
	// gets deleted.
	code := regexp.MustCompile(`(?m)^[^/].*`).FindAllString(body, -1)
	joined := strings.Join(code, "\n")
	for _, forbidden := range []string{
		"sharesDomain", "takenDomain", ".Domains", "occupied[",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("R-92.2 unverifiable: reputation.go touches %s, so the diversity "+
				"gate exists in two places and they will drift", forbidden)
		}
	}
	if !strings.Contains(joined, "planOrdered(shards,") {
		t.Error("PlanWithReputation no longer delegates to planOrdered; the gate it " +
			"is supposed to inherit may not be running at all")
	}
	// It must NOT call Plan, which would re-sort emptiest-first and discard the
	// ranking -- the original bug, which every set-based test passed through.
	if strings.Contains(joined, "return Plan(shards") {
		t.Error("PlanWithReputation calls Plan, whose own sort overrides the " +
			"reputation ranking; the ranking is a no-op")
	}
}
