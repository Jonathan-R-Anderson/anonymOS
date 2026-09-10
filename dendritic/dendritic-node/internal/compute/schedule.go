package compute

// M6 — the distributed scheduler: which nodes get a unit, and what to do when
// one of them is slow.
//
// THE THING THAT MAKES THIS MORE THAN LOAD BALANCING
// --------------------------------------------------
// Replica diversity is a CORRECTNESS feature, not resilience. M5 verifies work
// by having several nodes do it and comparing answers — which proves nothing at
// all if the replicas share a fault. Two machines with the same GPU, the same
// driver build and the same silicon errata do not fail independently: they
// agree with each other, confidently and wrongly, and a quorum of them passes
// verification.
//
// So the scheduler does not pick the N fastest nodes. It picks nodes that are
// unlikely to be wrong in the same way, and reports how well it managed. A
// quorum of three correlated nodes is weaker evidence than two uncorrelated
// ones, and the caller is told which it got rather than left to assume.
//
// MEASURED, NOT CLAIMED
// ---------------------
// Matching uses the benchmark figure a node published and any other node can
// reproduce (bench.go), not its model number. A machine that overstates itself
// takes work it cannot finish and misses the deadline — which is a reputation
// problem (M8), but only if the scheduler was using a number worth being wrong
// about in the first place.

import (
	"fmt"
	"sort"
	"time"
)

// ReferenceOpsPerSecond is the machine a unit's RefSeconds is quoted against.
//
// A fixed constant, not the network average. An average moves as nodes join, so
// a unit's declared cost would drift after it was issued and two schedulers
// would estimate differently. Roughly a mid-range desktop core, which is what
// most of this network is.
const ReferenceOpsPerSecond = 300_000_000

// Candidate is a node the scheduler may place work on.
type Candidate struct {
	Node    string  `json:"node"`
	Profile Profile `json:"profile"`
	Region  string  `json:"region,omitempty"`

	// FreeSlots is how many more units this node will take. Zero means it is
	// full, not that it is broken.
	FreeSlots int `json:"free_slots"`

	// Reliability is 0..1 from reputation (M8). 0 is unusable and 1 is
	// flawless; an unknown node should be given something middling rather than
	// zero, or nothing new ever gets work and the network cannot grow.
	Reliability float64 `json:"reliability"`
}

// Assignment is one unit placed on one node.
type Assignment struct {
	Node string `json:"node"`
	Unit string `json:"unit"`
	// EstimatedSeconds is when this node is expected to finish, from ITS
	// measured throughput. Used to spot stragglers later, so it is recorded
	// rather than recomputed against a different assumption.
	EstimatedSeconds int `json:"estimated_seconds"`
	// Speculative marks a duplicate issued because another node was late. It is
	// not a replica for quorum purposes — see Plan's comment.
	Speculative bool `json:"speculative,omitempty"`
}

// Placement is the scheduler's answer.
type Placement struct {
	Assignments []Assignment `json:"assignments"`

	// Diversity is how many distinct fault domains the replicas span. A domain
	// is (GPU vendor+model, CPU vendor, region) — the things that make two
	// machines fail the same way.
	//
	// Reported rather than merely aimed at, because a quorum of correlated
	// nodes is weaker evidence and whoever weighs the result deserves to know.
	// 1 means every replica shares a fault domain: they can agree and still all
	// be wrong.
	Diversity int `json:"diversity"`

	// Reason explains a short or empty placement in words fit for an operator.
	Reason string `json:"reason"`
}

// faultDomain is what two nodes must NOT share for their agreement to mean
// anything.
//
// Vendor and model rather than the node id: two machines in different countries
// running the same driver on the same silicon share the same bugs. Region is
// included because it correlates with power events, network partitions and — in
// practice — with buying the same hardware at the same time.
func faultDomain(c Candidate) string {
	gpu := "none"
	for _, g := range c.Profile.GPU {
		if g.DriverOK {
			gpu = g.Vendor + "/" + g.Model
			break
		}
	}
	region := c.Region
	if region == "" {
		region = "unknown"
	}
	return gpu + "|" + c.Profile.CPU.Vendor + "|" + region
}

// estimateSeconds is how long this unit should take on this node.
//
// Scales the unit's reference cost by the node's measured throughput. A node
// that published no benchmark is assumed to be reference speed — optimistic,
// but the alternative is refusing work to every node that has not benchmarked
// yet, and the deadline check below still catches it.
func estimateSeconds(u Unit, c Candidate) int {
	ref := u.RefSeconds
	if ref <= 0 {
		// No estimate given: fall back to the deadline, which at least keeps
		// the arithmetic below meaningful.
		ref = u.DeadlineSeconds
	}
	speed := float64(ReferenceOpsPerSecond)
	if c.Profile.Bench != nil && c.Profile.Bench.OpsPerSecond > 0 {
		speed = float64(c.Profile.Bench.OpsPerSecond)
	}
	scaled := float64(ref) * (float64(ReferenceOpsPerSecond) / speed)

	// More cores finish a parallel unit sooner, but not linearly and not below
	// the serial floor. Capped at the unit's own core request: a 32-core
	// machine does not run a 2-core unit sixteen times faster.
	cores := c.Profile.CPU.PhysicalCores
	if u.MinCores > 1 && cores > 1 {
		useful := cores
		if useful > u.MinCores {
			useful = u.MinCores
		}
		scaled /= float64(useful)
	}
	if scaled < 1 {
		scaled = 1
	}
	return int(scaled)
}

// Plan chooses nodes for a unit.
//
// Returns quorum-many primary assignments, chosen to span as many fault domains
// as possible. Fewer than quorum is a valid answer and says so in Reason — the
// caller should wait for more nodes rather than accept a result verified by too
// few, and silently returning a short placement would hide that decision.
func Plan(u Unit, candidates []Candidate, quorum Quorum, policy Policy) Placement {
	if quorum.Need <= 0 {
		quorum = DefaultQuorum()
	}
	want := Replicas(u, quorum)

	var eligible []Candidate
	var rejected int
	for _, c := range candidates {
		if c.FreeSlots <= 0 || c.Reliability <= 0 {
			rejected++
			continue
		}
		// The node's own governor has the final say at run time; this is the
		// scheduler declining to offer work that obviously cannot fit.
		fits, _ := u.FitsOn(c.Profile, Grant{Cores: c.Profile.CPU.PhysicalCores}, policy)
		if !fits {
			rejected++
			continue
		}
		// Deadline awareness: a slow reliable node is right for a loose
		// deadline and wrong for a tight one. Same node, different answer,
		// which is why this is per-unit rather than a standing ranking.
		if estimateSeconds(u, c) > u.DeadlineSeconds {
			rejected++
			continue
		}
		eligible = append(eligible, c)
	}

	if len(eligible) == 0 {
		return Placement{Reason: fmt.Sprintf(
			"no node can take this unit (%d considered, all unsuitable)", len(candidates))}
	}

	// Group by fault domain, best-first within each group. Sorting inside the
	// group and then taking one per group in turn is what produces a spread
	// rather than a cluster.
	groups := map[string][]Candidate{}
	for _, c := range eligible {
		domain := faultDomain(c)
		groups[domain] = append(groups[domain], c)
	}
	domains := make([]string, 0, len(groups))
	for domain := range groups {
		sort.Slice(groups[domain], func(i, j int) bool {
			return better(u, groups[domain][i], groups[domain][j])
		})
		domains = append(domains, domain)
	}
	// Deterministic order, so two schedulers given the same view place the same
	// work. Non-determinism here would mean the network doing a unit twice.
	sort.Slice(domains, func(i, j int) bool {
		a, b := groups[domains[i]][0], groups[domains[j]][0]
		if better(u, a, b) {
			return true
		}
		if better(u, b, a) {
			return false
		}
		return domains[i] < domains[j]
	})

	// Round-robin across domains: one from each before a second from any.
	var chosen []Candidate
	for round := 0; len(chosen) < want; round++ {
		progressed := false
		for _, domain := range domains {
			if round < len(groups[domain]) && len(chosen) < want {
				chosen = append(chosen, groups[domain][round])
				progressed = true
			}
		}
		if !progressed {
			break // every domain exhausted
		}
	}

	placement := Placement{Diversity: distinctDomains(chosen)}
	for _, c := range chosen {
		placement.Assignments = append(placement.Assignments, Assignment{
			Node:             c.Node,
			Unit:             u.Digest(),
			EstimatedSeconds: estimateSeconds(u, c),
		})
	}

	switch {
	case len(chosen) < quorum.Need:
		placement.Reason = fmt.Sprintf(
			"only %d node(s) can take this unit, and %d are needed to verify a result — "+
				"the work is placeable but not yet checkable", len(chosen), quorum.Need)
	case placement.Diversity < 2:
		// Placed, but say plainly what it is worth. Replicas sharing a fault
		// domain can agree and still all be wrong, which is the one thing
		// redundant execution cannot detect.
		placement.Reason = fmt.Sprintf(
			"%d replicas, all in one fault domain (%s) — they share hardware and driver, "+
				"so agreement between them is weaker evidence than it looks",
			len(chosen), faultDomain(chosen[0]))
	default:
		placement.Reason = fmt.Sprintf("%d replicas across %d fault domains",
			len(chosen), placement.Diversity)
	}
	return placement
}

// better ranks two candidates for one unit.
//
// Reliability dominates deliberately. A node twice as fast that fails a fifth
// of the time costs more than it saves: its failures are discovered at the
// deadline, and re-placing then has already burnt the time that made it
// attractive.
func better(u Unit, a, b Candidate) bool {
	// Coarse buckets rather than raw comparison, so a hair's difference in
	// reputation does not override a large difference in speed.
	ra, rb := int(a.Reliability*10), int(b.Reliability*10)
	if ra != rb {
		return ra > rb
	}
	ea, eb := estimateSeconds(u, a), estimateSeconds(u, b)
	if ea != eb {
		return ea < eb
	}
	return a.Node < b.Node // stable
}

func distinctDomains(candidates []Candidate) int {
	seen := map[string]bool{}
	for _, c := range candidates {
		seen[faultDomain(c)] = true
	}
	return len(seen)
}

// Straggler reports whether an in-flight assignment should be duplicated.
//
// The straggler problem is that a job finishes when its LAST unit does, so one
// slow node holds up everything. Waiting is the obvious response and the wrong
// one; re-issuing speculatively costs one extra execution and removes the tail.
//
// Two conditions, both required. Well past its own estimate — its own, because
// a node that is slow but was known to be slow is behaving as scheduled. And
// enough absolute time to be sure: on a unit estimated at four seconds, a
// scheduling hiccup can double the elapsed time without anything being wrong.
func Straggler(a Assignment, elapsed time.Duration) bool {
	if a.Speculative {
		// Never speculate on a speculation. Otherwise a genuinely hard unit
		// recruits the whole network into recomputing it.
		return false
	}
	if a.EstimatedSeconds <= 0 {
		return false
	}
	overdue := elapsed > time.Duration(a.EstimatedSeconds)*2*time.Second
	return overdue && elapsed > 30*time.Second
}

// Speculate issues a duplicate of a late assignment to a different node.
//
// The duplicate is marked Speculative and does NOT count toward quorum. That
// distinction matters: a speculative copy exists to beat a slow node to the
// answer, and letting it also serve as an independent replica would quietly
// reduce a unit's verification from N nodes to N-1 exactly when things are
// already going wrong.
func Speculate(u Unit, late Assignment, candidates []Candidate, exclude map[string]bool,
	policy Policy) (Assignment, bool) {

	var pool []Candidate
	for _, c := range candidates {
		if exclude[c.Node] || c.FreeSlots <= 0 || c.Reliability <= 0 {
			continue
		}
		if fits, _ := u.FitsOn(c.Profile, Grant{Cores: c.Profile.CPU.PhysicalCores}, policy); !fits {
			continue
		}
		pool = append(pool, c)
	}
	if len(pool) == 0 {
		return Assignment{}, false
	}
	sort.Slice(pool, func(i, j int) bool { return better(u, pool[i], pool[j]) })

	// The fastest available node, not the most diverse one. A speculative copy
	// is racing a straggler rather than adding evidence, and diversity is what
	// the primary replicas already bought.
	best := pool[0]
	return Assignment{
		Node:             best.Node,
		Unit:             u.Digest(),
		EstimatedSeconds: estimateSeconds(u, best),
		Speculative:      true,
	}, true
}
