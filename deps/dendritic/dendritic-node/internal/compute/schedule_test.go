package compute

import (
	"strings"
	"testing"
	"time"
)

// node builds a candidate with a measured benchmark, since matching is on
// measured capability rather than claims.
func node(name, cpuVendor, gpuVendor, region string, ops int64) Candidate {
	profile := Profile{
		CPU:   CPUInfo{PhysicalCores: 8, LogicalCores: 16, Vendor: cpuVendor, RAMBytes: 16 << 30},
		Bench: &Result{OpsPerSecond: ops, Version: KernelVersion},
	}
	if gpuVendor != "" {
		profile.GPU = []GPUInfo{{Vendor: gpuVendor, Model: "card", APIs: []string{"cuda"}, DriverOK: true}}
	}
	return Candidate{Node: name, Profile: profile, Region: region, FreeSlots: 4, Reliability: 0.9}
}

func schedUnit() Unit {
	u := cpuUnit()
	u.MinCores = 1
	u.RefSeconds = 60
	u.DeadlineSeconds = 3600
	return u
}

func openPolicy() Policy { return enabled().Normalise() }

// --- diversity, which is the correctness feature ---

func TestReplicasAreSpreadAcrossFaultDomains(t *testing.T) {
	// THE reason this scheduler is not a load balancer. Two machines with the
	// same GPU, driver and silicon errata do not fail independently — they
	// agree with each other, wrongly, and a quorum of them passes M5.
	u := schedUnit()
	candidates := []Candidate{
		node("a1", "GenuineIntel", "nvidia", "eu", 400_000_000),
		node("a2", "GenuineIntel", "nvidia", "eu", 399_000_000),
		node("a3", "GenuineIntel", "nvidia", "eu", 398_000_000),
		node("b1", "AuthenticAMD", "amd", "us", 300_000_000),
	}
	placement := Plan(u, candidates, DefaultQuorum(), openPolicy())
	if placement.Diversity < 2 {
		t.Fatalf("diversity %d — all replicas share a fault domain: %s",
			placement.Diversity, placement.Reason)
	}
	// The three fastest are all in one domain; a load balancer would take them.
	var picked []string
	for _, a := range placement.Assignments {
		picked = append(picked, a.Node)
	}
	found := false
	for _, name := range picked {
		if name == "b1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("picked only the fastest cluster %v, ignoring the independent node", picked)
	}
}

func TestASingleFaultDomainIsPlacedButFlagged(t *testing.T) {
	// Placed — refusing would be worse. But the caller is told plainly that
	// agreement between these replicas is weaker evidence than it looks, which
	// is the one thing redundant execution cannot detect for itself.
	u := schedUnit()
	candidates := []Candidate{
		node("a1", "GenuineIntel", "nvidia", "eu", 400_000_000),
		node("a2", "GenuineIntel", "nvidia", "eu", 400_000_000),
	}
	placement := Plan(u, candidates, DefaultQuorum(), openPolicy())
	if len(placement.Assignments) == 0 {
		t.Fatal("refused to place work it could place")
	}
	if placement.Diversity != 1 {
		t.Fatalf("diversity %d, want 1", placement.Diversity)
	}
	if !strings.Contains(placement.Reason, "weaker evidence") {
		t.Fatalf("did not warn about correlated replicas: %q", placement.Reason)
	}
}

// --- deadlines ---

func TestASlowNodeIsFineForALooseDeadlineAndWrongForATightOne(t *testing.T) {
	// Same node, different answer — which is why this is decided per unit
	// rather than as a standing ranking of nodes.
	slow := node("slow", "GenuineIntel", "", "eu", 30_000_000) // 10x below reference
	slow.FreeSlots = 8

	loose := schedUnit()
	loose.RefSeconds = 60
	loose.DeadlineSeconds = 3600
	if p := Plan(loose, []Candidate{slow}, Quorum{Need: 1}, openPolicy()); len(p.Assignments) == 0 {
		t.Fatalf("refused a slow node for a loose deadline: %s", p.Reason)
	}

	tight := schedUnit()
	tight.RefSeconds = 60
	tight.DeadlineSeconds = 90 // 60s reference work takes ~600s here
	if p := Plan(tight, []Candidate{slow}, Quorum{Need: 1}, openPolicy()); len(p.Assignments) > 0 {
		t.Fatal("gave a tight-deadline unit to a node that cannot finish in time")
	}
}

func TestEstimatesUseMeasuredThroughput(t *testing.T) {
	u := schedUnit()
	u.MinCores = 1
	u.RefSeconds = 100
	fast := node("fast", "GenuineIntel", "", "eu", ReferenceOpsPerSecond*2)
	slow := node("slow", "GenuineIntel", "", "eu", ReferenceOpsPerSecond/2)
	if estimateSeconds(u, fast) >= estimateSeconds(u, slow) {
		t.Fatalf("a node measured twice as fast did not estimate faster: %d vs %d",
			estimateSeconds(u, fast), estimateSeconds(u, slow))
	}
	if got := estimateSeconds(u, fast); got != 50 {
		t.Fatalf("estimate %ds for 100 reference-seconds at 2x speed, want 50", got)
	}
}

// --- ranking ---

func TestReliabilityOutranksSpeed(t *testing.T) {
	// A node twice as fast that fails a fifth of the time costs more than it
	// saves: the failure surfaces at the deadline, by which point the time that
	// made it attractive is already gone.
	u := schedUnit()
	quick := node("quick", "GenuineIntel", "", "eu", 800_000_000)
	quick.Reliability = 0.5
	steady := node("steady", "GenuineIntel", "", "eu", 300_000_000)
	steady.Reliability = 0.99

	if !better(u, steady, quick) {
		t.Fatal("preferred a fast unreliable node over a slower dependable one")
	}
}

func TestUnusableNodesAreNotConsidered(t *testing.T) {
	u := schedUnit()
	full := node("full", "GenuineIntel", "", "eu", 400_000_000)
	full.FreeSlots = 0
	banned := node("banned", "AuthenticAMD", "", "us", 400_000_000)
	banned.Reliability = 0

	placement := Plan(u, []Candidate{full, banned}, DefaultQuorum(), openPolicy())
	if len(placement.Assignments) != 0 {
		t.Fatalf("placed work on unusable nodes: %+v", placement.Assignments)
	}
	if !strings.Contains(placement.Reason, "no node") {
		t.Fatalf("unhelpful reason: %q", placement.Reason)
	}
}

func TestTooFewNodesToVerifyIsSaidOutLoud(t *testing.T) {
	// Placeable but not checkable. Silently returning one assignment would hide
	// that the result can never reach quorum, and the caller would wait forever
	// for a verdict that cannot come.
	u := schedUnit()
	placement := Plan(u, []Candidate{node("only", "GenuineIntel", "", "eu", 400_000_000)},
		Quorum{Need: 3}, openPolicy())
	if !strings.Contains(placement.Reason, "not yet checkable") {
		t.Fatalf("did not flag an unverifiable placement: %q", placement.Reason)
	}
}

func TestPlacementIsDeterministic(t *testing.T) {
	// Two schedulers with the same view must place the same work, or the
	// network does the unit twice and pays twice.
	u := schedUnit()
	candidates := []Candidate{
		node("c", "GenuineIntel", "nvidia", "eu", 400_000_000),
		node("a", "AuthenticAMD", "amd", "us", 400_000_000),
		node("b", "GenuineIntel", "", "ap", 400_000_000),
	}
	first := Plan(u, candidates, DefaultQuorum(), openPolicy())
	for i := 0; i < 20; i++ {
		again := Plan(u, candidates, DefaultQuorum(), openPolicy())
		if len(again.Assignments) != len(first.Assignments) {
			t.Fatal("placement size varied between runs")
		}
		for j := range again.Assignments {
			if again.Assignments[j].Node != first.Assignments[j].Node {
				t.Fatalf("placement varied between runs: %s vs %s",
					again.Assignments[j].Node, first.Assignments[j].Node)
			}
		}
	}
}

func TestGPUWorkOnlyGoesToUsableCards(t *testing.T) {
	u := schedUnit()
	u.Needs = "gpu:cuda"
	u.Deterministic = false

	cpuOnly := node("cpu", "GenuineIntel", "", "eu", 400_000_000)
	broken := node("broken", "GenuineIntel", "nvidia", "us", 400_000_000)
	broken.Profile.GPU[0].DriverOK = false
	good := node("good", "AuthenticAMD", "nvidia", "ap", 400_000_000)

	placement := Plan(u, []Candidate{cpuOnly, broken, good}, Quorum{Need: 1}, openPolicy())
	for _, a := range placement.Assignments {
		if a.Node != "good" {
			t.Fatalf("placed CUDA work on %q", a.Node)
		}
	}
	if len(placement.Assignments) == 0 {
		t.Fatalf("did not place CUDA work on a working CUDA node: %s", placement.Reason)
	}
}

// --- stragglers ---

func TestAStragglerIsDetectedOnlyWhenGenuinelyLate(t *testing.T) {
	a := Assignment{Node: "slow", EstimatedSeconds: 60}
	if Straggler(a, 70*time.Second) {
		t.Fatal("called a node late while it was still within a sensible margin")
	}
	if !Straggler(a, 200*time.Second) {
		t.Fatal("did not notice a node at more than 3x its own estimate")
	}
}

func TestShortUnitsAreNotDeclaredLateOnAHiccup(t *testing.T) {
	// On a unit estimated at four seconds, a scheduling hiccup can double the
	// elapsed time without anything being wrong.
	a := Assignment{Node: "quick", EstimatedSeconds: 4}
	if Straggler(a, 12*time.Second) {
		t.Fatal("duplicated a short unit over a few seconds of jitter")
	}
}

func TestSpeculationDoesNotCascade(t *testing.T) {
	// Otherwise a genuinely hard unit recruits the whole network into
	// recomputing it.
	a := Assignment{Node: "n", EstimatedSeconds: 60, Speculative: true}
	if Straggler(a, time.Hour) {
		t.Fatal("speculated on a speculation")
	}
}

func TestSpeculationAvoidsNodesAlreadyRunningTheUnit(t *testing.T) {
	u := schedUnit()
	candidates := []Candidate{
		node("busy", "GenuineIntel", "", "eu", 400_000_000),
		node("spare", "AuthenticAMD", "", "us", 500_000_000),
	}
	extra, ok := Speculate(u, Assignment{Node: "busy"}, candidates,
		map[string]bool{"busy": true}, openPolicy())
	if !ok {
		t.Fatal("found no node to speculate on")
	}
	if extra.Node != "spare" {
		t.Fatalf("speculated onto %q, which is already running the unit", extra.Node)
	}
	if !extra.Speculative {
		t.Fatal("a speculative copy must be marked, or it would count toward quorum " +
			"and quietly reduce verification exactly when things are going wrong")
	}
}

func TestSpeculationReportsWhenThereIsNowhereToGo(t *testing.T) {
	u := schedUnit()
	_, ok := Speculate(u, Assignment{Node: "busy"},
		[]Candidate{node("busy", "GenuineIntel", "", "eu", 400_000_000)},
		map[string]bool{"busy": true}, openPolicy())
	if ok {
		t.Fatal("claimed to have speculated with no candidate available")
	}
}
