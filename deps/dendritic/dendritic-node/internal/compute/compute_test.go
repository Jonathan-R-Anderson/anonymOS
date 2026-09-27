package compute

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// The kernel's determinism is the load-bearing property of this whole package,
// and of M5 after it. If two runs of the same input can differ, redundant
// execution stops being a verification method and the roadmap's plan to build
// CPU verification first collapses.

func TestSameInputGivesSameDigest(t *testing.T) {
	a := Run(42, 3)
	b := Run(42, 3)
	if a.Digest != b.Digest {
		t.Fatalf("same input produced different digests:\n  %s\n  %s", a.Digest, b.Digest)
	}
}

func TestDifferentSeedGivesDifferentDigest(t *testing.T) {
	if Run(1, 2).Digest == Run(2, 2).Digest {
		t.Fatal("different seeds produced the same digest")
	}
}

func TestRoundCountIsBoundIntoTheDigest(t *testing.T) {
	// Without this, a node could run one round, publish the digest, and claim
	// it did a hundred — the cheapest possible fraud against a paid workload.
	if Run(7, 1).Digest == Run(7, 2).Digest {
		t.Fatal("round count does not affect the digest")
	}
}

func TestDigestSurvivesGoroutineScheduling(t *testing.T) {
	// Run the same input from several goroutines at once. A digest that
	// depended on scheduling would be useless for consensus, and this is the
	// cheapest way to notice if someone later parallelises the inner loop.
	const workers = 8
	results := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() { results <- Run(99, 2).Digest }()
	}
	first := <-results
	for i := 1; i < workers; i++ {
		if got := <-results; got != first {
			t.Fatalf("concurrent runs disagreed:\n  %s\n  %s", first, got)
		}
	}
}

func TestVerifyAcceptsAnHonestResult(t *testing.T) {
	if !VerifyBenchmark(Run(1234, 2)) {
		t.Fatal("Verify rejected a result it had just produced")
	}
}

func TestVerifyRejectsATamperedDigest(t *testing.T) {
	claim := Run(1234, 2)
	claim.Digest = strings.Repeat("0", len(claim.Digest))
	if VerifyBenchmark(claim) {
		t.Fatal("Verify accepted a fabricated digest")
	}
}

func TestVerifyRejectsAnotherKernelVersion(t *testing.T) {
	// Refusing is right: a result from a different kernel is an unanswerable
	// question, and silently returning false would mark honest work from a
	// node on another version as fraud.
	claim := Run(5, 1)
	claim.Version = KernelVersion + 1
	if VerifyBenchmark(claim) {
		t.Fatal("Verify accepted a result from an unknown kernel version")
	}
}

func TestVerifyRejectsAShortenedRun(t *testing.T) {
	// The fraud this must catch: do less work, report the parameters of more.
	honest := Run(11, 4)
	cheat := Run(11, 1)
	cheat.Rounds = honest.Rounds // claim four rounds of work, having done one
	if VerifyBenchmark(cheat) {
		t.Fatal("Verify accepted a result computed with fewer rounds than claimed")
	}
}

func TestCalibrateAimsAtTheTargetDuration(t *testing.T) {
	result := Calibrate(3, 300*time.Millisecond)
	if result.Rounds < 1 {
		t.Fatalf("calibrated to %d rounds", result.Rounds)
	}
	// Generous bounds on purpose: this runs on shared CI and on whatever
	// hardware a volunteer has. The property worth asserting is that
	// calibration is in the right order of magnitude, not that it is precise.
	if result.ElapsedM > 5000 {
		t.Fatalf("calibrated run took %dms, target was 300ms", result.ElapsedM)
	}
	if !VerifyBenchmark(result) {
		t.Fatal("a calibrated result did not verify")
	}
}

func TestThroughputIsReported(t *testing.T) {
	result := Run(1, 2)
	if result.OpsPerSecond <= 0 {
		t.Fatalf("no throughput measured: %d ops/s", result.OpsPerSecond)
	}
	if result.MemBandwidthMBps <= 0 {
		t.Fatalf("no bandwidth measured: %d MB/s", result.MemBandwidthMBps)
	}
}

func TestRunIsSingleThreaded(t *testing.T) {
	// Guards the comment in Run(). Parallelising the inner loop would report a
	// bigger number and destroy the digest, so the declared thread count is
	// part of the contract rather than a detail.
	if got := Run(1, 1).Threads; got != 1 {
		t.Fatalf("kernel reported %d threads; a parallel kernel cannot produce a stable digest", got)
	}
}

// --- detection ---

func TestProbeAlwaysDescribesACPU(t *testing.T) {
	profile := Probe(Options{SkipBenchmark: true})
	if profile.CPU.LogicalCores < 1 {
		t.Fatalf("probe reported %d logical cores", profile.CPU.LogicalCores)
	}
	if profile.CPU.PhysicalCores < 1 {
		t.Fatalf("probe reported %d physical cores", profile.CPU.PhysicalCores)
	}
	if profile.CPU.PhysicalCores > profile.CPU.LogicalCores {
		t.Fatalf("more physical (%d) than logical (%d) cores",
			profile.CPU.PhysicalCores, profile.CPU.LogicalCores)
	}
	if profile.CPU.Arch != runtime.GOARCH {
		t.Fatalf("arch %q != %q", profile.CPU.Arch, runtime.GOARCH)
	}
}

func TestCPUIsAlwaysClaimedAndGPUIsNot(t *testing.T) {
	// Every machine is a CPU provider — that is the roadmap's point about the
	// broad base. A GPU claim has to be earned by a working driver.
	profile := Probe(Options{SkipBenchmark: true})
	caps := profile.Capabilities()
	if len(caps) == 0 || caps[0] != "cpu" {
		t.Fatalf("cpu not claimed: %v", caps)
	}

	profile.GPU = []GPUInfo{{Vendor: "nvidia", DriverOK: false}}
	for _, c := range profile.Capabilities() {
		if c == "gpu" {
			t.Fatal("claimed gpu for a card with no working driver — every job " +
				"routed here would fail at startup")
		}
	}

	profile.GPU = []GPUInfo{{Vendor: "nvidia", DriverOK: true}}
	found := false
	for _, c := range profile.Capabilities() {
		if c == "gpu" {
			found = true
		}
	}
	if !found {
		t.Fatal("did not claim gpu for a card with a working driver")
	}
}

func TestProbeBenchmarksByDefault(t *testing.T) {
	profile := Probe(Options{BenchTarget: 50 * time.Millisecond})
	if profile.Bench == nil {
		t.Fatal("no benchmark in a default probe")
	}
	if !VerifyBenchmark(*profile.Bench) {
		t.Fatal("a probe's own benchmark did not verify")
	}
}

func TestSummaryIsReadable(t *testing.T) {
	profile := Probe(Options{SkipBenchmark: true})
	summary := profile.Summary()
	if summary == "" || !strings.Contains(summary, "cores") {
		t.Fatalf("unhelpful summary: %q", summary)
	}
}
