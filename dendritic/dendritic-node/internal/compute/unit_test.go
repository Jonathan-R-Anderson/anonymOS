package compute

import (
	"strings"
	"testing"
)

func cpuUnit() Unit {
	return Unit{
		Runtime:         strings.Repeat("a", 64),
		Inputs:          []string{strings.Repeat("b", 64)},
		Needs:           "cpu",
		Class:           "media",
		DeadlineSeconds: 600,
		Deterministic:   true,
		MinCores:        2,
	}
}

// --- M4: the format ---

func TestAValidUnitIsAccepted(t *testing.T) {
	if err := cpuUnit().Validate(); err != nil {
		t.Fatalf("rejected a well-formed unit: %v", err)
	}
}

func TestAUnitWithoutADeadlineIsRejected(t *testing.T) {
	// A unit with no ceiling can occupy a volunteer's machine forever, which is
	// a promise this network cannot make.
	u := cpuUnit()
	u.DeadlineSeconds = 0
	if err := u.Validate(); err == nil {
		t.Fatal("accepted a unit with no deadline")
	}
}

func TestAUnitWithoutAClassIsRejected(t *testing.T) {
	// Not cosmetic: the class is what an operator filters on and what the
	// "what has my machine been doing" history is written from.
	u := cpuUnit()
	u.Class = ""
	if err := u.Validate(); err == nil {
		t.Fatal("accepted a unit with no job class")
	}
}

func TestAnUnknownRequirementIsRejectedNotIgnored(t *testing.T) {
	// Silently failing to match would leave the unit queued forever with no
	// explanation, which is the worst of both outcomes.
	u := cpuUnit()
	u.Needs = "quantum"
	if err := u.Validate(); err == nil {
		t.Fatal("accepted a unit requiring an unknown capability")
	}
}

func TestRuntimeMustBeADigestNotAName(t *testing.T) {
	// The single field that keeps a submitter from supplying code. A name or a
	// URL here would reintroduce exactly the arbitrary-payload problem the
	// signed catalogue exists to solve.
	for _, runtime := range []string{"ubuntu:latest", "https://example.com/img.tar", "", "abc"} {
		u := cpuUnit()
		u.Runtime = runtime
		if err := u.Validate(); err == nil {
			t.Errorf("accepted runtime %q, which is not a content digest", runtime)
		}
	}
}

func TestIdentityIsContentNotAssignment(t *testing.T) {
	// The idempotence property. A slow node is indistinguishable from a dead
	// one, so the scheduler WILL issue the same unit twice and both will come
	// back. By content those are one fact; by assignment id they would be two,
	// and the second would be paid for work already paid for.
	a, b := cpuUnit(), cpuUnit()
	if a.Digest() != b.Digest() {
		t.Fatal("two structurally identical units hashed differently")
	}
	if a.Digest() == "" {
		t.Fatal("empty digest")
	}
}

func TestAnyChangeMakesADifferentUnit(t *testing.T) {
	base := cpuUnit().Digest()
	for name, mutate := range map[string]func(*Unit){
		"seed":     func(u *Unit) { u.Seed = 99 },
		"params":   func(u *Unit) { u.Params = map[string]string{"quality": "high"} },
		"inputs":   func(u *Unit) { u.Inputs = append(u.Inputs, strings.Repeat("c", 64)) },
		"deadline": func(u *Unit) { u.DeadlineSeconds = 1200 },
		"class":    func(u *Unit) { u.Class = "train" },
	} {
		u := cpuUnit()
		mutate(&u)
		if u.Digest() == base {
			t.Errorf("changing %s did not change the unit's identity", name)
		}
	}
}

func TestParamOrderDoesNotChangeIdentity(t *testing.T) {
	// Two submitters describing the same work must produce the same unit, or
	// the network does it twice and pays twice.
	a := cpuUnit()
	a.Params = map[string]string{"width": "1920", "height": "1080", "codec": "av1"}
	b := cpuUnit()
	b.Params = map[string]string{"codec": "av1", "height": "1080", "width": "1920"}
	if a.Digest() != b.Digest() {
		t.Fatal("map iteration order leaked into the unit digest")
	}
}

// --- M4: fitting a unit to a node ---

func TestAUnitDoesNotFitWhenThePolicySaysNo(t *testing.T) {
	// The machine CAN, its owner is not lending it. Taking the unit anyway is
	// how a node misses a deadline it accepted.
	u := cpuUnit()
	grant := Grant{Cores: 0, Reason: "running on battery"}
	ok, why := u.FitsOn(eightCores(), grant, enabled().Normalise())
	if ok {
		t.Fatal("accepted work the governor refused")
	}
	if !strings.Contains(why, "battery") {
		t.Fatalf("lost the governor's reason: %q", why)
	}
}

func TestAUnitNeedingMoreCoresThanGrantedDoesNotFit(t *testing.T) {
	u := cpuUnit()
	u.MinCores = 8
	ok, why := u.FitsOn(eightCores(), Grant{Cores: 2}, enabled().Normalise())
	if ok {
		t.Fatalf("took a unit needing 8 cores with 2 on offer (%q)", why)
	}
}

func TestARefusedClassDoesNotFit(t *testing.T) {
	policy := enabled()
	policy.JobClasses = []string{"index"}
	u := cpuUnit() // class "media"
	if ok, _ := u.FitsOn(eightCores(), Grant{Cores: 4}, policy.Normalise()); ok {
		t.Fatal("ran a class the operator did not accept")
	}
}

func TestGPUWorkNeedsAWorkingDriverAndTheRightAPI(t *testing.T) {
	u := cpuUnit()
	u.Needs = "gpu:cuda"
	grant := Grant{Cores: 4}
	policy := enabled().Normalise()

	broken := eightCores()
	broken.GPU = []GPUInfo{{Vendor: "nvidia", APIs: []string{"cuda"}, DriverOK: false}}
	if ok, _ := u.FitsOn(broken, grant, policy); ok {
		t.Fatal("matched a GPU unit to a card with no working driver")
	}

	wrongAPI := eightCores()
	wrongAPI.GPU = []GPUInfo{{Vendor: "amd", APIs: []string{"rocm"}, DriverOK: true}}
	if ok, _ := u.FitsOn(wrongAPI, grant, policy); ok {
		t.Fatal("matched a CUDA unit to a ROCm-only card")
	}

	good := eightCores()
	good.GPU = []GPUInfo{{Vendor: "nvidia", APIs: []string{"cuda", "vulkan"}, DriverOK: true}}
	if ok, why := u.FitsOn(good, grant, policy); !ok {
		t.Fatalf("refused a CUDA unit on a working CUDA card: %q", why)
	}
}

// --- M5: verification ---

func resultFor(u Unit, node, output string) UnitResult {
	return UnitResult{Unit: u.Digest(), Output: output, Progress: 100, Node: node}
}

func TestTwoAgreeingNodesSettleADeterministicUnit(t *testing.T) {
	u := cpuUnit()
	check := Verify(u, []UnitResult{
		resultFor(u, "alice", "out1"),
		resultFor(u, "bob", "out1"),
	}, DefaultQuorum())
	if check.Verdict != VerdictAgreed {
		t.Fatalf("verdict %q: %s", check.Verdict, check.Reason)
	}
	if check.Output != "out1" {
		t.Fatalf("agreed output %q", check.Output)
	}
}

func TestOneResultIsNeverEnough(t *testing.T) {
	// A single replica proves nothing — returning plausible garbage is exactly
	// the behaviour being defended against.
	u := cpuUnit()
	check := Verify(u, []UnitResult{resultFor(u, "alice", "out1")}, DefaultQuorum())
	if check.Verdict != VerdictInsufficient {
		t.Fatalf("verdict %q for a single result", check.Verdict)
	}
}

func TestDisagreementIsReportedNotAdjudicated(t *testing.T) {
	// Disagreement proves somebody is wrong, not who. Treating the minority as
	// the liar is how an honest node with a failing DIMM gets slashed while a
	// coordinated pair of cheats agrees with each other.
	u := cpuUnit()
	check := Verify(u, []UnitResult{
		resultFor(u, "alice", "out1"),
		resultFor(u, "bob", "out2"),
	}, DefaultQuorum())
	if check.Verdict != VerdictDisagreed {
		t.Fatalf("verdict %q", check.Verdict)
	}
	if check.Output != "" {
		t.Fatal("named an agreed output despite disagreement")
	}
	if !strings.Contains(check.Reason, "dispute") {
		t.Fatalf("did not defer blame to the dispute process: %q", check.Reason)
	}
}

func TestAMajorityCarriesAndTheDissentIsKept(t *testing.T) {
	// The result stands AND the dissent is recorded — it is either a failing
	// machine or an attempt, and reputation needs to see it either way.
	u := cpuUnit()
	check := Verify(u, []UnitResult{
		resultFor(u, "alice", "out1"),
		resultFor(u, "bob", "out1"),
		resultFor(u, "mallory", "garbage"),
	}, DefaultQuorum())
	if check.Verdict != VerdictAgreed || check.Output != "out1" {
		t.Fatalf("verdict %q output %q", check.Verdict, check.Output)
	}
	if len(check.Dissenting) != 1 || check.Dissenting[0] != "mallory" {
		t.Fatalf("dissent not recorded: %v", check.Dissenting)
	}
}

func TestNonDeterministicWorkIsUndecidableNotDisagreed(t *testing.T) {
	// The roadmap's central asymmetry. Two honest GPUs differ in the last bits;
	// calling that fraud would punish correct work, and calling a coincidental
	// match agreement would pass garbage. Refusing to answer is the only honest
	// option this method has.
	u := cpuUnit()
	u.Deterministic = false
	u.Needs = "gpu:cuda"
	check := Verify(u, []UnitResult{
		resultFor(u, "alice", "out1"),
		resultFor(u, "bob", "out2"),
	}, DefaultQuorum())
	if check.Verdict != VerdictUndecidable {
		t.Fatalf("verdict %q — non-deterministic work cannot be checked by equality", check.Verdict)
	}
	if !strings.Contains(check.Reason, "tolerance") {
		t.Fatalf("did not point at the escalation path: %q", check.Reason)
	}
}

func TestAResultForAnotherUnitIsNotEvidence(t *testing.T) {
	// Content addressing makes this checkable rather than trusted: a result
	// cannot be re-attributed by relabelling it.
	u := cpuUnit()
	other := cpuUnit()
	other.Seed = 12345

	stray := resultFor(other, "mallory", "out1")
	check := Verify(u, []UnitResult{
		resultFor(u, "alice", "out1"),
		stray,
	}, DefaultQuorum())
	if check.Verdict == VerdictAgreed {
		t.Fatal("counted a result for a different unit toward quorum")
	}
}

func TestACheckpointDoesNotCountAsAnAnswer(t *testing.T) {
	// Otherwise a node banks credit for stopping early.
	u := cpuUnit()
	partial := resultFor(u, "bob", "out1")
	partial.Progress = 60
	partial.Checkpoint = "half"
	check := Verify(u, []UnitResult{resultFor(u, "alice", "out1"), partial}, DefaultQuorum())
	if check.Verdict == VerdictAgreed {
		t.Fatal("a partial checkpoint counted toward quorum")
	}
}

func TestAgreedFailureStopsReissuing(t *testing.T) {
	// Agreement about failure IS agreement, and worth distinguishing: without
	// it the scheduler keeps reissuing work that cannot succeed anywhere.
	u := cpuUnit()
	fail := func(node string) UnitResult {
		return UnitResult{Unit: u.Digest(), Node: node, Failed: true, Error: "bad input"}
	}
	check := Verify(u, []UnitResult{fail("alice"), fail("bob")}, DefaultQuorum())
	if check.Verdict != VerdictFailed {
		t.Fatalf("verdict %q", check.Verdict)
	}
	if !strings.Contains(check.Reason, "reissuing") {
		t.Fatalf("did not say reissuing is pointless: %q", check.Reason)
	}
}

func TestReplicasLeaveASpare(t *testing.T) {
	// Quorum + 1, so one node going offline does not force a second scheduling
	// round for every unit.
	if got := Replicas(cpuUnit(), DefaultQuorum()); got != 3 {
		t.Fatalf("replicas %d, want quorum(2)+1", got)
	}
}

// --- M10: the two pinning models Runtime accepts ---

func TestACatalogueReferenceIsAcceptedAsARuntime(t *testing.T) {
	// The relaxation M10 needs: catalogue images are built and tagged locally,
	// so there is no digest to pin until build.sh records one. Narrow on
	// purpose — see the runtime rules test below.
	embed, ok := LookupWorkload("embed")
	if !ok {
		t.Fatal("no embed workload to test against")
	}
	u := cpuUnit()
	u.Runtime = embed.Image
	if err := u.Validate(); err != nil {
		t.Fatalf("refused the catalogue's own image: %v", err)
	}
}

func TestASha256PrefixedDigestIsAcceptedAsARuntime(t *testing.T) {
	// What a digest-pinned catalogue will carry once images are pinned by
	// content. Accepting it now is what lets that change be a one-line edit to
	// the table rather than a format change.
	u := cpuUnit()
	u.Runtime = "sha256:" + strings.Repeat("c", 64)
	if err := u.Validate(); err != nil {
		t.Fatalf("refused a sha256-prefixed digest: %v", err)
	}
}

func TestAnArbitraryImageNameIsStillRefused(t *testing.T) {
	// The rule the relaxation must not have broken. Only the exact strings in
	// the catalogue pass; anything else that merely LOOKS like a reference is
	// still a submitter naming code, which is what the digest rule prevented.
	for _, runtime := range []string{
		"ubuntu:latest",
		"registry.local/compute-embed",
		"registry.local/anything:latest",
		"docker.io/library/alpine@sha256:" + strings.Repeat("d", 64),
		"sha256:short",
		"sha256:" + strings.Repeat("z", 64),
	} {
		u := cpuUnit()
		u.Runtime = runtime
		if err := u.Validate(); err == nil {
			t.Errorf("accepted runtime %q", runtime)
		}
	}
}

func TestInputsAreStillStrictlyContentDigests(t *testing.T) {
	// Only Runtime was relaxed. An input is fetched from a content-addressed
	// store, which has nothing to resolve a name against — a named input is
	// unfetchable rather than merely imprecise.
	embed, _ := LookupWorkload("embed")
	u := cpuUnit()
	u.Runtime = embed.Image
	u.Inputs = []string{embed.Image}
	if err := u.Validate(); err == nil {
		t.Fatal("accepted an image reference as an input blob")
	}
}
