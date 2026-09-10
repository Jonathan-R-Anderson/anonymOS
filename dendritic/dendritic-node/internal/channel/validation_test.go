package channel

// The deployment gate — roadmap P12.
//
// The single most important test in this file is the one asserting that the
// system is NOT currently deployable. Everything else here is machinery; that
// one is the fact.

import (
	"strings"
	"testing"
	"time"
)

const testChain = 1

// testEnvelope is a deployment that has actually been described: a workload and
// an on-call commitment. Without one, nothing validates — see OperatingEnvelope.
func testEnvelope() OperatingEnvelope {
	return OperatingEnvelope{
		Channels: 1000, Watchtowers: 2, SweepInterval: DefaultWatchInterval,
		OnCall: "primary paged, secondary escalates after 1h", OnCallResponse: 4 * time.Hour,
	}
}

// testHeaders is a deployment whose canonicality is settled, so the BUDGET
// tests reach the budget. Header trust is gated separately — see
// TestUnverifiedCanonicalityBlocksDeploymentOnItsOwn.
func testHeaders() HeaderTrust {
	return HeaderTrust{
		Status: CanonicalityVerified, Implementation: "test verifier",
		Anchor: "https://beaconstate.example",
	}
}

func goodEvidence(term string, measured time.Duration, now int64) Evidence {
	return Evidence{
		Term: term, Measured: measured, Samples: MinEvidenceSamples,
		ChainID: testChain, Method: "measured against a live chain", TakenAt: now,
		AtChannels: testEnvelope().Channels,
	}
}

// THE GATE. Nothing has been measured against a real chain, so the system must
// refuse to produce a number to deploy with.
func TestTheSystemIsNotYetDeployable(t *testing.T) {
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())
	// Canonicality settled, so this tests the BUDGET half of the gate.
	v.Headers = testHeaders()

	seconds, err := v.DeployableChallengePeriod(time.Now().Unix())
	if err == nil {
		t.Fatalf("the gate is open: it offered challengePeriod = %d with no evidence", seconds)
	}
	// The refusal has to say WHICH terms, or it is an obstacle rather than
	// information.
	for term := range termsNeedingEvidence {
		if !strings.Contains(err.Error(), term) {
			t.Errorf("the refusal does not mention the unvalidated %q: %v", term, err)
		}
	}
}

func TestAFullyValidatedBudgetIsDeployable(t *testing.T) {
	now := time.Now().Unix()
	budget := MainnetChallengeBudget()
	v := NewValidatedBudget(testChain, budget, testEnvelope())
	v.Headers = testHeaders()

	for _, term := range v.Budget.Terms() {
		if _, needs := termsNeedingEvidence[term.Name]; !needs {
			continue
		}
		// Measured at the budgeted value: the budget held.
		if err := v.Record(goodEvidence(term.Name, term.Dur, now)); err != nil {
			t.Fatalf("record %q: %v", term.Name, err)
		}
	}

	seconds, err := v.DeployableChallengePeriod(now)
	if err != nil {
		t.Fatalf("still refusing after full validation: %v", err)
	}
	if want := int64(budget.Recommend() / time.Second); seconds != want {
		t.Errorf("deployable %d, want %d", seconds, want)
	}
}

// A measurement that exceeds its budget REFUTES the budget. Filing it as a
// confirmation would be the exact failure this gate exists to prevent.
func TestEvidenceThatRefutesTheBudgetIsRejected(t *testing.T) {
	now := time.Now().Unix()
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())

	err := v.Record(goodEvidence("inclusion", 45*time.Minute, now))
	if err == nil {
		t.Fatal("a measurement of 45m was accepted against a 30m budget")
	}
	if !strings.Contains(err.Error(), "raise the term") {
		t.Errorf("the error does not say what to do: %v", err)
	}
	if _, ok := v.Evidence["inclusion"]; ok {
		t.Error("the refuting measurement was filed anyway")
	}
}

// Raising the term is the correct response, and it must then validate.
func TestRaisingARefutedTermMakesItValidatable(t *testing.T) {
	now := time.Now().Unix()
	budget := MainnetChallengeBudget()
	budget.Inclusion = time.Hour

	v := NewValidatedBudget(testChain, budget, testEnvelope())
	if err := v.Record(goodEvidence("inclusion", 45*time.Minute, now)); err != nil {
		t.Fatalf("45m still refused against a raised 1h budget: %v", err)
	}
	// And the answer moved, because the budget did.
	if budget.Recommend() <= MainnetChallengeBudget().Recommend() {
		t.Error("raising a term did not lengthen the recommendation")
	}
}

// A measurement from somewhere else does not validate this deployment.
func TestEvidenceFromAnotherChainIsRejected(t *testing.T) {
	now := time.Now().Unix()
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())

	e := goodEvidence("inclusion", 10*time.Minute, now)
	e.ChainID = 11155111 // a testnet
	if err := v.Record(e); err == nil {
		t.Fatal("testnet evidence validated a mainnet budget")
	}
}

// One observation is an anecdote.
func TestThinEvidenceIsRejected(t *testing.T) {
	now := time.Now().Unix()
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())

	e := goodEvidence("inclusion", 10*time.Minute, now)
	e.Samples = 3
	if err := v.Record(e); err == nil {
		t.Fatal("three samples were accepted as evidence")
	}
}

// A measurement nobody can repeat is not evidence.
func TestEvidenceWithoutAMethodIsRejected(t *testing.T) {
	now := time.Now().Unix()
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())

	e := goodEvidence("inclusion", 10*time.Minute, now)
	e.Method = ""
	if err := v.Record(e); err == nil {
		t.Fatal("a measurement with no method was accepted")
	}
}

// Networks change. Old evidence stops counting.
func TestExpiredEvidenceReopensTheGate(t *testing.T) {
	now := time.Now().Unix()
	old := now - int64((EvidenceMaxAge+24*time.Hour)/time.Second)

	budget := MainnetChallengeBudget()
	v := NewValidatedBudget(testChain, budget, testEnvelope())
	v.Headers = testHeaders()
	for _, term := range v.Budget.Terms() {
		if _, needs := termsNeedingEvidence[term.Name]; !needs {
			continue
		}
		if err := v.Record(goodEvidence(term.Name, term.Dur, old)); err != nil {
			t.Fatalf("record %q: %v", term.Name, err)
		}
	}

	if _, err := v.DeployableChallengePeriod(now); err == nil {
		t.Fatal("year-old measurements still counted as validation")
	}
	// Fresh evidence reopens it.
	for _, term := range v.Budget.Terms() {
		if _, needs := termsNeedingEvidence[term.Name]; !needs {
			continue
		}
		if err := v.Record(goodEvidence(term.Name, term.Dur, now)); err != nil {
			t.Fatalf("re-record %q: %v", term.Name, err)
		}
	}
	if _, err := v.DeployableChallengePeriod(now); err != nil {
		t.Fatalf("fresh evidence did not reopen the gate: %v", err)
	}
}

// The two exempt terms must not silently become required, and must not be
// satisfiable by filing evidence at them either.
func TestTheExemptTermsAreExemptForAReason(t *testing.T) {
	now := time.Now().Unix()
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())

	for _, term := range []string{"local work", "safety"} {
		if _, needs := termsNeedingEvidence[term]; needs {
			t.Errorf("%q now requires evidence; if that is intended, say why in the map", term)
		}
		if err := v.Record(goodEvidence(term, time.Second, now)); err == nil {
			t.Errorf("%q accepted evidence it does not take", term)
		}
	}
}

func TestUnknownTermsAreRejected(t *testing.T) {
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())
	if err := v.Record(goodEvidence("vibes", time.Second, time.Now().Unix())); err == nil {
		t.Fatal("evidence was filed against a term that does not exist")
	}
}

// Every term the budget has is either exempt with a stated reason or requires
// evidence with a stated reason. A term in neither list would be a guess nobody
// is tracking.
func TestEveryBudgetTermIsAccountedForByTheGate(t *testing.T) {
	exempt := map[string]bool{"local work": true, "safety": true}
	for _, term := range MainnetChallengeBudget().Terms() {
		_, needs := termsNeedingEvidence[term.Name]
		if !needs && !exempt[term.Name] {
			t.Errorf("term %q neither requires evidence nor is exempt", term.Name)
		}
		if needs && termsNeedingEvidence[term.Name] == "" {
			t.Errorf("term %q requires evidence but gives no reason", term.Name)
		}
	}
}

// The report has to be readable by whoever is deciding, and has to say plainly
// that it is not deployable.
func TestTheReportSaysWhereThingsStand(t *testing.T) {
	now := time.Now().Unix()
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())
	if err := v.Record(goodEvidence("inclusion", 20*time.Minute, now)); err != nil {
		t.Fatalf("record: %v", err)
	}

	report := v.Report(now)
	for _, want := range []string{"NOT DEPLOYABLE", "UNVALIDATED", "measured 20m0s", "n/a"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report is missing %q:\n%s", want, report)
		}
	}
}

// Nothing validates until the deployment has been described. A budget validated
// "in the abstract" is validated for nothing.
func TestAnUndescribedDeploymentValidatesNothing(t *testing.T) {
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), OperatingEnvelope{})
	if err := v.Record(goodEvidence("inclusion", 10*time.Minute, time.Now().Unix())); err == nil {
		t.Fatal("evidence was filed against a deployment nobody has described")
	}
}

// The outage term is a promise about people, and must not be shorter than the
// promise actually made.
func TestTheOutageTermCannotUndercutTheOnCallCommitment(t *testing.T) {
	envelope := testEnvelope()
	// Nobody is really on call: the honest response time is a day.
	envelope.OnCall = "somebody will notice eventually"
	envelope.OnCallResponse = 24 * time.Hour

	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), envelope)
	err := v.Record(goodEvidence("watchtower outage", 4*time.Hour, time.Now().Unix()))
	if err == nil {
		t.Fatal("a 4h outage term validated against a 24h on-call reality")
	}
	if !strings.Contains(err.Error(), "promise about people") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}
}

// Detection measured on a toy workload says nothing about the real one.
func TestDetectionMeasuredOnTheWrongWorkloadIsRejected(t *testing.T) {
	envelope := testEnvelope()
	envelope.Channels = 100_000

	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), envelope)
	e := goodEvidence("detection", 5*time.Minute, time.Now().Unix())
	e.AtChannels = 100 // measured on a laptop with a handful of channels

	if err := v.Record(e); err == nil {
		t.Fatal("a 100-channel sweep validated a 100,000-channel deployment")
	}
}

// ---- canonicality (P12-5) ---------------------------------------------------

// The gate must refuse on header trust ALONE, however well the budget is
// measured. A fabricated chain produces storage proofs that verify perfectly.
func TestUnverifiedCanonicalityBlocksDeploymentOnItsOwn(t *testing.T) {
	now := time.Now().Unix()
	v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())
	for _, term := range v.Budget.Terms() {
		if _, needs := termsNeedingEvidence[term.Name]; !needs {
			continue
		}
		if err := v.Record(goodEvidence(term.Name, term.Dur, now)); err != nil {
			t.Fatalf("record %q: %v", term.Name, err)
		}
	}
	// Every budget term validated, and still refused.
	_, err := v.DeployableChallengePeriod(now)
	if err == nil {
		t.Fatal("a fully measured budget deployed with unverified headers")
	}
	if !strings.Contains(err.Error(), "UNVERIFIED") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}

	v.Headers = HeaderTrust{
		Status: CanonicalityVerified,
		Implementation: "helios sidecar", Anchor: "https://beaconstate.info",
	}
	if _, err := v.DeployableChallengePeriod(now); err != nil {
		t.Fatalf("still refusing with verified headers: %v", err)
	}
}

// "Verified" must say by what and against which anchor, so a vendored light
// client cannot quietly pass as a native one.
func TestVerifiedCanonicalityMustNameItself(t *testing.T) {
	for _, h := range []HeaderTrust{
		{Status: CanonicalityVerified, Anchor: "https://beaconstate.info"},
		{Status: CanonicalityVerified, Implementation: "helios"},
	} {
		if err := h.Check(); err == nil {
			t.Errorf("an unnamed verifier passed: %+v", h)
		}
	}
}

// Accepting the risk is allowed, and requires a name against the decision.
func TestAcceptingTheRiskRequiresANameAndAReason(t *testing.T) {
	bare := HeaderTrust{Status: CanonicalityAcceptedRisk}
	if err := bare.Check(); err == nil {
		t.Fatal("the risk was accepted by nobody in particular")
	}
	named := HeaderTrust{
		Status: CanonicalityAcceptedRisk, AcceptedBy: "operator",
		Reason: "single-provider pilot, bounded funds",
	}
	if err := named.Check(); err != nil {
		t.Fatalf("a properly recorded acceptance was refused: %v", err)
	}
}

// ---- the reorg-depth sample floor (policy: 30 -> 18) -------------------------
//
// A DELIBERATE reduction, applied to the reorg-depth term ALONE. These tests
// exist to pin both halves of that: that eighteen now suffices for reorg, and
// that nothing else moved. The second half is the one worth having — a floor
// lowered globally would have quietly relaxed inclusion, repricing, detection
// and rpc failure, none of which was reviewed.

func TestReorgDepthNeedsEighteenObservations(t *testing.T) {
	now := time.Now().Unix()
	for _, tc := range []struct {
		samples int
		want    bool // accepted?
	}{
		{17, false}, // one short
		{18, true},  // the new floor, exactly
		{19, true},
		{30, true}, // the old floor still fine
	} {
		v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())
		v.Headers = testHeaders()
		e := goodEvidence(reorgTerm, 12*time.Second, now)
		e.Samples = tc.samples

		err := v.Record(e)
		if tc.want && err != nil {
			t.Errorf("%d reorg observations were refused: %v", tc.samples, err)
		}
		if !tc.want && err == nil {
			t.Errorf("%d reorg observations were accepted; the floor is %d",
				tc.samples, MinReorgSamples)
		}
	}
}

func TestTheReducedFloorAppliesToReorgAlone(t *testing.T) {
	// The whole point of scoping it. Every other term keeps 30.
	now := time.Now().Unix()
	for _, term := range []string{"inclusion", "repricing", "detection", "rpc failure"} {
		v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())
		v.Headers = testHeaders()
		e := goodEvidence(term, 30*time.Second, now)
		e.Samples = MinReorgSamples // 18 — enough for reorg, not for these
		if _, known := v.budgeted(term); !known {
			continue // not a term in this budget; nothing to assert
		}
		if err := v.Record(e); err == nil {
			t.Errorf("%q accepted %d samples; only %q was reduced",
				term, MinReorgSamples, reorgTerm)
		}
	}
}

func TestTheOtherReorgGuardsStillHold(t *testing.T) {
	// Reducing the COUNT must not have relaxed anything else. Each case is a
	// separate reason to refuse, at or above the new floor.
	now := time.Now().Unix()
	cases := []struct {
		name string
		mut  func(*Evidence)
	}{
		{"wrong chain", func(e *Evidence) { e.ChainID = testChain + 1 }},
		{"no method recorded", func(e *Evidence) { e.Method = "" }},
	}
	for _, tc := range cases {
		v := NewValidatedBudget(testChain, MainnetChallengeBudget(), testEnvelope())
		v.Headers = testHeaders()
		e := goodEvidence(reorgTerm, 12*time.Second, now)
		e.Samples = MinReorgSamples
		tc.mut(&e)
		if err := v.Record(e); err == nil {
			t.Errorf("%s was accepted at the new floor", tc.name)
		}
	}
}

// Expiry is NOT re-tested here. TestExpiredEvidenceReopensTheGate already
// covers it across every term including reorg depth, and lowering a sample
// floor does not touch EvidenceMaxAge. A second, weaker copy would only be a
// place for the two to disagree.
