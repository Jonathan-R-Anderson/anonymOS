package compute

import (
	"testing"
	"time"
)

var now = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return now.Add(-d) }
func dev() Device                   { return Device{Node: "n1", Device: "cpu"} }

func agreed(n int, age time.Duration) []Outcome {
	out := make([]Outcome, n)
	for i := range out {
		out[i] = Outcome{Agreed: true, At: ago(age)}
	}
	return out
}

func TestAnUnprovenDeviceIsMiddlingNotPerfectAndNotHopeless(t *testing.T) {
	// Both extremes are wrong. Perfect hands a newcomer the best work before it
	// has done any; hopeless is a closed shop nobody can earn out of.
	s := Rate(dev(), nil, now)
	if s.Value != PriorScore {
		t.Fatalf("unproven scored %.2f, want %.2f", s.Value, PriorScore)
	}
	if TierOf(s) == TierTrusted {
		t.Fatal("a device with no history was trusted")
	}
}

func TestOneResultDoesNotMakeATrackRecord(t *testing.T) {
	// The prior's whole job. Without it a single success reads as flawless and
	// the scheduler acts on it.
	s := Rate(dev(), agreed(1, time.Hour), now)
	if s.Value > 0.75 {
		t.Fatalf("one success scored %.2f — that is a track record from nothing", s.Value)
	}
}

func TestSustainedAgreementEarnsTrust(t *testing.T) {
	s := Rate(dev(), agreed(40, 48*time.Hour), now)
	if TierOf(s) != TierTrusted {
		t.Fatalf("40 recent agreements scored %.2f (%d obs) -> %s",
			s.Value, int(s.Observations), TierOf(s))
	}
}

func TestOldEvidenceFadesButNeverVanishes(t *testing.T) {
	// Half-life, not a window: no edge to game, and a long good record still
	// counts for something.
	recent := Rate(dev(), agreed(20, 24*time.Hour), now)
	old := Rate(dev(), agreed(20, 365*24*time.Hour), now)
	if old.Value >= recent.Value {
		t.Fatalf("year-old evidence (%.3f) counted as much as yesterday's (%.3f)",
			old.Value, recent.Value)
	}
	if old.Value <= 0 {
		t.Fatal("old evidence vanished entirely")
	}
}

func TestReplacedHardwareStopsPricingTodaysScheduling(t *testing.T) {
	// The roadmap's exact concern: excellent two years ago, failing since.
	history := agreed(200, 2*365*24*time.Hour)
	for i := 0; i < 10; i++ {
		history = append(history, Outcome{Agreed: false, At: ago(24 * time.Hour)})
	}
	s := Rate(dev(), history, now)
	if s.Value > 0.5 {
		t.Fatalf("scored %.2f — an ancient good record outvoted recent failures", s.Value)
	}
}

func TestBeingWrongIsWorseThanGivingUp(t *testing.T) {
	// Pricing them the same encourages the worse behaviour: a node that cannot
	// do the work should decline rather than guess.
	failed := Rate(dev(), []Outcome{{Failed: true, At: ago(time.Hour)}}, now)
	wrong := Rate(dev(), []Outcome{{Agreed: false, At: ago(time.Hour)}}, now)
	if failed.Value <= wrong.Value {
		t.Fatalf("failing (%.3f) scored no better than disagreeing (%.3f)",
			failed.Value, wrong.Value)
	}
}

func TestLateButCorrectIsPartialCredit(t *testing.T) {
	onTime := Rate(dev(), []Outcome{{Agreed: true, At: ago(time.Hour)}}, now)
	late := Rate(dev(), []Outcome{{Agreed: true, Late: true, At: ago(time.Hour)}}, now)
	if late.Value >= onTime.Value {
		t.Fatal("a missed deadline cost nothing")
	}
	wrong := Rate(dev(), []Outcome{{Agreed: false, At: ago(time.Hour)}}, now)
	if late.Value <= wrong.Value {
		t.Fatal("right-but-late scored no better than wrong")
	}
}

func TestDevicesAreScoredApart(t *testing.T) {
	// A working card and a flaky one in the same chassis are one node with two
	// track records. Averaging overstates the bad and understates the good.
	good := Rate(Device{"n1", "gpu:nvidia/A"}, agreed(30, 24*time.Hour), now)
	bad := Rate(Device{"n1", "gpu:nvidia/B"},
		[]Outcome{{Agreed: false, At: ago(time.Hour)}, {Agreed: false, At: ago(2 * time.Hour)}}, now)
	if good.Value <= bad.Value {
		t.Fatal("the two devices did not score apart")
	}
	// And a node summary must not let the good one hide the bad one.
	if Summarise([]Score{good, bad}) != bad.Value {
		t.Fatal("node summary averaged instead of taking the worst device")
	}
}

func TestTrustNeedsEvidenceNotJustAHighScore(t *testing.T) {
	// Otherwise "trusted" comes to mean "lucky twice".
	lucky := Rate(dev(), agreed(2, time.Hour), now)
	if TierOf(lucky) == TierTrusted {
		t.Fatalf("two successes reached trusted (%.2f, %.0f obs)",
			lucky.Value, lucky.Observations)
	}
}

func TestProbationIsKeptOffUnverifiableWork(t *testing.T) {
	// The gate that matters: nothing catches a probationary device being wrong
	// if the work cannot be checked.
	u := cpuUnit()
	u.Deterministic = false
	if ok, why := MayTake(TierProbation, u, 3); ok {
		t.Fatal("probation took non-deterministic work")
	} else if why == "" {
		t.Fatal("refused without saying why")
	}

	u.Deterministic = true
	if ok, _ := MayTake(TierProbation, u, 1); ok {
		t.Fatal("probation took unreplicated work")
	}
	if ok, _ := MayTake(TierProbation, u, 2); !ok {
		t.Fatal("probation refused replicated deterministic work, which is how it earns anything")
	}
}

func TestPrivilegesEscalate(t *testing.T) {
	if !(MaxUnitsFor(TierTrusted) > MaxUnitsFor(TierStandard) &&
		MaxUnitsFor(TierStandard) > MaxUnitsFor(TierProbation)) {
		t.Fatal("concurrency does not escalate with tier")
	}
	if MaxUnitsFor(TierProbation) < 1 {
		t.Fatal("probation cannot take any work, so it can never earn its way out")
	}
}

func TestScoreStaysInRange(t *testing.T) {
	for _, outcomes := range [][]Outcome{
		nil,
		agreed(500, time.Hour),
		{{Agreed: false, At: ago(time.Hour)}},
		{{Agreed: true, At: now.Add(time.Hour)}}, // clock skew: future timestamp
	} {
		v := Rate(dev(), outcomes, now).Value
		if v < 0 || v > 1 {
			t.Fatalf("score %.3f out of range", v)
		}
	}
}

func TestRankingIsDeterministic(t *testing.T) {
	scores := []Score{
		{Device: Device{"b", "cpu"}, Value: 0.8, Observations: 10},
		{Device: Device{"a", "cpu"}, Value: 0.8, Observations: 10},
		{Device: Device{"c", "cpu"}, Value: 0.9, Observations: 30},
	}
	first := Ranked(scores)
	for i := 0; i < 5; i++ {
		again := Ranked(scores)
		for j := range again {
			if again[j].Device.Node != first[j].Device.Node {
				t.Fatal("ranking varied between calls")
			}
		}
	}
	if first[0].Device.Node != "c" {
		t.Fatalf("best device was %q", first[0].Device.Node)
	}
}
