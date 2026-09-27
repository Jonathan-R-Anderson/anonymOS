package compute

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// A slow node is not a dead node. This is the branch that stops the network
// paying twice for every machine on a bad connection.
func TestRecentHeartbeatMeansWait(t *testing.T) {
	attempts := []Attempt{{
		Node: "a", Domain: "d1", Outcome: OutcomeRunning,
		StartedAt: t0.Add(-2 * time.Hour), LastHeartbeat: t0.Add(-30 * time.Second),
	}}
	if got := Assess(attempts, t0); got.Disposition != DispositionWait {
		t.Fatalf("got %s (%s), want wait", got.Disposition, got.Why)
	}
}

func TestSilentAttemptIsReassigned(t *testing.T) {
	attempts := []Attempt{{
		Node: "a", Domain: "d1", Outcome: OutcomeRunning,
		StartedAt: t0.Add(-2 * time.Hour), LastHeartbeat: t0.Add(-HeartbeatGrace - time.Minute),
	}}
	got := Assess(attempts, t0)
	if got.Disposition != DispositionReassign {
		t.Fatalf("got %s (%s), want reassign", got.Disposition, got.Why)
	}
}

// An attempt that never sent a heartbeat is judged from its start time, not
// treated as instantly dead — a node may legitimately take a moment to report.
func TestMissingHeartbeatFallsBackToStartTime(t *testing.T) {
	fresh := []Attempt{{Node: "a", Outcome: OutcomeRunning, StartedAt: t0.Add(-time.Second)}}
	if got := Assess(fresh, t0); got.Disposition != DispositionWait {
		t.Errorf("a just-started attempt got %s, want wait", got.Disposition)
	}
	stale := []Attempt{{Node: "a", Outcome: OutcomeRunning, StartedAt: t0.Add(-time.Hour)}}
	if got := Assess(stale, t0); got.Disposition != DispositionReassign {
		t.Errorf("a silent attempt got %s, want reassign", got.Disposition)
	}
}

// The rule this file exists for: a unit failing the same way on independent
// hardware is the unit's fault, not the nodes'.
func TestSameFailureAcrossDomainsIsPoison(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Domain: "d1", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "b", Domain: "d2", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "c", Domain: "d3", Outcome: OutcomeFailed, Reason: "segfault"},
	}
	got := Assess(attempts, t0)
	if got.Disposition != DispositionPoison {
		t.Fatalf("got %s (%s), want poison", got.Disposition, got.Why)
	}
}

// Three failures inside ONE fault domain is one observation repeated. Calling
// it poison is how a single broken driver blacklists valid work.
func TestSameFailureInOneDomainIsNotPoison(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Domain: "d1", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "b", Domain: "d1", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "c", Domain: "d1", Outcome: OutcomeFailed, Reason: "segfault"},
	}
	if got := Assess(attempts, t0); got.Disposition == DispositionPoison {
		t.Fatalf("one domain convicted the unit: %s", got.Why)
	}
}

// Different errors on different machines is what an unreliable network looks
// like, not what a defective unit looks like.
func TestDifferentFailuresAreNotPoison(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Domain: "d1", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "b", Domain: "d2", Outcome: OutcomeFailed, Reason: "out of memory"},
		{Node: "c", Domain: "d3", Outcome: OutcomeFailed, Reason: "disk full"},
	}
	if got := Assess(attempts, t0); got.Disposition == DispositionPoison {
		t.Fatalf("unrelated errors convicted the unit: %s", got.Why)
	}
}

// Abandonments say something about connections and nothing about the work. A
// network of flaky laptops must not be able to condemn a valid unit.
func TestAbandonmentsNeverProvePoison(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Domain: "d1", Outcome: OutcomeAbandoned, Reason: "lost contact"},
		{Node: "b", Domain: "d2", Outcome: OutcomeAbandoned, Reason: "lost contact"},
		{Node: "c", Domain: "d3", Outcome: OutcomeAbandoned, Reason: "lost contact"},
	}
	if got := Assess(attempts, t0); got.Disposition == DispositionPoison {
		t.Fatalf("abandonments convicted the unit: %s", got.Why)
	}
}

func TestCompletionWins(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Domain: "d1", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "b", Domain: "d2", Outcome: OutcomeCompleted},
	}
	if got := Assess(attempts, t0); got.Disposition != DispositionDone {
		t.Fatalf("got %s, want done", got.Disposition)
	}
}

func TestTooManyAttemptsIsExhaustedNotEndlessRetry(t *testing.T) {
	var attempts []Attempt
	for i := 0; i < MaxAttempts; i++ {
		attempts = append(attempts, Attempt{
			Node:    string(rune('a' + i)),
			Domain:  string(rune('A' + i)),
			Outcome: OutcomeAbandoned,
		})
	}
	if got := Assess(attempts, t0); got.Disposition != DispositionExhausted {
		t.Fatalf("got %s (%s), want exhausted", got.Disposition, got.Why)
	}
}

// A reassignment must resume from the furthest-along checkpoint, not from
// whichever happens to be first in the slice — restarting silently repeats
// work somebody already paid for.
func TestResumesFromTheNewestCheckpoint(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Domain: "d1", Outcome: OutcomeAbandoned,
			StartedAt: t0.Add(-3 * time.Hour), Checkpoint: "older"},
		{Node: "b", Domain: "d2", Outcome: OutcomeAbandoned,
			StartedAt: t0.Add(-1 * time.Hour), Checkpoint: "newer"},
	}
	got := Assess(attempts, t0)
	if got.ResumeFrom != "newer" {
		t.Fatalf("resumed from %q, want the newest checkpoint", got.ResumeFrom)
	}
}

func TestNoAttemptsMeansAssign(t *testing.T) {
	if got := Assess(nil, t0); got.Disposition != DispositionReassign {
		t.Fatalf("got %s, want reassign for an untried unit", got.Disposition)
	}
}

// Nobody is blamed for a defective unit. Otherwise the volunteers who accept
// the most work accumulate the most damage for doing exactly what was asked.
func TestPoisonBlamesNobody(t *testing.T) {
	failed := Attempt{Node: "a", Outcome: OutcomeFailed, Reason: "segfault"}
	if Blame(failed, DispositionPoison) {
		t.Error("a node was blamed for a unit judged defective")
	}
	if !Blame(failed, DispositionReassign) {
		t.Error("a genuine failure was not counted")
	}
}

func TestSuccessAndRunningAreNeverBlamed(t *testing.T) {
	for _, o := range []AttemptOutcome{OutcomeCompleted, OutcomeRunning} {
		if Blame(Attempt{Outcome: o}, DispositionDone) {
			t.Errorf("outcome %s was blamed", o)
		}
	}
}

// Two verifiers assessing the same attempts must reach the same decision, or
// the decision cannot be audited or disputed.
func TestAssessIsDeterministic(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Domain: "d1", Outcome: OutcomeFailed, Reason: "beta"},
		{Node: "b", Domain: "d2", Outcome: OutcomeFailed, Reason: "alpha"},
		{Node: "c", Domain: "d3", Outcome: OutcomeFailed, Reason: "alpha"},
		{Node: "d", Domain: "d4", Outcome: OutcomeFailed, Reason: "beta"},
	}
	first := Assess(attempts, t0)
	for i := 0; i < 50; i++ {
		if got := Assess(attempts, t0); got != first {
			t.Fatalf("run %d disagreed: %+v vs %+v", i, got, first)
		}
	}
}

// An unknown fault domain must not be assumed to be the same domain as every
// other unknown — that would suppress real poison entirely.
func TestUnknownDomainsCountSeparately(t *testing.T) {
	attempts := []Attempt{
		{Node: "a", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "b", Outcome: OutcomeFailed, Reason: "segfault"},
		{Node: "c", Outcome: OutcomeFailed, Reason: "segfault"},
	}
	if got := Assess(attempts, t0); got.Disposition != DispositionPoison {
		t.Fatalf("got %s (%s) — unknown domains were collapsed into one",
			got.Disposition, got.Why)
	}
}
