package main

// The filing tool decides what number enters a derivation that ends in an
// immutable constructor argument. These tests exist because a wrong value here
// cannot be corrected after deployment.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

// writeEvents builds an observer log. Depth and spacing are explicit so a test
// can state the answer it expects rather than deriving it the same way the code
// under test does — which would only prove the code agrees with itself.
func writeEvents(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func event(unix, height int64, depth int) string {
	return fmt.Sprintf(`{"detected_unix":%d,"at_height":%d,"depth":%d,`+
		`"head_at_detection":%d,"detected_by":"parent-linkage"}`, unix, height-1, depth, height)
}

func TestReorgReconstructionMatchesTheObserversFormula(t *testing.T) {
	// 101 blocks spanned inclusive, 1200 seconds apart -> 1200/100 = 12s.
	// Chosen so the expected interval is exact and stated here, not computed
	// by the same expression being tested.
	path := writeEvents(t,
		event(1_000_000, 1000, 1),
		event(1_000_600, 1050, 1),
		event(1_001_200, 1100, 1),
	)
	obs, err := readReorgObservation(path)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Reorgs != 3 {
		t.Errorf("reorgs %d, want 3", obs.Reorgs)
	}
	if obs.MaxDepth != 1 {
		t.Errorf("max depth %d, want 1", obs.MaxDepth)
	}
	if obs.Blocks != 101 {
		t.Errorf("blocks %d, want 101 (span is inclusive)", obs.Blocks)
	}
	if obs.BlockInterval != 12*time.Second {
		t.Errorf("interval %v, want 12s (span / blocks-1)", obs.BlockInterval)
	}
	if obs.MaxDepthTime != 12*time.Second {
		t.Errorf("max depth time %v, want 12s", obs.MaxDepthTime)
	}
}

func TestTheDeepestReorgWinsNotTheLast(t *testing.T) {
	// Measured is the WORST case. A later, shallower event must not overwrite it.
	path := writeEvents(t,
		event(1_000_000, 1000, 1),
		event(1_000_600, 1050, 4),
		event(1_001_200, 1100, 1),
	)
	obs, err := readReorgObservation(path)
	if err != nil {
		t.Fatal(err)
	}
	if obs.MaxDepth != 4 {
		t.Fatalf("max depth %d, want 4", obs.MaxDepth)
	}
	if want := 4 * 12 * time.Second; obs.MaxDepthTime != want {
		t.Errorf("max depth time %v, want %v", obs.MaxDepthTime, want)
	}
}

func TestAMalformedLogIsRefusedNotSkipped(t *testing.T) {
	// Silently skipping a bad line would shrink the sample and change the
	// interval, producing a plausible number from an incomplete file.
	path := writeEvents(t,
		event(1_000_000, 1000, 1),
		`{"detected_unix":"not-a-number"}`,
		event(1_001_200, 1100, 1),
	)
	if _, err := readReorgObservation(path); err == nil {
		t.Fatal("a malformed line was accepted")
	}
}

func TestAnEmptyLogIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReorgObservation(path); err == nil {
		t.Fatal("an empty log produced an observation")
	}
}

func TestASingleEventCannotFileAReorgAsCostless(t *testing.T) {
	// One event spans one block, so there is no interval to divide by and
	// MaxDepthTime would be zero — the claim that surviving a reorganisation
	// costs no time. The same guard chainprobe.finishObservation applies.
	path := writeEvents(t, event(1_000_000, 1000, 1))
	_, err := readReorgObservation(path)
	if err == nil {
		t.Fatal("a single observation was filed")
	}
	if !strings.Contains(err.Error(), "costless") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func TestTheRawLogIsNeverModified(t *testing.T) {
	path := writeEvents(t,
		event(1_000_000, 1000, 1),
		event(1_001_200, 1100, 1),
	)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readReorgObservation(path); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the observer's log was modified by reading it")
	}
}

// ---- the envelope and the outage commitment ---------------------------------

func productionEnvelope() channel.OperatingEnvelope {
	return channel.OperatingEnvelope{
		Channels: 1000, Watchtowers: 2, SweepInterval: 30 * time.Second,
		OnCall:         "A designated operator is responsible for watchtower incidents.",
		OnCallResponse: 15 * time.Minute,
	}
}

func TestTheProductionEnvelopeIsStated(t *testing.T) {
	if err := productionEnvelope().Stated(); err != nil {
		t.Fatalf("the production envelope does not satisfy Stated(): %v", err)
	}
	// And it is NOT the test envelope: 1000/2/30s are the operator's numbers.
	if productionEnvelope().SweepInterval != 30*time.Second {
		t.Error("the sweep interval is not the stated production value")
	}
}

func TestAnEnvelopeWithoutAnOnCallCommitmentIsRefused(t *testing.T) {
	// The outage term is a promise about people. Without one there is nothing
	// to validate, and the envelope says so rather than defaulting.
	for _, tc := range []struct {
		name string
		mut  func(*channel.OperatingEnvelope)
	}{
		{"no on-call text", func(e *channel.OperatingEnvelope) { e.OnCall = "" }},
		{"no response time", func(e *channel.OperatingEnvelope) { e.OnCallResponse = 0 }},
		{"no channel count", func(e *channel.OperatingEnvelope) { e.Channels = 0 }},
		{"no watchtowers", func(e *channel.OperatingEnvelope) { e.Watchtowers = 0 }},
		{"no sweep interval", func(e *channel.OperatingEnvelope) { e.SweepInterval = 0 }},
	} {
		env := productionEnvelope()
		tc.mut(&env)
		if err := env.Stated(); err == nil {
			t.Errorf("%s: the envelope was accepted anyway", tc.name)
		}
	}
}

// ---- what filing actually achieves ------------------------------------------

func TestFilingBothTermsLeavesExactlyTheFourMeasurementsOutstanding(t *testing.T) {
	// The point of phase 1: six terms become four, and NOT five or three.
	now := time.Now().Unix()
	env := productionEnvelope()
	v := channel.NewValidatedBudget(mainnet, channel.MainnetChallengeBudget(), env)

	obs, err := readReorgObservation("/home/bruns/p12-reorg/data/events.jsonl")
	if err != nil {
		t.Skipf("the real observer log is not present here: %v", err)
	}
	reorgEv, err := obs.AsEvidence(mainnet, now)
	if err != nil {
		t.Fatalf("reorg evidence: %v", err)
	}
	if err := v.Record(reorgEv); err != nil {
		t.Fatalf("recording reorg: %v", err)
	}
	if err := v.Record(channel.Evidence{
		Term: "watchtower outage", Measured: env.OnCallResponse,
		Samples: channel.MinEvidenceSamples, ChainID: mainnet,
		Method: "operational commitment", TakenAt: now, AtChannels: env.Channels,
	}); err != nil {
		t.Fatalf("recording outage: %v", err)
	}

	got := map[string]bool{}
	for _, term := range v.Unvalidated(now) {
		got[term] = true
	}
	for _, want := range []string{"detection", "inclusion", "repricing", "rpc failure"} {
		if !got[want] {
			t.Errorf("%q should still be unvalidated", want)
		}
	}
	for _, gone := range []string{"reorg depth", "watchtower outage"} {
		if got[gone] {
			t.Errorf("%q was filed but still counts as unvalidated", gone)
		}
	}
}

func TestTheGateStillRefusesWithoutCanonicality(t *testing.T) {
	// Filing evidence must not open the gate on its own. Canonicality is a
	// separate, human-supplied declaration and this tool never sets it.
	now := time.Now().Unix()
	env := productionEnvelope()
	v := channel.NewValidatedBudget(mainnet, channel.MainnetChallengeBudget(), env)
	if _, err := v.DeployableChallengePeriod(now); err == nil {
		t.Fatal("the gate opened with no canonicality and no evidence")
	}
}
