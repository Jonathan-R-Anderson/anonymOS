package p2p

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// The property the whole feature turns on. A node that has not measured its
// dispersal must produce NO placement block, so the coordinator can say "not
// reporting" -- rather than a zero-valued block, which renders as a node with no
// failures and a fully dispersed corpus. This project has already shipped that
// mistake once: a backlog counter that fell on schedule while every node stayed
// empty (roadmap phase 4.3, fault 5).
func TestAnUnobservedNodeSendsNoPlacementBlockAtAll(t *testing.T) {
	n := &Node{}
	if health := n.PlacementHealth(); health != nil {
		t.Fatalf("a node that has never run a pass claims to know its health: %+v", health)
	}
	if beacon := placementBeacon(n.PlacementHealth(), time.Now()); beacon != nil {
		t.Fatalf("an unobserved node built a placement beacon: %+v", beacon)
	}
}

// The same property one layer out -- absent must be a MISSING KEY on the wire,
// not a present object full of zeros -- is asserted against the real signed
// document in internal/heartbeat (TestANodeWithNoObservedPassSendsNoPlacementKey).
// It cannot be checked with a synthetic struct here: a typed nil pointer held in
// an `any` field is not empty as far as encoding/json is concerned, so such a
// test passes on the wrong thing and emits "placement":null regardless.

// A pass that found nothing wrong IS a measurement and must be reported. Going
// quiet when everything is fine would make a healthy node indistinguishable from
// a build that cannot report at all.
func TestAHealthyPassIsStillReported(t *testing.T) {
	n := &Node{}
	n.recordPlacementHealth(PlacementHealth{Objects: 12, FullyDispersed: 12, Peers: 9})
	health := n.PlacementHealth()
	if health == nil {
		t.Fatal("a completed pass with nothing to fix reported nothing")
	}
	if health.Objects != 12 || health.FullyDispersed != 12 {
		t.Fatalf("the pass was not recorded faithfully: %+v", health)
	}
	if health.ObservedAt.IsZero() {
		t.Error("the pass carries no observation time, so it can never go stale")
	}
}

// The reason is the point. "3 failures" sends an operator to SSH and grep; "3
// failures: storage capacity exceeded" is a fix. This asserts the reason survives
// from the peer's own error text, through the refusal map, into the JSON the
// coordinator receives.
func TestARefusalReasonReachesTheWire(t *testing.T) {
	n := &Node{}
	err := errors.New("store refused: storage capacity exceeded")
	reason := refusalReason(err)
	if reason == "" {
		t.Fatal("a peer answering 'capacity exceeded' was not classified as a refusal")
	}
	n.noteRefusal("12D3KooWFullDiskAAAAAAAAAAAAAAAA", reason)
	n.recordPlacementHealth(PlacementHealth{Peers: 3, Failed: 3})

	beacon := placementBeacon(n.PlacementHealth(), time.Now())
	if beacon == nil {
		t.Fatal("no beacon was built")
	}
	body, marshalErr := json.Marshal(beacon)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if !strings.Contains(string(body), "storage capacity exceeded") {
		t.Fatalf("the refusal reason never reached the wire: %s", body)
	}
	if len(beacon.Refusals) != 1 || beacon.Refusals[0].Count != 1 {
		t.Fatalf("the refusing peer was not counted: %+v", beacon.Refusals)
	}
}

// Each distinct answer must classify to its own phrase. Collapsing them would
// leave an operator knowing that three peers refuse and nothing about whether to
// free disk, fix a config or re-check the coordinator key -- which is exactly the
// week phase 4.3 was written after.
func TestEveryRefusalAnswerClassifiesToItsOwnPhrase(t *testing.T) {
	cases := map[string]string{
		"peer 12D3Koo: node is cache-only":                 "node is cache-only",
		"store rejected: storage capacity exceeded":        "storage capacity exceeded",
		"remote: node is draining, refusing new shards":    "node is draining",
		"lease: invalid coordinator lease signature":       "invalid coordinator lease signature",
		"shard was recalled recently, refusing":            "shard was recalled recently",
		"stream: unsupported operation":                    "unsupported operation",
		"rejected by this node":                            "rejected by this node",
		"dial backoff: no addresses for peer":              "",
		"context deadline exceeded":                        "",
		"i2p: tunnel build failed after 3 attempts":        "",
		"rejected by this node: storage capacity exceeded": "storage capacity exceeded",
		"EOF": "",
	}
	for text, want := range cases {
		if got := refusalReason(errors.New(text)); got != want {
			t.Errorf("%q classified as %q, wanted %q", text, got, want)
		}
	}
	if refusalReason(nil) != "" {
		t.Error("a nil error was classified as a refusal")
	}
}

// A dial that never completed is absence, not refusal, and must not appear in the
// report -- an operator chasing "peer X is refusing" when the truth is "the
// tunnel was busy" is chasing the wrong machine.
func TestAnUnreachablePeerIsNotReportedAsRefusing(t *testing.T) {
	n := &Node{}
	if answeredNo(errors.New("dial backoff")) {
		t.Fatal("an unreachable peer was counted as a refusal")
	}
	n.recordPlacementHealth(PlacementHealth{Peers: 4, Failed: 4})
	if report := n.PlacementHealth().Refusals; len(report) != 0 {
		t.Fatalf("a pass with no refusals reported some: %+v", report)
	}
}

// The report is bounded and ordered, because it is signed and sent by every node
// on the network every five minutes. Worst first so truncation keeps the peers
// doing the most damage, and stably ordered so a heartbeat does not appear to
// change every time Go reshuffles a map.
func TestTheRefusalReportIsBoundedAndWorstFirst(t *testing.T) {
	n := &Node{}
	for i := 0; i < maxReportedRefusals+4; i++ {
		peer := "12D3KooWPeer" + string(rune('A'+i)) + "AAAAAAAAAAAAAAAAAAAA"
		for r := 0; r <= i; r++ {
			n.noteRefusal(peer, "node is cache-only")
		}
	}
	report := n.refusalReport(maxReportedRefusals)
	if len(report) != maxReportedRefusals {
		t.Fatalf("report was not capped: %d entries", len(report))
	}
	for i := 1; i < len(report); i++ {
		if report[i-1].Count < report[i].Count {
			t.Fatalf("report is not worst-first: %+v", report)
		}
	}
	for _, entry := range report {
		if len(entry.Peer) != refusalPeerIDLength {
			t.Errorf("peer id was not shortened for the wire: %q", entry.Peer)
		}
	}
}

// A grudge that has expired is a peer already back in the candidate set.
// Reporting it would send an operator after a problem that fixed itself.
func TestAnExpiredRefusalIsNotReported(t *testing.T) {
	n := &Node{}
	const peer = "12D3KooWWasBrokenNowFixed"
	n.noteRefusal(peer, "node is cache-only")
	n.refusalMu.Lock()
	n.refusals[peer].last = time.Now().Add(-refusalCooldown - time.Minute)
	n.refusalMu.Unlock()
	if report := n.refusalReport(maxReportedRefusals); len(report) != 0 {
		t.Fatalf("an expired refusal is still on the report: %+v", report)
	}
}

// An unreadable recall ledger must arrive as an ABSENT count, never as zero
// outstanding. The recall counters exist because an unreadable row used to
// vanish from every total; reporting the whole ledger as zero would reintroduce
// that at the fleet level.
func TestAnUnknownRecallLedgerIsOmittedRatherThanZeroed(t *testing.T) {
	beacon := placementBeacon(&PlacementHealth{Objects: 5, Recalls: nil}, time.Now())
	if beacon.RecallsOutstanding != nil {
		t.Fatal("an unreadable recall ledger reported a count anyway")
	}
	body, err := json.Marshal(beacon)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "recalls_outstanding") {
		t.Fatalf("an unknown recall count still reached the wire: %s", body)
	}

	// A ledger that CAN be read reports zero as a real measurement.
	beacon = placementBeacon(&PlacementHealth{Recalls: &store.RecallSummary{}}, time.Now())
	if beacon.RecallsOutstanding == nil || *beacon.RecallsOutstanding != 0 {
		t.Fatal("a readable, empty recall ledger did not report zero")
	}
}

// The age is what makes a node that has stopped passing visibly stale instead of
// quietly authoritative.
func TestTheBeaconCarriesTheAgeOfThePass(t *testing.T) {
	now := time.Now()
	beacon := placementBeacon(
		&PlacementHealth{ObservedAt: now.Add(-7 * time.Minute)}, now)
	if beacon.AgeSeconds != 420 {
		t.Fatalf("age was %d seconds, wanted 420", beacon.AgeSeconds)
	}
	// A clock stepping backwards must not produce a pass from the future.
	beacon = placementBeacon(&PlacementHealth{ObservedAt: now.Add(time.Hour)}, now)
	if beacon.AgeSeconds != 0 {
		t.Fatalf("a backwards clock produced age %d", beacon.AgeSeconds)
	}
}
