// Package incident is E16.4's exercise: the incident-response procedure, run
// against a simulated relay compromise.
//
// It is a test-only package, like internal/axon/telemetry. There is nothing to
// build -- the deliverable is that the procedure in INCIDENT-RESPONSE.md has
// been EXECUTED once rather than only written, and that what it could not do is
// on the record.
//
// E16.4: "A published incident-response procedure exists and has been exercised
// once against a simulated relay compromise."
//
// WHY A TEST AND NOT A WRITE-UP. A tabletop exercise produces an opinion about
// what the code would do. This produces the answer. The three findings in
// INCIDENT-RESPONSE.md's last section all came from steps that failed to
// execute here, and none of them were visible from reading the runbook.
//
// WHAT THIS DOES NOT ESTABLISH. It exercises the procedure against the CODE, on
// one machine, with a synthetic pool. It does not exercise the human half --
// who is called, who decides, how long any of it takes -- and E16.4's "exercised"
// arguably means a drill with an operator in it. That half is not done and is
// not claimed.
package incident

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/contain"
	"github.com/syndichan/maniwani/storage-client/internal/axon/path"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
	"github.com/syndichan/maniwani/storage-client/internal/axon/profile"
)

// The compromised relay. One node id, carried through every step, because the
// procedure's whole question is "where does this thing appear".
const compromised = "relay-07"

// pool builds a synthetic relay set: `n` relays, each in its own /16 and ASN so
// the diversity ladder admits them and the drill is about compromise rather
// than about the constraint.
//
// A /16 PER RELAY, NOT A /24, and the drill got this wrong on its first run --
// which is itself worth recording, because it is the kind of mistake a responder
// makes under pressure. §8.7 gives PATHS a /16 failure domain while the
// annotation stores §7.5's /24 replication width: "the same relay is a /24 to
// the placement planner and a /16 to the path selector". Twenty-four relays in
// 198.51.x.10 are twenty-four distinct /24s and ONE /16, so no 3-hop path
// existed and ExactCompromise correctly reported all the mass as NoPath.
func pool(t *testing.T, n int) []path.Relay {
	t.Helper()
	out := make([]path.Relay, 0, n)
	for i := 0; i < n; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i), 0, 10})
		ann, err := peer.Annotate(addr)
		if err != nil {
			t.Fatalf("annotate %s: %v", addr, err)
		}
		ann.ASN = uint32(64500 + i)
		ann.ASNSource = peer.ASNSourceTable
		out = append(out, path.Relay{NodeID: relayID(i), Ann: ann})
	}
	return out
}

func relayID(i int) string {
	return "relay-" + twoDigits(i)
}

func twoDigits(i int) string {
	const d = "0123456789"
	return string([]byte{d[(i/10)%10], d[i%10]})
}

// TestE164Step1DetectWhereTheRelayAppears is step 1.
//
// A relay is a member of four separate structures with four separate lifetimes,
// and an operator who clears one and believes they are done has cleared one.
func TestE164Step1DetectWhereTheRelayAppears(t *testing.T) {
	relays := pool(t, 24)

	// The path selector's candidate pool.
	inPool := false
	for _, r := range relays {
		if r.NodeID == compromised {
			inPool = true
		}
	}
	if !inPool {
		t.Fatal("drill setup: the compromised relay is not in the pool")
	}

	// The local profile store. Observations exist because this node used it.
	profiles := profile.New(nil)
	if err := profiles.Observe(compromised, profile.ObsExtendRTT, 0.25, time.Now()); err != nil {
		t.Fatalf("drill setup: %v", err)
	}

	if _, ok := profiles.Get(compromised); !ok {
		t.Error("step 1: the relay has no profile entry, so the drill is not " +
			"exercising a relay this node actually used")
	}
	t.Logf("step 1: the relay is present in the candidate pool and the profile store")
}

// TestE164Step2BlastRadiusIsANumber is step 2, and the step that works.
//
// The procedure says to read the exposure BEFORE containing, because removal
// changes the pool and the number needed is the one that was true while the
// relay was in it. This asserts that the number is computable and that it is not
// a placeholder.
func TestE164Step2BlastRadiusIsANumber(t *testing.T) {
	relays := pool(t, 24)
	c := path.Default()
	uniform := func(path.Relay) float64 { return 1 }
	hostile := func(r path.Relay) bool { return r.NodeID == compromised }

	m := path.ExactCompromise(relays, 3, c, uniform, hostile)

	// One hostile relay in 24, three hops: AnyHop must be materially non-zero
	// and FirstAndLast must be much smaller. If either is zero the model is not
	// being driven and the step is theatre.
	if m.AnyHop <= 0 {
		t.Fatal("step 2: AnyHop is zero with a hostile relay in the pool — the " +
			"blast-radius step is not actually computing anything")
	}
	if m.FirstAndLast != 0 {
		t.Errorf("step 2: FirstAndLast is %g with ONE hostile relay; a single "+
			"relay cannot be both entry and exit, so this should be zero",
			m.FirstAndLast)
	}
	if m.AnyHop >= 1 {
		t.Errorf("step 2: AnyHop is %g — every path hostile from one relay in 24 "+
			"is not credible", m.AnyHop)
	}
	t.Logf("step 2: with 1 of %d relays hostile over 3 hops — AnyHop=%.4f "+
		"FirstAndLast=%.4f NoPath=%.4f", len(relays), m.AnyHop, m.FirstAndLast, m.NoPath)

	// And the correlation case the procedure says matters most: two hostile
	// relays, so entry and exit can both be theirs.
	twoHostile := func(r path.Relay) bool {
		return r.NodeID == compromised || r.NodeID == relayID(8)
	}
	m2 := path.ExactCompromise(relays, 3, c, uniform, twoHostile)
	if m2.FirstAndLast <= 0 {
		t.Error("step 2: FirstAndLast is zero with TWO hostile relays; the " +
			"correlation case is not being modelled")
	}
	t.Logf("step 2: with 2 hostile — AnyHop=%.4f FirstAndLast=%.4f",
		m2.AnyHop, m2.FirstAndLast)
}

// TestE164Step3ContainmentWorks is step 3, and it did not always.
//
// THE FIRST RUN OF THIS DRILL FOUND NO CONTAINMENT MECHANISM: dht.Table had
// Admit and no counterpart, peer.Peerbook had Observe and no counterpart, and
// profile.Forget dropped observations while leaving the peer exactly as
// selectable as before. Item 4.10b closed it with internal/axon/contain.
//
// A NOTE ON HOW THIS TEST USED TO BE WRITTEN, because it is the same defect the
// telemetry audit had. It recorded the missing API with t.Log and PASSED --
// narrating a finding rather than asserting it -- so when the API landed the
// drill went on reporting that it did not exist. A log line is not a guard. It
// now asserts the behaviour, so a regression fails here.
func TestE164Step3ContainmentWorks(t *testing.T) {
	relays := pool(t, 24)

	// The responder contains the relay, with a reason, and saves it.
	dir := t.TempDir()
	list := contain.New()
	if err := list.Deny(compromised, "drill: simulated relay compromise", time.Now()); err != nil {
		t.Fatalf("step 3: %v", err)
	}
	if err := list.Save(dir); err != nil {
		t.Fatalf("step 3: %v", err)
	}

	// The peerbook refuses it, and a sweep drops what was already recorded.
	pb := peer.NewPeerbook(nil, 1)
	pb.SetContainment(list)
	err := pb.Observe(compromised, []netip.Addr{netip.MustParseAddr("10.7.0.10")},
		peer.Evidence{
			Probers:   []peer.ProberID{"prober-a", "prober-b"},
			Networks:  []string{"net-1", "net-2"},
			At:        time.Unix(1_700_000_000, 0),
			Reachable: true,
		})
	if err == nil {
		t.Error("step 3: the peerbook accepted an observation about a contained peer")
	}

	// The routing table refuses it too, across a restart -- which is the point:
	// the old procedure said to restart the node, and an in-memory denial would
	// have been erased by the very act prescribed to enforce it.
	reloaded, err := contain.Load(dir)
	if err != nil {
		t.Fatalf("step 3: containment did not survive the restart: %v", err)
	}
	if !reloaded.Denied(compromised) {
		t.Error("step 3: the relay is not contained after a restart")
	}

	// The selector's pool. Item 4.10c gave Candidates an owner, so the relay is
	// kept out of selection by the containment list rather than by the caller
	// remembering to filter.
	//
	// ASSERTED, NOT LOGGED. Three findings in this file were first written as
	// t.Log and went stale the moment the gap they described was closed -- the
	// drill kept reporting a missing API that by then existed. Every step now
	// asserts the behaviour it claims.
	src := &path.Source{
		Peers:  &poolBook{relays: relays},
		Policy: path.PoolPolicy{Contained: list},
	}
	sel := &path.Selector{Candidates: src.Candidates}
	for i := 0; i < 25; i++ {
		got, _, err := sel.SelectPath(context.Background(), 3, path.Default(), path.WeightPolicy{})
		if err != nil {
			t.Fatalf("step 3: %v", err)
		}
		for _, r := range got {
			if r.NodeID == compromised {
				t.Fatal("step 3: the contained relay was selected")
			}
		}
	}
	if rep := src.LastReport(); rep.Contained != 1 {
		t.Errorf("step 3: the pool report does not name the containment: %+v", rep)
	}
	t.Log("step 3: contained in the peerbook, the routing table and the path " +
		"selector's pool, across a restart")
}

// poolBook adapts the drill's synthetic relays to a path.PeerSource, so step 3
// exercises the real Source/PoolPolicy path rather than a hand-filtered slice.
type poolBook struct{ relays []path.Relay }

func (b *poolBook) Entries() []peer.PeerEntry {
	out := make([]peer.PeerEntry, 0, len(b.relays))
	for _, r := range b.relays {
		out = append(out, peer.PeerEntry{
			NodeID:      r.NodeID,
			Annotations: []peer.Annotation{r.Ann},
			ReachState:  peer.ReachReachable,
		})
	}
	return out
}

// TestE164Step3TheBootstrapPathIsCheckedToo.
//
// The exercise's second finding: step 3's fallback was "restart the node", on
// the reasoning that the routing table and peerbook are in memory. The bootstrap
// peer cache is NOT -- it was added for T16.2 and persists the last accepted
// peer set precisely so a restart still joins -- so a contained host came back
// through a path that consulted nothing.
//
// Closed by item 4.10e. Asserted here rather than narrated, because the version
// of this test that merely LOGGED the finding went on reporting it for two days
// after the fix landed.
func TestE164Step3TheBootstrapPathIsCheckedToo(t *testing.T) {
	body := readProcedure(t)
	// The two-identity trap is now a MECHANISM rather than an instruction, so
	// the runbook must point at the call and not at a pair of ids to remember.
	// Item 4.10f: telling a responder under pressure to type two Deny calls is
	// not a fix.
	for _, want := range []string{"ContainmentIDs", "DenyAll", "all or nothing"} {
		if !contains(body, want) {
			t.Errorf("INCIDENT-RESPONSE.md does not mention %q — containing a "+
				"host in every structure has to be one call, not a paragraph "+
				"asking somebody to remember both spellings", want)
		}
	}
	// And it must no longer tell anyone to delete the cache by hand, which is
	// the instruction 4.10e replaced.
	if contains(body, "delete\n`bootstrap-peers.json`") {
		t.Error("the runbook still says to delete bootstrap-peers.json by hand")
	}
}

// TestE164Step5ReportPassesTheClaimChecker.
//
// S13 forbids four words and forbids an unscoped anonymity claim, and an
// incident report is the document most likely to contain one -- "users were not
// deanonymised" is the sentence everybody reaches for on day one. The procedure
// says to run check-claims.py; this asserts the procedure ITSELF passes it, so
// the runbook is not modelling the thing it forbids.
func TestE164Step5ReportPassesTheClaimChecker(t *testing.T) {
	// The checker is a Python script and is run in CI, not from here. What is
	// checkable in Go is that the procedure names it, so a responder is told to
	// run it rather than left to remember.
	body := readProcedure(t)
	for _, want := range []string{"check-claims.py", "S13"} {
		if !contains(body, want) {
			t.Errorf("INCIDENT-RESPONSE.md does not mention %q, so nothing tells "+
				"a responder what governs the write-up", want)
		}
	}
}

// TestE164ProcedureIsPublished is the other half of E16.4: it must EXIST.
func TestE164ProcedureIsPublished(t *testing.T) {
	body := readProcedure(t)
	// The named case. E16.4 is specific about it.
	if !contains(body, "relay") {
		t.Error("the procedure does not cover a relay compromise, which is the " +
			"case E16.4 names")
	}
	// And it must be honest about what was not exercised, or "exercised once"
	// reads as more than it is.
	if !contains(body, "NOT exercised") {
		t.Error("the procedure does not say which classes went unexercised")
	}
}

// TestE164Step2ZeroExposureCanMeanNoPathAtAll pins the trap the exercise fell
// into, because a responder will fall into it too.
//
// A pool with no drawable path reports AnyHop=0 and FirstAndLast=0 -- the same
// two numbers a SAFE network reports. Read alone they say "no exposure"; what
// they actually say is "no path". NoPath is the field that distinguishes them,
// which is why ExactCompromise reports it separately rather than folding it in.
//
// The exercise hit this for real: its first pool put 24 relays in 24 distinct
// /24s, which is ONE /16, and §8.7 gives paths a /16 failure domain. Every
// blast-radius number came back zero from a pool where nothing could be routed.
func TestE164Step2ZeroExposureCanMeanNoPathAtAll(t *testing.T) {
	// The mistake, reproduced: distinct /24s, one /16.
	var oneSixteen []path.Relay
	for i := 0; i < 24; i++ {
		addr := netip.AddrFrom4([4]byte{198, 51, byte(i), 10})
		ann, err := peer.Annotate(addr)
		if err != nil {
			t.Fatal(err)
		}
		ann.ASN = uint32(64500 + i)
		ann.ASNSource = peer.ASNSourceTable
		oneSixteen = append(oneSixteen, path.Relay{NodeID: relayID(i), Ann: ann})
	}

	uniform := func(path.Relay) float64 { return 1 }
	hostile := func(r path.Relay) bool { return r.NodeID == compromised }
	m := path.ExactCompromise(oneSixteen, 3, path.Default(), uniform, hostile)

	if m.AnyHop != 0 || m.FirstAndLast != 0 {
		t.Fatalf("drill: expected the no-path pool to report zero exposure, got "+
			"AnyHop=%g FirstAndLast=%g", m.AnyHop, m.FirstAndLast)
	}
	if m.NoPath == 0 {
		t.Fatal("NoPath is zero on a pool where no path exists — the field that " +
			"distinguishes 'safe' from 'nothing was measured' is not working, and " +
			"step 2 of the procedure cannot be trusted")
	}
	t.Logf("step 2 FINDING: AnyHop=%g FirstAndLast=%g NoPath=%g — the first two "+
		"are what a SAFE network reports. Read NoPath first.",
		m.AnyHop, m.FirstAndLast, m.NoPath)

	// And the procedure must say so, or the finding dies with this test.
	body := readProcedure(t)
	if !contains(body, "NoPath") {
		t.Error("INCIDENT-RESPONSE.md does not mention NoPath, so a responder is " +
			"not told that zero exposure can mean no path was drawable")
	}
}

// TestE164TheHumanHalfIsRunnable is 4.10d.
//
// The code half of E16.4 is discharged by the tests above. The half with a
// person in it -- who is called, who decides, how long it takes -- is NOT, and
// a test cannot discharge it. What a test CAN do is stop it from being
// forgotten, and stop the drill script from rotting into a page nobody could
// actually run.
//
// So this asserts the script exists, still names the things a drill needs to be
// a drill rather than a description of one, and STILL SAYS IT HAS NOT BEEN RUN.
// The last one is the point: when somebody runs it and fills in the record
// sheet, this test fails, and clearing it means updating E16.4's status
// deliberately rather than letting a claim drift in.
func TestE164TheHumanHalfIsRunnable(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(), "INCIDENT-DRILL.md"))
	if err != nil {
		t.Fatalf("E16.4's human half has no drill script: %v", err)
	}
	script := string(body)

	// A drill needs these to be one. Without injects it is a reading; without
	// measures it produces no evidence; without roles the interesting failure
	// -- a step only one person can do -- cannot surface.
	for _, want := range []string{
		"Injects",      // events delivered without warning
		"Roles",        // and a recorder who does not help
		"Record sheet", // where the findings land
		"T-contain",    // the step most likely to be slow
		"check-claims", // S13 governs the write-up
	} {
		if !contains(script, want) {
			t.Errorf("INCIDENT-DRILL.md does not mention %q, so it is a "+
				"description of a drill rather than one that can be run", want)
		}
	}

	// It must not quietly claim to have happened.
	if !contains(script, "NOT yet run") {
		t.Error("INCIDENT-DRILL.md no longer says it is unrun. If it HAS been " +
			"run, that is good news and this test is what makes you say so on " +
			"purpose: fill in the record sheet, update E16.4's status in " +
			"roadmap/, and change this assertion to match.")
	}
}
