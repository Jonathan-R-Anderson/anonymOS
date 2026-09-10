package peer

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func okProbe(context.Context, string, []netip.Addr) (bool, error)     { return true, nil }
func refuseProbe(context.Context, string, []netip.Addr) (bool, error) { return false, ErrProbeRefused }
func timeoutProbe(context.Context, string, []netip.Addr) (bool, error) {
	return false, context.DeadlineExceeded
}

func threeProbers(f ProbeFunc) []ProberRef {
	return []ProberRef{
		{ID: "p1", Network: "n1", Probe: f},
		{ID: "p2", Network: "n2", Probe: f},
		{ID: "p3", Network: "n3", Probe: f},
	}
}

// TestRefusedProbeMarksUnreachableWithinOneInterval is T3.2: a peer CLAIMING
// reachability that refuses the probe is marked unreachable within one probe
// interval.
func TestRefusedProbeMarksUnreachableWithinOneInterval(t *testing.T) {
	book := NewPeerbook(nil, 1)
	p := &Prober{Book: book, Interval: time.Minute, Probers: threeProbers(refuseProbe)}

	// The peer first establishes a reachable mark, so the test proves the
	// refusal REVOKES one rather than merely failing to create it.
	if err := book.Observe("peer-1", addrs("198.51.100.10"), Evidence{
		Probers: []ProberID{"p1", "p2"}, Networks: []string{"n1", "n2"}, Reachable: true, At: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if e, _ := book.Get("peer-1"); e.ReachState != ReachReachable {
		t.Fatalf("setup: state = %s, want reachable", e.ReachState)
	}

	start := time.Now()
	out, err := p.Round(context.Background(), "peer-1", addrs("198.51.100.10"), true /* claimed */)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if out.Refusals != 3 {
		t.Fatalf("refusals = %d, want 3", out.Refusals)
	}
	if !out.Recorded {
		t.Fatalf("refusal round was not recorded: %s", out.Reason)
	}
	e, ok := book.Get("peer-1")
	if !ok {
		t.Fatal("peer vanished from the peerbook")
	}
	if e.ReachState != ReachUnreachable {
		t.Fatalf("T3.2 violated: state = %s after a refused probe, want unreachable", e.ReachState)
	}
	if elapsed >= p.interval() {
		t.Fatalf("verdict took %v, longer than one probe interval %v", elapsed, p.interval())
	}
	if out.Claimed != true {
		t.Fatal("the peer's own claim was lost from the outcome")
	}
}

// TestTimeoutIsAlsoAFailure: a probe that never answers has the same
// consequence as a refusal, with a different operator message.
func TestTimeoutIsAlsoAFailure(t *testing.T) {
	book := NewPeerbook(nil, 2)
	p := &Prober{Book: book, Probers: threeProbers(timeoutProbe)}

	out, err := p.Round(context.Background(), "peer-2", addrs("198.51.100.11"), true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Refusals != 0 {
		t.Fatalf("a timeout was counted as a refusal (%d)", out.Refusals)
	}
	e, _ := book.Get("peer-2")
	if e.ReachState != ReachUnreachable {
		t.Fatalf("state = %s after every probe timed out, want unreachable", e.ReachState)
	}
}

// TestSuccessfulProbeMarksReachable is the positive control.
func TestSuccessfulProbeMarksReachable(t *testing.T) {
	book := NewPeerbook(nil, 3)
	p := &Prober{Book: book, Probers: threeProbers(okProbe)}

	out, err := p.Round(context.Background(), "peer-3", addrs("198.51.100.12"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Reachable || !out.Recorded {
		t.Fatalf("outcome = %+v, want reachable and recorded", out)
	}
	e, _ := book.Get("peer-3")
	if e.ReachState != ReachReachable {
		t.Fatalf("state = %s, want reachable", e.ReachState)
	}
	if e.ProbeQuorum < MinProbeQuorum {
		t.Fatalf("E3.3 violated: recorded quorum %d", e.ProbeQuorum)
	}
}

// TestPartialRefusalStillCountsTheSuccess: one prober succeeding is a
// successful dial-back, and a peer that refuses two of three probers but
// answers the third is reachable. The refusal is evidence about the refuser's
// willingness, not proof the peer is down.
func TestPartialRefusalStillCountsTheSuccess(t *testing.T) {
	book := NewPeerbook(nil, 4)
	p := &Prober{Book: book, Probers: []ProberRef{
		{ID: "p1", Network: "n1", Probe: refuseProbe},
		{ID: "p2", Network: "n2", Probe: refuseProbe},
		{ID: "p3", Network: "n3", Probe: okProbe},
	}}
	out, err := p.Round(context.Background(), "peer-4", addrs("198.51.100.13"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Reachable {
		t.Fatal("a completed dial-back was outweighed by refusals")
	}
	if out.Refusals != 2 {
		t.Fatalf("refusals = %d, want 2", out.Refusals)
	}
}

// TestThinRoundIsNotRecorded: a round from too few or too-correlated probers
// writes nothing, so E3.3 cannot be violated by the prober path either.
func TestThinRoundIsNotRecorded(t *testing.T) {
	book := NewPeerbook(nil, 5)

	single := &Prober{Book: book, Probers: []ProberRef{{ID: "p1", Network: "n1", Probe: okProbe}}}
	out, err := single.Round(context.Background(), "peer-5", addrs("198.51.100.14"), true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Recorded {
		t.Fatal("a single-prober round was recorded")
	}
	if _, ok := book.Get("peer-5"); ok {
		t.Fatal("E3.3 violated: an entry exists from a single-prober round")
	}

	oneNet := &Prober{Book: book, Probers: []ProberRef{
		{ID: "p1", Network: "n1", Probe: okProbe},
		{ID: "p2", Network: "n1", Probe: okProbe},
		{ID: "p3", Network: "n1", Probe: okProbe},
	}}
	out, err = oneNet.Round(context.Background(), "peer-6", addrs("198.51.100.15"), true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Recorded {
		t.Fatal("T3.4 violated: a single-network coalition produced a recorded mark")
	}
	if _, ok := book.Get("peer-6"); ok {
		t.Fatal("a single-network coalition created a peerbook entry")
	}
}

// TestClaimDoesNotInfluenceVerdict: the peer's advertisement is logged and
// ignored. Probing exists precisely so the probed node's word does not count.
func TestClaimDoesNotInfluenceVerdict(t *testing.T) {
	book := NewPeerbook(nil, 6)
	p := &Prober{Book: book, Probers: threeProbers(refuseProbe)}

	claimed, err := p.Round(context.Background(), "peer-7", addrs("198.51.100.16"), true)
	if err != nil {
		t.Fatal(err)
	}
	unclaimed, err := p.Round(context.Background(), "peer-8", addrs("198.51.100.17"), false)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Reachable != unclaimed.Reachable {
		t.Fatalf("the peer's own claim changed the verdict: %v vs %v", claimed.Reachable, unclaimed.Reachable)
	}
}
