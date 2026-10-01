package peer

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/contain"
)

// TestForgetWithoutDenyingIsTheatre: the next probe re-creates the entry.
func TestForgetWithoutDenyingIsTheatre(t *testing.T) {
	pb := NewPeerbook(nil, 1)
	addrs := []netip.Addr{netip.MustParseAddr("198.51.100.7")}
	if err := pb.Observe("relay-07", addrs, goodEvidence(true)); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !pb.Forget("relay-07") {
		t.Fatal("Forget says there was no entry")
	}
	if _, ok := pb.Get("relay-07"); ok {
		t.Fatal("Forget left the entry")
	}
	// Back on the next probe, because nothing denied it.
	if err := pb.Observe("relay-07", addrs, goodEvidence(true)); err != nil {
		t.Fatalf("re-Observe: %v", err)
	}
	if _, ok := pb.Get("relay-07"); !ok {
		t.Fatal("the peer did not come back, so this test is not testing what it claims")
	}
	t.Log("confirmed: Forget alone is undone by the next probe")
}

// TestContainedPeerIsRefusedOnObservation.
func TestContainedPeerIsRefusedOnObservation(t *testing.T) {
	pb := NewPeerbook(nil, 1)
	l := contain.New()
	if err := l.Deny("relay-07", "drill: simulated relay compromise", time.Now()); err != nil {
		t.Fatal(err)
	}
	pb.SetContainment(l)

	addrs := []netip.Addr{netip.MustParseAddr("198.51.100.7")}
	err := pb.Observe("relay-07", addrs, goodEvidence(true))
	if !errors.Is(err, ErrContained) {
		t.Fatalf("Observe of a contained peer: %v, want ErrContained", err)
	}
	if _, ok := pb.Get("relay-07"); ok {
		t.Error("a contained peer entered the peerbook")
	}
	// An uncontained peer is unaffected.
	if err := pb.Observe("relay-08", addrs, goodEvidence(true)); err != nil {
		t.Errorf("an uncontained peer was refused: %v", err)
	}
}

// TestContainmentIsCheckedBeforeTheQuorum.
//
// The quorum decides whether an observation is BELIEVABLE; containment decides
// whether this node will act on it at all. A contained peer whose evidence is
// also too thin should report containment, or an operator debugging it is sent
// to look at probe coverage instead of at their own decision.
func TestContainmentIsCheckedBeforeTheQuorum(t *testing.T) {
	pb := NewPeerbook(nil, 1)
	l := contain.New()
	if err := l.Deny("relay-07", "seized", time.Now()); err != nil {
		t.Fatal(err)
	}
	pb.SetContainment(l)

	thin := Evidence{
		Probers:   []ProberID{"prober-a"},
		Networks:  []string{"net-1"},
		At:        time.Unix(1_700_000_000, 0),
		Reachable: true,
	}
	err := pb.Observe("relay-07", []netip.Addr{netip.MustParseAddr("198.51.100.7")}, thin)
	if !errors.Is(err, ErrContained) {
		t.Errorf("got %v, want ErrContained — the reason given points at the "+
			"evidence rather than at the operator's own decision", err)
	}
}

// TestSweepContainedDropsExistingEntries.
func TestSweepContainedDropsExistingEntries(t *testing.T) {
	pb := NewPeerbook(nil, 1)
	addrs := []netip.Addr{netip.MustParseAddr("198.51.100.7")}
	for _, id := range []string{"relay-07", "relay-08", "relay-09"} {
		if err := pb.Observe(id, addrs, goodEvidence(true)); err != nil {
			t.Fatalf("Observe %s: %v", id, err)
		}
	}
	l := contain.New()
	if err := l.Deny("relay-08", "seized", time.Now()); err != nil {
		t.Fatal(err)
	}
	pb.SetContainment(l)
	if pb.Len() != 3 {
		t.Error("SetContainment swept on its own")
	}
	if got := pb.SweepContained(); got != 1 {
		t.Errorf("SweepContained removed %d, want 1", got)
	}
	if _, ok := pb.Get("relay-08"); ok {
		t.Error("the contained peer survived the sweep")
	}
	if _, ok := pb.Get("relay-07"); !ok {
		t.Error("the sweep took an uncontained peer with it")
	}
}
