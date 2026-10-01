package path

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/contain"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// fakeBook is a PeerSource without the probe quorum in the way. The quorum is
// peerbook's invariant (E3.3) and is tested there; this file is about what the
// pool does with entries that already exist.
type fakeBook struct{ entries []peer.PeerEntry }

func (f *fakeBook) Entries() []peer.PeerEntry { return f.entries }

func entry(t *testing.T, id, addr string, asn uint32, state peer.ReachState) peer.PeerEntry {
	t.Helper()
	a := netip.MustParseAddr(addr)
	ann, err := peer.Annotate(a)
	if err != nil {
		t.Fatal(err)
	}
	ann.ASN = asn
	ann.ASNSource = peer.ASNSourceTable
	return peer.PeerEntry{
		NodeID:      id,
		Addrs:       []netip.Addr{a},
		Annotations: []peer.Annotation{ann},
		ReachState:  state,
	}
}

func book(t *testing.T, n int, state peer.ReachState) *fakeBook {
	t.Helper()
	f := &fakeBook{}
	for i := 0; i < n; i++ {
		// A /16 apiece: §8.7 gives PATHS a /16 failure domain, and a pool built
		// in one /16 yields no path however many relays it holds.
		addr := netip.AddrFrom4([4]byte{10, byte(i), 0, 10}).String()
		f.entries = append(f.entries, entry(t, relayName(i), addr, uint32(64500+i), state))
	}
	return f
}

func relayName(i int) string {
	const d = "0123456789"
	return "relay-" + string([]byte{d[(i/10)%10], d[i%10]})
}

// TestPoolAdmitsOnlyReachablePeers is R3.
func TestPoolAdmitsOnlyReachablePeers(t *testing.T) {
	f := book(t, 6, peer.ReachReachable)
	f.entries = append(f.entries,
		entry(t, "relay-90", "10.90.0.10", 64590, peer.ReachUnreachable),
		entry(t, "relay-91", "10.91.0.10", 64591, peer.ReachUnknown),
		entry(t, "relay-92", "10.92.0.10", 64592, peer.ReachProbing),
	)

	relays, rep := Pool(f, PoolPolicy{})
	if len(relays) != 6 {
		t.Fatalf("pool admitted %d, want 6", len(relays))
	}
	if rep.Unreachable != 3 {
		t.Errorf("report says %d unreachable, want 3", rep.Unreachable)
	}
	if rep.Considered != 9 || rep.Admitted != 6 {
		t.Errorf("report: considered=%d admitted=%d, want 9 and 6",
			rep.Considered, rep.Admitted)
	}
	for _, r := range relays {
		if r.NodeID == "relay-90" || r.NodeID == "relay-91" || r.NodeID == "relay-92" {
			t.Errorf("%s entered the pool; a relay nobody can reach is a path "+
				"that silently fails (R3)", r.NodeID)
		}
	}
}

// TestAllowUnreachableIsOnTheRecord: a caller that would rather build a fragile
// path than none must say so, not get it by leaving a field unset.
func TestAllowUnreachableIsOnTheRecord(t *testing.T) {
	f := &fakeBook{entries: []peer.PeerEntry{
		entry(t, "relay-01", "10.1.0.10", 64501, peer.ReachUnknown),
	}}
	if relays, _ := Pool(f, PoolPolicy{}); len(relays) != 0 {
		t.Fatal("an unprobed peer entered the pool by default")
	}
	relays, rep := Pool(f, PoolPolicy{AllowUnreachable: true})
	if len(relays) != 1 {
		t.Fatalf("AllowUnreachable admitted %d, want 1", len(relays))
	}
	if rep.Unreachable != 0 {
		t.Errorf("report counts %d unreachable when they were admitted", rep.Unreachable)
	}
}

// TestContainedPeersNeverEnterThePool, and are counted as contained rather than
// as anything else.
func TestContainedPeersNeverEnterThePool(t *testing.T) {
	f := book(t, 6, peer.ReachReachable)
	list := contain.New()
	if err := list.Deny("relay-03", "drill: host seized", nowForTest()); err != nil {
		t.Fatal(err)
	}

	relays, rep := Pool(f, PoolPolicy{Contained: list})
	if rep.Contained != 1 {
		t.Errorf("report says %d contained, want 1", rep.Contained)
	}
	for _, r := range relays {
		if r.NodeID == "relay-03" {
			t.Fatal("a contained relay entered the candidate pool")
		}
	}
	// An operator's decision outranks every measurement: a contained peer that
	// is ALSO unreachable must still be reported as contained, or whoever reads
	// the counts goes to look at probe coverage instead of at their own list.
	f.entries[4].ReachState = peer.ReachUnreachable
	if err := list.Deny(f.entries[4].NodeID, "also seized", nowForTest()); err != nil {
		t.Fatal(err)
	}
	_, rep2 := Pool(f, PoolPolicy{Contained: list})
	if rep2.Contained != 2 {
		t.Errorf("a contained AND unreachable peer was not reported as contained: %+v", rep2)
	}
}

// TestPoolChecksContainmentEvenWhenTheSweepWasForgotten.
//
// Peerbook.Observe refuses a contained peer and SweepContained drops one
// already recorded, but the sweep is a call somebody has to make. A node that
// loaded a list at startup and forgot to sweep would otherwise hand contained
// relays straight to the selector.
func TestPoolChecksContainmentEvenWhenTheSweepWasForgotten(t *testing.T) {
	pb := peer.NewPeerbook(nil, 1)
	ev := peer.Evidence{
		Probers:   []peer.ProberID{"prober-a", "prober-b"},
		Networks:  []string{"net-1", "net-2"},
		At:        nowForTest(),
		Reachable: true,
	}
	for i := 0; i < 4; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i), 0, 10})
		if err := pb.Observe(relayName(i), []netip.Addr{addr}, ev); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}
	// Contained AFTER the entries exist, and no sweep is called.
	list := contain.New()
	if err := list.Deny(relayName(2), "seized", nowForTest()); err != nil {
		t.Fatal(err)
	}
	pb.SetContainment(list)

	relays, rep := Pool(pb, PoolPolicy{Contained: list})
	if rep.Contained != 1 {
		t.Errorf("the pool did not catch the unswept containment: %+v", rep)
	}
	for _, r := range relays {
		if r.NodeID == relayName(2) {
			t.Fatal("a contained relay reached the selector because nobody swept")
		}
	}
}

// TestUnannotatedPeersAreCountedSeparately: a peer with no address has no
// failure domain, so no diversity constraint can be applied to it at all.
func TestUnannotatedPeersAreCountedSeparately(t *testing.T) {
	f := book(t, 3, peer.ReachReachable)
	f.entries = append(f.entries, peer.PeerEntry{
		NodeID: "relay-99", ReachState: peer.ReachReachable,
	})
	relays, rep := Pool(f, PoolPolicy{})
	if rep.Unannotated != 1 {
		t.Errorf("report says %d unannotated, want 1", rep.Unannotated)
	}
	if len(relays) != 3 {
		t.Errorf("pool admitted %d, want 3", len(relays))
	}
}

// TestPoolCarriesNoWeight. The pool decides MEMBERSHIP; weighting is
// WeightPolicy's job and takes different inputs. A weight set here would be a
// second, unaudited weight source.
func TestPoolCarriesNoWeight(t *testing.T) {
	relays, _ := Pool(book(t, 4, peer.ReachReachable), PoolPolicy{})
	for _, r := range relays {
		if r.Weight != (Weight{}) {
			t.Errorf("%s left the pool carrying a weight: %+v", r.NodeID, r.Weight)
		}
	}
}

// TestSourceDrivesTheSelector is the point of the item: Candidates now has an
// owner, and a path can be drawn through it end to end.
func TestSourceDrivesTheSelector(t *testing.T) {
	list := contain.New()
	if err := list.Deny("relay-02", "drill: host seized", nowForTest()); err != nil {
		t.Fatal(err)
	}
	src := &Source{
		Peers:  book(t, 12, peer.ReachReachable),
		Policy: PoolPolicy{Contained: list},
	}
	sel := &Selector{Candidates: src.Candidates}

	for i := 0; i < 50; i++ {
		got, _, err := sel.SelectPath(context.Background(), 3, Default(), WeightPolicy{})
		if err != nil {
			t.Fatalf("SelectPath: %v", err)
		}
		for _, r := range got {
			if r.NodeID == "relay-02" {
				t.Fatal("the contained relay was selected")
			}
		}
	}
	if rep := src.LastReport(); rep.Contained != 1 || rep.Admitted != 11 {
		t.Errorf("LastReport: %+v, want 1 contained and 11 admitted", rep)
	}
}

// TestSourceReportsWhyThePoolWasEmpty.
//
// ErrNoPath alone cannot distinguish "no path exists on this network" from "no
// path exists because this node contained or failed to probe everybody", and a
// caller that cannot tell them apart will report the first while looking at the
// second.
func TestSourceReportsWhyThePoolWasEmpty(t *testing.T) {
	src := &Source{Peers: book(t, 8, peer.ReachUnknown)}
	sel := &Selector{Candidates: src.Candidates}

	_, _, err := sel.SelectPath(context.Background(), 3, Default(), WeightPolicy{})
	if err == nil {
		t.Fatal("a pool of unprobed peers produced a path")
	}
	rep := src.LastReport()
	if !rep.Empty() {
		t.Fatal("the report does not say the pool was empty")
	}
	if rep.Unreachable != 8 {
		t.Errorf("report: %+v — the reason should be reachability, not the network", rep)
	}
}

func nowForTest() time.Time { return time.Unix(1_700_000_000, 0) }
