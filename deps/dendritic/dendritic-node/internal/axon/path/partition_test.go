package path

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// D7 / T12.5 — what the partition detector catches, and what it cannot.
//
// T12.5 claims only a CRUDE partition: "two clients given disjoint descriptor
// sets both emit a diversity warning". §12's own failure-mode note says plainly
// that it "catches a crude partition and not a careful one". This file makes
// that precise, because a limitation stated in prose gets read as a rough edge
// rather than as a hole with a shape.

func partRelay(i int) Relay {
	// One relay per /24, so each is its own failure domain.
	pfx := netip.MustParsePrefix(fmt.Sprintf("198.%d.%d.0/24", i/256, i%256))
	return Relay{
		NodeID: fmt.Sprintf("relay-%04d", i),
		Ann:    peer.Annotation{Prefix: pfx, ASN: uint32(64500 + i)},
	}
}

// TestTheDetectorCatchesACrudePartition is T12.5 as written.
func TestTheDetectorCatchesACrudePartition(t *testing.T) {
	// A pool starved of candidates.
	var tiny []Relay
	for i := 0; i < params.PathMinCandidates-1; i++ {
		tiny = append(tiny, partRelay(i))
	}
	if partitioned, why := detectPartition(tiny, len(tiny)); !partitioned {
		t.Fatal("a starved candidate pool was not reported")
	} else {
		t.Logf("crude (volume): %s", why)
	}

	// A pool of adequate size crammed into too few failure domains.
	var crammed []Relay
	for i := 0; i < params.PathMinCandidates*2; i++ {
		crammed = append(crammed, partRelay(i))
	}
	if partitioned, why := detectPartition(crammed, params.PathMinDistinctPrefixes-1); !partitioned {
		t.Fatal("a pool concentrated in too few domains was not reported")
	} else {
		t.Logf("crude (concentration): %s", why)
	}
}

// TestTheDetectorCannotSeeACarefulPartition is D7, demonstrated.
//
// THE POINT IS THAT THIS TEST ASSERTS A LIMITATION, NOT A BUG. Both signals the
// detector has -- pool size and domain count -- are properties of the set a
// client was GIVEN. An adversary who hands out a subset that is large enough and
// diverse enough satisfies both while showing the client a network that is not
// the network. Nothing local distinguishes the two, because the client has
// nothing to compare against: that is R14's residual, not a missing heuristic.
func TestTheDetectorCannotSeeACarefulPartition(t *testing.T) {
	// The real network.
	var full []Relay
	for i := 0; i < 400; i++ {
		full = append(full, partRelay(i))
	}

	// Two clients, each handed a disjoint half. Every half is comfortably above
	// both floors and every relay sits in its own /24 and ASN.
	alice, bob := full[:200], full[200:]

	for name, view := range map[string][]Relay{"alice": alice, "bob": bob} {
		if len(view) < params.PathMinCandidates {
			t.Fatalf("%s's view is too small to make the point", name)
		}
		partitioned, why := detectPartition(view, len(view))
		if partitioned {
			t.Fatalf("%s's view was flagged (%s); the halves are not careful "+
				"enough for this test to demonstrate anything", name, why)
		}
	}

	// Disjoint, and neither side can tell.
	seen := map[string]bool{}
	for _, r := range alice {
		seen[r.NodeID] = true
	}
	for _, r := range bob {
		if seen[r.NodeID] {
			t.Fatal("the halves overlap, so this is not a partition")
		}
	}

	t.Logf("D7 confirmed: two clients hold disjoint %d-relay views, each above "+
		"the %d-candidate and %d-prefix floors, and detectPartition reports "+
		"nothing for either. The detector's inputs are properties of the set a "+
		"client was GIVEN, so a partition that is large and diverse enough is "+
		"invisible to it by construction.",
		len(alice), params.PathMinCandidates, params.PathMinDistinctPrefixes)
}

// TestDetectionWouldNeedASecondView names what the fix actually is.
//
// Not a better heuristic: a second CHANNEL. Two views obtained independently --
// a different guard, a different DHT region, a set a friend hands you out of
// band -- can be compared, and disjointness between them is evidence no single
// view carries. That is a protocol addition, and it is why D7 is research
// rather than a patch to detectPartition.
func TestDetectionWouldNeedASecondView(t *testing.T) {
	var full []Relay
	for i := 0; i < 400; i++ {
		full = append(full, partRelay(i))
	}
	alice, bob := full[:200], full[200:]

	overlap := func(a, b []Relay) int {
		in := map[string]bool{}
		for _, r := range a {
			in[r.NodeID] = true
		}
		n := 0
		for _, r := range b {
			if in[r.NodeID] {
				n++
			}
		}
		return n
	}

	// Honest case: two independent samples of one network overlap heavily.
	if got := overlap(full[:200], full[100:300]); got == 0 {
		t.Fatal("two overlapping samples reported no overlap; the measure is wrong")
	}
	// Partitioned case: zero overlap, which is the signal.
	if got := overlap(alice, bob); got != 0 {
		t.Fatalf("the disjoint halves overlap by %d", got)
	}
	t.Log("the discriminator exists between views and not inside one: honest " +
		"samples overlap, partitioned ones do not. Obtaining a second view is " +
		"the unbuilt part.")
}
