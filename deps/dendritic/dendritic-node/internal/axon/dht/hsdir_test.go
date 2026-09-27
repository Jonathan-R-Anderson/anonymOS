package dht

import (
	"errors"
	"testing"
)

func kb(b byte) []byte {
	out := make([]byte, 32)
	out[0] = b
	return out
}

// TestT75AllEightPositionsAreDistinct is the publish half of T7.5.
//
// "Publication reaches all 8 replica positions." Eight positions that collided
// would be fewer than eight regions to eclipse, which is the entire property
// §5 says the replica index buys.
func TestT75AllEightPositionsAreDistinct(t *testing.T) {
	pos, err := HSDirPositions(kb(1), 42, []byte("srv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != DescriptorReplicaPositions {
		t.Fatalf("got %d positions, want %d", len(pos), DescriptorReplicaPositions)
	}
	seen := map[Key]bool{}
	for i, k := range pos {
		if seen[k] {
			t.Fatalf("position %d collides with an earlier one; eclipsing the "+
				"descriptor costs fewer than %d regions", i, DescriptorReplicaPositions)
		}
		seen[k] = true
	}
}

// TestT75AnyOneOfEightIsFindable is the fetch half of T7.5.
//
// "A client fetching any 1 of 8 succeeds." The client picks an index; the
// publisher must have written that same key, so both sides must derive it
// identically from public inputs.
func TestT75AnyOneOfEightIsFindable(t *testing.T) {
	kBlind, period, srv := kb(7), uint64(9), []byte("consensus-srv")
	published, err := HSDirPositions(kBlind, period, srv)
	if err != nil {
		t.Fatal(err)
	}
	have := map[Key]bool{}
	for _, k := range published {
		have[k] = true
	}
	for j := 0; j < DescriptorReplicaPositions; j++ {
		want, err := HSDirIndex(kBlind, uint8(j), period, srv)
		if err != nil {
			t.Fatal(err)
		}
		if !have[want] {
			t.Fatalf("a client choosing replica %d looks at a key the publisher "+
				"never wrote", j)
		}
	}
}

// TestPositionsMoveEveryPeriod is why period_num is in the pre-image.
//
// Without it a service's holders would be a stable, enumerable set -- the
// standing eclipse target the rotation exists to deny.
func TestPositionsMoveEveryPeriod(t *testing.T) {
	a, _ := HSDirPositions(kb(3), 100, []byte("srv"))
	b, _ := HSDirPositions(kb(3), 101, []byte("srv"))
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("replica %d sits at the same key across periods; a service's "+
				"holders are then a fixed set anybody can enumerate once", i)
		}
	}
}

// TestPositionsDependOnTheSRV keeps the mapping unpredictable ahead of time.
func TestPositionsDependOnTheSRV(t *testing.T) {
	a, _ := HSDirPositions(kb(3), 100, []byte("srv-one"))
	b, _ := HSDirPositions(kb(3), 100, []byte("srv-two"))
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("replica %d ignores the SRV, so next period's holders can be "+
				"computed now and pre-positioned against", i)
		}
	}
}

// TestPositionsAreServiceSpecific stops two services sharing a holder set.
func TestPositionsAreServiceSpecific(t *testing.T) {
	a, _ := HSDirPositions(kb(1), 5, []byte("srv"))
	b, _ := HSDirPositions(kb(2), 5, []byte("srv"))
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("replica %d is the same for two different services", i)
		}
	}
}

// TestBadInputsAreRefused rather than producing a plausible key.
func TestBadInputsAreRefused(t *testing.T) {
	if _, err := HSDirIndex(nil, 0, 1, []byte("srv")); !errors.Is(err, ErrNoBlindedKey) {
		t.Fatalf("a missing blinded key produced a key: %v", err)
	}
	// An out-of-range index must fail loudly. Silently wrapping it would put a
	// descriptor at a position no client looks at, which presents as a service
	// that is simply unreachable.
	if _, err := HSDirIndex(kb(1), DescriptorReplicaPositions, 1, []byte("srv")); !errors.Is(err, ErrBadReplicaIndex) {
		t.Fatalf("replica index %d was accepted: %v", DescriptorReplicaPositions, err)
	}
}

// TestTheReplicaIndexIsInThePreImage guards the §7-vs-§5 resolution.
//
// §7.4 specifies j ∈ {0,1}; §5 declares 8 positions and T7.5 tests for 8. If
// DescriptorReplicaPositions is ever lowered to 2, this says so rather than
// letting six positions quietly stop being written.
func TestTheReplicaIndexIsInThePreImage(t *testing.T) {
	if DescriptorReplicaPositions != 8 {
		t.Fatalf("DescriptorReplicaPositions is %d; T7.5 is written against 8, and "+
			"§7.4's j ∈ {0,1} is the superseded figure",
			DescriptorReplicaPositions)
	}
	a, _ := HSDirIndex(kb(1), 0, 1, []byte("srv"))
	b, _ := HSDirIndex(kb(1), 1, 1, []byte("srv"))
	if a == b {
		t.Fatal("the replica index does not reach the hash, so all 8 positions " +
			"are one position")
	}
}
