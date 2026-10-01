package peer

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestPeerbookConcurrentAccess exercises the peerbook the way a node does:
// Observe writing while Sample/Get/Entries/Len read concurrently. Sample builds
// a slice of POINTERS into the entry map and dereferences them after releasing
// the lock, which is safe only because Observe REPLACES entries rather than
// mutating them in place. This asserts that invariant holds under -race, so a
// future in-place mutation that broke it would be caught here rather than in
// production. Run with -race.
func TestPeerbookConcurrentAccess(t *testing.T) {
	pb := NewPeerbook(nil, 7)
	ev := Evidence{
		Probers:   []ProberID{"pa", "pb"},
		Networks:  []string{"n1", "n2"},
		At:        time.Unix(1_700_000_000, 0),
		Reachable: true,
	}

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				id := nodeID(base*400 + i)
				addr := netip.AddrFrom4([4]byte{10, byte((base*400 + i) % 250), 0, 7})
				_ = pb.Observe(id, []netip.Addr{addr}, ev)
			}
		}(w)
	}
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 800; i++ {
				for _, e := range pb.Sample(8, DiversityConstraint{}) {
					_ = e.NodeID
					_ = e.ReachState
					_ = len(e.Addrs)
				}
				for _, e := range pb.Entries() {
					_ = e.ReachState
				}
				_ = pb.Len()
				_, _ = pb.Get(nodeID(i))
			}
		}()
	}
	wg.Wait()
}

func nodeID(i int) string {
	const d = "0123456789abcdef"
	return "node-" + string([]byte{d[(i/16)%16], d[i%16]})
}
