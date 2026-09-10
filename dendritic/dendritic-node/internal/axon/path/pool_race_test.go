package path

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// TestSourceRaceUnderConcurrentSelect: a Selector may draw paths concurrently
// (a node builds more than one circuit at once), and SelectPath is otherwise
// stateless. Source.Candidates writes s.last on every call, so two concurrent
// draws race on it. Run with -race.
func TestSourceRaceUnderConcurrentSelect(t *testing.T) {
	var entries []peer.PeerEntry
	for i := 0; i < 20; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i), 0, 10})
		ann, err := peer.Annotate(addr)
		if err != nil {
			t.Fatal(err)
		}
		ann.ASN = uint32(64500 + i)
		ann.ASNSource = peer.ASNSourceTable
		entries = append(entries, peer.PeerEntry{
			NodeID: relayNameR(i), Annotations: []peer.Annotation{ann},
			ReachState: peer.ReachReachable,
		})
	}
	src := &Source{Peers: &staticBook{entries}}
	sel := &Selector{Candidates: src.Candidates}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_, _, _ = sel.SelectPath(context.Background(), 3, Default(), WeightPolicy{})
				_ = src.LastReport()
			}
		}()
	}
	wg.Wait()
}

type staticBook struct{ e []peer.PeerEntry }

func (b *staticBook) Entries() []peer.PeerEntry { return b.e }

func relayNameR(i int) string {
	const d = "0123456789"
	return "relay-" + string([]byte{d[(i/10)%10], d[i%10]})
}
