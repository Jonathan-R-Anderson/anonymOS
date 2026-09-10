package circuit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
)

// TestCircuitTableConcurrentAccess exercises the relay circuit table's map
// operations concurrently: admit, lookup both directions, teardown, prune. A
// relay serves many circuits at once, so these run in parallel in production.
// Verified under -race, which never actually ran against this package before
// 2026-08-21. Run with -race.
func TestCircuitTableConcurrentAccess(t *testing.T) {
	tbl := NewCircuitTable(time.Now)
	var admitted sync.Map // id -> *RelayCircuit
	var idc uint64

	var wg sync.WaitGroup
	// Admitters.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				id := link.CircuitID(atomic.AddUint64(&idc, 1))
				_, r := newRelayCrypto(t)
				if rc, err := tbl.Admit("guard", id, r); err == nil {
					tbl.Link(rc, "next")
					admitted.Store(id, rc)
				}
			}
		}()
	}
	// Lookers + prune.
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				tbl.LookupForward("guard", link.CircuitID(uint64(i)%2000+1))
				tbl.LookupBackward("next", link.CircuitID(uint64(i)%2000+1))
				_ = tbl.Len()
				if i%200 == 0 {
					tbl.PruneQuarantine()
				}
			}
		}()
	}
	// Teardowners.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 800; i++ {
			admitted.Range(func(k, v any) bool {
				tbl.Teardown(v.(*RelayCircuit))
				admitted.Delete(k)
				return false // one per pass
			})
		}
	}()
	wg.Wait()
}
