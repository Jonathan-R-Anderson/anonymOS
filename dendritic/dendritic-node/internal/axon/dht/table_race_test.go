package dht

import (
	"net/netip"
	"sync"
	"testing"
)

// TestTableConcurrentAccess hammers a Table from many goroutines doing the
// operations a live DHT does concurrently: admit, query, sample, eject, sweep.
// dht is documented "race-clean", but until -race actually ran (2026-08-21)
// nothing verified that under concurrency. Run with -race.
func TestTableConcurrentAccess(t *testing.T) {
	srv := mkSRV(0x42)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))
	list := contained(t, ContactID(func() [32]byte { var p [32]byte; p[0] = 3; return p }()))
	table.SetContainment(list)

	mk := func(i int) Contact {
		addr := netip.AddrFrom4([4]byte{10, byte(i / 250), byte(i % 250), 1})
		return contactAt(uint64(70000+i), addr.String(), uint32(64000+i), srv, i%2 == 0)
	}

	var wg sync.WaitGroup
	// Writers: admit and eject.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c := mk(base*500 + i)
				_ = table.Admit(c)
				if i%50 == 0 {
					table.Eject(c.NodeIDPub)
				}
			}
		}(w)
	}
	// Readers: query, sample, len, siblings.
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := MustDeriveKey(ClassRelay, []byte("target"))
			for i := 0; i < 1000; i++ {
				_ = table.Closest(key, 8, true)
				_ = table.Siblings()
				_ = table.Len()
				if i%100 == 0 {
					table.SweepContained()
				}
			}
		}()
	}
	wg.Wait()
}
