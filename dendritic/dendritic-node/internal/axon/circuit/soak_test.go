package circuit

import (
	"crypto/rand"
	"flag"
	"runtime"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// P5's exit criteria E5.2, E5.3 and E5.4.

var soakMinutes = flag.Int("soak-minutes", 0, "run E5.2's sustained-throughput soak for this many minutes")

// buildPath assembles a 3-hop circuit's client and relay state without the wire
// exchange, so the soaks measure the data path rather than the handshake.
func buildPath(t *testing.T, class TrafficClass) (*Circuit, []*RelayCircuit, [][32]byte) {
	t.Helper()
	clients, relays := wideHops(t, 3)

	c, err := NewCircuit(1, class, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	afs := make([][32]byte, 3)
	rcs := make([]*RelayCircuit, 3)
	for i := 0; i < 3; i++ {
		if _, err := rand.Read(afs[i][:]); err != nil {
			t.Fatal(err)
		}
		static, _ := newRelayStatic(t)
		if err := c.AddHop(&Hop{Static: static, Crypto: clients[i]}); err != nil {
			t.Fatal(err)
		}
		rcs[i] = &RelayCircuit{
			PrevID: link.CircuitID(i + 1), NextID: link.CircuitID(100 + i),
			Crypto: relays[i], buildBudget: params.RelayBuildBudget,
		}
	}
	return c, rcs, afs
}

// TestE54ClassesAreIndistinguishableBySize is E5.4.
//
// A capture at hop 2 must not tell INTERACTIVE from BULK by cell size. Only
// timing may differ — the classes have different windows and, in v2, different
// padding regimes, and every one of those differences must stay off the wire's
// size axis.
func TestE54ClassesAreIndistinguishableBySize(t *testing.T) {
	sizes := map[TrafficClass]map[int]int{}

	for _, class := range []TrafficClass{ClassInteractive, ClassBulk} {
		sizes[class] = map[int]int{}
		c, rcs, afs := buildPath(t, class)

		// A spread of payload lengths, including empty and full.
		for _, n := range []int{0, 1, 100, RelayDataSize / 2, RelayDataSize} {
			msg := &RelayCell{Stream: 1, Cmd: RCmdData, Data: make([]byte, n)}
			block, err := c.SendRelay(afs[2], msg)
			if err != nil {
				t.Fatal(err)
			}
			flags := link.Flags(0)
			if class == ClassInteractive {
				flags |= link.FlagPriority
			}
			cell := &link.Cell{Circuit: c.ID(), Command: link.CmdRelay, Flags: flags, Payload: block}

			// Hop 1 forwards; the capture is taken at hop 2's inbound link.
			r1, err := ProcessForward(rcs[0], cell, afs[0], false)
			if err != nil {
				t.Fatal(err)
			}
			var buf [params.CellSize]byte
			if err := r1.Out.Encode(buf[:]); err != nil {
				t.Fatal(err)
			}
			sizes[class][len(buf)]++
			// The onion payload region must also be constant.
			sizes[class][len(r1.Out.Payload)]++
		}
	}

	// Every observed size must appear for both classes, with the same counts.
	for size, n := range sizes[ClassInteractive] {
		if sizes[ClassBulk][size] != n {
			t.Fatalf("E5.4 falsified: size %d appears %d times for INTERACTIVE and %d for BULK",
				size, n, sizes[ClassBulk][size])
		}
	}
	if len(sizes[ClassInteractive]) != len(sizes[ClassBulk]) {
		t.Fatalf("E5.4 falsified: the classes produce different size sets")
	}
	// And there is exactly one cell size and one payload size, whatever the
	// message length — a variable size would leak the message length too.
	if len(sizes[ClassInteractive]) != 2 {
		t.Fatalf("E5.4 falsified: %d distinct sizes observed, want 2 (cell and payload)",
			len(sizes[ClassInteractive]))
	}
	t.Logf("E5.4: INTERACTIVE and BULK produce identical size distributions across "+
		"payloads 0..%d; only the PRIORITY flag differs, and it changes scheduling, not size",
		RelayDataSize)
}

// TestE54PriorityFlagIsTheOnlyDifference: the flag that distinguishes the
// classes on the wire changes scheduling, and must not change anything a size
// capture can see.
func TestE54PriorityFlagIsTheOnlyDifference(t *testing.T) {
	body := make([]byte, params.MaxPayload)
	a := &link.Cell{Circuit: 1, Command: link.CmdRelay, Flags: link.FlagPriority, Payload: body}
	b := &link.Cell{Circuit: 1, Command: link.CmdRelay, Flags: 0, Payload: body}

	var ba, bb [params.CellSize]byte
	if err := a.Encode(ba[:]); err != nil {
		t.Fatal(err)
	}
	if err := b.Encode(bb[:]); err != nil {
		t.Fatal(err)
	}
	if len(ba) != len(bb) {
		t.Fatal("the priority flag changed the cell size")
	}
	diff := 0
	for i := range ba {
		if ba[i] != bb[i] {
			diff++
		}
	}
	if diff != 1 {
		t.Fatalf("the two classes differ in %d bytes, want exactly 1 (the flags byte)", diff)
	}
}

// TestE52NoResidualStateAfterTeardown is E5.2's second half: no hop retains
// circuit state 5 s after teardown — falsified by a residual entry.
func TestE52NoResidualStateAfterTeardown(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	tables := make([]*CircuitTable, 3)
	circuits := make([]*RelayCircuit, 3)
	for i := range tables {
		tables[i] = NewCircuitTable(clock)
		_, r := func() (*HopWide, *HopWide) { cs, rs := wideHops(t, 1); return cs[0], rs[0] }()
		rc, err := tables[i].Admit("prev", link.CircuitID(i+1), r)
		if err != nil {
			t.Fatal(err)
		}
		tables[i].Link(rc, "next")
		circuits[i] = rc
	}

	for i, tbl := range tables {
		tbl.Teardown(circuits[i])
	}
	now = now.Add(5 * time.Second)

	for i, tbl := range tables {
		if tbl.Len() != 0 {
			t.Fatalf("E5.2 falsified: hop %d retains %d circuits 5 s after teardown",
				i+1, tbl.Len())
		}
		if _, ok := tbl.LookupForward("prev", link.CircuitID(i+1)); ok {
			t.Fatalf("E5.2 falsified: hop %d retains a forward mapping", i+1)
		}
		if _, ok := tbl.LookupBackward("next", circuits[i].NextID); ok {
			t.Fatalf("E5.2 falsified: hop %d retains a backward mapping", i+1)
		}
	}
	t.Log("E5.2 (teardown half): zero residual entries at all three hops 5 s after teardown")
}

// TestE53MemoryReturnsAfterBuildTeardownCycles is E5.3: after 1000
// build/teardown cycles, relay memory returns within 5 % of baseline —
// **falsified by monotone growth**.
//
// HOW THIS IS MEASURED, and why the obvious version was wrong. The first
// attempt compared the heap after 1000 cycles against a baseline taken after 50
// warm-up cycles, and reported 160 % — which looked like a leak and was not one.
// At these absolute sizes (a ~400 KiB heap) the comparison was dominated by the
// runtime reaching steady state, not by circuit state. A percentage against a
// cold baseline measures the warm-up.
//
// E5.3's own wording says what to measure instead: MONOTONE GROWTH. So this runs
// successive equal batches and requires the growth to flatten. A leak keeps
// adding per batch; a bounded high-water mark adds once and then stops.
//
// It found one real thing on the way: a Go map never releases its bucket array,
// so the circuit tables held their busiest moment's memory for the life of the
// process. CircuitTable.compactLocked now rebuilds them when they empty out.
func TestE53MemoryReturnsAfterBuildTeardownCycles(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tbl := NewCircuitTable(func() time.Time { return now })

	cycle := func(i int) {
		_, rs := wideHops(t, 1)
		rc, err := tbl.Admit("prev", link.CircuitID(i), rs[0])
		if err != nil {
			t.Fatal(err)
		}
		tbl.Link(rc, "next")
		block := make([]byte, BlockSize)
		if err := rc.Crypto.WrapForward(block); err != nil {
			t.Fatal(err)
		}
		tbl.Teardown(rc)
	}

	const (
		batches    = 4
		perBatch   = 1000
		flatBudget = 5.0 // per cent of the first batch's growth
	)

	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}

	// Reach steady state before measuring anything.
	for i := 0; i < perBatch; i++ {
		cycle(i + 1)
	}
	now = now.Add(2 * params.CircuitIDQuarantine)
	tbl.PruneQuarantine()

	var growth []float64
	prev := heap()
	base := prev
	totalDrained := 0
	for b := 0; b < batches; b++ {
		for i := 0; i < perBatch; i++ {
			cycle(10_000_000 + b*perBatch + i)
		}
		now = now.Add(2 * params.CircuitIDQuarantine)
		totalDrained += tbl.PruneQuarantine()

		cur := heap()
		growth = append(growth, float64(cur)-float64(prev))
		prev = cur
	}

	if tbl.Len() != 0 {
		t.Fatalf("E5.3 falsified: %d circuits retained", tbl.Len())
	}
	if totalDrained != 2*batches*perBatch {
		t.Fatalf("E5.3: drained %d quarantine entries, want %d (two link-local ids per circuit)",
			totalDrained, 2*batches*perBatch)
	}

	t.Logf("E5.3: heap delta per %d-cycle batch: %v (baseline %d bytes, %d quarantine entries drained)",
		perBatch, growth, base, totalDrained)

	// Monotone growth is the failure. Each batch after the first must add a
	// small fraction of the baseline, not a repeat of the first batch's cost.
	for i, g := range growth {
		pct := g / float64(base) * 100
		if pct > flatBudget {
			t.Fatalf("E5.3 falsified: batch %d added %.1f%% of baseline (%.0f bytes); "+
				"growth is not flattening", i+1, pct, g)
		}
	}
	total := (float64(prev) - float64(base)) / float64(base) * 100
	if total > flatBudget {
		t.Fatalf("E5.3 falsified: %d cycles grew the heap %.1f%% overall",
			batches*perBatch, total)
	}
}

// TestE52SustainedThroughput is E5.2's first half.
//
// The full criterion is ten minutes; -soak-minutes sets the duration so the
// criterion can be run deliberately rather than on every build. With the flag
// unset it runs for two seconds, which proves the mechanism and measures a rate
// but IS NOT the criterion, and the log says so.
func TestE52SustainedThroughput(t *testing.T) {
	dur := 2 * time.Second
	full := false
	if *soakMinutes > 0 {
		dur = time.Duration(*soakMinutes) * time.Minute
		full = *soakMinutes >= 10
	}

	c, rcs, afs := buildPath(t, ClassBulk)
	payload := make([]byte, RelayDataSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var cells, bytesMoved uint64
	deadline := time.Now().Add(dur)
	start := time.Now()
	for time.Now().Before(deadline) {
		for i := 0; i < 256; i++ {
			msg := &RelayCell{Stream: 1, Cmd: RCmdData, Data: payload}
			block, err := c.SendRelay(afs[2], msg)
			if err != nil {
				t.Fatal(err)
			}
			cell := &link.Cell{Circuit: c.ID(), Command: link.CmdRelay, Payload: block}
			for h := 0; h < 3; h++ {
				res, err := ProcessForward(rcs[h], cell, afs[h], h == 2)
				if err != nil {
					// Zero cell loss is the criterion; any error is a lost cell.
					t.Fatalf("E5.2 falsified: cell %d lost at hop %d: %v", cells, h+1, err)
				}
				if h == 2 {
					if len(res.Relay.Data) != len(payload) {
						t.Fatalf("E5.2 falsified: cell %d truncated", cells)
					}
					break
				}
				cell = res.Out
			}
			cells++
			bytesMoved += uint64(len(payload))
		}
	}
	elapsed := time.Since(start)
	mbps := float64(bytesMoved) * 8 / elapsed.Seconds() / 1e6

	label := "PARTIAL RUN, NOT the criterion"
	if full {
		label = "full criterion"
	}
	t.Logf("E5.2 (%s): %d cells over a 3-hop circuit in %s, zero loss, "+
		"%.1f Mbit/s of relay payload single-threaded",
		label, cells, elapsed.Truncate(time.Millisecond), mbps)

	// The throughput half of E5.2 used to be REPORTED and never asserted,
	// because the criterion says "a stated throughput floor" and none was
	// stated (item 4.4b). Two floors are stated now (params), and each is a
	// regression tripwire far below the measured rate -- NOT a deployment SLA,
	// which stays open because §5.1 shows the §8.6 window binds first at any
	// real RTT.
	//
	// The smoke floor guards every run, including this default 2-second one and
	// runs under -race; it is low enough never to flake on machine variance and
	// trips only on catastrophic breakage.
	if mbps < params.CircuitThroughputSmokeFloorMbps {
		t.Fatalf("E5.2 regression: %.1f Mbit/s is below the smoke floor of "+
			"%.1f Mbit/s. This is ~67x under the measured 135 and survives "+
			"-race, so it means the crypto/framing path is catastrophically "+
			"broken, not that the machine is slow.",
			mbps, params.CircuitThroughputSmokeFloorMbps)
	}
	// The tighter regression floor is asserted only on the full soak, whose
	// 10-minute average is stable and which is never run under -race.
	if full && mbps < params.CircuitThroughputRegressionFloorMbps {
		t.Fatalf("E5.2 regression: %.1f Mbit/s over 10 minutes is below the "+
			"regression floor of %.1f Mbit/s (~6x under the measured 135). "+
			"If this hardware is merely slow rather than regressed, LOWER the "+
			"constant with a note -- do not delete the check.",
			mbps, params.CircuitThroughputRegressionFloorMbps)
	}
	if !full {
		t.Logf("E5.2 requires 10 minutes; run with -soak-minutes=10 to discharge it")
	}
}
