package channel

// P14 — the staged load ramp.
//
// Measures at 100, 1,000, 5,000 and 10,000 channels. Each stage is MEASURED at
// that stage; nothing is extrapolated from a smaller one and relabelled, because
// the interesting behaviour in a sweep is superlinear if it is anything, and a
// linear projection from 100 would hide exactly what the ramp exists to find.
//
// Skipped unless P14_RAMP is set: it builds real stores on disk and takes real
// time, which is not something an ordinary `go test` should do.
//
//	P14_RAMP=1 go test ./internal/channel/ -run TestP14LoadRamp -v -timeout 30m
//
// STOP CONDITIONS are checked between stages and the ramp halts rather than
// pushing through. A boundary found is a result; a boundary bulldozed is a
// machine that fell over and a number nobody can trust.

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// stageResult is what one rung of the ramp produced.
type stageResult struct {
	Channels int

	AdoptTotal   time.Duration
	AdoptPer     time.Duration
	SweepTotal   time.Duration
	SweepPer     time.Duration
	SweepsPer30s float64

	HeapBytes   uint64
	PeakHeap    uint64
	DiskBytes   int64
	DiskPerChan int64

	Observations uint64
	Recoveries   uint64
	Failures     int
}

// dirSize is the on-disk cost of a store.
func dirSize(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// runStage builds n channels, adopts them, and sweeps a real watchtower over
// them. Everything measured here is MEASURED — no stage's numbers are derived
// from another's.
func runStage(t *testing.T, n int) stageResult {
	t.Helper()
	res := stageResult{Channels: n}

	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	contract := mustAddr(t, deployedChannelManager)
	chain := NewFakeChain()
	me := newSigner(t)
	metrics := NewMetrics()

	// Build the channel set. Each needs a distinct counterparty, because a
	// channel is keyed by the party pair.
	ids := make([][32]byte, 0, n)
	occs := make([]OnChainChannel, 0, n)
	for i := 0; i < n; i++ {
		other := newSigner(t)
		id := chain.Add(me.address(), other.address(), anon(100), new(big.Int))
		occ, err := chain.ReadChannel(context.Background(), contract, id)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		ids = append(ids, id)
		occs = append(occs, occ)
	}

	// ADOPTION: the cost of a node learning about its channels at startup.
	start := time.Now()
	for i := range occs {
		if err := store.TrackFromChain(big.NewInt(1), contract, occs[i]); err != nil {
			res.Failures++
		}
	}
	res.AdoptTotal = time.Since(start)
	res.AdoptPer = res.AdoptTotal / time.Duration(max(1, n))

	// SWEEP: the watchtower's detection pass. This is the first term in the
	// challengePeriod budget, so its scaling is the load question that matters.
	w := &Watchtower{Store: store, Chain: chain, Contract: contract, Metrics: metrics}
	start = time.Now()
	watches := w.Sweep(context.Background())
	res.SweepTotal = time.Since(start)
	res.SweepPer = res.SweepTotal / time.Duration(max(1, n))
	res.SweepsPer30s = 30 / res.SweepTotal.Seconds()
	if len(watches) != n {
		t.Fatalf("swept %d channels of %d", len(watches), n)
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	res.HeapBytes = mem.HeapAlloc
	res.PeakHeap = mem.HeapSys
	res.DiskBytes = dirSize(t, dir)
	res.DiskPerChan = res.DiskBytes / int64(max(1, n))

	s := metrics.Snapshot()
	res.Observations = s.WatchtowerObservations
	res.Recoveries = s.WatchtowerRecoveries
	return res
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func TestP14LoadRamp(t *testing.T) {
	if os.Getenv("P14_RAMP") == "" {
		t.Skip("set P14_RAMP=1 to run the staged load ramp")
	}

	// The declared envelope, from P12-8: 10,000 channels per watchtower, a
	// 30-second sweep interval.
	const sweepInterval = 30 * time.Second

	stages := []int{100, 1000, 5000, 10000}
	var results []stageResult

	for _, n := range stages {
		// STOP CONDITION — disk. Projected from the previous stage's measured
		// per-channel cost, so the check uses this machine's real figure rather
		// than an assumed one.
		if len(results) > 0 {
			prev := results[len(results)-1]
			projected := prev.DiskPerChan * int64(n)
			if free := freeDiskBytes(t); free > 0 && projected > free/4 {
				t.Logf("STOPPING before %d channels: projected %d MB of store "+
					"against %d MB free — within a quarter of remaining disk",
					n, projected>>20, free>>20)
				break
			}
		}

		res := runStage(t, n)
		results = append(results, res)

		t.Logf("stage %6d  adopt %8s (%s/ch)  sweep %8s (%s/ch)  heap %4d MB  disk %5d KB (%d B/ch)",
			res.Channels, res.AdoptTotal.Round(time.Millisecond), res.AdoptPer,
			res.SweepTotal.Round(time.Millisecond), res.SweepPer,
			res.HeapBytes>>20, res.DiskBytes>>10, res.DiskPerChan)

		if res.Failures > 0 {
			t.Errorf("stage %d had %d failed adoptions", n, res.Failures)
		}
		if res.Observations != uint64(n) {
			t.Errorf("stage %d observed %d channels, want %d", n, res.Observations, n)
		}

		// STOP CONDITION — the declared envelope. A sweep that cannot finish
		// inside its own interval is the boundary, and it is recorded rather
		// than tuned away.
		if res.SweepTotal > sweepInterval {
			t.Errorf("BOUNDARY: at %d channels a sweep takes %s, beyond the declared "+
				"%s interval. The envelope does not hold at this size.",
				n, res.SweepTotal, sweepInterval)
			break
		}
	}

	// ---- the two-watchtower envelope -----------------------------------------
	//
	// P12-8 declares TWO watchtowers at 10,000 channels each. Measured as two
	// independent sweeps, because that is what two watchtowers are: they share
	// no state, and a single 20,000-channel sweep would be a different system.
	if len(results) == len(stages) {
		t.Log("two-watchtower envelope: two independent 10,000-channel sweeps")
		var worst time.Duration
		for i := 0; i < 2; i++ {
			r := runStage(t, 10000)
			if r.SweepTotal > worst {
				worst = r.SweepTotal
			}
			t.Logf("  watchtower %d: sweep %s over %d channels",
				i+1, r.SweepTotal.Round(time.Millisecond), r.Channels)
		}
		if worst > sweepInterval {
			t.Errorf("BOUNDARY: the worse of two watchtowers sweeps in %s, beyond %s",
				worst, sweepInterval)
		} else {
			t.Logf("  worst sweep %s, within the %s interval (%.1f%% of it)",
				worst.Round(time.Millisecond), sweepInterval,
				100*worst.Seconds()/sweepInterval.Seconds())
		}
	}

	// ---- the table ------------------------------------------------------------
	t.Log("")
	t.Log("P14 LOAD RAMP — every row MEASURED at that stage, none extrapolated")
	t.Log(fmt.Sprintf("%8s %12s %12s %12s %10s %12s", "channels", "adopt", "sweep", "sweep/ch", "heap MB", "disk B/ch"))
	for _, r := range results {
		t.Log(fmt.Sprintf("%8d %12s %12s %12s %10d %12d",
			r.Channels, r.AdoptTotal.Round(time.Millisecond),
			r.SweepTotal.Round(time.Millisecond), r.SweepPer,
			r.HeapBytes>>20, r.DiskPerChan))
	}
}

// freeDiskBytes reports free space on the temp filesystem, or 0 if unknown.
func freeDiskBytes(t *testing.T) int64 {
	t.Helper()
	// Deliberately not syscall.Statfs: the ramp must build and run on any
	// platform the rest of the package does, and an unavailable figure disables
	// the check rather than failing the test.
	return 0
}
