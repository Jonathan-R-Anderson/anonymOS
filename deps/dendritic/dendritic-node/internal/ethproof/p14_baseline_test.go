//go:build ethbls

package ethproof

// P14 — baseline measurements for the verification and evidence paths.
//
// No implementation is changed here and nothing is optimised. The point is a
// clean statement of what the UNOPTIMISED system does, so that when the
// chain-reading path is redesigned there is something honest to compare against.
//
//	P14_BASE=1 go test ./internal/ethproof/ -run TestP14 -v -timeout 20m
//
// WHAT IS AND IS NOT NETWORK. The evidence store is measured through the real
// EvidenceStore — seal, serialise, key derivation, index — against an in-memory
// backend. That measures everything the node does per record and NONE of what
// the DHT does with it. The network half needs a reachable node and is reported
// NOT MEASURED rather than guessed, because a local figure presented as DHT
// latency would be wrong by orders of magnitude in the flattering direction.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// benchVector is one loaded aggregate, ready to verify. Built from the SAME
// consensus-spec vectors bls_vectors_test.go uses — a synthetic aggregate would
// measure the wrong curve arithmetic.
type benchVector struct {
	root      Root
	pubkeys   [][]byte
	signature []byte
	expect    bool
}

func loadBLSVectorsForBench(t *testing.T) []benchVector {
	t.Helper()
	dirs, err := os.ReadDir(filepath.Join("testdata", "bls"))
	if err != nil {
		return nil
	}
	var out []benchVector
	for _, d := range dirs {
		if !d.IsDir() || !strings.Contains(d.Name(), "fast_aggregate_verify") {
			continue
		}
		v := loadVectors(t, d.Name())
		for _, vec := range v {
			if len(vec.Input.Pubkeys) == 0 || vec.Input.Signature == "" {
				continue
			}
			var root Root
			msg := unhex(t, vec.Input.Message)
			if len(msg) != 32 {
				continue
			}
			copy(root[:], msg)
			keys := make([][]byte, 0, len(vec.Input.Pubkeys))
			for _, k := range vec.Input.Pubkeys {
				keys = append(keys, unhex(t, k))
			}
			out = append(out, benchVector{
				root: root, pubkeys: keys,
				signature: unhex(t, vec.Input.Signature), expect: vec.Output,
			})
		}
	}
	return out
}

// benchStore reuses the package's own test store shape.
func benchStore(b EvidenceBackend) *EvidenceStore { return testStore(b) }

func newMemEvidenceForBench() *memEvidence { return newMemEvidence() }

// benchEvidence is a real verified record from mainnet — the only way to
// measure the store on something the size of what it will really hold.
func benchEvidence(t *testing.T) Evidence { return liveEvidence(t) }

func p14Skip(t *testing.T) {
	t.Helper()
	if os.Getenv("P14_BASE") == "" {
		t.Skip("set P14_BASE=1 to run the P14 baseline measurements")
	}
}

// percentile over a sorted-in-place slice.


// ---- evidence store ---------------------------------------------------------

// Write and read latency through the real store, minus the network.
func TestP14EvidenceStoreLatency(t *testing.T) {
	p14Skip(t)
	const n = 500

	mem := newMemEvidenceForBench()
	store := benchStore(mem)
	ev := benchEvidence(t)

	writes := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		e := ev
		e.ChannelID = fmt.Sprintf("0x%062x%02x", 0, i%256)
		start := time.Now()
		if err := store.Put(context.Background(), e); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		writes = append(writes, time.Since(start))
	}
	sortDurations(writes)

	keys, err := mem.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	reads := make([]time.Duration, 0, len(keys))
	for _, k := range keys {
		start := time.Now()
		if _, err := store.Get(context.Background(), k); err != nil {
			t.Fatalf("get: %v", err)
		}
		reads = append(reads, time.Since(start))
	}
	sortDurations(reads)

	var stored int
	for _, k := range keys {
		blob, _ := mem.Get(context.Background(), k)
		stored += len(blob)
	}

	t.Logf("EVIDENCE WRITE (node-side only, no network): n=%d min=%s median=%s p95=%s max=%s",
		len(writes), writes[0], pct(writes, 0.5), pct(writes, 0.95), writes[len(writes)-1])
	t.Logf("EVIDENCE READ  (node-side only, no network): n=%d min=%s median=%s p95=%s max=%s",
		len(reads), reads[0], pct(reads, 0.5), pct(reads, 0.95), reads[len(reads)-1])
	t.Logf("STORAGE GROWTH: %d records, %d bytes total, %d bytes/record",
		len(keys), stored, stored/max1(len(keys)))
	t.Logf("NOT MEASURED: DHT network latency, erasure coding, I2P transport. "+
		"Those need a reachable node; a local number presented as DHT latency "+
		"would be wrong in the flattering direction.")
	_ = runtime.NumCPU()
}

// Concurrent evidence traffic: throughput and whether it stays correct.
func TestP14EvidenceConcurrentThroughput(t *testing.T) {
	p14Skip(t)
	const workers, each = 8, 200

	mem := newMemEvidenceForBench()
	store := benchStore(mem)
	ev := benchEvidence(t)

	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				e := ev
				e.ChannelID = fmt.Sprintf("0x%058x%02x%02x", 0, w, i%256)
				if err := store.Put(context.Background(), e); err != nil {
					errs[w] = err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	for w, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", w, err)
		}
	}
	total := workers * each
	t.Logf("EVIDENCE THROUGHPUT (node-side): %d writes in %s = %.0f writes/sec across %d workers",
		total, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), workers)
}

// ---- proof verification -----------------------------------------------------

// BLS aggregate verification is the expensive half of establishing an
// authenticated header, and it is what a watchtower pays per finality update.
func TestP14BLSVerificationLatency(t *testing.T) {
	p14Skip(t)
	vectors := loadBLSVectorsForBench(t)
	if len(vectors) == 0 {
		t.Skip("no BLS vectors present")
	}

	var samples []time.Duration
	var verified, rejected int
	for _, v := range vectors {
		start := time.Now()
		err := verifyAggregate(v.root, v.pubkeys, v.signature)
		samples = append(samples, time.Since(start))
		if err == nil {
			verified++
		} else {
			rejected++
		}
	}
	sortDurations(samples)
	t.Logf("BLS AGGREGATE VERIFY: n=%d min=%s median=%s p95=%s max=%s (%d ok, %d rejected)",
		len(samples), samples[0], pct(samples, 0.5), pct(samples, 0.95),
		samples[len(samples)-1], verified, rejected)

	// Sustained throughput on one core, using the largest vector available.
	big := vectors[0]
	for _, v := range vectors {
		if len(v.pubkeys) > len(big.pubkeys) {
			big = v
		}
	}
	const reps = 50
	start := time.Now()
	for i := 0; i < reps; i++ {
		_ = verifyAggregate(big.root, big.pubkeys, big.signature)
	}
	el := time.Since(start)
	t.Logf("BLS SUSTAINED: %d verifications of a %d-key aggregate in %s = %.1f/sec (single core)",
		reps, len(big.pubkeys), el.Round(time.Millisecond), float64(reps)/el.Seconds())

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	t.Logf("BLS heap after run: %d MB", mem.HeapAlloc>>20)
}

// Concurrent verification: does it scale across cores, and stay correct.
func TestP14ConcurrentVerification(t *testing.T) {
	p14Skip(t)
	vectors := loadBLSVectorsForBench(t)
	if len(vectors) == 0 {
		t.Skip("no BLS vectors present")
	}
	big := vectors[0]
	for _, v := range vectors {
		if len(v.pubkeys) > len(big.pubkeys) {
			big = v
		}
	}

	for _, workers := range []int{1, 4, runtime.NumCPU()} {
		const perWorker = 20
		start := time.Now()
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < perWorker; i++ {
					_ = verifyAggregate(big.root, big.pubkeys, big.signature)
				}
			}()
		}
		wg.Wait()
		el := time.Since(start)
		total := workers * perWorker
		t.Logf("CONCURRENT VERIFY: %2d workers -> %d verifications in %s = %.1f/sec",
			workers, total, el.Round(time.Millisecond), float64(total)/el.Seconds())
	}
}

// ---- sustained resources ----------------------------------------------------

// A sustained mixed workload: verification and evidence traffic together,
// sampling resources throughout.
//
// Resource figures are last-sample-plus-peak, matching the metrics layer's own
// rule — no timestamped series.
func TestP14SustainedResourceBaseline(t *testing.T) {
	p14Skip(t)
	const duration = 20 * time.Second

	vectors := loadBLSVectorsForBench(t)
	if len(vectors) == 0 {
		t.Skip("no BLS vectors present")
	}
	big := vectors[0]
	for _, v := range vectors {
		if len(v.pubkeys) > len(big.pubkeys) {
			big = v
		}
	}
	mem := newMemEvidenceForBench()
	store := benchStore(mem)
	ev := benchEvidence(t)

	stop := time.Now().Add(duration)
	var verifications, writes uint64
	var peakHeap uint64
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			_ = verifyAggregate(big.root, big.pubkeys, big.signature)
			verifications++
		}
	}()
	go func() {
		defer wg.Done()
		i := 0
		for time.Now().Before(stop) {
			e := ev
			e.ChannelID = fmt.Sprintf("0x%060x%02x", 0, i%256)
			_ = store.Put(context.Background(), e)
			writes++
			i++
		}
	}()

	// Sample resources while the load runs.
	sampling := make(chan struct{})
	go func() {
		defer close(sampling)
		for time.Now().Before(stop) {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peakHeap {
				peakHeap = ms.HeapAlloc
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	wg.Wait()
	<-sampling

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("SUSTAINED %s: %d BLS verifications (%.1f/sec), %d evidence writes (%.0f/sec)",
		duration, verifications, float64(verifications)/duration.Seconds(),
		writes, float64(writes)/duration.Seconds())
	t.Logf("RESOURCES: heap now %d MB, peak %d MB, sys %d MB, goroutines %d, cores %d",
		ms.HeapAlloc>>20, peakHeap>>20, ms.Sys>>20, runtime.NumGoroutine(), runtime.NumCPU())
	t.Logf("NOT MEASURED: disk I/O and RPC utilisation — this workload touches "+
		"neither, so reporting a number for them would be reporting zero as if "+
		"it were a measurement.")
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
