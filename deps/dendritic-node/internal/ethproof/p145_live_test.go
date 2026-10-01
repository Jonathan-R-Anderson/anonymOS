package ethproof

// P14.5 — the PRODUCTION implementation against real mainnet.
//
// The pre-implementation harness measured a throwaway copy of this logic. This
// runs the shipped code: ReceiptsRoot, BuildMPT, EncodeExecutionHeader,
// ChainFollower and RPCSource, against blocks the beacon chain authenticates.
//
//	P145=1 CHAIN_PROBE=1 ETH_RPC_URL=... BEACON_API_URL=... \
//	  go test ./internal/ethproof/ -run TestP145Live -v -timeout 40m
//
// The reference root never comes from whoever supplies the receipts. Two
// providers, and the one serving the data does not get to grade it.

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func p145LiveSkip(t *testing.T) (*RPCSource, *BeaconFinalizedSource) {
	t.Helper()
	if os.Getenv("P145") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P145=1 CHAIN_PROBE=1 to run the live P14.5 tests")
	}
	rpc := os.Getenv("ETH_RPC_URL")
	beaconURL := os.Getenv("BEACON_API_URL")
	if rpc == "" || beaconURL == "" {
		t.Skip("set ETH_RPC_URL and BEACON_API_URL")
	}
	if sameProvider(rpc, beaconURL) {
		t.Fatalf("consensus and execution are the same provider (%s); the "+
			"reference root must not come from whoever supplies the receipts",
			providerOf(rpc))
	}
	return &RPCSource{
			Endpoint: rpc, MaxRetries: 5, MinInterval: 120 * time.Millisecond, MaxBatch: 25,
		}, &BeaconFinalizedSource{
			Beacon: NewBeaconClient(beaconURL), Spec: SpecAltair,
		}
}

// The core property, through the production path.
func TestP145LiveAuthenticatedReceiptsRoundTrip(t *testing.T) {
	src, beacon := p145LiveSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized block: %v", err)
	}
	if !head.Authenticated() {
		t.Fatal("the finalised block is not authenticated")
	}
	t.Logf("AUTHENTICATED block %d, hash %x, receiptsRoot %x",
		head.Number, head.Hash[:8], head.ReceiptsRoot[:8])

	receipts, err := src.ReceiptsByNumber(ctx, head.Number)
	if err != nil {
		t.Fatalf("receipts: %v", err)
	}
	// AuthenticateReceipts is the gate: there is no boolean to ignore.
	verified, err := AuthenticateReceipts(head.ReceiptsRoot, receipts)
	if err != nil {
		t.Fatalf("PRODUCTION REBUILD FAILED against the authenticated root: %v", err)
	}

	types := map[uint64]int{}
	logs := 0
	for _, r := range verified {
		types[r.Type]++
		logs += len(r.Logs)
	}
	t.Logf("ROUND TRIP EXACT through production code: %d receipts, %d logs, types %v",
		len(verified), logs, types)

	// The bloom must agree with the receipts, and both are authenticated.
	if union := unionBloom(verified); union != head.LogsBloom {
		t.Error("the receipt blooms do not union to the authenticated logsBloom")
	} else {
		t.Logf("  receipt blooms union to the authenticated logsBloom "+
			"(%d/2048 bits set)", BloomBitsSet(head.LogsBloom))
	}
}

// Legacy and every EIP-2718 type on current mainnet, plus the fork-aware header
// encoder, over a run of consecutive blocks.
func TestP145LiveTypedReceiptsAndHeaderEncoding(t *testing.T) {
	src, beacon := p145LiveSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}

	const blocks = 12
	headers, err := src.HeadersDescending(ctx, head.Number, blocks)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}

	// The backwards walk, through production code, anchored at the authenticated
	// hash. Every link binds by hash, never by height.
	expected := head.Hash
	types := map[uint64]int{}
	forks := map[string]int{}
	for i, h := range headers {
		fork, err := ExecutionForkAt(1, h.Time)
		if err != nil {
			t.Fatalf("fork for block %v: %v", h.Number, err)
		}
		forks[fork.String()]++
		b, err := BlockFromParentLink(h, fork, expected)
		if err != nil {
			t.Fatalf("block %d of the walk did not authenticate: %v", i, err)
		}

		receipts, err := src.ReceiptsByNumber(ctx, b.Number)
		if err != nil {
			t.Fatalf("receipts %d: %v", b.Number, err)
		}
		verified, err := AuthenticateReceipts(b.ReceiptsRoot, receipts)
		if err != nil {
			t.Fatalf("block %d receipts did not rebuild to its AUTHENTICATED "+
				"receiptsRoot: %v", b.Number, err)
		}
		for _, r := range verified {
			types[r.Type]++
		}
		expected = b.ParentHash
	}

	t.Logf("BACKWARDS WALK: %d consecutive headers re-encoded and authenticated "+
		"by hash, anchored at the finalised block", blocks)
	t.Logf("  fork layouts used: %v", forks)
	t.Logf("  receipt types round-tripped: %v", types)
	for _, want := range []uint64{0, 2} {
		if types[want] == 0 {
			t.Errorf("no type 0x%x receipts seen — coverage is incomplete", want)
		}
	}
	if types[3] == 0 && types[4] == 0 {
		t.Log("  NOTE: no blob (0x3) or setcode (0x4) receipts in this window; " +
			"they are intermittent, and the earlier fixture run covered them")
	}
}

// A header whose fork layout is wrong must FAIL, not produce a plausible hash.
func TestP145LiveWrongForkLayoutIsRefused(t *testing.T) {
	src, beacon := p145LiveSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}
	headers, err := src.HeadersDescending(ctx, head.Number, 1)
	if err != nil || len(headers) != 1 {
		t.Fatalf("headers: %v", err)
	}
	h := headers[0]

	if _, err := AuthenticateHeader(h, ForkPrague, head.Hash); err != nil {
		t.Fatalf("the correct layout failed: %v", err)
	}
	for _, wrong := range []ExecutionFork{ForkLondon, ForkShanghai, ForkCancun} {
		if _, err := AuthenticateHeader(h, wrong, head.Hash); err == nil {
			t.Errorf("layout %s produced the authenticated hash for a Prague block — "+
				"a wrong field count must never verify", wrong)
		}
	}
	if _, err := AuthenticateHeader(h, ForkUnknown, head.Hash); err == nil {
		t.Error("ForkUnknown encoded a header; the zero value must refuse")
	}
	t.Log("only the recorded layout verifies; London, Shanghai, Cancun and " +
		"ForkUnknown all refuse")
}

// MEASUREMENT A — bloom rate for ACTIVE contracts.
//
// Ours is idle, so its 82% skip rate is a best case that says nothing about a
// busy deployment. These are real mainnet contracts spanning the range, so the
// production envelope can be stated as a range rather than as the idle number.
func TestP145LiveActiveContractBloomRate(t *testing.T) {
	src, beacon := p145LiveSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}

	subjects := []struct {
		name string
		addr [20]byte
	}{
		{"WETH (very active)", addr20("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")},
		{"USDC (very active)", addr20("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")},
		{"Uniswap V3 router", addr20("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")},
		{"ChannelManagerV2 (ours, idle)", addr20("ae70526931FF460894133201f6C8cA91bbA0E177")},
	}

	const blocks = 60
	headers, err := src.HeadersDescending(ctx, head.Number, blocks)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}

	// Authenticate the whole window first, so every bloom tested is a real one.
	expected := head.Hash
	auth := make([]AuthenticatedBlock, 0, blocks)
	for _, h := range headers {
		fork, err := ExecutionForkAt(1, h.Time)
		if err != nil {
			t.Fatalf("fork: %v", err)
		}
		b, err := BlockFromParentLink(h, fork, expected)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		auth = append(auth, b)
		expected = b.ParentHash
	}

	var saturation int
	for _, b := range auth {
		saturation += BloomBitsSet(b.LogsBloom)
	}
	t.Logf("MEASUREMENT A — bloom skip rate over %d AUTHENTICATED blocks", blocks)
	t.Logf("  average bloom saturation: %d/2048 (%.0f%%)",
		saturation/len(auth), 100*float64(saturation)/float64(len(auth))/2048)

	for _, s := range subjects {
		positives := 0
		for _, b := range auth {
			if b.MayContainAddress(s.addr) {
				positives++
			}
		}
		skipped := blocks - positives
		// Cost per 30-second sweep: ~2.5 blocks, receipts fetched only on a hit.
		fetchesPerSweep := 2.5 * float64(positives) / float64(blocks)
		t.Logf("  %-30s skip %3d/%d (%3.0f%%)  ->  %.2f receipt fetches per 30s sweep",
			s.name, skipped, blocks, 100*float64(skipped)/float64(blocks), fetchesPerSweep)
	}
	t.Log("  A contract in every block is the worst case: 2.5 fetches per sweep, " +
		"which at the measured 79ms is still under 0.7% of the interval. The " +
		"bloom saves work; it is not what makes the design viable.")
}

// MEASUREMENT B — what the provider actually does at its limit.
//
// Deliberately unthrottled and unretried, so the refusal is observed rather than
// smoothed over. Kept short: this is somebody's paid quota.
func TestP145LiveRateLimitBehaviour(t *testing.T) {
	if os.Getenv("P145_RATELIMIT") == "" {
		t.Skip("set P145_RATELIMIT=1 — this deliberately trips the provider's limit")
	}
	src, beacon := p145LiveSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}

	// No throttle, no retries: surface the limit immediately.
	hot := &RPCSource{Endpoint: src.Endpoint, MaxRetries: 0, MinInterval: 0}
	const burst = 40
	var firstRefusalAt = -1
	var ok, refused int
	start := time.Now()
	for i := 0; i < burst; i++ {
		_, err := hot.ReceiptsByNumber(ctx, head.Number-uint64(i))
		if err != nil {
			refused++
			if firstRefusalAt < 0 {
				firstRefusalAt = i
			}
		} else {
			ok++
		}
	}
	burstTime := time.Since(start)
	stats := hot.Stats()
	t.Logf("MEASUREMENT B — provider behaviour at the limit")
	t.Logf("  unthrottled burst: %d requests in %s", burst, burstTime.Round(time.Millisecond))
	t.Logf("  succeeded %d, refused %d, first refusal at request %d",
		ok, refused, firstRefusalAt)
	t.Logf("  RPCSource counted %d rate-limit events separately from %d calls",
		stats.RateLimited, stats.Calls)
	if refused == 0 {
		t.Logf("  the limit was NOT reached at this burst size; the sustainable " +
			"rate is at least this high")
	}

	// Recovery: does a pause restore service, and how long does it take?
	if refused > 0 {
		for _, pause := range []time.Duration{time.Second, 2 * time.Second, 5 * time.Second} {
			time.Sleep(pause)
			probe := &RPCSource{Endpoint: src.Endpoint, MaxRetries: 0}
			_, err := probe.ReceiptsByNumber(ctx, head.Number)
			t.Logf("  after %s pause: %v", pause, errText(err))
			if err == nil {
				break
			}
		}
	}

	// What the limit means for catch-up, which is when it hurts.
	throttled := &RPCSource{Endpoint: src.Endpoint, MaxRetries: 5, MinInterval: 120 * time.Millisecond}
	throttled.ResetStats()
	cstart := time.Now()
	for i := 0; i < 10; i++ {
		if _, err := throttled.ReceiptsByNumber(ctx, head.Number-uint64(i)); err != nil {
			t.Fatalf("throttled fetch %d failed: %v", i, err)
		}
	}
	ts := throttled.Stats()
	t.Logf("  THROTTLED (120ms floor, 5 retries): 10 blocks in %s, "+
		"%d rate-limit events, %d retries",
		time.Since(cstart).Round(time.Millisecond), ts.RateLimited, ts.Retries)
	t.Log("  A rate limit during CATCH-UP is the dangerous case: it is exactly " +
		"when the watchtower is furthest behind. Counted separately so it is " +
		"visible before it matters, never folded into a latency average.")
}

// MEASUREMENT C — the worst case: many channels changing at once.
//
// Measured locally against a synthesised block, because 10,000 real closes
// cannot be produced on mainnet. The BLOCK is synthetic; the trie, the encoding
// and the authentication are the production ones.
func TestP145WorstCaseManyChannelsInOneWindow(t *testing.T) {
	if os.Getenv("P145") == "" {
		t.Skip("set P145=1")
	}

	// How many closeUnilateral calls fit in a block at all? 143,869 gas each
	// (doc/fixtures/p14-economics.md), against a 30M block. That is the real
	// ceiling on "10,000 channels change in one window" and it is worth stating
	// before measuring a scenario the chain cannot produce.
	const closeGas = 143_869
	const blockGas = 30_000_000
	perBlock := blockGas / closeGas
	t.Logf("MEASUREMENT C — worst case, many channels changing at once")
	t.Logf("  closeUnilateral is %d gas; a 30M block holds at most %d of them",
		closeGas, perBlock)
	t.Logf("  a 30s window is ~2.5 blocks, so the chain itself caps a window at "+
		"~%d closes — 10,000 in one window is not reachable", perBlock*5/2)

	for _, n := range []int{208, 1000, 5000, 10000} {
		receipts := make([]Receipt, 0, n)
		for i := 0; i < n; i++ {
			var id [32]byte
			for b := 0; b < 8; b++ {
				id[31-b] = byte(uint64(i) >> (8 * b))
			}
			var sig, by [32]byte
			copy(sig[:], Keccak256([]byte("CloseStarted(bytes32,address,uint64,uint256)")))
			by[31] = 1
			log := Log{
				Address: addr20("ae70526931FF460894133201f6C8cA91bbA0E177"),
				Topics:  [][32]byte{sig, id, by},
				Data:    make([]byte, 64),
			}
			r := Receipt{
				TxIndex: uint64(i), Type: 2, Status: 1,
				CumulativeGasUsed: uint64(i+1) * closeGas,
				Logs:              []Log{log},
			}
			r.Bloom = BloomFromLogs(r.Logs)
			receipts = append(receipts, r)
		}

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		start := time.Now()
		root, err := ReceiptsRoot(receipts)
		build := time.Since(start)
		if err != nil {
			t.Fatalf("build at %d: %v", n, err)
		}
		var authRoot Root
		copy(authRoot[:], root)

		start = time.Now()
		verified, err := AuthenticateReceipts(authRoot, receipts)
		verify := time.Since(start)
		if err != nil {
			t.Fatalf("authenticate at %d: %v", n, err)
		}

		var bloom Bloom2048
		for _, r := range verified {
			for i := range bloom {
				bloom[i] |= r.Bloom[i]
			}
		}
		b := BlockFromFinalizedPayload(ExecutionPayloadHeader{
			ReceiptsRoot: authRoot, LogsBloom: bloom, BlockNumber: 1,
		})
		start = time.Now()
		logs, err := b.AuthenticatedLogsFrom(
			addr20("ae70526931FF460894133201f6C8cA91bbA0E177"), verified)
		extract := time.Since(start)
		if err != nil {
			t.Fatalf("extract at %d: %v", n, err)
		}
		if len(logs) != n {
			t.Fatalf("extracted %d logs, want %d", len(logs), n)
		}
		runtime.ReadMemStats(&after)

		t.Logf("  %6d events in one block: build %8s  authenticate %8s  extract %7s  "+
			"alloc %d MB", n, build.Round(time.Microsecond), verify.Round(time.Microsecond),
			extract.Round(time.Microsecond), (after.TotalAlloc-before.TotalAlloc)>>20)
	}

	t.Log("  The receipt work is local and cheap even far past what a block can " +
		"hold. The real worst-case cost is downstream: every distinct channel " +
		"named by an event is re-read from the inner reader, so N changed " +
		"channels costs N chain reads — the same as the status quo, which is " +
		"the honest floor and is not improved by this design.")
}

func addr20(hexs string) [20]byte {
	b, err := hexData("0x"+hexs, 20)
	if err != nil {
		panic(err)
	}
	var out [20]byte
	copy(out[:], b)
	return out
}

func errText(err error) string {
	if err == nil {
		return "recovered"
	}
	return err.Error()
}

// MEASUREMENT 4, redone against the PRODUCTION follower.
//
// The design-phase catch-up figures assumed clean-run latencies. Measurement B
// showed the provider refusing at roughly six receipt fetches a second, so a
// number derived from unthrottled latency would describe a catch-up that cannot
// happen. This runs the real ChainFollower over a real gap and extrapolates from
// what it actually achieved, retries and all.
func TestP145LiveCatchUpThroughput(t *testing.T) {
	src, beacon := p145LiveSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	gap := 200
	if v := os.Getenv("P145_CATCHUP_BLOCKS"); v != "" {
		fmt.Sscanf(v, "%d", &gap)
	}

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}

	// The checkpoint must name a block by HASH, so walk back to find one
	// honestly rather than inventing a height.
	headers, err := src.HeadersDescending(ctx, head.Number, gap+1)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	expected := head.Hash
	var startCP FollowerCheckpoint
	for i, h := range headers {
		fork, err := ExecutionForkAt(1, h.Time)
		if err != nil {
			t.Fatalf("fork: %v", err)
		}
		b, err := BlockFromParentLink(h, fork, expected)
		if err != nil {
			t.Fatalf("walk at %d: %v", i, err)
		}
		expected = b.ParentHash
		startCP = FollowerCheckpoint{BlockNumber: b.Number, BlockHash: b.Hash}
	}

	store := &FileCheckpointStore{Path: t.TempDir() + "/checkpoint.json"}
	f := &ChainFollower{
		ChainID: 1, Contract: addr20("ae70526931FF460894133201f6C8cA91bbA0E177"),
		Headers: src, Finalized: beacon, Store: store, BatchSize: 25,
	}
	if err := f.InitializeAt(startCP); err != nil {
		t.Fatalf("init: %v", err)
	}

	src.ResetStats()
	start := time.Now()
	prog, err := f.Advance(ctx, func(AuthenticatedBlock, []Log) error { return nil })
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("catch-up failed after %s: %v", elapsed.Round(time.Second), err)
	}
	st := src.Stats()

	perBlock := elapsed / time.Duration(max2(1, prog.BlocksExamined))
	t.Logf("MEASUREMENT 4 (production) — real catch-up over %d finalised blocks",
		prog.BlocksExamined)
	t.Logf("  %s total, %s per block", elapsed.Round(time.Millisecond), perBlock.Round(time.Millisecond))
	t.Logf("  skipped by AUTHENTICATED bloom: %d/%d (%.0f%%), receipts fetched: %d, logs: %d",
		prog.BlocksSkipped, prog.BlocksExamined,
		100*float64(prog.BlocksSkipped)/float64(max2(1, prog.BlocksExamined)),
		prog.BlocksFetched, prog.LogsFound)
	t.Logf("  provider: %d calls, %d RATE-LIMIT events, %d retries, %d batch shrinks, settled batch %d",
		st.Calls, st.RateLimited, st.Retries, st.BatchShrinks, st.LastBatch)

	for _, o := range []struct {
		name   string
		blocks int
	}{{"1 hour", 300}, {"24 hours", 7200}, {"1 week", 50400}} {
		d := time.Duration(o.blocks) * perBlock
		t.Logf("  %-9s = %6d blocks: %s", o.name, o.blocks, d.Round(time.Second))
	}
	t.Log("  Extrapolated from a run that INCLUDED rate-limit retries, so it is " +
		"a rate the provider actually sustained rather than a clean-run best case.")

	// The checkpoint must have advanced to the head, durably.
	cp, ok, err := store.LoadCheckpoint()
	if err != nil || !ok {
		t.Fatalf("checkpoint not persisted: %v", err)
	}
	if cp.BlockNumber != prog.To {
		t.Fatalf("checkpoint is at %d, the advance reached %d", cp.BlockNumber, prog.To)
	}
	t.Logf("  checkpoint persisted at block %d (hash %x) — a restart resumes here",
		cp.BlockNumber, cp.BlockHash[:8])
}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}
