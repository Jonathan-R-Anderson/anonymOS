package ethproof

// P14.6d — compute-unit accounting, and the post-upgrade catch-up measurement.
//
// MEASUREMENT ONLY. No production code is changed. The endpoint is configuration
// (ETH_RPC_URL); the verification path is byte-for-byte the same one P14.5
// shipped, and switching provider tiers touches none of it.
//
//	PROJECTION (runs anywhere, no network):
//	  go test ./internal/ethproof/ -run TestP146DProjectedMonthlyCU -v
//
//	MEASUREMENT (needs the upgraded endpoint):
//	  P146D=1 CHAIN_PROBE=1 ETH_RPC_URL=... BEACON_API_URL=... \
//	    P146D_BLOCKS=2000 go test ./internal/ethproof/ -run TestP146DCatchUp -v -timeout 60m
//
// WHY CU IS COUNTED HERE AND NOT IN RPCSource
// -------------------------------------------
// RPCSource.Stats() counts CALLS, and a batch of 25 headers is one call. Alchemy
// bills per METHOD INVOCATION, so a batch of 25 costs 25 units of billing and 1
// unit of "calls". Counting CU inside RPCSource would mean teaching production
// code a provider's price list, which is exactly the kind of coupling that goes
// stale silently. It lives in the test that cares.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Alchemy's published weights. BILLED CU is what appears on the invoice;
// THROUGHPUT CU is what the rate limiter charges against the per-second cap, and
// for eth_getBlockReceipts the two differ by 25x — which is the entire reason
// the free tier throttled us at one call per second.
const (
	cuBlockByNumber        = 20
	cuBlockReceipts        = 20
	cuGetProof             = 20
	cuThroughputReceipts   = 500
	cuThroughputPerSecFree = 500
	cuThroughputPerSecPAYG = 10000
	usdPerMillionCU        = 0.45
)

// cuCounter wraps a HeaderSource and counts METHOD INVOCATIONS, not requests.
type cuCounter struct {
	inner HeaderSource

	mu           sync.Mutex
	headerCalls  int
	receiptCalls int
	receiptTime  time.Duration
	headerTime   time.Duration
	receiptLat   []time.Duration
}

func (c *cuCounter) HeadersDescending(ctx context.Context, from uint64, count int) ([]ExecutionHeader, error) {
	start := time.Now()
	h, err := c.inner.HeadersDescending(ctx, from, count)
	took := time.Since(start)
	c.mu.Lock()
	c.headerTime += took
	// Every header in the batch is a separate eth_getBlockByNumber invocation as
	// far as billing is concerned, whether or not they shared a request.
	c.headerCalls += count
	c.mu.Unlock()
	return h, err
}

func (c *cuCounter) ReceiptsByNumber(ctx context.Context, n uint64) ([]Receipt, error) {
	start := time.Now()
	r, err := c.inner.ReceiptsByNumber(ctx, n)
	took := time.Since(start)
	c.mu.Lock()
	c.receiptCalls++
	c.receiptTime += took
	c.receiptLat = append(c.receiptLat, took)
	c.mu.Unlock()
	return r, err
}

// latency reports the per-call distribution. A call that waited on a provider
// backoff shows up here as a multi-second outlier, so this is how "backoff time"
// is evidenced rather than asserted.
func (c *cuCounter) latency() (median, p95, max time.Duration, overTwoSec int) {
	c.mu.Lock()
	d := append([]time.Duration(nil), c.receiptLat...)
	c.mu.Unlock()
	if len(d) == 0 {
		return
	}
	sortDurations(d)
	for _, x := range d {
		if x >= 2*time.Second {
			overTwoSec++
		}
	}
	return pct(d, 0.5), pct(d, 0.95), d[len(d)-1], overTwoSec
}

func (c *cuCounter) totals() (headers, receipts, cu int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.headerCalls, c.receiptCalls,
		c.headerCalls*cuBlockByNumber + c.receiptCalls*cuBlockReceipts
}

// The projection, from measured parameters. Runs offline.
func TestP146DProjectedMonthlyCU(t *testing.T) {
	// MEASURED INPUTS, all from earlier P14 work:
	const (
		blocksPerDay  = 7200 // mainnet, 12s slots
		bloomHitRate  = 0.20 // P14.5 catch-up: 159/200 skipped
		watchtowers   = 2    // the declared P12-8 envelope
		daysPerMonth  = 30
		weekBlocks    = 50400
		perBlockMsPAY = 24.5 // P14.5 measured "actual work" without rate limits
	)

	headersDay := blocksPerDay
	receiptsDay := int(float64(blocksPerDay) * bloomHitRate)
	cuDay := headersDay*cuBlockByNumber + receiptsDay*cuBlockReceipts
	cuMonth := cuDay * daysPerMonth
	cuMonthFleet := cuMonth * watchtowers

	t.Logf("STEADY STATE, per watchtower")
	t.Logf("  finality advances one epoch (32 slots) every ~6.4 min; Advance makes")
	t.Logf("  ZERO Alchemy calls when the finalised head has not moved.")
	t.Logf("  headers  %6d/day x %d CU = %9d CU", headersDay, cuBlockByNumber, headersDay*cuBlockByNumber)
	t.Logf("  receipts %6d/day x %d CU = %9d CU  (%.0f%% bloom-hit, measured)",
		receiptsDay, cuBlockReceipts, receiptsDay*cuBlockReceipts, bloomHitRate*100)
	t.Logf("  = %d CU/day, %.2fM CU/month", cuDay, float64(cuMonth)/1e6)
	t.Logf("FLEET of %d watchtowers: %.2fM CU/month", watchtowers, float64(cuMonthFleet)/1e6)
	t.Logf("  against the free tier's 30M/month allowance: %.0f%% of it",
		100*float64(cuMonthFleet)/30e6)

	weekCU := weekBlocks*cuBlockByNumber + int(float64(weekBlocks)*bloomHitRate)*cuBlockReceipts
	t.Logf("")
	t.Logf("ONE-WEEK CATCH-UP: %d headers + %d receipt fetches = %.2fM CU = $%.2f",
		weekBlocks, int(float64(weekBlocks)*bloomHitRate), float64(weekCU)/1e6,
		float64(weekCU)/1e6*usdPerMillionCU)

	t.Logf("")
	t.Logf("COST at $%.2f/M CU (PAYG, first 300M):", usdPerMillionCU)
	t.Logf("  steady state, fleet : $%.2f/month", float64(cuMonthFleet)/1e6*usdPerMillionCU)
	t.Logf("  + one catch-up/month: $%.2f/month",
		(float64(cuMonthFleet)+float64(weekCU))/1e6*usdPerMillionCU)

	// THE POINT: volume was never the constraint. Throughput was.
	t.Logf("")
	t.Logf("WHY THE UPGRADE IS ABOUT THROUGHPUT, NOT VOLUME:")
	t.Logf("  eth_getBlockReceipts bills %d CU but costs %d THROUGHPUT CU",
		cuBlockReceipts, cuThroughputReceipts)
	t.Logf("  free tier %d CU/s  -> %.1f receipt fetches/sec",
		cuThroughputPerSecFree, float64(cuThroughputPerSecFree)/cuThroughputReceipts)
	t.Logf("  PAYG      %d CU/s -> %.0f receipt fetches/sec (%.0fx)",
		cuThroughputPerSecPAYG, float64(cuThroughputPerSecPAYG)/cuThroughputReceipts,
		float64(cuThroughputPerSecPAYG)/cuThroughputPerSecFree)

	// A runaway is the thing an alert has to catch, so size it here.
	runawayCUperSec := float64(cuThroughputPerSecPAYG) / cuThroughputReceipts * cuBlockReceipts
	runawayDay := runawayCUperSec * 86400
	t.Logf("")
	t.Logf("RUNAWAY CEILING (a loop fetching receipts flat out at PAYG throughput):")
	t.Logf("  %.0f CU/s = %.1fM CU/day = $%.2f/day = $%.0f/month",
		runawayCUperSec, runawayDay/1e6, runawayDay/1e6*usdPerMillionCU,
		runawayDay*30/1e6*usdPerMillionCU)
	t.Logf("  ALERT RECOMMENDATION: $25/month catches that within ~2 days while")
	t.Logf("  sitting ~5x above expected spend.")

	if cuMonthFleet > 30_000_000 {
		t.Errorf("projected fleet usage %.1fM CU/month exceeds even the FREE "+
			"allowance; the volume assumption needs revisiting", float64(cuMonthFleet)/1e6)
	}
}

// The post-upgrade measurement. Requires the higher-throughput endpoint.
//
// Deliberately measures the SAME shape as the P14.5 baseline (243 ms/block, 20
// rate-limit events over 200 blocks) so the before/after is like-for-like.
func TestP146DCatchUpOnUpgradedTier(t *testing.T) {
	if os.Getenv("P146D") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P146D=1 CHAIN_PROBE=1 — needs the UPGRADED endpoint")
	}
	rpc, beaconURL := os.Getenv("ETH_RPC_URL"), os.Getenv("BEACON_API_URL")
	if rpc == "" || beaconURL == "" {
		t.Skip("set ETH_RPC_URL and BEACON_API_URL")
	}
	if sameProvider(rpc, beaconURL) {
		t.Fatalf("consensus and execution are the same provider; the reference " +
			"root must not come from whoever supplies the receipts")
	}

	gap := 2000
	if v := os.Getenv("P146D_BLOCKS"); v != "" {
		fmt.Sscanf(v, "%d", &gap)
	}

	// NO THROTTLE. The whole point is to find out whether the limit still binds.
	// MaxRetries stays non-zero so a refusal is survivable, but every refusal is
	// counted and reported — if the result depends on them, the upgrade did not
	// solve the problem and the number must say so.
	src := &RPCSource{Endpoint: rpc, MaxRetries: 5, MinInterval: 0, MaxBatch: 100}
	counted := &cuCounter{inner: src}
	beacon := &BeaconFinalizedSource{Beacon: NewBeaconClient(beaconURL), Spec: SpecAltair}

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}

	// Walk back by HASH to find an honest checkpoint, exactly as catch-up does.
	headers, err := src.HeadersDescending(ctx, head.Number, gap+1)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	expected := head.Hash
	var startCP FollowerCheckpoint
	for i, h := range headers {
		fork, err := ExecutionForkAt(1, h.Time)
		if err != nil {
			t.Fatalf("fork at %d: %v", i, err)
		}
		b, err := BlockFromParentLink(h, fork, expected)
		if err != nil {
			t.Fatalf("walk at %d: %v", i, err)
		}
		expected = b.ParentHash
		startCP = FollowerCheckpoint{BlockNumber: b.Number, BlockHash: b.Hash}
	}

	store := &FileCheckpointStore{Path: t.TempDir() + "/cp.json"}
	f := &ChainFollower{
		ChainID: 1, Contract: addr20("ae70526931FF460894133201f6C8cA91bbA0E177"),
		Headers: counted, Finalized: beacon, Store: store, BatchSize: 100,
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
	hdrCalls, rcptCalls, cu := counted.totals()
	_ = hdrCalls

	per := elapsed / time.Duration(max2(1, prog.BlocksExamined))
	t.Logf("MEASURED CATCH-UP on the upgraded tier")
	t.Logf("  %d blocks in %s = %s/block", prog.BlocksExamined,
		elapsed.Round(time.Millisecond), per.Round(time.Microsecond))
	t.Logf("  effective %.2f eth_getBlockReceipts/sec", float64(rcptCallsOf(counted))/elapsed.Seconds())
	t.Logf("  batch size configured %d, shrinks %d, settled %d", 100, st.BatchShrinks, st.LastBatch)
	t.Logf("  bloom-skipped %d/%d (%.0f%%), receipts fetched %d",
		prog.BlocksSkipped, prog.BlocksExamined,
		100*float64(prog.BlocksSkipped)/float64(max2(1, prog.BlocksExamined)),
		prog.BlocksFetched)
	t.Logf("")
	t.Logf("  RATE-LIMIT EVENTS: %d   retries: %d   batch shrinks: %d",
		st.RateLimited, st.Retries, st.BatchShrinks)
	if st.RateLimited == 0 {
		t.Logf("  -> the provider limit NO LONGER BINDS this workload")
	} else {
		t.Errorf("  -> the limit STILL BINDS: %d refusals. The measured time "+
			"below still contains backoff and must not be reported as clean.",
			st.RateLimited)
	}
	t.Logf("")
	med, p95, mx, slow := counted.latency()
	t.Logf("  BACKOFF: %s", func() string {
		if st.RateLimited == 0 && st.Retries == 0 {
			return "ZERO — no provider refusal, so no backoff was entered"
		}
		return fmt.Sprintf("%d retries; backoff starts at 2s and doubles, so at "+
			"least %s was spent waiting", st.Retries, time.Duration(st.Retries)*2*time.Second)
	}())
	t.Logf("  receipt call latency: median %s, p95 %s, max %s (%d calls >= 2s)",
		med.Round(time.Millisecond), p95.Round(time.Millisecond),
		mx.Round(time.Millisecond), slow)
	t.Logf("  time in receipt calls %s, in header batches %s, of %s wall",
		counted.receiptTime.Round(time.Second), counted.headerTime.Round(time.Second),
		elapsed.Round(time.Second))
	t.Logf("")
	t.Logf("  ACTUAL CU: %d eth_getBlockByNumber + %d eth_getBlockReceipts = %d CU",
		hdrCalls, rcptCalls, cu)
	t.Logf("  = %.4f CU/block, $%.4f for this run",
		float64(cu)/float64(max2(1, prog.BlocksExamined)),
		float64(cu)/1e6*usdPerMillionCU)

	// Extrapolate to the outage durations, from THIS measured rate.
	t.Logf("")
	t.Logf("  EXTRAPOLATED from this measured per-block rate:")
	for _, o := range []struct {
		name   string
		blocks int
	}{{"1 hour", 300}, {"24 hours", 7200}, {"1 week", 50400}} {
		d := time.Duration(o.blocks) * per
		blockCU := float64(cu) / float64(max2(1, prog.BlocksExamined)) * float64(o.blocks)
		t.Logf("    %-9s = %6d blocks: %-10s  %.2fM CU  $%.2f", o.name, o.blocks,
			d.Round(time.Second), blockCU/1e6, blockCU/1e6*usdPerMillionCU)
	}
	t.Logf("")
	t.Logf("  BASELINE (free tier, P14.5): 243 ms/block, 20 rate-limit events " +
		"over 200 blocks, 1 week = 3h24m")
	t.Logf("  IMPROVEMENT: %.1fx", 243.0/float64(per.Milliseconds()|1))
	t.Log("")
	t.Log("  THE OUTAGE BUDGET IS NOT VALIDATED BY THIS NUMBER. This measures " +
		"catch-up throughput against one provider on one day. The 4-hour Outage " +
		"term and challengePeriod remain exactly as they were.")
}

// ---------------------------------------------------------------------------
// P14.6e — what throughput does the CURRENT plan ACTUALLY provide?
//
// The published figure is 500 CU/s and eth_getBlockReceipts is documented at 500
// throughput CU, implying exactly one call per second. That is a documented
// number, not a measured one, and the two need not agree — a burst probe already
// showed 13 of 25 concurrent requests succeeding, which one-per-second does not
// predict.
//
// Measures the real sustained rate, sequentially and concurrently, and reports
// throughput SEPARATELY from monthly volume. They are different resources and
// conflating them is how the wrong plan gets bought.
// ---------------------------------------------------------------------------

type probeResult struct {
	concurrency int
	duration    time.Duration
	ok          int
	refused     int
	http429     int
}

func (p probeResult) okPerSec() float64 { return float64(p.ok) / p.duration.Seconds() }
func (p probeResult) cuPerSec() float64 { return p.okPerSec() * cuThroughputReceipts }
func (p probeResult) refusalRate() float64 {
	if p.ok+p.refused == 0 {
		return 0
	}
	return 100 * float64(p.refused) / float64(p.ok+p.refused)
}

// probePacedRate issues requests at a TARGET RATE and reports what got served.
//
// The first version of this hammered at fixed concurrency with no pacing and got
// 98-100% refusals at every rung — which measures what happens when you spam a
// provider, not what rate it will sustain. Sustainable throughput is the highest
// offered rate at which refusals stay near zero, so the rate is the independent
// variable and refusals are the reading.
func probePacedRate(t *testing.T, endpoint string, head uint64,
	perSec float64, window time.Duration) probeResult {
	t.Helper()

	// MaxRetries 0: a retry would hide the refusal, and the refusal IS the
	// measurement.
	src := &RPCSource{Endpoint: endpoint, MaxRetries: 0, MinInterval: 0}
	res := probeResult{concurrency: 1}

	interval := time.Duration(float64(time.Second) / perSec)
	deadline := time.Now().Add(window)
	start := time.Now()
	i := 0
	for time.Now().Before(deadline) {
		next := time.Now().Add(interval)
		_, err := src.ReceiptsByNumber(context.Background(), head-uint64(i%4000))
		if err == nil {
			res.ok++
		} else {
			res.refused++
		}
		i++
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	res.duration = time.Since(start)
	res.http429 = src.Stats().RateLimited
	return res
}

func TestP146ECurrentPlanThroughput(t *testing.T) {
	if os.Getenv("P146E") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P146E=1 CHAIN_PROBE=1 — this deliberately trips the rate limit")
	}
	endpoint := os.Getenv("ETH_RPC_URL")
	if endpoint == "" {
		t.Skip("set ETH_RPC_URL")
	}
	src := &RPCSource{Endpoint: endpoint, MaxRetries: 3, MinInterval: 200 * time.Millisecond}
	head := p146Head(t, src)

	window := 20 * time.Second
	if v := os.Getenv("P146E_WINDOW"); v != "" {
		var secs int
		fmt.Sscanf(v, "%d", &secs)
		window = time.Duration(secs) * time.Second
	}

	t.Logf("MEASURED THROUGHPUT of the CURRENT plan — eth_getBlockReceipts")
	t.Logf("published expectation: 500 CU/s cap, 500 throughput CU/call => 1.0 call/s")
	t.Logf("")

	// Let the token bucket recover before starting, so the first rung is not
	// paying for whatever ran before it.
	time.Sleep(15 * time.Second)

	var clean float64
	for _, rate := range []float64{0.5, 1.0, 1.5, 2.0, 3.0} {
		r := probePacedRate(t, endpoint, head, rate, window)
		verdict := "CLEAN"
		if r.refused > 0 {
			verdict = "REFUSALS"
		}
		t.Logf("  offered %.1f/s: %3d ok, %3d refused (%.0f%%), %d HTTP 429 => served %.2f/s  %s",
			rate, r.ok, r.refused, r.refusalRate(), r.http429, r.okPerSec(), verdict)
		if r.refused == 0 && r.okPerSec() > clean {
			clean = r.okPerSec()
		}
		time.Sleep(15 * time.Second)
	}

	t.Logf("")
	if clean == 0 {
		t.Logf("NO RATE WAS CLEAN — even %.1f/s drew refusals.", 0.5)
	} else {
		t.Logf("HIGHEST CLEAN SUSTAINED RATE: %.2f eth_getBlockReceipts/sec", clean)
		t.Logf("  = %.0f effective throughput CU/s against a documented 500 CU/s cap",
			clean*cuThroughputReceipts)
	}
	best := probeResult{ok: int(clean * window.Seconds()), duration: window}
	_ = best

	// What that rate means for the catch-up the budget cares about.
	const weekBlocks, bloomHit = 50400, 0.20
	receiptFetches := float64(weekBlocks) * bloomHit
	t.Logf("")
	t.Logf("IMPLIED ONE-WEEK CATCH-UP at the best measured rate:")
	if clean > 0 {
		t.Logf("  %.0f receipt fetches / %.2f per sec = %s (receipts alone)",
			receiptFetches, clean,
			(time.Duration(receiptFetches/clean) * time.Second).Round(time.Minute))
	}
	t.Logf("  against the 4-hour Outage budget term")
	t.Log("")
	t.Log("THROUGHPUT AND MONTHLY VOLUME ARE SEPARATE RESOURCES. This measures " +
		"throughput only. Monthly CU is reported separately and is not a " +
		"constraint at our volume.")
}

// ---------------------------------------------------------------------------
// P14.6f — the upgrade TRIGGER.
//
// The 2,000-block confirmatory run measured a 54% skip rate, against 75-82% from
// earlier 60-200 block samples. That is not noise to average away: the break-even
// for the 4-hour budget is 75.4%, so the two samples fall on OPPOSITE SIDES of
// the line and the small ones were too small to decide it.
//
// The skip rate has TWO independent drivers, and only one is ours:
//
//	true positives   our contract actually emitted   <- our channel activity
//	false positives  saturation^3, 3 hash positions  <- everyone ELSE's activity
//
// A trigger built only on our own activity would miss the half of the problem
// that mainnet congestion causes. This measures both.
// ---------------------------------------------------------------------------

func TestP146FSkipRateAndUpgradeTrigger(t *testing.T) {
	if os.Getenv("P146F") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P146F=1 CHAIN_PROBE=1")
	}
	rpc, beaconURL := os.Getenv("ETH_RPC_URL"), os.Getenv("BEACON_API_URL")
	if rpc == "" || beaconURL == "" {
		t.Skip("set ETH_RPC_URL and BEACON_API_URL")
	}
	// Headers only: 20 CU each, so 25/sec fits inside the measured 500 CU/s.
	src := &RPCSource{Endpoint: rpc, MaxRetries: 5, MinInterval: 0, MaxBatch: 100}
	beacon := &BeaconFinalizedSource{Beacon: NewBeaconClient(beaconURL), Spec: SpecAltair}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}
	blocks := 3000
	if v := os.Getenv("P146F_BLOCKS"); v != "" {
		fmt.Sscanf(v, "%d", &blocks)
	}

	ours := addr20("ae70526931FF460894133201f6C8cA91bbA0E177")
	headers, err := src.HeadersDescending(ctx, head.Number, blocks)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}

	// Walk by hash so every bloom read is an AUTHENTICATED one, not a claim.
	expected := head.Hash
	var satTotal, hits int
	buckets := map[int]int{}
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
		s := BloomBitsSet(b.LogsBloom)
		satTotal += s
		buckets[s*10/2048]++
		if b.MayContainAddress(ours) {
			hits++
		}
	}

	n := len(headers)
	skip := 100 * float64(n-hits) / float64(n)
	avgSat := float64(satTotal) / float64(n) / 2048
	t.Logf("AUTHENTICATED BLOOM SAMPLE: %d consecutive finalised blocks", n)
	t.Logf("  skip rate      : %.1f%%  (%d of %d blocks excluded outright)", skip, n-hits, n)
	t.Logf("  bloom hit rate : %.1f%%", 100*float64(hits)/float64(n))
	t.Logf("  avg saturation : %.1f%% of 2048 bits", 100*avgSat)
	t.Logf("  theory: FP = saturation^3 = %.1f%%  (our contract is IDLE, so every "+
		"hit is a false positive)", 100*avgSat*avgSat*avgSat)
	t.Logf("  saturation distribution (decile of 2048 bits -> blocks):")
	for d := 0; d <= 10; d++ {
		if buckets[d] > 0 {
			t.Logf("    %2d0-%2d0%%: %5d", d, d+1, buckets[d])
		}
	}

	// What the measured rate means for the budget, at the MEASURED throughput.
	const (
		cuPerSec   = 500.0 // measured: 1.00 receipts/sec x 500 throughput CU
		weekBlocks = 50400.0
		budgetSec  = 4 * 3600.0
	)
	hdrSec := weekBlocks * cuBlockByNumber / cuPerSec
	fetches := weekBlocks * float64(hits) / float64(n)
	rcptSec := fetches * cuThroughputReceipts / cuPerSec
	total := hdrSec + rcptSec
	t.Logf("")
	t.Logf("ONE-WEEK CATCH-UP at this skip rate and the MEASURED 1.00 receipts/sec:")
	t.Logf("  headers %.0f min + receipts %.2f h = %.2f h  (%.0f%% of the 4h budget)",
		hdrSec/60, rcptSec/3600, total/3600, 100*total/budgetSec)

	// The break-even, and what it means as a trigger.
	avail := budgetSec - hdrSec
	beFetches := avail * cuPerSec / cuThroughputReceipts
	beSkip := 100 * (1 - beFetches/weekBlocks)
	t.Logf("")
	t.Logf("BREAK-EVEN skip rate for a one-week catch-up inside 4h: %.1f%%", beSkip)
	if skip < beSkip {
		t.Logf("  MEASURED %.1f%% IS BELOW IT — the current throughput does NOT meet "+
			"the requirement today.", skip)
	} else {
		t.Logf("  measured %.1f%% is above it, by %.1f points", skip, skip-beSkip)
	}

	// The trigger: at what emit-rate does OUR activity push us under, given the
	// false-positive floor we do not control?
	fp := avgSat * avgSat * avgSat
	t.Logf("")
	t.Logf("UPGRADE TRIGGER — skip = (1 - ourEmitRate) x (1 - FP), FP = %.3f measured", fp)
	if 1-fp > 0 {
		maxEmit := 1 - (beSkip/100)/(1-fp)
		if maxEmit < 0 {
			t.Logf("  FP ALONE (%.1f%%) already puts skip below break-even.", 100*fp)
			t.Logf("  ZERO channel activity is required to breach it — congestion did it.")
		} else {
			t.Logf("  our contract may emit in at most %.2f%% of blocks (%.0f blocks/day)",
				100*maxEmit, maxEmit*7200)
		}
	}
	t.Log("")
	t.Log("NOT A VALIDATION OF THE 4-HOUR OUTAGE TERM. This measures one input to " +
		"it — catch-up throughput — on one provider over one window. The budget " +
		"is unchanged.")
}

// probeOfferedRate launches requests at a TARGET RATE regardless of how long
// each takes.
//
// The earlier paced probe issued them sequentially, so its ceiling was 1/latency
// — about 12/s at 80 ms. That is fine for measuring a 1/s limit and useless for
// measuring a 20/s one: it would report the prober's own bound as the provider's.
// Here each request goes in its own goroutine on a fixed schedule, so the offered
// rate is independent of latency.
func probeOfferedRate(t *testing.T, endpoint string, head uint64,
	perSec float64, window time.Duration) probeResult {
	t.Helper()

	src := &RPCSource{Endpoint: endpoint, MaxRetries: 0, MinInterval: 0}
	res := probeResult{concurrency: 0}
	var mu sync.Mutex
	var wg sync.WaitGroup

	interval := time.Duration(float64(time.Second) / perSec)
	deadline := time.Now().Add(window)
	start := time.Now()
	i := 0
	for time.Now().Before(deadline) {
		wg.Add(1)
		go func(n uint64) {
			defer wg.Done()
			_, err := src.ReceiptsByNumber(context.Background(), n)
			mu.Lock()
			if err == nil {
				res.ok++
			} else {
				res.refused++
			}
			mu.Unlock()
		}(head - uint64(i%4000))
		i++
		time.Sleep(interval)
	}
	wg.Wait()
	res.duration = time.Since(start)
	res.http429 = src.Stats().RateLimited
	return res
}

func TestP146GUpgradedThroughputCeiling(t *testing.T) {
	if os.Getenv("P146G") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P146G=1 CHAIN_PROBE=1")
	}
	endpoint := os.Getenv("ETH_RPC_URL")
	if endpoint == "" {
		t.Skip("set ETH_RPC_URL")
	}
	src := &RPCSource{Endpoint: endpoint, MaxRetries: 3, MinInterval: 100 * time.Millisecond}
	head := p146Head(t, src)

	window := 15 * time.Second
	t.Logf("UPGRADED-TIER THROUGHPUT CEILING — eth_getBlockReceipts")
	t.Logf("  free tier measured: 1.00/s clean, 429 at 1.5/s")
	t.Logf("  PAYG expectation: 10,000 CU/s / 500 throughput CU = 20/s")
	t.Logf("")

	var clean float64
	for _, rate := range []float64{5, 10, 15, 20, 25, 30} {
		r := probeOfferedRate(t, endpoint, head, rate, window)
		verdict := "CLEAN"
		if r.refused > 0 {
			verdict = "REFUSALS"
		}
		t.Logf("  offered %4.0f/s: %4d ok, %4d refused (%.0f%%), %d HTTP 429 => served %5.2f/s  %s",
			rate, r.ok, r.refused, r.refusalRate(), r.http429, r.okPerSec(), verdict)
		if r.refused == 0 && r.okPerSec() > clean {
			clean = r.okPerSec()
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("")
	if clean == 0 {
		t.Logf("NO RATE WAS CLEAN at or above 5/s")
	} else {
		t.Logf("HIGHEST CLEAN SUSTAINED RATE: %.2f eth_getBlockReceipts/sec", clean)
		t.Logf("  = %.0f effective throughput CU/s", clean*cuThroughputReceipts)
		t.Logf("  vs free tier's measured 1.00/s => %.0fx", clean/1.0)
	}
	t.Log("")
	t.Log("Throughput only. Monthly CU volume is a separate resource and is " +
		"reported separately.")
}

func rcptCallsOf(c *cuCounter) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.receiptCalls
}
