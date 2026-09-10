package ethproof

// P14.6 — does a LOCAL execution node actually serve receipts faster?
//
// MEASUREMENT ONLY. No production code is changed and none is added: every
// function exercised here is the shipped P14.5 implementation, called exactly as
// the watchtower calls it. That is half the point — if the local node needed a
// special path through the verifier, the answer to the acceptance question would
// already be no.
//
//	P146=1 P146_RPC_URL=http://127.0.0.1:18545 \
//	  go test ./internal/ethproof/ -run TestP146 -v -timeout 30m
//
// WHAT A DEVNET CAN AND CANNOT TELL US
// ------------------------------------
// The devnet's database fits entirely in page cache, so its latency is a LOWER
// BOUND — the best a local node could possibly do, not a prediction for a 1.2 TB
// mainnet dataset where receipts come off disk. Reported as a bound and never as
// a forecast.
//
// What it DOES isolate is the question the Alchemy number cannot answer: of the
// measured 79 ms, how much is inherent to serving ~450 receipts — RLP decode plus
// JSON serialisation of a megabyte of data — and how much is network and
// provider overhead? If serialisation alone costs 60 ms, a local node buys
// little, and no amount of hardware changes that.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func p146Skip(t *testing.T) *RPCSource {
	t.Helper()
	if os.Getenv("P146") == "" {
		t.Skip("set P146=1 to run the local-node measurements")
	}
	url := os.Getenv("P146_RPC_URL")
	if url == "" {
		t.Skip("set P146_RPC_URL to a local execution node")
	}
	// No throttle and no retries: a local node has no rate limit, and adding one
	// here would measure this harness rather than the node.
	return &RPCSource{Endpoint: url, MaxRetries: 0, MinInterval: 0}
}

func p146Head(t *testing.T, s *RPCSource) uint64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []any{},
	})
	raw, _, err := s.call(context.Background(), body)
	if err != nil {
		t.Fatalf("blockNumber: %v", err)
	}
	var hexs string
	if err := json.Unmarshal(raw, &hexs); err != nil {
		t.Fatalf("blockNumber decode: %v", err)
	}
	n, err := hexQuantity(hexs)
	if err != nil {
		t.Fatalf("blockNumber parse: %v", err)
	}
	return n
}

// The headline measurement: latency and the whole C+E pipeline, per block.
func TestP146LocalNodeReceiptPipeline(t *testing.T) {
	src := p146Skip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	head := p146Head(t, src)
	blocks := 200
	if head < uint64(blocks)+2 {
		t.Fatalf("only %d blocks on the node; need %d", head, blocks+2)
	}
	// Start where the chain is actually FULL. Blocks mined after the load
	// generator stopped are empty, and an empty block answers in microseconds —
	// leaving them in would pull the median down and flatter the local node with
	// work it did not do.
	from := head - 1
	if v := os.Getenv("P146_FROM_BLOCK"); v != "" {
		fmt.Sscanf(v, "%d", &from)
	}

	var fetchD, decodeD, encodeD, buildD, authD []time.Duration
	var counts []int
	var totalLogs, totalBytes int

	for i := 0; i < blocks; i++ {
		n := from - uint64(i)

		// 1. FETCH — the raw RPC, network time only.
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockReceipts",
			"params": []any{fmt.Sprintf("0x%x", n)},
		})
		raw, net, err := src.call(ctx, body)
		if err != nil {
			t.Fatalf("block %d receipts: %v", n, err)
		}
		fetchD = append(fetchD, net)
		totalBytes += len(raw)

		// 2. DECODE — provider JSON into typed receipts.
		start := time.Now()
		receipts, err := DecodeRPCReceipts(raw)
		if err != nil {
			t.Fatalf("block %d decode: %v", n, err)
		}
		decodeD = append(decodeD, time.Since(start))
		counts = append(counts, len(receipts))
		for _, r := range receipts {
			totalLogs += len(r.Logs)
		}

		// 3. ENCODE — canonical EIP-2718 bytes.
		start = time.Now()
		for _, r := range receipts {
			if _, err := r.Encode(); err != nil {
				t.Fatalf("block %d encode: %v", n, err)
			}
		}
		encodeD = append(encodeD, time.Since(start))

		// 4. BUILD — the receipts trie.
		start = time.Now()
		root, err := ReceiptsRoot(receipts)
		if err != nil {
			t.Fatalf("block %d build: %v", n, err)
		}
		buildD = append(buildD, time.Since(start))

		// 5. AUTHENTICATE — the production gate, against the block's own root.
		var want Root
		copy(want[:], root)
		start = time.Now()
		if _, err := AuthenticateReceipts(want, receipts); err != nil {
			t.Fatalf("block %d authenticate: %v", n, err)
		}
		authD = append(authD, time.Since(start))
	}

	report := func(name string, d []time.Duration) time.Duration {
		sortDurations(d)
		t.Logf("%-22s median %-11s p95 %-11s max %-11s min %s",
			name, pct(d, 0.5), pct(d, 0.95), d[len(d)-1], d[0])
		return pct(d, 0.5)
	}
	t.Logf("LOCAL NODE over %d consecutive blocks (loopback)", blocks)
	fetch := report("eth_getBlockReceipts", fetchD)
	decode := report("decode JSON", decodeD)
	encode := report("encode receipts", encodeD)
	build := report("trie construction", buildD)
	auth := report("authenticate (gate)", authD)

	empty := 0
	for _, c := range counts {
		if c == 0 {
			empty++
		}
	}
	if empty > 0 {
		t.Errorf("%d of %d blocks in the sample are EMPTY; the median is not "+
			"measuring a mainnet-sized block. Set P146_FROM_BLOCK.", empty, blocks)
	}
	total := 0
	minC, maxC := counts[0], counts[0]
	for _, c := range counts {
		total += c
		if c < minC {
			minC = c
		}
		if c > maxC {
			maxC = c
		}
	}
	t.Logf("")
	t.Logf("receipts per block: min %d, max %d, mean %d (mainnet measured ~450)",
		minC, maxC, total/len(counts))
	t.Logf("logs: %d total, %.1f per receipt (mainnet ~2.3)",
		totalLogs, float64(totalLogs)/float64(max2(1, total)))
	t.Logf("payload: %.2f MB total, %.0f KB per block",
		float64(totalBytes)/(1<<20), float64(totalBytes)/float64(blocks)/1024)

	// AuthenticateReceipts calls ReceiptsRoot internally, which encodes every
	// receipt and builds the trie. So `encode` and `build` above are diagnostic
	// breakdowns of work that `auth` ALSO does — adding all five would count the
	// trie construction three times and inflate the pipeline figure.
	//
	// The real per-block cost is fetch + decode + auth.
	pipeline := fetch + decode + auth
	t.Logf("")
	t.Logf("NOTE: encode and build are diagnostics INSIDE auth, not additional " +
		"work. The pipeline below counts each stage once.")
	t.Logf("FULL C+E PIPELINE per block: %s  (fetch %s + decode %s + authenticate %s)",
		pipeline.Round(time.Microsecond), fetch.Round(time.Microsecond),
		decode.Round(time.Microsecond), auth.Round(time.Microsecond))
	_, _ = encode, build
	t.Logf("")
	t.Logf("AGAINST THE ALCHEMY POOLED MEASUREMENT (79.4 ms median):")
	t.Logf("  local fetch      %s", fetch.Round(time.Microsecond))
	t.Logf("  speedup on fetch %.1fx", 79.4e6/float64(fetch))
	t.Logf("  NOTE: the devnet DB is entirely in page cache. This is a LOWER "+
		"BOUND on local-node latency, not a forecast for a %s dataset.", "1.2 TB")
}

// The acceptance question's second half: no special local-node trust path.
//
// Every step below is the shipped implementation. If a local node needed its own
// route through the verifier, that would be the bypass the whole design forbids.
func TestP146LocalNodePassesTheSameGate(t *testing.T) {
	src := p146Skip(t)
	ctx := context.Background()
	head := p146Head(t, src)
	n := head - 1
	if v := os.Getenv("P146_FROM_BLOCK"); v != "" {
		fmt.Sscanf(v, "%d", &n)
	}

	// The production fork selector REFUSES an unrecognised chain. Asserted here
	// rather than worked around: it is the behaviour that stops a testnet layout
	// being applied to mainnet by accident.
	if _, err := ExecutionForkAt(1337, uint64(time.Now().Unix())); err == nil {
		t.Fatal("ExecutionForkAt accepted chain 1337; unrecorded chains must refuse")
	}
	t.Log("ExecutionForkAt(1337) refuses, as it must — the layout below is " +
		"supplied EXPLICITLY by this test, not inferred for an unknown chain")

	headers, err := src.HeadersDescending(ctx, n, 2)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}

	// Ask the node what it thinks the hash is. It is not believed — it is the
	// value the header must reproduce.
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
		"params": []any{fmt.Sprintf("0x%x", n), false},
	})
	raw, _, err := src.call(ctx, body)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	var hdr struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("header decode: %v", err)
	}
	claimed, err := hexData(hdr.Hash, 32)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	var claimed32 [32]byte
	copy(claimed32[:], claimed)

	// GATE 1 — the header must hash to what it claims. Production encoder.
	if _, err := AuthenticateHeader(headers[0], ForkPrague, claimed32); err != nil {
		t.Fatalf("the local node's header did not reproduce its own hash: %v", err)
	}
	t.Logf("header re-encoded and hashed to %x — the node's claim, verified "+
		"rather than believed", claimed32[:8])

	// The parent link, the same one catch-up walks.
	if _, err := BlockFromParentLink(headers[1], ForkPrague, headers[0].ParentHash); err != nil {
		t.Fatalf("parent link from the local node failed: %v", err)
	}
	t.Log("parentHash link verified through BlockFromParentLink — the catch-up path")

	// GATE 2 — receipts must rebuild to the receiptsRoot inside that header.
	receipts, err := src.ReceiptsByNumber(ctx, n)
	if err != nil {
		t.Fatalf("receipts: %v", err)
	}
	var rroot Root
	copy(rroot[:], headers[0].ReceiptRoot[:])
	verified, err := AuthenticateReceipts(rroot, receipts)
	if err != nil {
		t.Fatalf("LOCAL NODE RECEIPTS FAILED THE GATE: %v", err)
	}
	t.Logf("%d receipts from the local node rebuilt to the receiptsRoot bound "+
		"into the verified header", len(verified))

	// And tampering is still caught — the gate is not weaker for local data.
	if len(verified) == 0 {
		t.Fatal("the measured block has no receipts; the tamper check below " +
			"would be vacuous. Point P146_FROM_BLOCK at a full block.")
	}
	if len(verified) > 1 {
		tampered := append([]Receipt(nil), verified...)
		tampered[0].CumulativeGasUsed++
		if _, err := AuthenticateReceipts(rroot, tampered); err == nil {
			t.Fatal("a tampered local receipt PASSED; the gate is not being applied")
		}
		t.Log("a tampered local receipt is still refused — no local-node exemption")
	}
}

// The finality-distance question, measured against the node's real trie history.
//
// This is the risk P14.6 identified: proofs are taken at the AUTHENTICATED
// FINALISED block, and a full node keeps only a limited window of state.
func TestP146ProofWindowAgainstFinalityDistance(t *testing.T) {
	src := p146Skip(t)
	ctx := context.Background()
	head := p146Head(t, src)

	cfgAddr := os.Getenv("P146_PROOF_ADDR")
	if cfgAddr == "" {
		cfgAddr = "0x0000000000000000000000000000000000000000"
	}

	getProof := func(n uint64) error {
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "eth_getProof",
			"params": []any{cfgAddr, []string{}, fmt.Sprintf("0x%x", n)},
		})
		_, _, err := src.call(ctx, body)
		return err
	}

	// Walk back until the node stops being able to answer. The boundary is the
	// number that matters, not a documented default.
	var lastOK uint64
	var firstFail uint64
	var failErr error
	probes := []uint64{0, 1, 8, 32, 64, 96, 127, 128, 129, 160, 192, 256, 400}
	t.Logf("eth_getProof against a --gcmode full node, head %d", head)
	for _, back := range probes {
		if back >= head {
			continue
		}
		err := getProof(head - back)
		if err == nil {
			lastOK = back
			t.Logf("  %4d blocks back: ok", back)
		} else {
			if firstFail == 0 {
				firstFail, failErr = back, err
			}
			msg := err.Error()
			if len(msg) > 90 {
				msg = msg[:90] + "…"
			}
			t.Logf("  %4d blocks back: REFUSED — %s", back, msg)
		}
	}

	t.Logf("")
	t.Logf("deepest successful proof: %d blocks back", lastOK)
	if firstFail > 0 {
		t.Logf("first refusal at %d blocks back: %v", firstFail, failErr)
		if strings.Contains(strings.ToLower(fmt.Sprint(failErr)), "missing trie node") {
			t.Log("  -> exactly the 'missing trie node' failure P14.6 predicted")
		}
	} else {
		t.Log("no refusal within the probed range on this node")
	}

	// The requirement, from our own code: proofs are requested at the finalised
	// block, which on mainnet is 64-96 blocks behind the head.
	t.Logf("")
	t.Logf("REQUIREMENT: client.go requests eth_getProof at the AUTHENTICATED " +
		"FINALISED block — 64-96 blocks behind head on mainnet, and UNBOUNDED " +
		"during a finality stall.")
	switch {
	case firstFail == 0:
		t.Logf("VERDICT: this node answered every probe; the window is at least %d.", lastOK)
	case firstFail > 96:
		t.Logf("VERDICT: window is ~%d blocks. Normal finality (64-96) FITS, with "+
			"%d blocks of margin. A finality STALL does not fit.", firstFail, firstFail-96)
	default:
		t.Errorf("VERDICT: the window is only ~%d blocks, INSIDE the 64-96 finality "+
			"distance. A plain full node cannot serve our proofs at all.", firstFail)
	}
}

// The comparison leg, measured in the SAME session and the same way.
//
// Payload size is reported for both sides because it is the variable that
// actually drives serialisation cost. Comparing a devnet block against a mainnet
// block without it would be comparing two different amounts of work.
func TestP146AlchemyComparisonLeg(t *testing.T) {
	if os.Getenv("P146") == "" {
		t.Skip("set P146=1")
	}
	url := os.Getenv("ETH_RPC_URL")
	if url == "" {
		t.Skip("set ETH_RPC_URL for the comparison leg")
	}
	// Pooled, throttled enough not to trip the limit — a rate-limited sample
	// would measure the provider's refusal rather than its latency.
	src := &RPCSource{Endpoint: url, MaxRetries: 3, MinInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	head := p146Head(t, src)
	const blocks = 12
	var fetchD, pipeD []time.Duration
	var counts, bytesTotal, logsTotal int

	for i := 0; i < blocks; i++ {
		n := head - 2 - uint64(i)
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockReceipts",
			"params": []any{fmt.Sprintf("0x%x", n)},
		})
		raw, net, err := src.call(ctx, body)
		if err != nil {
			t.Fatalf("block %d: %v", n, err)
		}
		fetchD = append(fetchD, net)
		bytesTotal += len(raw)

		// decode + authenticate. AuthenticateReceipts rebuilds the trie itself,
		// so the root is computed once here and once inside the gate — the same
		// shape the local-node leg reports, for a like-for-like comparison.
		root, err := ReceiptsRoot(mustDecode(t, raw))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		var want Root
		copy(want[:], root)
		start := time.Now()
		receipts, err := DecodeRPCReceipts(raw)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, err := AuthenticateReceipts(want, receipts); err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		pipeD = append(pipeD, time.Since(start))
		counts += len(receipts)
		for _, r := range receipts {
			logsTotal += len(r.Logs)
		}
	}
	sortDurations(fetchD)
	sortDurations(pipeD)
	st := src.Stats()
	t.Logf("MAINNET via Alchemy, pooled, %d blocks", blocks)
	t.Logf("  eth_getBlockReceipts  median %s  p95 %s  max %s",
		pct(fetchD, 0.5), pct(fetchD, 0.95), fetchD[len(fetchD)-1])
	t.Logf("  local pipeline        median %s", pct(pipeD, 0.5))
	t.Logf("  receipts/block %d, logs/receipt %.1f, payload %.0f KB/block",
		counts/blocks, float64(logsTotal)/float64(max2(1, counts)),
		float64(bytesTotal)/float64(blocks)/1024)
	t.Logf("  provider: %d calls, %d rate-limit events", st.Calls, st.RateLimited)
}

func mustDecode(t *testing.T, raw []byte) []Receipt {
	t.Helper()
	r, err := DecodeRPCReceipts(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return r
}

// The catch-up pipeline's other half: batched headers.
//
// Catch-up is not receipts alone. Every block in the gap needs its header
// fetched, re-encoded and hashed to prove the parentHash link — measured against
// Alchemy at 3.9 ms per header batched. This is the local-node equivalent.
func TestP146LocalHeaderBatchThroughput(t *testing.T) {
	src := p146Skip(t)
	ctx := context.Background()
	head := p146Head(t, src)

	for _, size := range []int{1, 25, 100} {
		if uint64(size)+2 > head {
			continue
		}
		var fetchD, verifyD []time.Duration
		const reps = 5
		for r := 0; r < reps; r++ {
			from := head - 1 - uint64(r)
			start := time.Now()
			headers, err := src.HeadersDescending(ctx, from, size)
			fetchD = append(fetchD, time.Since(start))
			if err != nil {
				t.Fatalf("headers(%d): %v", size, err)
			}

			// Verification is the part that cannot be batched: each header must
			// hash to what the block after it declared.
			start = time.Now()
			expected := headers[0].ParentHash
			for i := 1; i < len(headers); i++ {
				b, err := BlockFromParentLink(headers[i], ForkPrague, expected)
				if err != nil {
					t.Fatalf("parent link at %d: %v", i, err)
				}
				expected = b.ParentHash
			}
			verifyD = append(verifyD, time.Since(start))
		}
		sortDurations(fetchD)
		sortDurations(verifyD)
		perHeader := (pct(fetchD, 0.5) + pct(verifyD, 0.5)) / time.Duration(size)
		t.Logf("batch %3d: fetch %-11s verify %-11s => %s per header",
			size, pct(fetchD, 0.5).Round(time.Microsecond),
			pct(verifyD, 0.5).Round(time.Microsecond), perHeader.Round(time.Microsecond))
	}
	t.Log("Alchemy measured 3.94 ms per header at batch 100; 43 ms unbatched.")
}

// devnetAnchor stands in for the beacon light client, which cannot exist on a
// devnet.
//
// It does NOT trust the node: it fetches the head header, re-encodes it and
// requires it to hash to the value the node claims, then anchors on that. So the
// anchor is self-verified rather than asserted — but it is an anchor of OUR
// choosing, not one a sync committee signed, and that difference is exactly what
// the mainnet leg (TestP145Live*) covers and this one cannot.
type devnetAnchor struct {
	src  *RPCSource
	head uint64
}

func (d *devnetAnchor) FinalizedBlock(ctx context.Context) (AuthenticatedBlock, error) {
	headers, err := d.src.HeadersDescending(ctx, d.head, 1)
	if err != nil {
		return AuthenticatedBlock{}, err
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
		"params": []any{fmt.Sprintf("0x%x", d.head), false},
	})
	raw, _, err := d.src.call(ctx, body)
	if err != nil {
		return AuthenticatedBlock{}, err
	}
	var hdr struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return AuthenticatedBlock{}, err
	}
	claimed, err := hexData(hdr.Hash, 32)
	if err != nil {
		return AuthenticatedBlock{}, err
	}
	var c32 [32]byte
	copy(c32[:], claimed)
	// The production header gate. If it does not reproduce the hash, there is no
	// anchor and the follower gets nothing.
	return BlockFromParentLink(headers[0], ForkPrague, c32)
}

// THE COMPLETE C+E CATCH-UP, through the shipped ChainFollower.
//
// Not the RPC call: bloom filtering, batched header walking, parentHash
// verification, receipt authentication and checkpoint persistence, exactly as a
// restarted watchtower would run them.
func TestP146FullCatchUpPipelineLocal(t *testing.T) {
	src := p146Skip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	head := p146Head(t, src)
	gap := 200
	if v := os.Getenv("P146_GAP"); v != "" {
		fmt.Sscanf(v, "%d", &gap)
	}
	if head < uint64(gap)+4 {
		t.Fatalf("chain is %d blocks; need %d", head, gap+4)
	}
	anchorAt := head - 1

	// The emitter is in EVERY block, so it is the worst case the bloom can
	// present: no block is skippable. An absent address is the best case.
	emitter := os.Getenv("P146_EMITTER")
	if emitter == "" {
		t.Skip("set P146_EMITTER to the log-emitting contract address")
	}
	present := addr20(strings.TrimPrefix(emitter, "0x"))
	absent := present
	absent[0] ^= 0xFF

	// ChainID 1 is set ONLY so the production fork selector resolves to the
	// Prague layout, which is genuinely the layout these headers use (they carry
	// requestsHash). No other property of chain identity is relied on, and
	// ExecutionForkAt still refuses 1337 — asserted in the gate test above.
	run := func(label string, contract [20]byte) {
		store := &FileCheckpointStore{Path: t.TempDir() + "/cp.json"}
		f := &ChainFollower{
			ChainID: 1, Contract: contract, Headers: src,
			Finalized: &devnetAnchor{src: src, head: anchorAt},
			Store:     store, BatchSize: 25,
		}
		headers, err := src.HeadersDescending(ctx, anchorAt, gap+1)
		if err != nil {
			t.Fatalf("headers: %v", err)
		}
		expected := [32]byte{}
		{
			b, err := (&devnetAnchor{src: src, head: anchorAt}).FinalizedBlock(ctx)
			if err != nil {
				t.Fatalf("anchor: %v", err)
			}
			expected = b.Hash
		}
		var startCP FollowerCheckpoint
		for _, h := range headers {
			b, err := BlockFromParentLink(h, ForkPrague, expected)
			if err != nil {
				t.Fatalf("walk: %v", err)
			}
			expected = b.ParentHash
			startCP = FollowerCheckpoint{BlockNumber: b.Number, BlockHash: b.Hash}
		}
		if err := f.InitializeAt(startCP); err != nil {
			t.Fatalf("init: %v", err)
		}

		src.ResetStats()
		start := time.Now()
		prog, err := f.Advance(ctx, func(AuthenticatedBlock, []Log) error { return nil })
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("%s: catch-up failed: %v", label, err)
		}
		per := elapsed / time.Duration(max2(1, prog.BlocksExamined))
		st := src.Stats()
		t.Logf("%s", label)
		t.Logf("  %d blocks in %s = %s/block", prog.BlocksExamined,
			elapsed.Round(time.Millisecond), per.Round(time.Microsecond))
		t.Logf("  bloom-skipped %d/%d (%.0f%%), receipts fetched %d, logs %d",
			prog.BlocksSkipped, prog.BlocksExamined,
			100*float64(prog.BlocksSkipped)/float64(max2(1, prog.BlocksExamined)),
			prog.BlocksFetched, prog.LogsFound)
		t.Logf("  provider: %d calls, %d rate-limit events", st.Calls, st.RateLimited)
		for _, o := range []struct {
			name   string
			blocks int
		}{{"1 hour", 300}, {"24 hours", 7200}, {"1 week", 50400}} {
			t.Logf("    %-9s = %6d blocks: %s", o.name, o.blocks,
				(time.Duration(o.blocks) * per).Round(time.Second))
		}
	}

	run("WORST CASE — contract emits in every block, bloom skips nothing", present)
	run("BEST CASE — contract absent, bloom skips everything", absent)
	t.Log("Measured against Alchemy: 243 ms/block WITH rate limits (1 week = 3h24m), " +
		"~24.5 ms/block of actual work without them.")
}
