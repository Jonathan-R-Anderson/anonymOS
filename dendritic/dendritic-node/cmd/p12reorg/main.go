package main

// P12-8 reorg observation — durable, restart-safe, unattended.
//
// WHY THIS EXISTS RATHER THAN internal/channel.ObserveReorgs
// ----------------------------------------------------------
// ObserveReorgs detects a reorganisation by noticing that a height it has
// ALREADY SEEN now reports a different hash. That only fires if the head
// number goes backwards or repeats between polls.
//
// Post-merge mainnet reorgs are usually single-slot: block N is orphaned,
// a different block N takes its place, and the chain immediately extends to
// N+1. A poller watching only the head number sees N, then N+1, then N+2 —
// monotonic, nothing repeated, nothing detected. The rewrite is invisible.
//
// This observer checks CHAIN LINKAGE instead: every new head must name our
// recorded hash for the previous height as its parent. A single-slot reorg
// breaks that link immediately and is caught on the next poll.
//
//	head N+1 parentHash ──?── hash we recorded for N
//	                    mismatch  =>  N was rewritten
//
// The detector can only ever find MORE events than the height-collision
// method, never fewer. It does not change what counts as evidence, and this
// program files none.
//
// DURABILITY
// ----------
// Everything is appended to disk as it is observed, and the counters are
// rebuilt from a state file on restart. A crash costs at most the poll in
// flight. State lives outside /tmp and outside the repository so neither a
// reboot nor a checkout can erase an observation measured in weeks.
//
// SILENCE IS NOT SUCCESS
// ----------------------
// An observer whose RPC is dead reports zero reorgs indefinitely, which looks
// exactly like a quiet chain. So poll failures, stalls and gaps are recorded
// as first-class health data, and the alerting layer reads them.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	pollInterval = 4 * time.Second
	// windowSize is how many recent heights are retained for linkage checks.
	// Far deeper than any reorg mainnet has produced post-merge; the cost is a
	// few kilobytes.
	windowSize = 256
	// maxWalkback bounds the search for a fork point so a pathological
	// response cannot spin.
	maxWalkback = 128
	// stallAfter is how long without a new block before the run is considered
	// unhealthy rather than merely quiet.
	stallAfter = 5 * time.Minute
)

type block struct {
	Number uint64 `json:"number"`
	Hash   string `json:"hash"`
	Parent string `json:"parent"`
	Time   int64  `json:"timestamp"`
}

type reorgEvent struct {
	DetectedUnix int64  `json:"detected_unix"`
	AtHeight     uint64 `json:"at_height"`
	Depth        int    `json:"depth"`
	OldHash      string `json:"old_hash"`
	NewHash      string `json:"new_hash"`
	HeadAtTime   uint64 `json:"head_at_detection"`
	Method       string `json:"detected_by"`
}

// state is everything needed to resume. Written atomically.
type state struct {
	StartedUnix   int64             `json:"started_unix"`
	Blocks        int               `json:"blocks_observed"`
	Reorgs        int               `json:"reorgs_observed"`
	MaxDepth      int               `json:"max_depth"`
	Highest       uint64            `json:"highest_block"`
	FirstBlock    uint64            `json:"first_block"`
	FirstSeenUnix int64             `json:"first_seen_unix"`
	LastSeenUnix  int64             `json:"last_block_seen_unix"`
	PollOK        int64             `json:"poll_successes"`
	PollFail      int64             `json:"poll_failures"`
	Restarts      int               `json:"restarts"`
	Window        map[string]string `json:"window"` // height -> hash
}

type observer struct {
	dir      string
	endpoint string
	client   *http.Client
	st       state
}

func (o *observer) path(n string) string { return filepath.Join(o.dir, n) }

func (o *observer) appendLine(file string, v any) {
	f, err := os.OpenFile(o.path(file), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(v)
	f.Write(append(b, '\n'))
}

// saveState writes atomically: a torn state file on a power cut would lose the
// whole observation, which is the one thing this program exists to prevent.
func (o *observer) saveState() {
	b, err := json.MarshalIndent(o.st, "", "  ")
	if err != nil {
		return
	}
	tmp := o.path("state.json.tmp")
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, o.path("state.json"))
	}
}

func (o *observer) loadState() {
	b, err := os.ReadFile(o.path("state.json"))
	if err != nil {
		o.st = state{StartedUnix: time.Now().Unix(), Window: map[string]string{}}
		return
	}
	if json.Unmarshal(b, &o.st) != nil || o.st.Window == nil {
		o.st.Window = map[string]string{}
	}
	o.st.Restarts++
}

func (o *observer) rpc(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, "POST", o.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

func hexToU64(s string) uint64 {
	v := new(big.Int)
	v.SetString(strings.TrimPrefix(s, "0x"), 16)
	return v.Uint64()
}

func (o *observer) getBlock(ctx context.Context, tag string) (block, error) {
	r, err := o.rpc(ctx, "eth_getBlockByNumber", tag, false)
	if err != nil {
		return block{}, err
	}
	var b struct {
		Number     string `json:"number"`
		Hash       string `json:"hash"`
		ParentHash string `json:"parentHash"`
		Timestamp  string `json:"timestamp"`
	}
	if err := json.Unmarshal(r, &b); err != nil || b.Hash == "" {
		return block{}, fmt.Errorf("empty block for %s", tag)
	}
	return block{
		Number: hexToU64(b.Number), Hash: b.Hash,
		Parent: b.ParentHash, Time: int64(hexToU64(b.Timestamp)),
	}, nil
}

func (o *observer) remember(b block) {
	o.st.Window[fmt.Sprint(b.Number)] = b.Hash
	if len(o.st.Window) > windowSize {
		for k := range o.st.Window {
			if hexToU64(k) < b.Number-windowSize {
				delete(o.st.Window, k)
			}
		}
	}
}

func (o *observer) recorded(n uint64) (string, bool) {
	h, ok := o.st.Window[fmt.Sprint(n)]
	return h, ok
}

// backfill fetches heights between the last one held and the new head, so no
// height passes unobserved and unlinked.
//
// Bounded by maxWalkback: after a long outage the gap is a hole in the record,
// and it is recorded as such rather than pretended away by fetching thousands
// of blocks whose reorgs we could no longer have witnessed live anyway.
func (o *observer) backfill(ctx context.Context, head block) {
	if o.st.Highest == 0 || head.Number <= o.st.Highest+1 {
		return
	}
	gap := head.Number - o.st.Highest - 1
	if gap > maxWalkback {
		o.appendLine("gaps.jsonl", map[string]any{
			"from": o.st.Highest, "to": head.Number, "missed_heights": gap,
			"noted_unix": time.Now().Unix(),
			"note":       "gap exceeds walkback; these heights were never observed live",
		})
		return
	}
	for h := o.st.Highest + 1; h < head.Number; h++ {
		b, err := o.getBlock(ctx, fmt.Sprintf("0x%x", h))
		if err != nil {
			continue
		}
		if prev, ok := o.recorded(h - 1); ok && prev != b.Parent {
			o.recordReorg(ctx, b, "parent-linkage-backfill")
		}
		o.remember(b)
		o.appendLine("blocks.jsonl", b)
	}
}

// recordReorg walks back from a broken link to find where our view and the
// chain's agree again. That distance is the depth.
func (o *observer) recordReorg(ctx context.Context, head block, method string) {
	depth := 0
	var atHeight uint64 = head.Number
	oldHash, newHash := "", ""

	for i := 0; i < maxWalkback; i++ {
		h := head.Number - 1 - uint64(i)
		known, ok := o.recorded(h)
		if !ok {
			break // no view this far back; cannot attribute more depth
		}
		actual, err := o.getBlock(ctx, fmt.Sprintf("0x%x", h))
		if err != nil {
			break
		}
		if actual.Hash == known {
			break // agreement — the fork point is here
		}
		depth++
		atHeight, oldHash, newHash = h, known, actual.Hash
		o.st.Window[fmt.Sprint(h)] = actual.Hash
	}
	if depth == 0 {
		depth = 1
		atHeight = head.Number - 1
		oldHash, _ = o.recorded(atHeight)
	}

	o.st.Reorgs++
	if depth > o.st.MaxDepth {
		o.st.MaxDepth = depth
	}
	ev := reorgEvent{
		DetectedUnix: time.Now().Unix(), AtHeight: atHeight, Depth: depth,
		OldHash: oldHash, NewHash: newHash, HeadAtTime: head.Number, Method: method,
	}
	o.appendLine("events.jsonl", ev)
	// A separate file the alerting layer can stat cheaply, and a human can see.
	f, err := os.OpenFile(o.path("ALERT-REORG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		fmt.Fprintf(f, "%s REORG depth=%d at height %d (head %d) old=%s new=%s\n",
			time.Now().UTC().Format(time.RFC3339), depth, atHeight, head.Number,
			short(oldHash), short(newHash))
		f.Close()
	}
	fmt.Printf("REORG depth=%d height=%d head=%d\n", depth, atHeight, head.Number)
}

func short(h string) string {
	if len(h) > 14 {
		return h[:14]
	}
	return h
}

func (o *observer) writeStatus() {
	now := time.Now()
	elapsed := now.Sub(time.Unix(o.st.StartedUnix, 0))
	stalled := o.st.LastSeenUnix > 0 &&
		now.Sub(time.Unix(o.st.LastSeenUnix, 0)) > stallAfter
	health := "healthy"
	if stalled {
		health = "STALLED — no new block within " + stallAfter.String()
	}
	body := fmt.Sprintf(`P12-8 reorg observation
updated       %s
started       %s
elapsed       %s
blocks        %d   (first %d, highest %d)
reorgs        %d
max depth     %d
polls         %d ok / %d failed
restarts      %d
health        %s

NOT EVIDENCE. Zero reorgs observed does not bound the depth of one; it is an
absence of events, and ReorgObservation.AsEvidence refuses to convert it.
`,
		now.UTC().Format(time.RFC3339), time.Unix(o.st.StartedUnix, 0).UTC().Format(time.RFC3339),
		elapsed.Truncate(time.Second), o.st.Blocks, o.st.FirstBlock, o.st.Highest,
		o.st.Reorgs, o.st.MaxDepth, o.st.PollOK, o.st.PollFail, o.st.Restarts, health)
	tmp := o.path("status.txt.tmp")
	if os.WriteFile(tmp, []byte(body), 0o644) == nil {
		os.Rename(tmp, o.path("status.txt"))
	}
}

func main() {
	dir := os.Getenv("P12_REORG_DIR")
	if dir == "" {
		fmt.Println("P12_REORG_DIR is required")
		os.Exit(2)
	}
	endpoint := os.Getenv("ETH_RPC_URL")
	if endpoint == "" {
		fmt.Println("ETH_RPC_URL is required")
		os.Exit(2)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Println("cannot create", dir, err)
		os.Exit(2)
	}

	o := &observer{dir: dir, endpoint: endpoint,
		client: &http.Client{Timeout: 20 * time.Second}}
	o.loadState()
	o.saveState()

	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	fmt.Printf("observing from %s (restart #%d), blocks so far %d, reorgs %d\n",
		dir, o.st.Restarts, o.st.Blocks, o.st.Reorgs)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	lastStatus := time.Time{}

	for {
		select {
		case <-ctx.Done():
			o.saveState()
			o.writeStatus()
			fmt.Println("stopped cleanly; state saved")
			return
		case <-ticker.C:
		}

		head, err := o.getBlock(ctx, "latest")
		if err != nil {
			o.st.PollFail++
			if time.Since(lastStatus) > 30*time.Second {
				o.writeStatus()
				o.saveState()
				lastStatus = time.Now()
			}
			continue
		}
		o.st.PollOK++

		switch known, ok := o.recorded(head.Number); {
		case ok && known != head.Hash:
			// The height we already recorded now reports a different hash.
			o.recordReorg(ctx, head, "height-collision")
			o.remember(head)

		case !ok:
			// A height we have not recorded. Every height between the last one
			// we hold and this head must be fetched and linked, or a reorg in a
			// skipped height is silently missed. Polling is faster than block
			// production so gaps are rare, but "rare" is not "never" and this
			// observation is meant to run for weeks.
			o.backfill(ctx, head)

			// Check linkage to the previous height, which is what catches a
			// single-slot rewrite.
			if prev, havePrev := o.recorded(head.Number - 1); havePrev && prev != head.Parent {
				o.recordReorg(ctx, head, "parent-linkage")
			}
			if o.st.Highest == 0 {
				o.st.FirstBlock = head.Number
				o.st.FirstSeenUnix = time.Now().Unix()
				o.st.Blocks = 1
			} else if head.Number > o.st.Highest {
				o.st.Blocks += int(head.Number - o.st.Highest)
			}
			if head.Number > o.st.Highest {
				o.st.Highest = head.Number
				o.st.LastSeenUnix = time.Now().Unix()
			}
			o.remember(head)
			o.appendLine("blocks.jsonl", head)
		}

		if time.Since(lastStatus) > 30*time.Second {
			o.saveState()
			o.writeStatus()
			lastStatus = time.Now()
		}
	}
}
