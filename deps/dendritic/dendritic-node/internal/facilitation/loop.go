package facilitation

import (
	"context"
	"crypto/ed25519"
	"log"
	"time"
)

// The epoch loop: what a node does, forever, to be paid.
//
// Each pass advertises what it holds, audits the peers it was drawn to audit,
// and uploads the receipts it earned. Everything it needs that it cannot know
// alone — the epoch randomness, the network's assignments — is fetched, and a
// pass that cannot fetch them does nothing rather than guessing.

// EpochLoopConfig is what the loop needs to run.
type EpochLoopConfig struct {
	Agent     *Agent
	Scheduler *Scheduler
	Store     ShardReader
	Spool     *ReceiptStore
	Gateway   *GatewayClient
	Pub       ed25519.PublicKey
	Logger    *log.Logger
	Interval  time.Duration // how often to run a pass
	EpochOf   func(time.Time) uint64

	// anchor pins epoch numbers to the chain's numbering. Fetched on the first
	// pass that can reach the site and reused after: it describes genesis,
	// which never moves.
	anchor EpochAnchor
}

// DefaultEpochSeconds matches the roadmap's one-hour epochs. Long enough that
// settlement gas is amortised over real work, short enough that an operator
// sees earnings the same day.
const DefaultEpochSeconds = 3600

// EpochAt maps wall-clock time to an epoch number counted from the unix epoch.
//
// Used only where no anchor is available (tests, and the pre-genesis log line).
// The live loop uses the published EpochAnchor instead, because this function's
// origin — 1970 — is not the origin EpochManager counts from, and a node using
// it asks the chain about epochs that do not exist. See anchor.go.
func EpochAt(t time.Time) uint64 { return uint64(t.Unix()) / DefaultEpochSeconds }

// RunEpochLoop runs until the context is cancelled.
func RunEpochLoop(ctx context.Context, cfg EpochLoopConfig) {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Minute
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// One pass immediately: a node restarted mid-epoch should not sit idle
	// until the next tick, since unaudited time is unpaid time.
	runEpochPass(ctx, &cfg)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runEpochPass(ctx, &cfg)
		}
	}
}

// epochNow resolves the current epoch, fetching the anchor if this is the first
// pass that can reach the site. Returns false when the network has no epoch
// numbering yet, which is a reason to wait rather than to invent one.
func epochNow(ctx context.Context, cfg *EpochLoopConfig) (uint64, bool) {
	if cfg.EpochOf != nil {
		return cfg.EpochOf(time.Now()), true
	}
	if !cfg.anchor.Valid() {
		if cfg.Gateway == nil {
			return 0, false
		}
		anchor, err := cfg.Gateway.FetchEpochAnchor(ctx)
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("proof-of-facilitation: %v — waiting for genesis", err)
			}
			return 0, false
		}
		cfg.anchor = anchor
		if cfg.Logger != nil {
			cfg.Logger.Printf("proof-of-facilitation: epoch anchor is epoch %d at unix %d, %ds each",
				anchor.Epoch, anchor.At, anchor.Seconds)
		}
	}
	return cfg.anchor.EpochAt(time.Now()), true
}

func runEpochPass(ctx context.Context, cfg *EpochLoopConfig) {
	logf := func(format string, args ...any) {
		if cfg.Logger != nil {
			cfg.Logger.Printf("proof-of-facilitation: "+format, args...)
		}
	}
	epoch, ok := epochNow(ctx, cfg)
	if !ok {
		return
	}

	// 1. Advertise what we hold, so others can audit us. Done first: being
	// auditable is what earns, and it costs nothing if the rest fails.
	assignments, err := LocalAssignments(cfg.Agent.NodeID(), cfg.Store)
	if err != nil {
		logf("could not enumerate local shards: %v", err)
	} else {
		// A large node advertises a rotating window rather than everything, so
		// the relay accepts it and every shard still takes its turn over
		// successive epochs.
		advertised := AdvertisableAssignments(assignments, epoch)
		if err := cfg.Gateway.PublishAssignments(ctx, cfg.Pub, advertised); err != nil {
			logf("could not advertise %d of %d shard(s): %v",
				len(advertised), len(assignments), err)
		} else if len(advertised) < len(assignments) {
			logf("advertised %d of %d shard(s) this epoch; the window rotates so "+
				"all of them are auditable over time", len(advertised), len(assignments))
		}
	}

	// 2. Upload receipts earned earlier. Before auditing, so a node that is
	// drawn for no duty this epoch still gets paid for the last one.
	if cfg.Spool != nil {
		if earned, err := cfg.Spool.ListEpoch(epoch - 1); err == nil && len(earned) > 0 {
			if stored, err := cfg.Gateway.UploadReceipts(ctx, earned); err != nil {
				logf("could not upload %d receipt(s) for epoch %d: %v", len(earned), epoch-1, err)
			} else if stored > 0 {
				logf("uploaded %d receipt(s) for epoch %d", stored, epoch-1)
			}
		}
	}

	// 3. Audit the peers we were drawn to audit.
	seed, err := cfg.Gateway.EpochRandomness(ctx, epoch)
	if err != nil {
		// No randomness means no legitimate draw. Skipping is the only safe
		// move: auditing on a guessed seed produces receipts whose witness sets
		// nobody else agrees with.
		logf("no randomness for epoch %d yet (%v) — skipping this pass", epoch, err)
		return
	}
	network, candidates, err := cfg.Gateway.FetchAssignments(ctx)
	if err != nil {
		logf("could not read the assignment directory: %v", err)
		return
	}
	if len(network) == 0 {
		logf("no assignments advertised network-wide yet — nothing to audit")
		return
	}

	results, err := cfg.Scheduler.RunEpoch(ctx, seed, epoch, network, candidates)
	if err != nil {
		logf("epoch %d audit run failed: %v", epoch, err)
		return
	}
	passed, failed, unreachable := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Passed:
			passed++
		case r.Err == ErrPeerUnreachable:
			unreachable++
		default:
			failed++
		}
	}
	if len(results) > 0 {
		// Unreachable is counted apart from failed on purpose: one is a peer
		// that was offline, the other is a peer that could not prove it still
		// holds the data, and conflating them would libel the first.
		logf("epoch %d: audited %d assignment(s) — %d passed, %d failed, %d unreachable",
			epoch, len(results), passed, failed, unreachable)
	}
}
