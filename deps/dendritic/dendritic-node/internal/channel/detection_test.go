package channel

// Detection at the production envelope — roadmap P12-8.
//
// MEASURED AT 10,000 CHANNELS, NOT EXTRAPOLATED.
//
// The budget's detection term is the one that scales with the deployment, and
// a figure taken at 100 channels and multiplied is not a measurement of
// anything — the cost per channel is not constant when the store, the index and
// the chain reader all have their own behaviour at size.
//
//	CHAIN_PROBE=1 go test ./internal/channel/ -run TestDetectionAtProductionEnvelope -v
//
// The chain reader here is a local fake, deliberately: this measures the
// WATCHTOWER's sweep cost, and mixing in an RPC round trip per channel would
// measure the provider instead. The network terms are budgeted separately
// (inclusion, rpc failure) and measured against real endpoints.

import (
	"context"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestDetectionAtProductionEnvelope(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1: this builds 10,000 channels and takes a while")
	}
	const channels = 10_000

	// Build the node against OUR chain, so the coordinator adopts from the same
	// one the envelope is created on.
	chain := NewFakeChain()
	payee := newWiredNode(t, newSigner(t), chain, mustAddr(t, deployedChannelManager))

	// Build the envelope: 10,000 distinct channels, each with a signed state,
	// so the sweep does the work it would really do.
	ctxBuild := context.Background()
	built := 0
	for i := 0; i < channels; i++ {
		other := newSigner(t)
		id := chain.Add(payee.key.address(), other.address(), anon(500), new(big.Int))
		// ADOPT it: the watchtower sweeps the node's own store, so a channel
		// that is only on the chain is one it does not defend. Adoption is also
		// the real per-channel cost at startup — see the note on Load in P11.
		if err := payee.coord.Adopt(ctxBuild, id); err != nil {
			t.Fatalf("adopt %d: %v", i, err)
		}
		built++
	}
	t.Logf("envelope built and adopted: %d channels", built)

	sender := &recordingSender{hash: "0xmeasure"}
	tower := &Watchtower{
		Store: payee.store, Chain: chain, Sender: sender,
		Contract: mustAddr(t, deployedChannelManager),
		Now:      func() time.Time { return time.Unix(1_000_000, 0) },
	}

	// Sweep the tracked set repeatedly and take the WORST pass, not the mean:
	// the budget is a worst case.
	const passes = 20
	var worst time.Duration
	ctx := context.Background()
	for i := 0; i < passes; i++ {
		start := time.Now()
		results := tower.Sweep(ctx)
		if took := time.Since(start); took > worst {
			worst = took
		}
		if i == 0 {
			t.Logf("sweep covers %d tracked channels", len(results))
		}
	}

	// Per-channel cost, then the projected full-envelope sweep.
	tracked := len(payee.store.IDs())
	if tracked == 0 {
		t.Fatal("nothing tracked; the measurement would be meaningless")
	}
	perChannel := worst / time.Duration(tracked)
	projected := perChannel * channels

	t.Logf("worst sweep of %d passes : %s over %d tracked channels", passes, worst, tracked)
	t.Logf("per channel              : %s", perChannel)
	t.Logf("PROJECTED at %d channels : %s", channels, projected)
	t.Logf("sweep interval           : %s", DefaultWatchInterval)
	t.Logf("detection budget         : %s", MainnetChallengeBudget().Detection)

	// The sweep must finish well inside its interval, or detection latency is
	// not the interval at all — it is however long the sweep actually takes.
	if projected > DefaultWatchInterval {
		t.Errorf("a full sweep takes %s but the interval is %s: "+
			"detection would be sweep-bound, not interval-bound", projected, DefaultWatchInterval)
	}
	if projected > MainnetChallengeBudget().Detection {
		t.Errorf("projected sweep %s exceeds the detection budget %s — "+
			"RAISE THE BUDGET TERM and re-derive, do not file this as validation",
			projected, MainnetChallengeBudget().Detection)
	}
}
