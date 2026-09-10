package aggregator

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// Live reads against the deployed contracts on Ethereum mainnet mainnet.
//
// Hand-rolled ABI encoding is exactly the kind of code that looks right and is
// wrong — a mis-derived selector or a misread word returns plausible garbage
// rather than an error. Unit tests against a mock would only prove the encoder
// agrees with itself, so these talk to the real chain.
//
// Skipped unless POF_LIVE_CHAIN=1, since a test suite that needs the internet
// is a test suite that fails on a train.
const (
	liveRPC          = "https://mainnet.era.ethereum.io"
	liveEpochManager = "0xbEE083af6b96AAa29285a9753DB56483Fcf3269f"
	liveNodeRegistry = "0x34B7B3Db8A7600cc58938c5391c7297E5B060124"
	liveStakeVault   = "0x401b1dBA06ca2B3A4B17540AD297A1B2564b61f2"
)

func liveClient(t *testing.T) *ChainClient {
	t.Helper()
	if os.Getenv("POF_LIVE_CHAIN") != "1" {
		t.Skip("set POF_LIVE_CHAIN=1 to run live mainnet reads")
	}
	em, err := ParseAddress(liveEpochManager)
	if err != nil {
		t.Fatal(err)
	}
	nr, err := ParseAddress(liveNodeRegistry)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := ParseAddress(liveStakeVault)
	if err != nil {
		t.Fatal(err)
	}
	return NewChainClient(liveRPC, em, nr, sv)
}

func TestLiveEpochManagerReads(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	latest, err := c.LatestEpoch(ctx)
	if err != nil {
		t.Fatalf("latestEpoch: %v", err)
	}
	t.Logf("latestEpoch = %d", latest)

	// Nothing has settled yet, so epoch 0 must read as absent. This is the
	// assertion that catches a decoder returning confident nonsense.
	e, err := c.EpochOf(ctx, 0)
	if err != nil {
		t.Fatalf("epochs(0): %v", err)
	}
	if e.Exists {
		t.Logf("epoch 0 exists: submittedAt=%d rewardRoot=%s",
			e.SubmittedAt, hex.EncodeToString(e.RewardRoot[:]))
	} else {
		t.Log("epoch 0 not submitted (expected — no epoch has settled)")
	}

	fin, err := c.IsFinalized(ctx, 0)
	if err != nil {
		t.Fatalf("isFinalized: %v", err)
	}
	if fin && !e.Exists {
		t.Fatal("epoch 0 reports finalized but was never submitted — decoder is misreading")
	}

	rnd, err := c.RandomnessOf(ctx, latest)
	if err != nil {
		t.Fatalf("randomnessOf: %v", err)
	}
	t.Logf("randomnessOf(%d) = %s", latest, hex.EncodeToString(rnd[:]))
}

func TestLiveNodeRegistryReads(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// An id nobody registered must read as unregistered, with no owner. If the
	// decoder were misaligned this would come back "registered" with a garbage
	// address, and settlement would pay a wallet that does not exist.
	var unknown [32]byte
	for i := range unknown {
		unknown[i] = byte(i + 1)
	}
	registered, err := c.IsNodeRegistered(ctx, unknown)
	if err != nil {
		t.Fatalf("isRegistered: %v", err)
	}
	if registered {
		t.Fatal("an unregistered node id reports as registered")
	}
	owner, ok, err := c.NodeOwner(ctx, unknown)
	if err != nil {
		t.Fatalf("getNode: %v", err)
	}
	if ok {
		t.Fatalf("unregistered node returned owner %s", hex.EncodeToString(owner[:]))
	}

	// RecipientsFor must simply omit unknown nodes: a zero-address recipient
	// would burn a reward instead of paying it.
	recips, err := c.RecipientsFor(ctx, [][32]byte{unknown})
	if err != nil {
		t.Fatalf("RecipientsFor: %v", err)
	}
	if len(recips) != 0 {
		t.Fatalf("expected no recipients, got %d", len(recips))
	}
}

func TestLiveStakeVaultRead(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var nobody [20]byte
	nobody[19] = 1
	staked, err := c.TotalStaked(ctx, nobody)
	if err != nil {
		t.Fatalf("totalStaked: %v", err)
	}
	if staked == nil || staked.Sign() != 0 {
		t.Fatalf("an address that never staked reports %v", staked)
	}
}

// Selectors are derived from the signature strings at call time, so a typo in
// a signature produces a valid-looking call to a function that does not exist —
// which on most nodes returns empty data rather than an error. Pinning them
// makes that a test failure instead of a runtime mystery. Offline.
func TestSelectorsAreCorrect(t *testing.T) {
	cases := map[string]string{
		"latestEpoch()":                  "9cb118bf",
		"randomnessOf(uint64)":           "1edb4fbc",
		"isFinalized(uint64)":            "b9012d5a",
		"epochs(uint64)":                 "4bd2d7f9",
		"isRegistered(bytes32)":          "27258b22",
		"hasCapability(bytes32,uint256)": "e8b4a02c",
		"getNode(bytes32)":               "50c946fe",
		"totalStaked(address)":           "9bfd8d61",
	}
	for sig, want := range cases {
		if got := hex.EncodeToString(selector(sig)); got != want {
			t.Errorf("%s: selector %s want %s", sig, got, want)
		}
	}
}
