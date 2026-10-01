package channel

// The watchtower — roadmap P10.
//
// The behaviour under test is the one nobody sees until it matters: a stale
// close, submitted by a counterparty who knows the payer stopped watching six
// months ago. Every test here is a variation on "did the honest state win, and
// if it could not, did anyone find out".
//
// The failure that costs money is silent. A watchtower that skips a challenge
// and logs nothing looks exactly like a watchtower with nothing to do, so the
// cases below assert as hard on WHAT WAS REPORTED as on what was sent.

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"
)

type recordingSender struct {
	sent []SignedState
	err  error
	hash string
}

func (r *recordingSender) Challenge(_ context.Context, _ Address, signed SignedState) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	r.sent = append(r.sent, signed)
	if r.hash == "" {
		return "0x" + string(make([]byte, 0)) + "deadbeef", nil
	}
	return r.hash, nil
}

// watched builds a node holding a signed state, plus the chain it sits on.
func watched(t *testing.T, nonce uint64) (*Watchtower, *FakeChain, *recordingSender, [32]byte) {
	t.Helper()
	payer, payee, id := wiredPair(t, anon(500))

	// Move the channel to `nonce` through the real payment path, so the state
	// the watchtower defends is one the system actually produced.
	for i := uint64(1); i <= nonce; i++ {
		if _, err := payer.coord.Pay(context.Background(), id, intent(byte(i)),
			payTransition(1), directPeer{t, payee.coord}); err != nil {
			t.Fatalf("pay %d: %v", i, err)
		}
	}

	chain := NewFakeChain()
	chain.Add(payer.key.address(), payee.key.address(), anon(500), new(big.Int))

	sender := &recordingSender{hash: "0xc0ffee"}
	tower := &Watchtower{
		Store: payee.store, Chain: chain, Sender: sender,
		Contract: mustAddr(t, deployedChannelManager),
		Now:      func() time.Time { return time.Unix(1_000_000, 0) },
	}
	return tower, chain, sender, id
}

// fullWindow is a close that has just started under the deployed
// challengePeriod. Tests that are not ABOUT the margin must use it, or they
// quietly become margin tests the day the derivation changes.
func fullWindow() int64 {
	return 1_000_000 + RecommendedChallengePeriod()
}

func TestAnOpenChannelIsQuiet(t *testing.T) {
	tower, _, sender, id := watched(t, 3)

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchQuiet {
		t.Fatalf("outcome %q, want quiet", got.Outcome)
	}
	if len(sender.sent) != 0 {
		t.Error("a challenge was sent against a channel nobody is closing")
	}
}

// The case the watchtower exists for.
func TestAStaleCloseIsChallenged(t *testing.T) {
	tower, chain, sender, id := watched(t, 5)

	// The counterparty submits nonce 2, three payments ago.
	chain.StartClose(id, 2, 1_000_000+int64(24*time.Hour/time.Second))

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchChallenged {
		t.Fatalf("outcome %q (%v), want challenged", got.Outcome, got.Err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("%d challenges sent, want 1", len(sender.sent))
	}
	// The state submitted must be the best one held, not merely a better one.
	if sent := sender.sent[0].State.Nonce; sent != 5 {
		t.Errorf("challenged with nonce %d, want the latest 5", sent)
	}
	if !sender.sent[0].Complete() {
		t.Error("a challenge was sent with an incompletely signed state")
	}
	if got.TxHash == "" {
		t.Error("no transaction hash recorded; an operator cannot follow it up")
	}
}

// An honest close must not be fought. Challenging one wastes gas and, worse,
// would make the logs of a healthy system indistinguishable from an attacked one.
func TestAnHonestCloseIsLeftAlone(t *testing.T) {
	tower, chain, sender, id := watched(t, 4)
	chain.StartClose(id, 4, fullWindow())

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchHonest {
		t.Fatalf("outcome %q, want honest", got.Outcome)
	}
	if len(sender.sent) != 0 {
		t.Error("an honest close was challenged")
	}
}

// The contract requires STRICTLY greater. An equal nonce is not better, and
// submitting it would revert — spending gas to achieve nothing.
func TestAnEqualNonceIsNotBetter(t *testing.T) {
	tower, chain, sender, id := watched(t, 4)
	chain.StartClose(id, 4, fullWindow())

	if got := tower.Check(context.Background(), id); got.Outcome != WatchHonest {
		t.Fatalf("outcome %q, want honest", got.Outcome)
	}
	if len(sender.sent) != 0 {
		t.Error("a challenge was sent at an equal nonce; the contract would revert it")
	}
}

// Past the deadline there is nothing to be done, and pretending otherwise
// wastes gas on a certain revert.
func TestAClosedWindowIsReportedNotAttempted(t *testing.T) {
	tower, chain, sender, id := watched(t, 5)
	chain.StartClose(id, 1, 999_000) // already past

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchFailed {
		t.Fatalf("outcome %q, want failed", got.Outcome)
	}
	if !errors.Is(got.Err, ErrTooLate) {
		t.Errorf("error %v, want ErrTooLate", got.Err)
	}
	if len(sender.sent) != 0 {
		t.Error("a challenge was sent after the window closed")
	}
}

// Inside the margin the transaction is unlikely to confirm in time. Refusing
// loudly beats sending hopefully: a broadcast still writes "challenge sent"
// into a log somebody later reads as "we were fine".
func TestInsideTheMarginItRefusesLoudly(t *testing.T) {
	tower, chain, sender, id := watched(t, 5)
	tower.Margin = 15 * time.Minute
	chain.StartClose(id, 1, 1_000_000+60) // one minute left

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchFailed {
		t.Fatalf("outcome %q, want failed", got.Outcome)
	}
	if got.Err == nil {
		t.Fatal("no error recorded; this must reach a human")
	}
	if len(sender.sent) != 0 {
		t.Error("a challenge was attempted inside the margin")
	}
	if got.Remaining != 60 {
		t.Errorf("remaining %d, want 60", got.Remaining)
	}
}

// Just outside the margin it must still try. A watchtower that gave up early
// would be a watchtower that never acts.
func TestOutsideTheMarginItActs(t *testing.T) {
	tower, chain, sender, id := watched(t, 5)
	tower.Margin = 15 * time.Minute
	chain.StartClose(id, 1, 1_000_000+int64(16*time.Minute/time.Second))

	if got := tower.Check(context.Background(), id); got.Outcome != WatchChallenged {
		t.Fatalf("outcome %q (%v), want challenged", got.Outcome, got.Err)
	}
	if len(sender.sent) != 1 {
		t.Errorf("%d challenges sent, want 1", len(sender.sent))
	}
}

func TestABroadcastFailureIsReportedNotSwallowed(t *testing.T) {
	tower, chain, sender, id := watched(t, 5)
	sender.err = errors.New("rpc refused the transaction")
	chain.StartClose(id, 1, fullWindow())

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchFailed {
		t.Fatalf("outcome %q, want failed", got.Outcome)
	}
	if got.Err == nil {
		t.Fatal("a failed broadcast produced no error")
	}
}

// An unreachable chain must not read as "nothing to do". That is the failure
// mode where a watchtower sleeps through the attack it was built for.
func TestAnUnreachableChainIsAFailureNotQuiet(t *testing.T) {
	tower, chain, _, id := watched(t, 5)
	chain.Err = errors.New("rpc down")

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchFailed {
		t.Fatalf("outcome %q, want failed — an unreachable chain is not silence", got.Outcome)
	}
}

// The decision inputs are recorded whatever happens. "Why did you not
// challenge" is the first question an incident asks.
func TestEveryPassRecordsWhatItSaw(t *testing.T) {
	tower, chain, _, id := watched(t, 7)
	chain.StartClose(id, 3, fullWindow())

	got := tower.Check(context.Background(), id)
	if got.OnChainNonce != 3 || got.BestNonce != 7 {
		t.Errorf("recorded on-chain %d / best %d, want 3 / 7", got.OnChainNonce, got.BestNonce)
	}
	if got.Deadline != fullWindow() {
		t.Errorf("deadline %d not recorded", got.Deadline)
	}
	if got.Remaining != RecommendedChallengePeriod() {
		t.Errorf("remaining %d, want %d", got.Remaining, RecommendedChallengePeriod())
	}
}

func TestASettledChannelNeedsNothing(t *testing.T) {
	tower, chain, sender, id := watched(t, 5)
	chain.Settled(id)

	if got := tower.Check(context.Background(), id); got.Outcome != WatchSettled {
		t.Fatalf("outcome %q, want settled", got.Outcome)
	}
	if len(sender.sent) != 0 {
		t.Error("a settled channel was challenged")
	}
}

// A watchtower with no way to send must say so rather than report quiet.
func TestAMissingSenderIsAFailure(t *testing.T) {
	tower, chain, _, id := watched(t, 5)
	tower.Sender = nil
	chain.StartClose(id, 1, fullWindow())

	got := tower.Check(context.Background(), id)
	if got.Outcome != WatchFailed || got.Err == nil {
		t.Fatalf("outcome %q err %v; a stale close with no sender must be loud",
			got.Outcome, got.Err)
	}
}

func TestSweepCoversEveryTrackedChannel(t *testing.T) {
	tower, _, _, _ := watched(t, 2)

	seen := 0
	tower.OnResult = func(Watch) { seen++ }
	results := tower.Sweep(context.Background())

	if len(results) == 0 {
		t.Fatal("swept nothing")
	}
	if seen != len(results) {
		t.Errorf("reported %d results but returned %d", seen, len(results))
	}
}

// A watchtower can only submit states both parties already signed. It holds no
// key of theirs and cannot construct one — which is what makes delegating to a
// stranger's watchtower no worse than having none.
func TestAWatchtowerCanOnlySubmitWhatWasAlreadySigned(t *testing.T) {
	tower, chain, sender, id := watched(t, 4)
	chain.StartClose(id, 1, fullWindow())

	if got := tower.Check(context.Background(), id); got.Outcome != WatchChallenged {
		t.Fatalf("outcome %q", got.Outcome)
	}

	// Whatever it sent must verify as a state signed by BOTH parties — the same
	// check the contract performs before honouring it.
	signed := sender.sent[0]
	ch, _ := tower.Store.Get(id)
	digest := signed.State.Digest(ch.ChainID, ch.Contract)
	for name, sig := range map[string][]byte{"A": signed.SigA, "B": signed.SigB} {
		who, err := RecoverSigner(digest, sig)
		if err != nil {
			t.Fatalf("signature %s does not recover: %v", name, err)
		}
		if who != ch.PartyA && who != ch.PartyB {
			t.Errorf("signature %s recovers to %s, who is not in this channel", name, who)
		}
	}
}
