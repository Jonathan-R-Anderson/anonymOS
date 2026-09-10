package channel

// The challengePeriod derivation, and the measurement it rests on — P10.
//
// challengePeriod is immutable once deployed. That makes this the one number in
// the system that cannot be fixed later, so the tests here are less about the
// arithmetic — which is addition — than about the claim underneath it: that the
// LOCAL term is an over-estimate, measured rather than hoped for.
//
// If the local path ever grows past its budget, this fails. That is the point:
// the budget is a promise about the code, and a promise nothing checks is a
// guess.

import (
	"context"
	"math/big"
	"testing"
	"time"
)

func TestTheBudgetIsTheSumOfItsTerms(t *testing.T) {
	b := MainnetChallengeBudget()

	var manual time.Duration
	for _, term := range b.Terms() {
		manual += term.Dur
	}
	if b.Total() != manual {
		t.Fatalf("total %s does not match its terms %s", b.Total(), manual)
	}
	// Added, not averaged. A budget that combined these statistically would fail
	// exactly when two things went wrong together.
	if b.Total() < b.Outage {
		t.Error("the total is smaller than its largest term")
	}
}

func TestEveryTermIsAccountedFor(t *testing.T) {
	// A term silently left at zero is a failure mode nobody budgeted for.
	for _, term := range MainnetChallengeBudget().Terms() {
		if term.Dur <= 0 {
			t.Errorf("term %q is zero; it must be argued for, not omitted", term.Name)
		}
	}
}

func TestTheRecommendationRoundsUp(t *testing.T) {
	// Down is how a safety margin stops being one.
	cases := []struct {
		total time.Duration
		want  time.Duration
	}{
		{7*time.Hour + 31*time.Minute, 8 * time.Hour},
		{8 * time.Hour, 8 * time.Hour},
		{8*time.Hour + time.Second, 9 * time.Hour},
		{time.Minute, time.Hour},
	}
	for _, tc := range cases {
		b := ChallengeBudget{Safety: tc.total}
		if got := b.Recommend(); got != tc.want {
			t.Errorf("total %s recommended %s, want %s", tc.total, got, tc.want)
		}
	}
}

func TestTheRecommendationCoversTheTotal(t *testing.T) {
	b := MainnetChallengeBudget()
	if b.Recommend() < b.Total() {
		t.Fatalf("recommended %s is less than the budget %s", b.Recommend(), b.Total())
	}
}

func TestRaisingATermRaisesTheAnswer(t *testing.T) {
	// The derivation has to be live. A "budget" that ignored its inputs would be
	// a constant with extra steps.
	base := MainnetChallengeBudget()
	worse := base
	worse.Outage = base.Outage + 4*time.Hour

	if worse.Total() <= base.Total() {
		t.Fatal("a longer outage did not lengthen the budget")
	}
	if worse.Recommend() <= base.Recommend() {
		t.Fatal("a longer outage did not change the recommendation")
	}
}

func TestTheDeployedValueIsInSeconds(t *testing.T) {
	// The constructor takes seconds. Getting this wrong by a factor of 60 is a
	// channel defended for eight minutes instead of eight hours.
	want := int64(MainnetChallengeBudget().Recommend() / time.Second)
	if got := RecommendedChallengePeriod(); got != want {
		t.Fatalf("RecommendedChallengePeriod() = %d, want %d", got, want)
	}
	if got := RecommendedChallengePeriod(); got < 3600 {
		t.Errorf("a challenge period of %ds is under an hour; that cannot be right", got)
	}
}

// The margin must leave room for everything still ahead of a watchtower that
// has only just noticed — but must not be so large it refuses every real case.
func TestTheWatchMarginLeavesRoomForTheRestOfThePath(t *testing.T) {
	period := MainnetChallengeBudget().Recommend()
	margin := WatchMarginFor(period)

	if margin <= 0 {
		t.Fatal("a zero margin means attempting challenges that cannot arrive")
	}
	if margin >= period {
		t.Fatalf("margin %s is the whole period %s; nothing would ever be attempted",
			margin, period)
	}
	// Detection and outage are behind it by the time it acts; the rest is not.
	b := MainnetChallengeBudget()
	if margin < b.Inclusion {
		t.Errorf("margin %s does not even cover inclusion %s", margin, b.Inclusion)
	}
}

// A period too short for the assumptions must fail loudly rather than quietly
// defending nothing.
func TestAnUndefendablePeriodRefusesEverything(t *testing.T) {
	tiny := 5 * time.Minute
	if got := WatchMarginFor(tiny); got != tiny {
		t.Fatalf("margin %s for an undefendable %s period; it must refuse, not shrink",
			got, tiny)
	}
}

// ---- the measurement --------------------------------------------------------

// The local term, actually measured.
//
// This is the only term the code controls. Everything else is a property of the
// chain or of whoever runs the watchtower, and a budget that guessed at this one
// too would be guessing all the way down.
//
// Measured on the worst realistic shape: a channel carrying a full lock set,
// which is the largest calldata the dispute path ever encodes.
func TestLocalPathFitsItsBudget(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	// Build a state with locks outstanding — more to encode, more to hash, so
	// the measurement is taken on the largest calldata the dispute path builds.
	for i := 0; i < 8; i++ {
		add := StateTransition{
			Kind: KindLockAdd, Amount: anon(1),
			LockID: [32]byte{31: byte(i + 1)}, Hash: [32]byte{31: byte(i + 9)},
			Expiry: payer.clock + 3600,
		}
		result, err := payer.coord.Pay(ctx, id, intent(byte(i+1)), add,
			directPeer{t, payee.coord})
		if err != nil {
			t.Fatalf("lock %d: %v", i, err)
		}
		if !result.Done {
			t.Fatalf("lock %d refused: %s", i, result.Rejected)
		}
	}

	chain := NewFakeChain()
	chain.Add(payer.key.address(), payee.key.address(), anon(500), new(big.Int))
	chain.StartClose(id, 1, time.Now().Unix()+86400)

	sender := &recordingSender{hash: "0xabc"}
	tower := &Watchtower{
		Store: payee.store, Chain: chain, Sender: sender,
		Contract: mustAddr(t, deployedChannelManager),
	}

	// The whole local path: detect, retrieve, decide, encode, sign, hand to the
	// sender. Everything except the network.
	const runs = 200
	start := time.Now()
	for i := 0; i < runs; i++ {
		if got := tower.Check(ctx, id); got.Outcome != WatchChallenged {
			t.Fatalf("run %d: outcome %q (%v)", i, got.Outcome, got.Err)
		}
	}
	perRun := time.Since(start) / runs

	budget := MainnetChallengeBudget().Local
	if perRun > budget {
		t.Fatalf("the local path takes %s, over its %s budget — "+
			"raise ChallengeBudget.Local and re-derive challengePeriod", perRun, budget)
	}
	t.Logf("local path: %s per channel (budget %s, %.0fx headroom)",
		perRun, budget, float64(budget)/float64(perRun))
}

// The calldata a challenge carries must be encodable at all for a state with
// locks — the shape the measurement above assumes.
func TestAChallengeEncodesAStateWithLocks(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(5),
		LockID: [32]byte{31: 1}, Hash: [32]byte{31: 9},
		Expiry: payer.clock + 3600,
	}
	result, err := payer.coord.Pay(context.Background(), id, intent(1), add,
		directPeer{t, payee.coord})
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if !result.Done {
		t.Fatalf("lock refused: %s", result.Rejected)
	}
	ch, _ := payee.store.Get(id)

	data, err := ChallengeCalldata(ch.Latest)
	if err != nil {
		t.Fatalf("ChallengeCalldata: %v", err)
	}
	if len(data) < 4 {
		t.Fatal("no calldata")
	}
	for i, b := range selChallenge {
		if data[i] != b {
			t.Fatalf("wrong selector: %x", data[:4])
		}
	}
}

// A checkpointed state cannot go down the dispute path: the contract hashes
// these with the withdrawals at zero, so submitting one would be submitting a
// different state than the one that was signed.
func TestAWithdrawalCannotBeSubmittedToTheDisputePath(t *testing.T) {
	signed := SignedState{
		State: State{
			Nonce: 4, BalanceA: big.NewInt(1), BalanceB: big.NewInt(2),
			WithdrawA: big.NewInt(3),
		},
		SigA: make([]byte, 65), SigB: make([]byte, 65),
	}
	if _, err := ChallengeCalldata(signed); err == nil {
		t.Fatal("a state with a withdrawal was accepted by the dispute path")
	}
}

// The watchtower's default must be the derived one, or the two drift — and the
// direction they drift is a watchtower attempting challenges that cannot land.
func TestTheWatchtowerDefaultMarginIsTheDerivedOne(t *testing.T) {
	want := WatchMarginFor(MainnetChallengeBudget().Recommend())
	if DefaultWatchMargin != want {
		t.Fatalf("DefaultWatchMargin is %s but the budget derives %s",
			DefaultWatchMargin, want)
	}
	// And it must be a real fraction of the period rather than a token amount.
	period := MainnetChallengeBudget().Recommend()
	if DefaultWatchMargin < period/8 {
		t.Errorf("margin %s is under an eighth of the %s period; that is not a margin",
			DefaultWatchMargin, period)
	}
}
