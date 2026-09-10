package compute

import (
	"errors"
	"math"
	"testing"
)

func rates() Rates { return Rates{CPUPerRefSecond: 10, GPUPerRefSecond: 40} }

func pricedUnit() Unit {
	u := cpuUnit()
	u.RefSeconds = 60
	return u
}

// --- priced in work, not wall-clock time ---

func TestPriceDoesNotDependOnHowLongANodeTook(t *testing.T) {
	// THE caution from the roadmap. Paying for elapsed time rewards slow
	// hardware — the same unit would pay a struggling laptop several times what
	// it pays a workstation — and pays for idling.
	//
	// Enforced structurally rather than by assertion: neither Quote nor Reward
	// accepts a duration or a UnitResult, so there is nothing to pay elapsed
	// time from. This test pins the shape.
	u := pricedUnit()
	a, err := Quote(u, rates(), DefaultQuorum())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Quote(u, rates(), DefaultQuorum())
	if a != b {
		t.Fatal("the same unit quoted differently twice")
	}
	// 60 reference-seconds x 10 per second x 3 replicas.
	if a != 60*10*3 {
		t.Fatalf("quote %d, want %d", a, 60*10*3)
	}
}

func TestAUnitWithNoReferenceCostIsRefusedNotGuessed(t *testing.T) {
	// Pricing from the deadline would charge for the time the unit was ALLOWED
	// rather than the work it contains — the wall-clock mistake in a hat.
	u := pricedUnit()
	u.RefSeconds = 0
	if _, err := Quote(u, rates(), DefaultQuorum()); !errors.Is(err, ErrNoCost) {
		t.Fatalf("err %v, want ErrNoCost", err)
	}
}

func TestGPUAndCPUArePricedSeparately(t *testing.T) {
	cpu := pricedUnit()
	gpu := pricedUnit()
	gpu.Needs = "gpu:cuda"
	c, _ := Quote(cpu, rates(), DefaultQuorum())
	g, _ := Quote(gpu, rates(), DefaultQuorum())
	if g <= c {
		t.Fatalf("gpu %d not priced above cpu %d — a blended rate systematically "+
			"overpays one and underpays the other", g, c)
	}
}

func TestVerificationIsChargedForBecauseItIsRealWork(t *testing.T) {
	u := pricedUnit()
	one, _ := Quote(u, rates(), Quorum{Need: 1})
	three, _ := Quote(u, rates(), Quorum{Need: 3})
	if three <= one {
		t.Fatal("more replicas did not cost more; the extra nodes' work is real " +
			"and somebody has to be paid for it")
	}
}

// --- the reputation floor ---

func TestANewNodeEarnsHalfRateNotNothing(t *testing.T) {
	// The sharp edge the roadmap warns about. If zero reputation multiplies the
	// reward to zero, nobody can ever start earning, the network cannot grow,
	// and the formula has quietly become a closed shop.
	u := pricedUnit()
	newcomer, err := Reward(u, rates(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if newcomer <= 0 {
		t.Fatal("a node with no reputation earned nothing and can never earn any")
	}
	proven, _ := Reward(u, rates(), 1.0)
	if newcomer != proven/2 {
		t.Fatalf("newcomer %d, proven %d — want half", newcomer, proven)
	}
}

func TestReputationCannotMintMoney(t *testing.T) {
	// A bug upstream that inflates reputation must not be able to inflate a
	// payment.
	u := pricedUnit()
	sane, _ := Reward(u, rates(), 1.0)
	for _, absurd := range []float64{1.5, 1e9, math.Inf(1)} {
		got, _ := Reward(u, rates(), absurd)
		if got != sane {
			t.Fatalf("reputation %v paid %d, want %d", absurd, got, sane)
		}
	}
}

func TestGarbageReputationDoesNotPanicOrGoNegative(t *testing.T) {
	// NaN and negatives arrive from real upstream services. Neither may become
	// a negative payment or a panic in a settlement path.
	u := pricedUnit()
	for _, bad := range []float64{math.NaN(), -1, math.Inf(-1)} {
		got, err := Reward(u, rates(), bad)
		if err != nil {
			t.Fatalf("reputation %v errored: %v", bad, err)
		}
		if got <= 0 {
			t.Fatalf("reputation %v paid %d", bad, got)
		}
	}
}

// --- budget ceiling ---

func TestTheCeilingIsAHardStop(t *testing.T) {
	u := pricedUnit()
	if _, err := QuoteWithin(u, rates(), DefaultQuorum(), 100); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("err %v, want ErrOverBudget — a runaway loop must exhaust its "+
			"own ceiling and stop", err)
	}
	if _, err := QuoteWithin(u, rates(), DefaultQuorum(), 100000); err != nil {
		t.Fatalf("refused a quote inside the ceiling: %v", err)
	}
}

// --- escrow ---

func TestEscrowNeverPaysOutMoreThanWasHeld(t *testing.T) {
	// A distributed system WILL deliver a duplicate settlement message. Without
	// this invariant, that mints money.
	e, err := Hold("job1", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Release(600); err != nil {
		t.Fatal(err)
	}
	if err := e.Release(600); !errors.Is(err, ErrOverRelease) {
		t.Fatalf("err %v — the second release exceeded what was held", err)
	}
	if e.Released != 600 {
		t.Fatalf("released %d", e.Released)
	}
}

func TestRefundReturnsExactlyTheUnspentRemainder(t *testing.T) {
	e, _ := Hold("job1", 1000)
	_ = e.Release(300)
	back, err := e.Refund()
	if err != nil {
		t.Fatal(err)
	}
	if back != 700 {
		t.Fatalf("refunded %d, want 700", back)
	}
	if e.Held != e.Released+e.Refunded {
		t.Fatalf("books do not balance: held %d, out %d", e.Held, e.Released+e.Refunded)
	}
}

func TestAClosedEscrowCannotBeDrawnOnLate(t *testing.T) {
	e, _ := Hold("job1", 100)
	_, _ = e.Refund()
	if err := e.Release(10); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("err %v — money that has gone home cannot be paid out again", err)
	}
}

// --- settlement ---

func settledUnit() (Unit, *Escrow) {
	u := pricedUnit()
	cost, _ := Quote(u, rates(), DefaultQuorum())
	e, _ := Hold("job1", cost)
	return u, e
}

func TestAgreeingNodesArePaidAndDissentersAreNot(t *testing.T) {
	u, e := settledUnit()
	check := Check{Verdict: VerdictAgreed, Agreeing: []string{"alice", "bob"},
		Dissenting: []string{"mallory"}}
	paid, err := e.Settle(u, check, rates(), map[string]float64{"alice": 1, "bob": 1, "mallory": 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(paid) != 2 || paid["alice"] == 0 || paid["bob"] == 0 {
		t.Fatalf("paid %v", paid)
	}
	if _, got := paid["mallory"]; got {
		t.Fatal("paid a node whose answer disagreed with the verified result")
	}
}

func TestBeingWrongIsNotPaidForAndIsNotPunishedHere(t *testing.T) {
	// Slashing belongs to a dispute process that can be appealed. Settlement
	// simply does not pay.
	u, e := settledUnit()
	before := e.Held
	check := Check{Verdict: VerdictAgreed, Agreeing: []string{"alice", "bob"},
		Dissenting: []string{"mallory"}}
	paid, _ := e.Settle(u, check, rates(), map[string]float64{"alice": 1, "bob": 1})
	if paid["mallory"] < 0 {
		t.Fatal("settlement took money from a dissenting node")
	}
	if e.Released+e.Refunded != before {
		t.Fatalf("books do not balance after settlement")
	}
}

func TestAgreedFailureRefundsEverybody(t *testing.T) {
	// Harsh on the nodes, and correct: paying for agreed failure makes
	// submitting impossible work profitable.
	u, e := settledUnit()
	before := e.Held
	paid, err := e.Settle(u, Check{Verdict: VerdictFailed}, rates(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(paid) != 0 {
		t.Fatalf("paid %v for work nobody completed", paid)
	}
	if e.Refunded != before {
		t.Fatalf("refunded %d of %d", e.Refunded, before)
	}
}

func TestAnUndecidedResultMovesNoMoneyAndIsNotAnError(t *testing.T) {
	// "Not yet" is a normal state. Erroring would make callers treat an open
	// question as a broken job; paying would foreclose it.
	for _, verdict := range []Verdict{VerdictDisagreed, VerdictInsufficient, VerdictUndecidable} {
		u, e := settledUnit()
		paid, err := e.Settle(u, Check{Verdict: verdict, Agreeing: []string{"alice"}},
			rates(), map[string]float64{"alice": 1})
		if err != nil {
			t.Fatalf("%s errored: %v", verdict, err)
		}
		if len(paid) != 0 || e.Released != 0 || e.Closed {
			t.Fatalf("%s moved money or closed the escrow", verdict)
		}
	}
}

func TestSettlementCannotOverdrawAShortEscrow(t *testing.T) {
	// A short escrow is a pricing bug. Paying what is left beats stranding the
	// money while it is investigated, and must never go negative.
	u := pricedUnit()
	e, _ := Hold("job1", 100) // far under the real quote
	paid, err := e.Settle(u, Check{Verdict: VerdictAgreed,
		Agreeing: []string{"alice", "bob", "carol"}}, rates(),
		map[string]float64{"alice": 1, "bob": 1, "carol": 1})
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	for _, amount := range paid {
		if amount <= 0 {
			t.Fatal("a zero or negative payment was recorded")
		}
		total += amount
	}
	if total > 100 {
		t.Fatalf("paid out %d from an escrow holding 100", total)
	}
	if e.Released+e.Refunded != e.Held {
		t.Fatal("books do not balance")
	}
}

func TestSettlementIsGatedOnTheVerdictNotALisOfWinners(t *testing.T) {
	// Settle takes the Check, so payment cannot be authorised by anything
	// weaker than the thing that decided the result was right.
	u, e := settledUnit()
	paid, _ := e.Settle(u, Check{Agreeing: []string{"alice"}}, rates(),
		map[string]float64{"alice": 1})
	if len(paid) != 0 {
		t.Fatal("paid on a Check carrying no verdict")
	}
}
