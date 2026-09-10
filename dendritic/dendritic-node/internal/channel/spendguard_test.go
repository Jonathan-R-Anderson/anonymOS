package channel

// Every test here is a refusal except the two proving a configured budget
// authorises anything at all. That ratio is the point: this type exists to say
// no, and a bug in it is a bug that spends real money.

import (
	"errors"
	"math/big"
	"testing"
)

func wei(n int64) *big.Int { return big.NewInt(n) }

var _ SpendGuard = (*SpendBudget)(nil)

func TestABudgetMustBeConfigured(t *testing.T) {
	// The zero value authorises nothing, and construction refuses rather than
	// substituting a number nobody chose.
	for _, tc := range []struct {
		name              string
		total, perTx      *big.Int
		count             int
	}{
		{"no total", nil, wei(100), 10},
		{"zero total", wei(0), wei(100), 10},
		{"no per-tx", wei(1000), nil, 10},
		{"zero per-tx", wei(1000), wei(0), 10},
		{"no count", wei(1000), wei(100), 0},
		{"per-tx over total", wei(100), wei(1000), 10},
	} {
		if _, err := NewSpendBudget(tc.total, tc.perTx, tc.count); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

func TestTheZeroBudgetAuthorisesNothing(t *testing.T) {
	var b SpendBudget
	if err := b.Authorise(wei(1)); err == nil {
		t.Fatal("an unconfigured budget authorised a transaction")
	}
}

func TestANilBudgetAuthorisesNothing(t *testing.T) {
	var b *SpendBudget
	if err := b.Authorise(wei(1)); err == nil {
		t.Fatal("a nil budget authorised a transaction")
	}
}

func TestAConfiguredBudgetAuthorisesWithinItsCeiling(t *testing.T) {
	b, err := NewSpendBudget(wei(1000), wei(400), 5)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := b.Authorise(wei(400)); err != nil {
			t.Fatalf("authorisation %d refused: %v", i+1, err)
		}
	}
	spent, count := b.Spent()
	if spent.Cmp(wei(800)) != 0 || count != 2 {
		t.Fatalf("spent %v over %d txs, want 800 over 2", spent, count)
	}
	if b.Remaining().Cmp(wei(200)) != 0 {
		t.Errorf("remaining %v, want 200", b.Remaining())
	}
}

func TestTheTotalCeilingHolds(t *testing.T) {
	b, _ := NewSpendBudget(wei(1000), wei(600), 10)
	if err := b.Authorise(wei(600)); err != nil {
		t.Fatal(err)
	}
	// 600 + 600 = 1200 > 1000.
	if err := b.Authorise(wei(600)); err == nil {
		t.Fatal("the run spent past its total ceiling")
	}
	// And the refusal did not consume the allowance.
	if spent, _ := b.Spent(); spent.Cmp(wei(600)) != 0 {
		t.Errorf("a refused transaction was charged: spent %v", spent)
	}
}

func TestThePerTransactionCeilingHolds(t *testing.T) {
	b, _ := NewSpendBudget(wei(10_000), wei(100), 10)
	if err := b.Authorise(wei(101)); err == nil {
		t.Fatal("a single transaction exceeded the per-transaction limit")
	}
}

func TestTheTransactionCountLimitHolds(t *testing.T) {
	// So a loop with a bug cannot spend the ceiling in thousands of tiny pieces.
	b, _ := NewSpendBudget(wei(1_000_000), wei(1), 3)
	for i := 0; i < 3; i++ {
		if err := b.Authorise(wei(1)); err != nil {
			t.Fatalf("authorisation %d refused: %v", i+1, err)
		}
	}
	if err := b.Authorise(wei(1)); err == nil {
		t.Fatal("the run sent more transactions than its limit")
	}
}

func TestAnAuthorisationIsNeverRefunded(t *testing.T) {
	// A transaction that was authorised and then failed still consumed its
	// allowance. Forgetting that lets a failing loop retry past the ceiling.
	b, _ := NewSpendBudget(wei(100), wei(60), 10)
	if err := b.Authorise(wei(60)); err != nil {
		t.Fatal(err)
	}
	// Caller's transaction failed here — nothing tells the budget, deliberately.
	if err := b.Authorise(wei(60)); err == nil {
		t.Fatal("a failed transaction's allowance was silently returned")
	}
}

func TestACostlessTransactionCannotBeAuthorised(t *testing.T) {
	b, _ := NewSpendBudget(wei(1000), wei(100), 10)
	if err := b.Authorise(nil); err == nil {
		t.Fatal("a transaction with no stated cost was authorised")
	}
	if err := b.Authorise(wei(-1)); err == nil {
		t.Fatal("a negative cost was authorised")
	}
}

// ---- dry run -----------------------------------------------------------------

func TestADryRunAuthorisesNothingButStillCounts(t *testing.T) {
	b := DryRun()
	for i := 0; i < 3; i++ {
		if err := b.Authorise(wei(500)); !errors.Is(err, ErrDryRun) {
			t.Fatalf("dry run returned %v, want ErrDryRun", err)
		}
	}
	// It reports what the real run WOULD have cost — that is the whole use.
	spent, count := b.Spent()
	if count != 3 || spent.Cmp(wei(1500)) != 0 {
		t.Errorf("dry run reported %v over %d txs, want 1500 over 3", spent, count)
	}
}

func TestADryRunCannotBecomeARealRunByForgettingAFlag(t *testing.T) {
	// There is no setter that turns a rehearsal into a broadcast. The only way
	// to spend is to construct a budget that says what it may spend.
	b := DryRun()
	if err := b.Authorise(wei(1)); !errors.Is(err, ErrDryRun) {
		t.Fatal("a dry run authorised a transaction")
	}
}

// ---- preflight ---------------------------------------------------------------

func TestAnUnfundableRunIsRefusedBeforeItStarts(t *testing.T) {
	// Discovering halfway through that the treasury is empty leaves a run with
	// an unknown worst case, which is not evidence.
	b, _ := NewSpendBudget(wei(1000), wei(100), 10)
	if err := b.CheckBalance(wei(999)); err == nil {
		t.Fatal("a run was started against a balance that cannot cover its ceiling")
	}
	if err := b.CheckBalance(wei(1000)); err != nil {
		t.Fatalf("an exactly-fundable run was refused: %v", err)
	}
	if err := b.CheckBalance(nil); err == nil {
		t.Fatal("an unknown balance was accepted")
	}
}
