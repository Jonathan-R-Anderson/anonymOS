package channel

// The measurement spend ceiling — roadmap P12 phase 3.
//
// WHY A CEILING IS CONFIGURATION AND NOT A DEFAULT
// ------------------------------------------------
// Nothing in this repository had a spend limit, so the honest options were to
// introduce one as a REQUIRED value or to invent a number. A default here would
// be a number nobody chose, authorising real money on a chain where mistakes do
// not reverse. So the zero value refuses: a Budget with no ceiling authorises
// nothing at all, and the caller has to say what it is willing to spend.
//
// WHAT IT COUNTS
// --------------
// The WORST case, not the likely one. Every authorisation is charged at
// gas x feeCap — what the transaction may cost if the base fee runs up
// underneath it — because a ceiling that only holds when fees stay flat is a
// ceiling that fails exactly when it is needed.
//
// Spent is never decremented. A transaction that was authorised and then failed
// still consumed its allowance as far as this is concerned: the run asked for
// permission and got it, and forgetting that would let a failing loop retry its
// way past the limit.

import (
	"fmt"
	"math/big"
	"sync"
)

// SpendBudget authorises measurement transactions up to a stated ceiling.
//
// Safe for concurrent use. Construct with NewSpendBudget; the zero value
// refuses everything, which is the intended behaviour for "nobody set a limit"
// rather than a bug to work around.
type SpendBudget struct {
	mu sync.Mutex
	// maxTotal is the whole run's ceiling in wei. Nil or zero refuses.
	maxTotal *big.Int
	// maxPerTx bounds any single transaction. Nil or zero refuses.
	maxPerTx *big.Int
	// maxCount bounds how many transactions the run may send at all, so a loop
	// with a bug cannot spend the ceiling in thousands of tiny pieces.
	maxCount int

	spent *big.Int
	count int
	// dryRun authorises nothing and records nothing. It exists so a run can be
	// rehearsed against the real endpoints and the real ceiling without
	// broadcasting, and so the rehearsal cannot silently become the real thing.
	dryRun bool
}

// NewSpendBudget states what a measurement run may spend.
//
// Returns an error rather than clamping: a caller that asked for a ceiling of
// zero has not made a decision, and quietly substituting one would put this
// code in charge of somebody else's money.
func NewSpendBudget(maxTotalWei, maxPerTxWei *big.Int, maxCount int) (*SpendBudget, error) {
	if maxTotalWei == nil || maxTotalWei.Sign() <= 0 {
		return nil, fmt.Errorf(
			"spend: no total ceiling configured; a measurement run must state what it may spend")
	}
	if maxPerTxWei == nil || maxPerTxWei.Sign() <= 0 {
		return nil, fmt.Errorf("spend: no per-transaction ceiling configured")
	}
	if maxCount <= 0 {
		return nil, fmt.Errorf("spend: no transaction count limit configured")
	}
	if maxPerTxWei.Cmp(maxTotalWei) > 0 {
		return nil, fmt.Errorf(
			"spend: the per-transaction ceiling (%s wei) exceeds the total (%s wei)",
			maxPerTxWei, maxTotalWei)
	}
	return &SpendBudget{
		maxTotal: new(big.Int).Set(maxTotalWei),
		maxPerTx: new(big.Int).Set(maxPerTxWei),
		maxCount: maxCount,
		spent:    new(big.Int),
	}, nil
}

// DryRun returns a budget that refuses every authorisation.
//
// A rehearsal is not a cheaper version of the real run — it is a different
// thing, and it must not be possible to turn one into the other by forgetting a
// flag. Everything upstream of the guard still executes: endpoints are reached,
// nonces read, gas estimated, the signer's address verified. Only the spending
// stops.
func DryRun() *SpendBudget { return &SpendBudget{dryRun: true, spent: new(big.Int)} }

// ErrDryRun is what a rehearsal returns instead of authorising.
var ErrDryRun = fmt.Errorf("spend: dry run — nothing was signed or broadcast")

// Authorise implements SpendGuard.
func (b *SpendBudget) Authorise(maxCostWei *big.Int) error {
	if b == nil {
		return fmt.Errorf("spend: no budget configured; refusing to authorise a transaction")
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.dryRun {
		// Counted so a rehearsal still reports how many transactions the real
		// run would have sent, and what it would have cost.
		b.count++
		if maxCostWei != nil {
			b.spent.Add(b.spent, maxCostWei)
		}
		return ErrDryRun
	}
	if b.maxTotal == nil || b.maxTotal.Sign() <= 0 {
		return fmt.Errorf(
			"spend: no ceiling configured; the zero budget authorises nothing")
	}
	if maxCostWei == nil || maxCostWei.Sign() < 0 {
		return fmt.Errorf("spend: a transaction with no stated cost cannot be authorised")
	}
	if b.count >= b.maxCount {
		return fmt.Errorf("spend: %d transactions already sent, the limit is %d",
			b.count, b.maxCount)
	}
	if maxCostWei.Cmp(b.maxPerTx) > 0 {
		return fmt.Errorf(
			"spend: this transaction may cost %s wei, over the per-transaction limit of %s",
			maxCostWei, b.maxPerTx)
	}
	after := new(big.Int).Add(b.spent, maxCostWei)
	if after.Cmp(b.maxTotal) > 0 {
		return fmt.Errorf(
			"spend: this transaction would bring the run to %s wei, over the ceiling of %s",
			after, b.maxTotal)
	}

	// Charged BEFORE the transaction is signed, and never refunded. See the
	// header: an authorisation that was granted and then wasted still counted.
	b.spent = after
	b.count++
	return nil
}

// Spent reports the worst-case wei authorised so far and how many transactions.
func (b *SpendBudget) Spent() (*big.Int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return new(big.Int).Set(b.spent), b.count
}

// Remaining is what is left of the ceiling, at worst-case pricing.
func (b *SpendBudget) Remaining() *big.Int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxTotal == nil {
		return new(big.Int)
	}
	left := new(big.Int).Sub(b.maxTotal, b.spent)
	if left.Sign() < 0 {
		return new(big.Int)
	}
	return left
}

// CheckBalance refuses a run the account cannot afford at worst-case pricing.
//
// Separate from Authorise because it is a PREFLIGHT question — asked once,
// before anything is sent, about whether the whole run is fundable. Discovering
// halfway through that the treasury is empty leaves a measurement run with an
// unknown worst case, which is not evidence.
func (b *SpendBudget) CheckBalance(balanceWei *big.Int) error {
	if balanceWei == nil {
		return fmt.Errorf("spend: the account balance is unknown")
	}
	b.mu.Lock()
	total := b.maxTotal
	b.mu.Unlock()
	if total == nil || total.Sign() <= 0 {
		return fmt.Errorf("spend: no ceiling configured")
	}
	if balanceWei.Cmp(total) < 0 {
		return fmt.Errorf(
			"spend: the account holds %s wei but the run is authorised to spend up to %s; "+
				"fund it or lower the ceiling", balanceWei, total)
	}
	return nil
}
