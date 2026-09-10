package channel

// SCPP/1 §4.2 and §5. The properties here are what make a proposal unambiguous
// and a retry safe.

import (
	"math/big"
	"testing"
)

func txChannel(t *testing.T) (*Channel, *signer, *signer) {
	t.Helper()
	tipper, recipient := newSigner(t), newSigner(t)
	return newFundedChannel(t, tipper, recipient, anon(500)), tipper, recipient
}

// The property retries depend on: same base, same transition, same bytes.
func TestApplyIsDeterministic(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	tr := StateTransition{Kind: KindPay, Amount: anon(25)}

	first, err := tr.Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	second, err := tr.Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("apply again: %v", err)
	}
	if err := first.Equal(second); err != nil {
		t.Fatalf("two applications of one transition differ: %v", err)
	}
	// And the digest agrees, which is what actually gets signed.
	if first.Digest(ch.ChainID, ch.Contract) != second.Digest(ch.ChainID, ch.Contract) {
		t.Fatal("digests differ between two applications")
	}
}

func TestApplyDoesNotMutateTheChannel(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	before := ch.Latest.State.Nonce
	if _, err := (StateTransition{Kind: KindPay, Amount: anon(25)}).Apply(ch, tipper.address()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if ch.Latest.State.Nonce != before {
		t.Fatal("Apply advanced the channel; it must be pure")
	}
}

func TestPayMovesFromTheProposer(t *testing.T) {
	ch, tipper, recipient := txChannel(t)
	next, err := (StateTransition{Kind: KindPay, Amount: anon(25)}).Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	tipperBal, recipientBal := next.BalanceB, next.BalanceA
	if ch.IsA(tipper.address()) {
		tipperBal, recipientBal = next.BalanceA, next.BalanceB
	}
	if tipperBal.Cmp(anon(475)) != 0 {
		t.Fatalf("tipper holds %s, want 475", tipperBal)
	}
	if recipientBal.Cmp(anon(25)) != 0 {
		t.Fatalf("recipient holds %s, want 25", recipientBal)
	}
	_ = recipient
}

// Check 8 of §4.2, enforced through check 7: a state that pays its own sender
// is not what Apply produces, so Matches rejects it.
func TestAStateThatPaysItsOwnSenderIsRejected(t *testing.T) {
	ch, tipper, recipient := txChannel(t)

	// The recipient needs a balance for the reversed direction to be arithmetically
	// possible at all — otherwise this test passes for the wrong reason.
	opening, err := (StateTransition{Kind: KindPay, Amount: anon(100)}).Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("opening pay: %v", err)
	}
	if err := ch.Accept(signState(t, ch, opening, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	tr := StateTransition{Kind: KindPay, Amount: anon(25)}

	// What the RECIPIENT paying 25 looks like. Perfectly conserved, perfectly
	// legal, and Channel.Accept would take it happily.
	backwards, err := tr.Apply(ch, recipient.address())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !backwards.Conserved(ch.DepositA, ch.DepositB) {
		t.Fatal("the reversed state does not conserve; the test proves nothing")
	}

	// The tipper proposes it while claiming to be paying 25 — a state that pays
	// its own sender. Only check 7 catches this.
	if err := tr.Matches(ch, tipper.address(), backwards); err == nil {
		t.Fatal("a proposal paying its own sender was accepted")
	}
}

func TestANonPartyCannotPropose(t *testing.T) {
	ch, _, _ := txChannel(t)
	stranger := newSigner(t)
	_, err := (StateTransition{Kind: KindPay, Amount: anon(25)}).Apply(ch, stranger.address())
	if err != ErrNotAParty {
		t.Fatalf("got %v, want ErrNotAParty", err)
	}
}

func TestPayRefusesMoreThanTheProposerHas(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	_, err := (StateTransition{Kind: KindPay, Amount: anon(501)}).Apply(ch, tipper.address())
	if err != ErrInsufficient {
		t.Fatalf("got %v, want ErrInsufficient", err)
	}
}

func TestPayRefusesZeroAndNegative(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	for _, amount := range []*big.Int{nil, new(big.Int), anon(-5)} {
		if _, err := (StateTransition{Kind: KindPay, Amount: amount}).Apply(ch, tipper.address()); err != ErrAmountNotPositive {
			t.Fatalf("amount %v: got %v, want ErrAmountNotPositive", amount, err)
		}
	}
}

// A lock takes value out of the payer and puts it in NEITHER balance.
func TestLockAddParksValueOutsideBothBalances(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	tr := StateTransition{
		Kind: KindLockAdd, Amount: anon(50),
		LockID: [32]byte{31: 1}, Hash: [32]byte{31: 9}, Expiry: 1 << 40,
	}
	next, err := tr.Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	sum := new(big.Int).Add(next.BalanceA, next.BalanceB)
	if sum.Cmp(anon(450)) != 0 {
		t.Fatalf("balances total %s, want 450 with 50 locked", sum)
	}
	if len(next.Pending) != 1 || next.Pending[0].Amount.Cmp(anon(50)) != 0 {
		t.Fatal("the lock was not recorded")
	}
	if next.Pending[0].PayerIsA != ch.IsA(tipper.address()) {
		t.Fatal("the lock names the wrong payer")
	}
	// And it still conserves, which is what Channel.Accept will check.
	if !next.Conserved(ch.DepositA, ch.DepositB) {
		t.Fatal("a locked state does not conserve the deposits")
	}
}

func TestLockAddRefusesADuplicateID(t *testing.T) {
	ch, tipper, recipient := txChannel(t)
	tr := StateTransition{
		Kind: KindLockAdd, Amount: anon(50),
		LockID: [32]byte{31: 1}, Hash: [32]byte{31: 9}, Expiry: 1 << 40,
	}
	next, err := tr.Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := ch.Accept(signState(t, ch, next, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := tr.Apply(ch, tipper.address()); err != ErrLockExists {
		t.Fatalf("got %v, want ErrLockExists", err)
	}
}

func TestLockSettleNeedsThePreimageAndPaysThePayee(t *testing.T) {
	ch, tipper, recipient := txChannel(t)

	var preimage [32]byte
	copy(preimage[:], []byte("the secret"))
	var hash [32]byte
	copy(hash[:], keccak(preimage[:]))

	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50),
		LockID: [32]byte{31: 1}, Hash: hash, Expiry: 1 << 40,
	}
	locked, err := add.Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := ch.Accept(signState(t, ch, locked, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	var wrong [32]byte
	wrong[0] = 0xff
	bad := StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: wrong}
	if _, err := bad.Apply(ch, recipient.address()); err != ErrPreimageBad {
		t.Fatalf("wrong preimage: got %v, want ErrPreimageBad", err)
	}

	// The payee proposes the settle — the one kind where the proposer gains.
	good := StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: preimage}
	next, err := good.Apply(ch, recipient.address())
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if len(next.Pending) != 0 {
		t.Fatal("the lock survived its settlement")
	}
	recipientBal := next.BalanceB
	if ch.IsA(recipient.address()) {
		recipientBal = next.BalanceA
	}
	if recipientBal.Cmp(anon(50)) != 0 {
		t.Fatalf("recipient holds %s after settling a 50 lock", recipientBal)
	}
}

func TestLockRefundReturnsValueToThePayer(t *testing.T) {
	ch, tipper, recipient := txChannel(t)
	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50),
		LockID: [32]byte{31: 1}, Hash: [32]byte{31: 9}, Expiry: 1 << 40,
	}
	locked, err := add.Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := ch.Accept(signState(t, ch, locked, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	next, err := (StateTransition{Kind: KindLockRefund, LockID: [32]byte{31: 1}}).Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("refund: %v", err)
	}
	tipperBal := next.BalanceB
	if ch.IsA(tipper.address()) {
		tipperBal = next.BalanceA
	}
	if tipperBal.Cmp(anon(500)) != 0 {
		t.Fatalf("tipper holds %s after a refund, want the full 500", tipperBal)
	}
	if len(next.Pending) != 0 {
		t.Fatal("the lock survived its refund")
	}
}

func TestSettleAndRefundNeedAnExistingLock(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	for _, tr := range []StateTransition{
		{Kind: KindLockSettle, LockID: [32]byte{31: 9}},
		{Kind: KindLockRefund, LockID: [32]byte{31: 9}},
	} {
		if _, err := tr.Apply(ch, tipper.address()); err != ErrNoSuchLock {
			t.Fatalf("%s: got %v, want ErrNoSuchLock", tr.Kind, err)
		}
	}
}

// closeCooperative refuses a state with a non-zero root, so CLOSE must refuse
// to build one.
func TestCloseRefusesWhileALockIsPending(t *testing.T) {
	ch, tipper, recipient := txChannel(t)
	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50),
		LockID: [32]byte{31: 1}, Hash: [32]byte{31: 9}, Expiry: 1 << 40,
	}
	locked, _ := add.Apply(ch, tipper.address())
	if err := ch.Accept(signState(t, ch, locked, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := (StateTransition{Kind: KindClose}).Apply(ch, tipper.address()); err != ErrLocksRemain {
		t.Fatalf("got %v, want ErrLocksRemain", err)
	}
}

func TestUnknownKindIsRefused(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	if _, err := (StateTransition{Kind: "TRANSFER"}).Apply(ch, tipper.address()); err == nil {
		t.Fatal("an unknown transition kind was applied")
	}
}

// The contract requires locks sorted by id. Inserting out of order must still
// produce a canonical set, or the root will not match on chain.
func TestLocksStayInCanonicalOrder(t *testing.T) {
	ch, tipper, recipient := txChannel(t)

	for _, id := range []byte{5, 2, 9, 1} {
		tr := StateTransition{
			Kind: KindLockAdd, Amount: anon(10),
			LockID: [32]byte{31: id}, Hash: [32]byte{31: id}, Expiry: 1 << 40,
		}
		next, err := tr.Apply(ch, tipper.address())
		if err != nil {
			t.Fatalf("lock %d: %v", id, err)
		}
		if err := ch.Accept(signState(t, ch, next, tipper, recipient)); err != nil {
			t.Fatalf("lock %d accept: %v", id, err)
		}
	}

	locks := ch.Latest.State.Pending
	if len(locks) != 4 {
		t.Fatalf("%d locks, want 4", len(locks))
	}
	for i := 1; i < len(locks); i++ {
		if !lessID(locks[i-1].ID, locks[i].ID) {
			t.Fatalf("locks out of order at %d", i)
		}
	}
}

// Every state Apply produces must be one Channel.Accept will take. If those two
// ever disagree, a node can build a payment it cannot then record.
func TestAppliedStatesAreAlwaysAcceptable(t *testing.T) {
	ch, tipper, recipient := txChannel(t)

	steps := []StateTransition{
		{Kind: KindPay, Amount: anon(5)},
		{Kind: KindPay, Amount: anon(25)},
		{Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 3}, Hash: [32]byte{31: 3}, Expiry: 1 << 40},
		{Kind: KindLockRefund, LockID: [32]byte{31: 3}},
		{Kind: KindPay, Amount: anon(100)},
	}
	for i, tr := range steps {
		next, err := tr.Apply(ch, tipper.address())
		if err != nil {
			t.Fatalf("step %d (%s): %v", i, tr.Kind, err)
		}
		if err := ch.Accept(signState(t, ch, next, tipper, recipient)); err != nil {
			t.Fatalf("step %d (%s) produced a state Accept refused: %v", i, tr.Kind, err)
		}
	}
	if got := ch.BalanceOf(recipient.address()); got.Cmp(anon(130)) != 0 {
		t.Fatalf("recipient holds %s, want 130", got)
	}
}

// The first state has no predecessor, so it starts from the on-chain deposits.
func TestTheFirstStateStartsFromTheDeposits(t *testing.T) {
	ch, tipper, _ := txChannel(t)
	next, err := (StateTransition{Kind: KindPay, Amount: anon(5)}).Apply(ch, tipper.address())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if next.Nonce != 1 {
		t.Fatalf("first nonce is %d, want 1", next.Nonce)
	}
	total := new(big.Int).Add(next.BalanceA, next.BalanceB)
	if total.Cmp(anon(500)) != 0 {
		t.Fatalf("first state totals %s, want the 500 deposited", total)
	}
}
