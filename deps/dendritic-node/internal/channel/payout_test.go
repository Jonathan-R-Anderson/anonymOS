package channel

// P6. The payout worker, and the lifecycle the checkpoint exists to make
// possible.
//
// The crash cases are the point: a node that died between broadcasting and
// recording cannot know what it did, and every test here checks that it asks
// the chain rather than guessing.

import (
	"context"
	"errors"
	"math/big"
	"testing"
)

// payoutRig is a node with a chain, a writer, and a channel it can pay over.
type payoutRig struct {
	t      *testing.T
	dir    string
	store  *Store
	chain  *FakeChain
	writer *FakeChainWriter
	worker *PayoutWorker
	me     *signer
	peer   *signer
	id     [32]byte
	clock  int64
}

func newPayoutRig(t *testing.T, deposit int64) *payoutRig {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	me, peer := newSigner(t), newSigner(t)
	chain := NewFakeChain()
	id := chain.Add(me.address(), peer.address(), anon(deposit), new(big.Int))

	occ, err := chain.ReadChannel(context.Background(), Address{}, id)
	if err != nil {
		t.Fatalf("chain read: %v", err)
	}
	if err := store.TrackFromChain(big.NewInt(1), Address{}, occ); err != nil {
		t.Fatalf("track: %v", err)
	}

	writer := &FakeChainWriter{Chain: chain}
	r := &payoutRig{
		t: t, dir: dir, store: store, chain: chain, writer: writer,
		me: me, peer: peer, id: id, clock: 1_000_000,
	}
	r.worker = NewPayoutWorker(store, chain, writer, Address{})
	r.worker.SetClock(func() int64 { return r.clock })
	return r
}

// agree walks a transition through both signatures into the store — what SCPP/1
// would have done, without needing two nodes for a settlement test.
func (r *payoutRig) agree(tr StateTransition, proposer *signer) {
	r.t.Helper()
	ch, ok := r.store.Get(r.id)
	if !ok {
		r.t.Fatal("channel missing")
	}
	next, err := tr.Apply(ch, proposer.address())
	if err != nil {
		r.t.Fatalf("apply %s: %v", tr.Kind, err)
	}
	if err := r.store.Accept(r.id, signState(r.t, ch, next, r.me, r.peer)); err != nil {
		r.t.Fatalf("accept %s: %v", tr.Kind, err)
	}
}

func (r *payoutRig) channel() *Channel {
	r.t.Helper()
	ch, ok := r.store.Get(r.id)
	if !ok {
		r.t.Fatal("channel missing")
	}
	return ch
}

// refresh does what a coordinator would after a checkpoint lands.
func (r *payoutRig) refresh() {
	r.t.Helper()
	occ, err := r.chain.ReadChannel(context.Background(), Address{}, r.id)
	if err != nil {
		r.t.Fatalf("chain read: %v", err)
	}
	if err := r.store.RefreshFromChain(occ); err != nil {
		r.t.Fatalf("refresh: %v", err)
	}
}

// setChainDeposits is the chain applying a checkpoint's collateral reduction.
func (r *payoutRig) setChainDeposits(a, b *big.Int) {
	r.chain.mu.Lock()
	defer r.chain.mu.Unlock()
	occ := r.chain.Channels[r.id]
	occ.DepositA, occ.DepositB = a, b
	r.chain.Channels[r.id] = occ
}

// ---- the lifecycle the checkpoint exists for --------------------------------

// checkpoint → still open → more tips → checkpoint → still open → close.
//
// The thing that was impossible before: value comes out repeatedly and the
// channel survives it.
func TestAChannelSurvivesRepeatedCheckpoints(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	if err := r.worker.SetPolicy(r.id, PayoutPolicy{Mode: PayoutOnInterval, IntervalSeconds: 3600}); err != nil {
		t.Fatalf("policy: %v", err)
	}

	// Tips, then a draw-down of 75 by the peer.
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(75)}, r.peer)

	r.clock += 4000 // due
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeSubmitted {
		t.Fatalf("first checkpoint: %v %v", outcome, err)
	}
	calls := r.writer.Calls()
	if len(calls) != 1 || calls[0].Op != "checkpoint" {
		t.Fatalf("submitted %+v, want a checkpoint", calls)
	}

	// The chain applied it: collateral down to 925, channel STILL OPEN.
	r.setChainDeposits(anon(925), new(big.Int))
	r.refresh()
	if ch := r.channel(); ch.Status != StatusOpen {
		t.Fatalf("channel status %d after a checkpoint, want Open", ch.Status)
	}

	// Tipping continues against the new collateral.
	r.agree(StateTransition{Kind: KindPay, Amount: anon(200)}, r.me)
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(150)}, r.peer)

	r.clock += 4000
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeSubmitted {
		t.Fatalf("second checkpoint: %v %v", outcome, err)
	}
	if len(r.writer.Calls()) != 2 {
		t.Fatalf("%d calls, want 2", len(r.writer.Calls()))
	}
	r.setChainDeposits(anon(775), new(big.Int))
	r.refresh()

	// And finally a close, which ends it.
	if err := r.worker.SetPolicy(r.id, PayoutPolicy{Mode: PayoutOnClose}); err != nil {
		t.Fatalf("policy: %v", err)
	}
	r.agree(StateTransition{Kind: KindPay, Amount: anon(50)}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeSubmitted {
		t.Fatalf("close: %v %v", outcome, err)
	}
	last := r.writer.Calls()
	if last[len(last)-1].Op != "closeCooperative" {
		t.Fatalf("final op %s, want closeCooperative", last[len(last)-1].Op)
	}

	// The chain says Settled; the worker confirms it from there, not from its
	// own record of having sent something.
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("confirm: %v %v", outcome, err)
	}
	if got := r.channel().Payout.Phase; got != PhaseConfirmed {
		t.Fatalf("phase %s", got)
	}
}

// A checkpoint must not disturb a payment in flight.
func TestACheckpointLeavesALockAlone(t *testing.T) {
	r := newPayoutRig(t, 1000)

	r.agree(StateTransition{Kind: KindPay, Amount: anon(200)}, r.me)
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: r.clock + 9000,
	}, r.me)
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(150)}, r.peer)

	st := r.channel().Latest.State
	if len(st.Pending) != 1 || st.Pending[0].Amount.Cmp(anon(50)) != 0 {
		t.Fatal("the lock did not survive the checkpoint")
	}
	// balances + locked + withdrawn still equals the deposit.
	if !st.Conserved(r.channel().DepositA, r.channel().DepositB) {
		t.Fatal("a checkpoint around a live lock does not conserve")
	}
	// Resolved by ADDRESS, not by role: the peer is party A for about half of
	// all key pairs, and hardcoding WithdrawB makes this test pass or fail on a
	// coin flip. The same trap the production code is built to avoid.
	drawn := orZero(st.WithdrawB)
	if r.channel().IsA(r.peer.address()) {
		drawn = orZero(st.WithdrawA)
	}
	if drawn.Cmp(anon(150)) != 0 {
		t.Fatalf("withdrawal recorded as %s, want 150", drawn)
	}
}

// ---- the crash table ---------------------------------------------------------

// Broadcast succeeded, the node died before recording it. On restart the local
// record says nothing happened; the chain says otherwise, and the chain wins.
func TestBroadcastThenCrashBeforeRecording(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()

	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}

	// The writer broadcasts and the chain moves — then the process dies before
	// the record is written.
	r.writer.OnSend = func(FakeTx) {
		// Simulate the crash by discarding everything after the send: a fresh
		// store, loaded from a disk that never saw the update.
	}
	if _, err := r.worker.Settle(ctx, r.id); err != nil {
		t.Fatalf("settle: %v", err)
	}

	// Wipe the local phase, as a crash before the write would have left it.
	if err := r.store.Update(r.id, func(c *Channel) error {
		c.Payout.Phase = PhaseNone
		c.Payout.TxHash = ""
		return nil
	}); err != nil {
		t.Fatalf("simulate crash: %v", err)
	}

	// The node has no idea it sent anything. It asks.
	outcome, err := r.worker.Settle(ctx, r.id)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome != OutcomeConfirmed {
		t.Fatalf("outcome %s, want CONFIRMED — the chain knew", outcome)
	}
	if got := r.channel().Payout.Phase; got != PhaseConfirmed {
		t.Fatalf("phase %s", got)
	}
	// And it did not send a second transaction.
	if n := len(r.writer.Calls()); n != 1 {
		t.Fatalf("%d transactions sent, want 1", n)
	}
}

// The broadcast itself failed. Nothing is marked settled, and it is retryable.
func TestABroadcastFailureSettlesNothing(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()

	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	r.writer.FailWith = errors.New("rpc rejected: insufficient funds for gas")

	outcome, err := r.worker.Settle(ctx, r.id)
	if err == nil || outcome != OutcomeFailed {
		t.Fatalf("outcome %s err %v", outcome, err)
	}
	rec := r.channel().Payout
	if rec.Phase != PhaseFailed || rec.LastError == "" {
		t.Fatalf("record %+v", rec)
	}

	// The channel is untouched and a retry works once the RPC does.
	r.writer.FailWith = nil
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeSubmitted {
		t.Fatalf("retry: %v %v", outcome, err)
	}
}

// Submitted is not confirmed. The worker must not report a settlement because
// it managed to send something.
func TestSubmittedIsNotConfirmed(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	r.writer.Chain = nil // the chain does NOT move: the transaction is pending

	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeSubmitted {
		t.Fatalf("settle: %v %v", outcome, err)
	}
	if got := r.channel().Payout.Phase; got != PhaseSubmitted {
		t.Fatalf("phase %s, want submitted", got)
	}

	// A second pass still finds the chain Open, so it does not invent a
	// confirmation — it tries again, which is safe because the contract reverts
	// a duplicate.
	if outcome, _ := r.worker.Settle(ctx, r.id); outcome == OutcomeConfirmed {
		t.Fatal("a pending transaction was reported confirmed")
	}
}

// A settled channel is recognised however it got that way.
func TestAnAlreadySettledChannelIsNotResubmitted(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()

	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	// Somebody else closed it — the counterparty, or a previous run.
	r.chain.mu.Lock()
	occ := r.chain.Channels[r.id]
	occ.Status = StatusSettled
	r.chain.Channels[r.id] = occ
	r.chain.mu.Unlock()

	outcome, err := r.worker.Settle(ctx, r.id)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if outcome != OutcomeConfirmed {
		t.Fatalf("outcome %s", outcome)
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent for an already-settled channel", n)
	}
}

// A unilateral close in its window is not something to submit against.
func TestAClosingChannelIsLeftToItsWindow(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	r.chain.mu.Lock()
	occ := r.chain.Channels[r.id]
	occ.Status = StatusClosing
	r.chain.Channels[r.id] = occ
	r.chain.mu.Unlock()

	outcome, err := r.worker.Settle(ctx, r.id)
	if err != nil || outcome != OutcomeAwaitingWindow {
		t.Fatalf("outcome %s err %v", outcome, err)
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent during a challenge window", n)
	}
}

// ---- policy ------------------------------------------------------------------

func TestNothingHappensBeforeItIsDue(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	if err := r.worker.SetPolicy(r.id, PayoutPolicy{Mode: PayoutOnInterval, IntervalSeconds: 3600}); err != nil {
		t.Fatalf("policy: %v", err)
	}
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(50)}, r.peer)

	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeNotDue {
		t.Fatalf("outcome %s err %v", outcome, err)
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent before the interval elapsed", n)
	}
}

func TestAnUnusedChannelIsNotWorthGas(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	// Nothing was ever signed: the deposits are already where they belong.
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeNothingToDo {
		t.Fatalf("outcome %s err %v", outcome, err)
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent for an unused channel", n)
	}
}

// Closing needs locks resolved first — the contract refuses otherwise, and the
// worker should not spend gas discovering that.
func TestClosingRefusesWhileALockIsLive(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	r.agree(StateTransition{Kind: KindPay, Amount: anon(200)}, r.me)
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: r.clock + 9000,
	}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}

	outcome, err := r.worker.Settle(ctx, r.id)
	if outcome != OutcomeLocksPending || !errors.Is(err, ErrLocksUnresolved) {
		t.Fatalf("outcome %s err %v", outcome, err)
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent with a lock outstanding", n)
	}
}

// A checkpoint state cannot be used to close: the close paths sign zero
// withdrawals, so it would revert on chain.
func TestACheckpointStateIsNotAClose(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(75)}, r.peer)

	// Policy says close, but the latest state takes value out.
	if err := r.worker.SetPolicy(r.id, PayoutPolicy{Mode: PayoutOnClose}); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	outcome, err := r.worker.Settle(ctx, r.id)
	if outcome != OutcomeFailed || err == nil {
		t.Fatalf("outcome %s err %v", outcome, err)
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent for a state that would revert", n)
	}
}

// ---- collateral tracking -------------------------------------------------------

// After a checkpoint the deposits on chain are smaller. A node that did not
// notice would refuse every later payment as unconserved.
func TestCollateralFollowsTheChainAfterACheckpoint(t *testing.T) {
	r := newPayoutRig(t, 1000)
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(75)}, r.peer)

	// The chain applied it.
	r.setChainDeposits(anon(925), new(big.Int))
	r.refresh()

	ch := r.channel()
	total := new(big.Int).Add(ch.DepositA, ch.DepositB)
	if total.Cmp(anon(925)) != 0 {
		t.Fatalf("collateral %s, want the chain's 925", total)
	}

	// And the next ordinary payment conserves against the NEW collateral.
	next, err := (StateTransition{Kind: KindPay, Amount: anon(10)}).Apply(ch, r.me.address())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !next.Conserved(ch.DepositA, ch.DepositB) {
		t.Fatal("payments after a checkpoint do not conserve; collateral was not refreshed")
	}
	if err := r.store.Accept(r.id, signState(t, ch, next, r.me, r.peer)); err != nil {
		t.Fatalf("accept after checkpoint: %v", err)
	}
}

func TestRefreshRefusesFabricatedCollateral(t *testing.T) {
	r := newPayoutRig(t, 1000)
	// The same guard as adoption: a hand-built value has no chain marker.
	forged := OnChainChannel{ID: r.id, DepositA: anon(999999), Status: StatusOpen}
	if err := r.store.RefreshFromChain(forged); err != ErrNotFromChain {
		t.Fatalf("got %v, want ErrNotFromChain", err)
	}
}

// ---- calldata ------------------------------------------------------------------

// Frozen from the compiled ABI. A contract signature change must break here
// rather than at the first reverted settlement.
func TestSelectorsMatchTheCompiledContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"checkpoint", selCheckpoint, "2355a987"},
		{"closeCooperative", selCloseCooperative, "1bddaa55"},
		{"claimLock", selClaimLock, "9f19081b"},
		{"expireLock", selExpireLock, "bca59a10"},
	} {
		if hexOf(tc.got) != tc.want {
			t.Errorf("%s selector %s, want %s", tc.name, hexOf(tc.got), tc.want)
		}
	}
}

func TestCalldataRefusesAnUnsignedState(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ch := r.channel() // nothing signed yet
	if _, err := CheckpointCalldata(ch); err != ErrNothingToSubmit {
		t.Fatalf("checkpoint: got %v", err)
	}
	if _, err := CloseCooperativeCalldata(ch); err != ErrNothingToSubmit {
		t.Fatalf("close: got %v", err)
	}
}

func TestCloseCalldataRefusesOutstandingLocks(t *testing.T) {
	r := newPayoutRig(t, 1000)
	r.agree(StateTransition{Kind: KindPay, Amount: anon(200)}, r.me)
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: r.clock + 9000,
	}, r.me)
	if _, err := CloseCooperativeCalldata(r.channel()); err != ErrLocksUnresolved {
		t.Fatalf("got %v, want ErrLocksUnresolved", err)
	}
}

// ---- a pass over everything ------------------------------------------------------

func TestOnePassCoversEveryChannel(t *testing.T) {
	r := newPayoutRig(t, 1000)
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	report := r.worker.Pass(context.Background())
	if len(report) != 1 || report[r.id] != OutcomeSubmitted {
		t.Fatalf("report %v", report)
	}
}

// ---- resolving locks, then taking the money out -------------------------------
//
// Two paths, and they are not interchangeable:
//
//	cooperative   both parties co-sign LOCK_SETTLE / LOCK_REFUND. The lock
//	              resolves into balances off chain and no transaction happens.
//	force close   claimLock / expireLock against the contract, for when the
//	              counterparty is gone and the channel is closing unilaterally.
//
// These test the first, because it is the one every ordinary payment takes.

// LOCK_ADD → settle with the preimage → checkpoint. Value that arrived through
// a lock can be drawn down like any other.
func TestALockSettlesThenTheValueIsDrawnDown(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()
	if err := r.worker.SetPolicy(r.id, PayoutPolicy{Mode: PayoutOnInterval, IntervalSeconds: 3600}); err != nil {
		t.Fatalf("policy: %v", err)
	}

	var preimage [32]byte
	copy(preimage[:], []byte("a routed tip"))
	var hash [32]byte
	copy(hash[:], keccak(preimage[:]))

	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(120), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 9000,
	}, r.me)

	// The peer learned the secret; the settle is CO-SIGNED, not a transaction.
	r.agree(StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: preimage}, r.peer)

	st := r.channel().Latest.State
	if len(st.Pending) != 0 {
		t.Fatal("the lock survived its settlement")
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent to settle a lock cooperatively", n)
	}
	if got := r.channel().BalanceOf(r.peer.address()); got.Cmp(anon(120)) != 0 {
		t.Fatalf("peer holds %s after the lock settled, want 120", got)
	}

	// And now that value can be checkpointed out like any other.
	r.agree(StateTransition{Kind: KindCheckpoint, Amount: anon(120)}, r.peer)
	r.clock += 4000
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeSubmitted {
		t.Fatalf("checkpoint: %v %v", outcome, err)
	}
	calls := r.writer.Calls()
	if len(calls) != 1 || calls[0].Op != "checkpoint" {
		t.Fatalf("submitted %+v", calls)
	}
	// The channel stays open, so the lock → balance → chain journey did not
	// cost a close.
	r.setChainDeposits(anon(880), new(big.Int))
	r.refresh()
	if r.channel().Status != StatusOpen {
		t.Fatal("the channel closed")
	}
}

// LOCK_ADD → the expiry passes → refund → close. The payer gets it back and the
// channel can still be settled normally.
func TestALockRefundsThenTheChannelCloses(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()

	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(120), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: r.clock + 1000,
	}, r.me)

	// Nobody ever produced the secret. Past the expiry, the payer takes it back
	// — again co-signed, not submitted.
	r.clock += 2000
	r.agree(StateTransition{Kind: KindLockRefund, LockID: [32]byte{31: 1}}, r.me)

	if len(r.channel().Latest.State.Pending) != 0 {
		t.Fatal("the lock survived its refund")
	}
	if got := r.channel().BalanceOf(r.me.address()); got.Cmp(anon(1000)) != 0 {
		t.Fatalf("payer holds %s after a refund, want the whole 1000", got)
	}

	// A close now works, because nothing is outstanding.
	if err := r.worker.RequestClose(r.id); err != nil {
		t.Fatalf("request close: %v", err)
	}
	if outcome, err := r.worker.Settle(ctx, r.id); err != nil || outcome != OutcomeSubmitted {
		t.Fatalf("close: %v %v", outcome, err)
	}
	if calls := r.writer.Calls(); calls[len(calls)-1].Op != "closeCooperative" {
		t.Fatalf("submitted %+v", calls)
	}
}

// The force-close path: the counterparty is gone, so the locks are resolved
// against the CONTRACT rather than by agreement.
func TestResolveLocksGoesToTheChainWhenNobodyWillCoSign(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()

	var preimage [32]byte
	copy(preimage[:], []byte("known"))
	var hash [32]byte
	copy(hash[:], keccak(preimage[:]))

	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 9000,
	}, r.me)
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 2},
		Hash: [32]byte{31: 0xee}, Expiry: r.clock + 100,
	}, r.me)

	// One secret is known; the other lock has expired.
	r.clock += 500
	claimed, refunded, err := r.worker.ResolveLocks(ctx, r.id,
		map[[32]byte][32]byte{hash: preimage})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if claimed != 1 || refunded != 1 {
		t.Fatalf("claimed %d refunded %d, want 1 and 1", claimed, refunded)
	}

	ops := map[string]int{}
	for _, c := range r.writer.Calls() {
		ops[c.Op]++
	}
	if ops["claimLock"] != 1 || ops["expireLock"] != 1 {
		t.Fatalf("calls %v", ops)
	}
}

// A lock that is neither openable nor expired is somebody's live claim, and is
// left exactly where it is.
func TestALiveUnopenableLockIsLeftAlone(t *testing.T) {
	r := newPayoutRig(t, 1000)
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 0xaa}, Expiry: r.clock + 9000,
	}, r.me)

	claimed, refunded, err := r.worker.ResolveLocks(context.Background(), r.id, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if claimed != 0 || refunded != 0 {
		t.Fatalf("claimed %d refunded %d, want nothing touched", claimed, refunded)
	}
	if n := len(r.writer.Calls()); n != 0 {
		t.Fatalf("%d transactions sent against a live lock", n)
	}
}

// ---- the regression class the Clone bug belongs to ---------------------------

// Every money-bearing field must survive Clone independently of the original.
//
// Written to fail loudly when a NEW field is added and forgotten: the Payout
// field was added late and shared its pointer, which let Store.Update's trial
// mutate the live record before the write it was trialling had succeeded. Add a
// field, add it here.
func TestCloneSharesNothingMutable(t *testing.T) {
	r := newPayoutRig(t, 1000)
	r.agree(StateTransition{Kind: KindPay, Amount: anon(100)}, r.me)
	if err := r.worker.SetPolicy(r.id, PayoutPolicy{Mode: PayoutOnInterval, IntervalSeconds: 60}); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := r.store.Update(r.id, func(c *Channel) error {
		c.NoteSigned(99, [32]byte{1})
		c.NoteApplied([32]byte{2}, 1)
		c.Pending = &PendingProposal{Intent: [32]byte{3}, State: State{Nonce: 99}}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	live := r.channel()
	clone := live.Clone()

	// Mutate every mutable thing on the clone.
	clone.DepositA.SetInt64(1)
	clone.DepositB.SetInt64(1)
	clone.ChainID.SetInt64(999)
	clone.Latest.State.BalanceA.SetInt64(1)
	clone.Latest.State.Nonce = 4242
	clone.Signed[99] = [32]byte{0xff}
	clone.Applied[[32]byte{2}] = 4242
	clone.Pending.State.Nonce = 4242
	clone.Payout.Phase = PhaseConfirmed
	clone.Payout.DueAt = 4242

	again := r.channel()
	switch {
	case again.DepositA.Cmp(live.DepositA) != 0, again.DepositB.Cmp(live.DepositB) != 0:
		t.Fatal("deposits are shared")
	case again.ChainID.Cmp(big.NewInt(1)) != 0:
		t.Fatal("chain id is shared")
	case again.Latest.State.Nonce == 4242:
		t.Fatal("the latest state is shared")
	case again.Signed[99] == [32]byte{0xff}:
		t.Fatal("the signed-nonce ledger is shared")
	case again.Applied[[32]byte{2}] == 4242:
		t.Fatal("the applied-intent set is shared")
	case again.Pending != nil && again.Pending.State.Nonce == 4242:
		t.Fatal("the pending proposal is shared")
	case again.Payout != nil && (again.Payout.Phase == PhaseConfirmed || again.Payout.DueAt == 4242):
		t.Fatal("the payout record is shared")
	}
}
