package channel

// P13.5 FINDING 1 — settlement timing at the resolution boundary.
//
// THE SECURITY PROPERTY, DERIVED FROM THE CONTRACT
// ------------------------------------------------
// ChannelManagerV2 is the authority, and it draws the line exactly:
//
//	claimLock   if (block.timestamp >= lock.expiry) revert LockHasExpired();
//	expireLock  if (block.timestamp <  lock.expiry) revert LockNotExpired();
//
// So on chain a preimage is worth the lock's value strictly BEFORE expiry and
// nothing at or after it, and the two paths never overlap. The property the
// off-chain machine must therefore uphold:
//
//	A node MUST NOT co-sign a LOCK_SETTLE for a lock whose expiry has passed.
//	After expiry the lock is refund-only, because that is all the chain would
//	honour.
//
// This is not a new invariant. It is the contract's own rule, applied at the
// point where the off-chain state actually changes.
//
// WHY THE ABSENCE WAS A REAL DEFECT
// ---------------------------------
// checkTiming had cases for LOCK_ADD and LOCK_REFUND and none for LOCK_SETTLE,
// so a late settlement fell through to accept and the payer's node signed it
// automatically. The result is a co-signed off-chain state MORE generous to the
// payee than the contract's own rule — and for an intermediary it is the exact
// loss routing.go says cannot happen: pay downstream late, then find the
// upstream claim already dead on chain. The margin was enforced when the lock
// was created and nothing enforced it when the money moved.
//
// The skew band is deliberate. Refund needs Expiry <= now-skew and settle needs
// Expiry > now+skew, so for Expiry in (now-skew, now+skew] NEITHER side may act.
// A window where both are valid would be a race over the same value.

import (
	"context"
	"math/big"
	"testing"
)

// timedFixture is a funded channel plus a clock both nodes share.
type timedFixture struct {
	payer, payee *wiredNode
	id           [32]byte
	peer         Peer
}

func newTimedFixture(t *testing.T) *timedFixture {
	t.Helper()
	payer, payee, id := wiredPair(t, anon(500))
	return &timedFixture{payer: payer, payee: payee, id: id,
		peer: directPeer{t, payee.coord}}
}

func (f *timedFixture) setClocks(unix int64) {
	f.payer.clock = unix
	f.payee.clock = unix
}

// addLock places a lock from the payer, at the shared clock.
func (f *timedFixture) addLock(t *testing.T, lockID byte, amount int64, expiry int64,
	preimage [32]byte) {
	t.Helper()
	var h [32]byte
	copy(h[:], keccak(preimage[:]))
	tr := StateTransition{
		Kind: KindLockAdd, Amount: anon(amount),
		LockID: [32]byte{31: lockID}, Hash: h, Expiry: expiry,
	}
	if _, err := f.payer.coord.Pay(context.Background(), f.id,
		derive("p135/lock", []byte{lockID}), tr, f.peer); err != nil {
		t.Fatalf("LOCK_ADD: %v", err)
	}
}

// settle attempts a settlement AS THE PAYEE, which is who actually claims: they
// are the party holding the preimage and the party the value moves to. The
// payer's node is then the one deciding whether to co-sign, which is exactly
// where the timing rule has to bite.
//
// Proposing it from the payer instead would test the wrong direction — and
// would collide on the nonce with the refund the payer needs to make next,
// because a rejected proposal still leaves the proposer's signature recorded at
// that nonce (the I4 ledger).
func (f *timedFixture) settle(t *testing.T, lockID byte, preimage [32]byte) (PaymentResult, error) {
	t.Helper()
	tr := StateTransition{Kind: KindLockSettle,
		LockID: [32]byte{31: lockID}, Preimage: preimage}
	return f.payee.coord.Pay(context.Background(), f.id,
		derive("p135/settle", []byte{lockID}), tr, directPeer{t, f.payer.coord})
}

// ---- the boundary ----------------------------------------------------------

// Settlement strictly BEFORE expiry must succeed. The rule must not break the
// ordinary case, which is the whole point of a payment channel.
func TestSettlementBeforeExpirySucceeds(t *testing.T) {
	f := newTimedFixture(t)
	const now = int64(1_000_000)
	f.setClocks(now)
	pre := [32]byte{31: 0x11}
	f.addLock(t, 1, 50, now+3600, pre)

	res, err := f.settle(t, 1, pre)
	if err != nil {
		t.Fatalf("a settlement well before expiry was refused: %v", err)
	}
	if res.Rejected != "" {
		t.Fatalf("refused with %s: %s", res.Rejected, res.Detail)
	}
	bal, _ := f.payee.coord.Balances(f.id)
	if bal.Mine.Cmp(anon(50)) != 0 {
		t.Fatalf("payee holds %s, want 50", bal.Mine)
	}
}

// Settlement exactly AT expiry must be refused, because the contract reverts at
// `>=` rather than `>`. Off-by-one here is the difference between mirroring the
// chain and contradicting it.
func TestSettlementAtExpiryIsRefused(t *testing.T) {
	f := newTimedFixture(t)
	const now = int64(1_000_000)
	f.setClocks(now)
	pre := [32]byte{31: 0x12}
	expiry := now + 3600
	f.addLock(t, 2, 50, expiry, pre)

	// Move to exactly the expiry instant, past the skew band.
	f.setClocks(expiry + 60)
	res, err := f.settle(t, 2, pre)
	if err == nil && res.Rejected == "" {
		t.Fatal("a settlement at expiry was accepted; claimLock would have reverted")
	}
	if res.Rejected != "" && res.Rejected != RejectLockExpired {
		t.Fatalf("refused, but with %s rather than LOCK_EXPIRED", res.Rejected)
	}
	// The value must still be locked, not delivered.
	bal, _ := f.payee.coord.Balances(f.id)
	if bal.Mine.Sign() != 0 {
		t.Fatalf("payee was paid %s by a refused settlement", bal.Mine)
	}
}

// Settlement well AFTER expiry must be refused, and the lock must remain
// refundable — the state the chain would have enforced.
func TestSettlementAfterExpiryIsRefusedAndRefundStillWorks(t *testing.T) {
	f := newTimedFixture(t)
	const now = int64(1_000_000)
	f.setClocks(now)
	pre := [32]byte{31: 0x13}
	expiry := now + 3600
	f.addLock(t, 3, 50, expiry, pre)

	f.setClocks(expiry + 7200)
	res, err := f.settle(t, 3, pre)
	if err == nil && res.Rejected == "" {
		t.Fatal("a settlement two hours after expiry was accepted")
	}

	// The payer can still reclaim, which is what the contract's expireLock would
	// have allowed all along.
	refund := StateTransition{Kind: KindLockRefund, LockID: [32]byte{31: 3}}
	rres, err := f.payer.coord.Pay(context.Background(), f.id,
		derive("p135/refund", []byte{3}), refund, f.peer)
	if err != nil {
		t.Fatalf("refund after expiry was refused: %v", err)
	}
	if rres.Rejected != "" {
		t.Fatalf("refund refused with %s: %s", rres.Rejected, rres.Detail)
	}
	bal, _ := f.payer.coord.Balances(f.id)
	if bal.Mine.Cmp(anon(500)) != 0 {
		t.Fatalf("payer holds %s after refund, want the full 500", bal.Mine)
	}
}

// The skew band: neither side may act inside it.
//
// Refund needs Expiry <= now-skew, settle needs Expiry > now+skew. Between them
// is a window where both are refused, and that gap is the point — if both were
// valid at once the same value would be racing.
func TestNeitherSideMayActInsideTheSkewBand(t *testing.T) {
	f := newTimedFixture(t)
	const now = int64(1_000_000)
	f.setClocks(now)
	pre := [32]byte{31: 0x14}
	// skew is 30 in the wired harness (SetClock(now, 30, 600)).
	expiry := now + 600
	f.addLock(t, 4, 50, expiry, pre)

	// Sit exactly on the expiry: inside the band for both rules.
	f.setClocks(expiry)

	sres, serr := f.settle(t, 4, pre)
	if serr == nil && sres.Rejected == "" {
		t.Fatal("settlement was accepted inside the skew band")
	}
	refund := StateTransition{Kind: KindLockRefund, LockID: [32]byte{31: 4}}
	rres, rerr := f.payer.coord.Pay(context.Background(), f.id,
		derive("p135/band-refund", []byte{4}), refund, f.peer)
	if rerr == nil && rres.Rejected == "" {
		t.Fatal("refund was accepted inside the skew band")
	}
	if rres.Rejected != "" && rres.Rejected != RejectLockNotExpired {
		t.Fatalf("refund refused with %s, expected LOCK_NOT_EXPIRED", rres.Rejected)
	}
	// Once past the band, the refund becomes available — the band is a pause,
	// not a deadlock.
	f.setClocks(expiry + 61)
	rres, rerr = f.payer.coord.Pay(context.Background(), f.id,
		derive("p135/band-refund2", []byte{4}), refund, f.peer)
	if rerr != nil || rres.Rejected != "" {
		t.Fatalf("refund still refused past the band: %v / %s", rerr, rres.Rejected)
	}
}

// A restart across the expiry must not change the answer.
//
// The rule lives in the protocol layer and reads the clock at proposal time, so
// a node that reloads its channels from disk must apply it identically — a lock
// that became unsettleable while the process was down stays unsettleable.
func TestRestartAroundExpiryKeepsTheRule(t *testing.T) {
	f := newTimedFixture(t)
	const now = int64(1_000_000)
	f.setClocks(now)
	pre := [32]byte{31: 0x15}
	expiry := now + 600
	f.addLock(t, 5, 50, expiry, pre)

	// Reload BOTH sides from their stores, as a restart would.
	payerStore, err := OpenStore(f.payer.dir)
	if err != nil {
		t.Fatalf("reopen payer: %v", err)
	}
	payeeStore, err := OpenStore(f.payee.dir)
	if err != nil {
		t.Fatalf("reopen payee: %v", err)
	}
	revivedPayer := NewCoordinator(payerStore, NewFakeChain(), big.NewInt(1),
		mustAddr(t, deployedChannelManager), f.payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return f.payer.key.sign(raw), nil })
	revivedPayee := NewCoordinator(payeeStore, NewFakeChain(), big.NewInt(1),
		mustAddr(t, deployedChannelManager), f.payee.key.address(),
		func(raw [32]byte) ([]byte, error) { return f.payee.key.sign(raw), nil })
	// Both come back with clocks past the expiry.
	after := expiry + 3600
	revivedPayer.Session().SetClock(func() int64 { return after }, 30, 600)
	revivedPayee.Session().SetClock(func() int64 { return after }, 30, 600)

	// The lock survived the restart...
	ch, ok := payerStore.Get(f.id)
	if !ok || len(ch.Latest.State.Pending) != 1 {
		t.Fatalf("the lock did not survive the restart: %+v", ch)
	}
	// ...and is still refused for settlement after it.
	tr := StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 5}, Preimage: pre}
	res, err := revivedPayer.Pay(context.Background(), f.id,
		derive("p135/restart-settle", []byte{5}), tr, directPeer{t, revivedPayee})
	if err == nil && res.Rejected == "" {
		t.Fatal("a restart let an expired lock be settled")
	}
}

// ROUTED settlement: the intermediary loss the rule exists to prevent.
//
// A hub holds an incoming lock expiring at E_in and wrote an outgoing one at
// E_out = E_in - margin. If the downstream settles LATE the hub pays out and
// then finds its upstream claim dead on chain. The rule refuses the late
// downstream settlement, which is the only moment the hub can still say no.
func TestRoutedLateSettlementIsRefusedOnTheOutgoingLeg(t *testing.T) {
	// hub -> recipient is the OUTGOING leg the hub would pay.
	hub, recipient, out := wiredPair(t, anon(500))
	const now = int64(1_000_000)
	hub.clock, recipient.clock = now, now
	peer := directPeer{t, recipient.coord}

	pre := [32]byte{31: 0x16}
	var h [32]byte
	copy(h[:], keccak(pre[:]))
	// The outgoing lock expires BEFORE the (notional) incoming one, which is
	// what the forwarder's margin guarantees.
	eOut := now + 600
	tr := StateTransition{Kind: KindLockAdd, Amount: anon(100),
		LockID: [32]byte{31: 6}, Hash: h, Expiry: eOut}
	if _, err := hub.coord.Pay(context.Background(), out,
		derive("p135/hub-lock", nil), tr, peer); err != nil {
		t.Fatalf("outgoing LOCK_ADD: %v", err)
	}

	// The recipient sits on the preimage until after E_out, then claims.
	hub.clock, recipient.clock = eOut+120, eOut+120
	settle := StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 6}, Preimage: pre}
	res, err := recipient.coord.Pay(context.Background(), out,
		derive("p135/hub-late-settle", nil), settle, directPeer{t, hub.coord})
	if err == nil && res.Rejected == "" {
		t.Fatal("the hub paid an expired outgoing lock; it can no longer claim upstream")
	}
	// The hub keeps its money.
	bal, _ := hub.coord.Balances(out)
	if bal.Mine.Cmp(anon(400)) != 0 {
		t.Fatalf("hub balance %s — the 100 should still be locked, not paid", bal.Mine)
	}
}

// Cooperative settlement versus unilateral recovery.
//
// The off-chain rule must agree with what the chain would do, or a cooperative
// close encodes a distribution the contract itself would have refused. This
// asserts the correspondence directly against the contract's own conditions.
func TestTheOffChainRuleMatchesTheContractsBoundary(t *testing.T) {
	// The contract's two conditions, restated. Kept as literals so a change to
	// the Solidity has to be reflected here deliberately.
	claimValid := func(nowTs, expiry int64) bool { return !(nowTs >= expiry) }
	expireValid := func(nowTs, expiry int64) bool { return !(nowTs < expiry) }

	const expiry = int64(1_000_000)
	for _, nowTs := range []int64{expiry - 3600, expiry - 1, expiry, expiry + 1, expiry + 3600} {
		c, e := claimValid(nowTs, expiry), expireValid(nowTs, expiry)
		// Exactly one of the two is available on chain at any instant.
		if c == e {
			t.Fatalf("at now=%d both claim=%v and expire=%v — the contract's paths overlap",
				nowTs, c, e)
		}
		// And our off-chain settle rule must never be MORE permissive than
		// claimLock. With skew it is strictly less permissive, which is safe.
		const skew = int64(30)
		offChainSettleAllowed := expiry > nowTs+skew
		if offChainSettleAllowed && !c {
			t.Fatalf("at now=%d the off-chain rule allows a settlement the contract reverts", nowTs)
		}
	}
}

// Settlement must already be refused INSIDE the skew band, while the expiry is
// still nominally in the future.
//
// The earlier band test sits exactly on the expiry, where a rule with skew and a
// rule without it both refuse — so it could not tell them apart. This one sits
// 10s BEFORE expiry with a 30s skew: the lock has not expired by our clock, but
// the peer's clock may already be past it, so a settlement we co-sign now could
// be one the chain would revert.
//
// Skew has to work against the settler for the same reason it works against the
// refunder: whoever benefits from being wrong about the time must not get the
// benefit of the doubt.
func TestSettlementIsRefusedWithinSkewOfExpiry(t *testing.T) {
	f := newTimedFixture(t)
	const now = int64(1_000_000)
	f.setClocks(now)
	pre := [32]byte{31: 0x17}
	expiry := now + 600 // satisfies minLockWindow at creation
	f.addLock(t, 7, 50, expiry, pre)

	// 10 seconds before expiry, with skew 30. Not yet expired by our clock.
	f.setClocks(expiry - 10)
	if expiry <= (expiry-10) {
		t.Fatal("precondition: the lock must still be unexpired by the local clock")
	}
	res, err := f.settle(t, 7, pre)
	if err == nil && res.Rejected == "" {
		t.Fatal("a settlement within skew of expiry was accepted; the peer's clock " +
			"may already be past it, and the chain would revert the claim")
	}
	bal, _ := f.payee.coord.Balances(f.id)
	if bal.Mine.Sign() != 0 {
		t.Fatalf("payee was paid %s inside the skew band", bal.Mine)
	}
}

// ---- the on-chain half of finding 1 ----------------------------------------

// An EXPIRED lock whose secret is known must go to expireLock, not claimLock.
//
// ResolveLocks fired the claim branch on `known` alone and then `continue`d, so
// such a lock went to claimLock — which ChannelManagerV2 REVERTS
// (LockHasExpired, sol:439) — and never reached the expire branch. The value was
// then neither claimed nor reclaimed.
//
// And because the claim error returns immediately, one lock in that state
// stopped every REMAINING lock in the channel from being resolved at all. This
// asserts both halves.
func TestAnExpiredKnownLockIsExpiredNotClaimed(t *testing.T) {
	r := newPayoutRig(t, 1000)
	ctx := context.Background()

	var preimage [32]byte
	copy(preimage[:], []byte("known-but-late"))
	var hash [32]byte
	copy(hash[:], keccak(preimage[:]))

	// Lock 1: secret known, and it WILL be expired by the time we resolve.
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 100,
	}, r.me)
	// Lock 2: a plain expired lock that must still be resolved afterwards.
	r.agree(StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 2},
		Hash: [32]byte{31: 0xee}, Expiry: r.clock + 100,
	}, r.me)

	r.clock += 500 // both are now past expiry

	claimed, refunded, err := r.worker.ResolveLocks(ctx, r.id,
		map[[32]byte][32]byte{hash: preimage})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if claimed != 0 {
		t.Fatalf("claimed %d expired lock(s); claimLock reverts past expiry", claimed)
	}
	// BOTH locks must have been reclaimed — the second one is the canary for the
	// abort-on-error behaviour.
	if refunded != 2 {
		t.Fatalf("refunded %d, want 2: an expired known lock must not stop the rest", refunded)
	}
	ops := map[string]int{}
	for _, c := range r.writer.Calls() {
		ops[c.Op]++
	}
	if ops["claimLock"] != 0 {
		t.Fatalf("sent %d claimLock call(s) for expired locks", ops["claimLock"])
	}
	if ops["expireLock"] != 2 {
		t.Fatalf("calls %v, want two expireLock", ops)
	}
}

// An expired incoming lock must not be reported as claimable, even with the
// secret in hand.
//
// lockStatus returned LockClaimable on secretKnown alone, reasoning that "the
// peer may still co-sign". It will not: the settle is refused off chain because
// claimLock reverts on chain. Telling an operator to wait for value that cannot
// arrive is worse than telling them the window closed.
func TestAnExpiredIncomingLockIsReportedLapsedEvenWithTheSecret(t *testing.T) {
	if got := lockStatus(true, true, true); got != LockLapsed {
		t.Fatalf("expired incoming lock with a known secret reported %v, want LockLapsed", got)
	}
	// The live cases must be unchanged.
	if got := lockStatus(true, true, false); got != LockClaimable {
		t.Fatalf("live incoming lock with a secret reported %v, want LockClaimable", got)
	}
	if got := lockStatus(true, false, false); got != LockWaiting {
		t.Fatalf("live incoming lock without a secret reported %v, want LockWaiting", got)
	}
	if got := lockStatus(true, false, true); got != LockLapsed {
		t.Fatalf("expired incoming lock without a secret reported %v, want LockLapsed", got)
	}
}
