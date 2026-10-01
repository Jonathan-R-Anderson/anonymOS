package channel

// P7-b. A → Hub → B, over real sockets, with the hub's money on the line.
//
// The tests are about the two ways a hub loses money and the fact that neither
// can happen: paid downstream and unable to claim upstream, or paid upstream
// without having paid downstream.

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// routedNode is one participant in a route.
type routedNode struct {
	t     *testing.T
	dir   string
	store *Store
	coord *Coordinator
	vault *PreimageVault
	fwd   *Forwarder
	key   *signer
	addr  string
	stop  func()
	clock int64
}

func newRoutedNode(t *testing.T, key *signer, chain *FakeChain, contract Address, clock int64) *routedNode {
	t.Helper()
	dir := t.TempDir()
	n := &routedNode{t: t, dir: dir, key: key, clock: clock}
	n.open(chain, contract)
	return n
}

// open (re)loads everything from disk — used for the restart tests too.
func (n *routedNode) open(chain *FakeChain, contract Address) {
	n.t.Helper()
	store, err := OpenStore(n.dir)
	if err != nil {
		n.t.Fatalf("OpenStore: %v", err)
	}
	vault, err := OpenPreimageVault(n.dir)
	if err != nil {
		n.t.Fatalf("OpenPreimageVault: %v", err)
	}
	coord := NewCoordinator(store, chain, big.NewInt(1), contract, n.key.address(),
		func(raw [32]byte) ([]byte, error) { return n.key.sign(raw), nil })
	coord.Session().SetClock(func() int64 { return n.clock }, 30, 60)
	coord.Session().SetPreimageVault(vault)
	coord.SetPreimageVault(vault)
	coord.SetClock(func() int64 { return n.clock })

	fwd := NewForwarder(coord, vault, n.key.address())
	fwd.SetClock(func() int64 { return n.clock }, 3600)

	n.store, n.coord, n.vault, n.fwd = store, coord, vault, fwd
}

func (n *routedNode) listen() {
	n.t.Helper()
	addr, stop := listening(n.t, n.coord)
	n.addr, n.stop = addr, stop
}

func (n *routedNode) restart(chain *FakeChain, contract Address) {
	n.t.Helper()
	if n.stop != nil {
		n.stop()
		n.stop = nil
	}
	n.open(chain, contract)
}

func (n *routedNode) balance(id [32]byte) *big.Int {
	n.t.Helper()
	ch, ok := n.coord.Channel(id)
	if !ok {
		n.t.Fatal("channel missing")
	}
	return ch.BalanceOf(n.key.address())
}

func (n *routedNode) locks(id [32]byte) []HTLC {
	n.t.Helper()
	ch, ok := n.coord.Channel(id)
	if !ok {
		n.t.Fatal("channel missing")
	}
	return ch.Latest.State.Pending
}

// route builds A → Hub → B with a funded channel on each leg.
type threeNodes struct {
	a, hub, b  *routedNode
	upstream   [32]byte // A ↔ Hub
	downstream [32]byte // Hub ↔ B
	chain      *FakeChain
	contract   Address
	clock      int64
}

func newRoute(t *testing.T, deposit int64) *threeNodes {
	t.Helper()
	const start = 1_000_000
	contract := mustAddr(t, deployedChannelManager)
	chain := NewFakeChain()

	ak, hk, bk := newSigner(t), newSigner(t), newSigner(t)
	upstream := chain.Add(ak.address(), hk.address(), anon(deposit), new(big.Int))
	downstream := chain.Add(hk.address(), bk.address(), anon(deposit), new(big.Int))

	r := &threeNodes{
		a:        newRoutedNode(t, ak, chain, contract, start),
		hub:      newRoutedNode(t, hk, chain, contract, start),
		b:        newRoutedNode(t, bk, chain, contract, start),
		upstream: upstream, downstream: downstream,
		chain: chain, contract: contract, clock: start,
	}
	for _, n := range []*routedNode{r.a, r.hub, r.b} {
		n.listen()
	}
	ctx := context.Background()
	for _, tc := range []struct {
		n  *routedNode
		id [32]byte
	}{{r.a, upstream}, {r.hub, upstream}, {r.hub, downstream}, {r.b, downstream}} {
		if err := tc.n.coord.Adopt(ctx, tc.id); err != nil {
			t.Fatalf("adopt: %v", err)
		}
	}
	return r
}

func (r *threeNodes) stop() {
	for _, n := range []*routedNode{r.a, r.hub, r.b} {
		if n.stop != nil {
			n.stop()
			n.stop = nil
		}
	}
}

func (r *threeNodes) advance(seconds int64) {
	r.clock += seconds
	for _, n := range []*routedNode{r.a, r.hub, r.b} {
		n.clock = r.clock
	}
}

func peerAt(n *routedNode) Peer { return NewStreamPeer(n.addr) }

func secret(word string) (preimage, hash [32]byte) {
	copy(preimage[:], word)
	copy(hash[:], keccak(preimage[:]))
	return
}

// ---- the happy path ------------------------------------------------------------

// A pays B through the hub, and the hub ends whole.
func TestAPaymentTravelsThroughAHubAndTheHubEndsWhole(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	preimage, hash := secret("the routed tip")

	hubBefore := r.hub.balance(r.upstream)

	// A locks 100 to the hub, expiring well out.
	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub lock: %v", err)
	}

	// The hub forwards it, on the same hash, expiring EARLIER.
	pending := r.hub.fwd.Pending()
	if len(pending) != 1 {
		t.Fatalf("hub sees %d incoming locks", len(pending))
	}
	if _, err := r.hub.fwd.Forward(ctx, pending[0], r.downstream, intent(2), peerAt(r.b)); err != nil {
		t.Fatalf("forward: %v", err)
	}
	out := r.hub.locks(r.downstream)
	if len(out) != 1 {
		t.Fatalf("%d outgoing locks", len(out))
	}
	if out[0].Expiry >= pending[0].Lock.Expiry {
		t.Fatalf("outgoing expiry %d is not earlier than incoming %d",
			out[0].Expiry, pending[0].Lock.Expiry)
	}

	// B settles downstream, revealing the secret.
	if _, err := r.b.coord.Pay(ctx, r.downstream, intent(3), StateTransition{
		Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: preimage,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("B settle: %v", err)
	}
	if got := r.b.balance(r.downstream); got.Cmp(anon(100)) != 0 {
		t.Fatalf("B holds %s, want 100", got)
	}

	// The hub learned the secret while signing, and can now claim upstream.
	if _, known := r.hub.vault.Lookup(hash); !known {
		t.Fatal("the hub did not remember the secret it just paid out on")
	}
	if problems := r.hub.fwd.SweepClaimable(ctx, func([32]byte) (Peer, error) {
		return peerAt(r.a), nil
	}); len(problems) != 0 {
		t.Fatalf("claiming upstream: %v", problems)
	}

	// Whole: it paid 100 downstream and recovered 100 upstream.
	hubAfter := r.hub.balance(r.upstream)
	gained := new(big.Int).Sub(hubAfter, hubBefore)
	if gained.Cmp(anon(100)) != 0 {
		t.Fatalf("the hub gained %s upstream after paying 100 downstream", gained)
	}
	if len(r.hub.locks(r.upstream)) != 0 || len(r.hub.locks(r.downstream)) != 0 {
		t.Fatal("locks are still outstanding after a completed route")
	}
}

// ---- the payment that never completes --------------------------------------------

// B never claims. Everything refunds, downstream first, and nobody is out of
// pocket.
func TestAnUnclaimedRouteRefundsBackwards(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("never revealed")

	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub lock: %v", err)
	}
	pending := r.hub.fwd.Pending()
	if _, err := r.hub.fwd.Forward(ctx, pending[0], r.downstream, intent(2), peerAt(r.b)); err != nil {
		t.Fatalf("forward: %v", err)
	}

	// Nobody ever produces the secret. Past the DOWNSTREAM expiry — and past the
	// skew margin both sides allow — the hub takes its outgoing lock back.
	r.advance(20000 - 3600 + 400)
	if problems := r.hub.fwd.RefundExpired(ctx, func([32]byte) (Peer, error) {
		return peerAt(r.b), nil
	}); len(problems) != 0 {
		t.Fatalf("hub refund: %v", problems)
	}
	if n := len(r.hub.locks(r.downstream)); n != 0 {
		t.Fatalf("%d downstream locks survived the refund", n)
	}
	// The hub's full downstream deposit is back where it started.
	if got := r.hub.balance(r.downstream); got.Cmp(anon(1000)) != 0 {
		t.Fatalf("hub downstream %s, want the whole 1000 back", got)
	}

	// Then A's lock expires and A takes that back.
	r.advance(4000)
	if problems := r.a.fwd.RefundExpired(ctx, func([32]byte) (Peer, error) {
		return peerAt(r.hub), nil
	}); len(problems) != 0 {
		t.Fatalf("A refund: %v", problems)
	}

	if n := len(r.a.locks(r.upstream)); n != 0 {
		t.Fatalf("%d upstream locks survived the refund", n)
	}
	if got := r.a.balance(r.upstream); got.Cmp(anon(1000)) != 0 {
		t.Fatalf("A holds %s, want the whole 1000 back", got)
	}
	// And the hub gained nothing from a payment that never happened.
	if got := r.hub.balance(r.upstream); got.Sign() != 0 {
		t.Fatalf("hub holds %s upstream after a failed route", got)
	}
}

// A hub that vanishes cannot strand the payer: the upstream lock expires and A
// recovers without the hub's cooperation being required to START the refund.
func TestAPayerRecoversWhenTheHubDisappears(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("into the void")

	aBefore := r.a.balance(r.upstream)
	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 5000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub lock: %v", err)
	}
	if got := r.a.balance(r.upstream); got.Cmp(aBefore) == 0 {
		t.Fatal("the lock did not take value out of A's balance")
	}

	// The hub goes away entirely — it is not even listening.
	r.hub.stop()
	r.hub.stop = nil

	r.advance(6000)
	problems := r.a.fwd.RefundExpired(ctx, func([32]byte) (Peer, error) {
		return peerAt(r.hub), nil
	})
	if len(problems) == 0 {
		t.Fatal("refunding against an absent hub reported success")
	}
	// A cannot finish the refund cooperatively, and the value is still locked —
	// which is exactly when the on-chain path exists. What must be true is that
	// A's position is RECOVERABLE: the lock is expired, so expireLock on chain
	// returns it, and the state proving that is the one A holds.
	locks := r.a.locks(r.upstream)
	if len(locks) != 1 {
		t.Fatalf("%d locks held", len(locks))
	}
	if locks[0].Expiry > r.a.clock {
		t.Fatal("the lock has not expired, so nothing is recoverable yet")
	}
	held, ok := r.a.coord.Channel(r.upstream)
	if !ok || !held.Latest.Complete() {
		t.Fatal("A holds no fully signed state to force-close with")
	}
}

// ---- the hub's own safety ---------------------------------------------------------

// The margin is not a courtesy. A hub must refuse to forward when the incoming
// lock does not outlive the outgoing one by enough to claim in.
func TestAHubRefusesToForwardWithoutMargin(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("too tight")

	// An incoming lock expiring inside the hub's margin.
	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 600,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub lock: %v", err)
	}
	pending := r.hub.fwd.Pending()
	if len(pending) != 1 {
		t.Fatalf("hub sees %d incoming", len(pending))
	}
	_, err := r.hub.fwd.Forward(ctx, pending[0], r.downstream, intent(2), peerAt(r.b))
	if !errors.Is(err, ErrNoMargin) {
		t.Fatalf("got %v, want ErrNoMargin", err)
	}
	if len(r.hub.locks(r.downstream)) != 0 {
		t.Fatal("the hub created a downstream obligation it could not recover")
	}
}

// A hub cannot forward against a lock it put up itself.
func TestAHubWillNotForwardItsOwnLock(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("mine")

	if _, err := r.hub.coord.Pay(ctx, r.downstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 9},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.b)); err != nil {
		t.Fatalf("hub lock: %v", err)
	}
	// Its own outgoing lock must not appear as something to forward.
	for _, in := range r.hub.fwd.Pending() {
		if in.Lock.ID == [32]byte{31: 9} {
			t.Fatal("the hub listed its own outgoing lock as incoming")
		}
	}
}

// Claiming without the secret is refused locally rather than proposed and
// rejected.
func TestClaimingWithoutTheSecretIsRefused(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("unknown to the hub")

	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub lock: %v", err)
	}
	pending := r.hub.fwd.Pending()
	if _, err := r.hub.fwd.ClaimUpstream(ctx, pending[0], intent(5), peerAt(r.a)); !errors.Is(err, ErrSecretUnknown) {
		t.Fatalf("got %v, want ErrSecretUnknown", err)
	}
}

// A lock this node can open is claimable, not refundable — taking it back would
// reclaim a payment that has in effect happened.
func TestAnOpenableLockIsNotRefunded(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	preimage, hash := secret("known")

	if _, err := r.hub.coord.Pay(ctx, r.downstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 1000,
	}, peerAt(r.b)); err != nil {
		t.Fatalf("hub lock: %v", err)
	}
	if err := r.hub.vault.Learn(preimage); err != nil {
		t.Fatalf("learn: %v", err)
	}

	r.advance(2000)
	problems := r.hub.fwd.RefundExpired(ctx, func([32]byte) (Peer, error) { return peerAt(r.b), nil })
	if len(problems) != 0 {
		t.Fatalf("refund reported problems: %v", problems)
	}
	if len(r.hub.locks(r.downstream)) != 1 {
		t.Fatal("an openable lock was refunded out from under its payee")
	}
}

// ---- the crash that would cost real money ------------------------------------------

// THE ONE. The hub learns a secret by paying downstream, then dies. On restart
// the secret must still be there, or it has paid and cannot collect.
func TestAPreimageSurvivesACrashBetweenPayingAndClaiming(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	preimage, hash := secret("worth remembering")

	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub lock: %v", err)
	}
	pending := r.hub.fwd.Pending()
	if _, err := r.hub.fwd.Forward(ctx, pending[0], r.downstream, intent(2), peerAt(r.b)); err != nil {
		t.Fatalf("forward: %v", err)
	}

	// B takes the money. The hub signs, and dies immediately after.
	if _, err := r.b.coord.Pay(ctx, r.downstream, intent(3), StateTransition{
		Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: preimage,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("B settle: %v", err)
	}
	hubPaid := r.hub.balance(r.downstream)

	r.hub.restart(r.chain, r.contract)
	r.hub.listen()

	// The secret came back from disk.
	if _, known := r.hub.vault.Lookup(hash); !known {
		t.Fatal("the hub forgot the secret it had already paid for")
	}
	// And it is still down the money it paid, so the claim matters.
	if got := r.hub.balance(r.downstream); got.Cmp(hubPaid) != 0 {
		t.Fatalf("downstream balance changed across the restart: %s vs %s", got, hubPaid)
	}

	// It finishes the job it did not know it had started.
	if problems := r.hub.fwd.SweepClaimable(ctx, func([32]byte) (Peer, error) {
		return peerAt(r.a), nil
	}); len(problems) != 0 {
		t.Fatalf("sweeping after restart: %v", problems)
	}
	if len(r.hub.locks(r.upstream)) != 0 {
		t.Fatal("the upstream lock is still outstanding after the sweep")
	}
}

// The vault refuses to load a record that does not hash to its own key — a
// corrupted secret is worse than a missing one, because it produces a claim the
// contract rejects at the moment it is needed.
func TestACorruptVaultStopsTheNode(t *testing.T) {
	dir := t.TempDir()
	v, err := OpenPreimageVault(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	preimage, _ := secret("genuine")
	if err := v.Learn(preimage); err != nil {
		t.Fatalf("learn: %v", err)
	}

	path := filepath.Join(dir, "preimages.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Flip a byte of the stored SECRET so it no longer hashes to its key.
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k, v := range stored {
		stored[k] = "ff" + v[2:]
	}
	edited, _ := json.Marshal(stored)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := OpenPreimageVault(dir); err == nil {
		t.Fatal("the node started with a preimage that does not match its hash")
	}
}

// ---- what an operator sees while a payment is in flight (P7-c) -----------------
//
// Driven through the REAL routing engine rather than injected records: a lock
// appears because a payment created it, and disappears because that payment
// resolved. Two independently-built representations of HTLC state would agree
// in tests and diverge in production.

func TestALockAppearsAndResolvesInTheOperatorView(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	preimage, hash := secret("visible")

	// Before anything, B has nothing and nothing pending.
	before, err := r.b.coord.Exposure(r.downstream)
	if err != nil {
		t.Fatalf("exposure: %v", err)
	}
	if before.Available != "0" || before.Incoming != "0" {
		t.Fatalf("B starts at %+v", before)
	}

	// A pays B through the hub. The lock reaches B.
	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub: %v", err)
	}
	pending := r.hub.fwd.Pending()
	if _, err := r.hub.fwd.Forward(ctx, pending[0], r.downstream, intent(2), peerAt(r.b)); err != nil {
		t.Fatalf("forward: %v", err)
	}

	// B sees value in flight — and it is NOT in the available balance.
	locks, err := r.b.coord.Locks(r.downstream)
	if err != nil {
		t.Fatalf("locks: %v", err)
	}
	if len(locks) != 1 {
		t.Fatalf("B sees %d locks", len(locks))
	}
	if !locks[0].Incoming || locks[0].Status != LockWaiting {
		t.Fatalf("B sees %+v, want an incoming lock waiting", locks[0])
	}
	if locks[0].ExpiresIn <= 0 {
		t.Fatalf("expiry reported as %ds away", locks[0].ExpiresIn)
	}

	inflight, _ := r.b.coord.Exposure(r.downstream)
	if inflight.Available != "0" {
		t.Fatalf("a lock inflated B's available balance to %s", inflight.Available)
	}
	if inflight.Incoming != anon(100).String() {
		t.Fatalf("incoming %s, want 100", inflight.Incoming)
	}
	if inflight.Total != anon(100).String() {
		t.Fatalf("total exposure %s, want 100", inflight.Total)
	}

	// The hub's view of the SAME payment is the mirror image: its own money out.
	hubLocks, _ := r.hub.coord.Locks(r.downstream)
	if len(hubLocks) != 1 || hubLocks[0].Incoming || hubLocks[0].Status != LockOffered {
		t.Fatalf("the hub sees %+v, want its own outgoing offer", hubLocks)
	}
	hubExp, _ := r.hub.coord.Exposure(r.downstream)
	if hubExp.Outgoing != anon(100).String() {
		t.Fatalf("hub outgoing %s, want 100 of its own at risk", hubExp.Outgoing)
	}

	// B settles. The lock leaves the pending view and the value becomes real.
	if _, err := r.b.coord.Pay(ctx, r.downstream, intent(3), StateTransition{
		Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: preimage,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("B settle: %v", err)
	}
	after, _ := r.b.coord.Exposure(r.downstream)
	if after.Available != anon(100).String() {
		t.Fatalf("available %s after settling, want 100", after.Available)
	}
	if after.Incoming != "0" {
		t.Fatalf("incoming %s after settling, want nothing left in flight", after.Incoming)
	}
	settled, _ := r.b.coord.Locks(r.downstream)
	if len(settled) != 0 {
		t.Fatalf("%d locks still shown after settlement", len(settled))
	}
}

// The other ending: nobody settles, the lock expires, and the view says so
// before the refund and stops saying it afterwards.
func TestAnExpiringLockIsShownAsRecoverableThenDisappears(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("never claimed")

	if _, err := r.hub.coord.Pay(ctx, r.downstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 5000,
	}, peerAt(r.b)); err != nil {
		t.Fatalf("lock: %v", err)
	}

	// Live: the hub's own money, offered.
	live, _ := r.hub.coord.Locks(r.downstream)
	if len(live) != 1 || live[0].Status != LockOffered {
		t.Fatalf("%+v, want offered", live)
	}
	// And B, on the other side, is waiting for a secret nobody has.
	waiting, _ := r.b.coord.Locks(r.downstream)
	if len(waiting) != 1 || waiting[0].Status != LockWaiting {
		t.Fatalf("%+v, want waiting", waiting)
	}

	// Past the expiry the same lock reads differently on each side: recoverable
	// to the payer, lost to the payee.
	r.advance(6000)
	expired, _ := r.hub.coord.Locks(r.downstream)
	if expired[0].Status != LockRefundable {
		t.Fatalf("payer sees %s, want refundable", expired[0].Status)
	}
	if expired[0].ExpiresIn >= 0 {
		t.Fatalf("ExpiresIn %d, want negative once past", expired[0].ExpiresIn)
	}
	lapsed, _ := r.b.coord.Locks(r.downstream)
	if lapsed[0].Status != LockLapsed {
		t.Fatalf("payee sees %s, want lapsed", lapsed[0].Status)
	}

	// The refund clears it, and the value comes back to available.
	if problems := r.hub.fwd.RefundExpired(ctx, func([32]byte) (Peer, error) {
		return peerAt(r.b), nil
	}); len(problems) != 0 {
		t.Fatalf("refund: %v", problems)
	}
	gone, _ := r.hub.coord.Locks(r.downstream)
	if len(gone) != 0 {
		t.Fatalf("%d locks after the refund", len(gone))
	}
	exp, _ := r.hub.coord.Exposure(r.downstream)
	if exp.Available != anon(1000).String() || exp.Outgoing != "0" {
		t.Fatalf("after refund %+v, want the whole 1000 available and nothing at risk", exp)
	}
}

// A hub mid-route holds a secret it has paid for. Its upstream lock reads
// claimable and its downstream one reads settling — the same secret, opposite
// meanings, which is the pair an operator most needs to understand.
func TestAHubMidRouteSeesBothSidesOfOneSecret(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	preimage, hash := secret("both sides")

	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub: %v", err)
	}
	pending := r.hub.fwd.Pending()
	if _, err := r.hub.fwd.Forward(ctx, pending[0], r.downstream, intent(2), peerAt(r.b)); err != nil {
		t.Fatalf("forward: %v", err)
	}
	// The hub learns the secret the only way it can: by paying downstream.
	if err := r.hub.vault.Learn(preimage); err != nil {
		t.Fatalf("learn: %v", err)
	}

	up, _ := r.hub.coord.Locks(r.upstream)
	if len(up) != 1 || up[0].Status != LockClaimable {
		t.Fatalf("upstream %+v, want claimable", up)
	}
	down, _ := r.hub.coord.Locks(r.downstream)
	if len(down) != 1 || down[0].Status != LockSettling {
		t.Fatalf("downstream %+v, want settling", down)
	}
}

// A node with no vault cannot claim anything, and says so rather than implying
// it could.
func TestWithoutAVaultNothingReadsAsClaimable(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("unknowable")

	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("lock: %v", err)
	}
	r.hub.coord.SetPreimageVault(nil)
	locks, _ := r.hub.coord.Locks(r.upstream)
	if len(locks) != 1 || locks[0].Status != LockWaiting {
		t.Fatalf("%+v, want waiting without a vault", locks)
	}
}
