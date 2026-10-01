package channel

// P13.5 FINDING 2 — the "misblinded hop", and why it is not the vulnerability
// it looked like.
//
// THE CLAIM
// ---------
// "The payer picks the route and holds every blinding; SettleRoute computes all
// hops' scalars at once, so nothing makes a hop's scalar contingent on a
// downstream payment actually happening."
//
// Every clause of that is TRUE about SettleRoute. The conclusion does not
// follow, because SettleRoute is not on the production path.
//
// WHAT ACTUALLY HAPPENS
// ---------------------
// A hop claims upstream through Forwarder.ClaimUpstream (routing.go), which
// does exactly one thing to obtain its authorisation:
//
//	preimage, known := f.vault.Lookup(in.Lock.Hash)
//	if !known { return ErrSecretUnknown }
//
// A HASH PREIMAGE, from the vault, keyed by the incoming lock's own hash. Not a
// scalar, not a blinding, nothing derived from BuildLocks. And the vault learns
// that preimage when the DOWNSTREAM settlement reveals it. So the hop's upstream
// claim is contingent on the downstream payment by construction: without the
// downstream reveal there is no preimage, and without the preimage
// ClaimUpstream refuses before it ever reaches the channel.
//
// The point-based LockChain is adaptor machinery for a routing design that is
// built but not wired in. It is real code with real tests and no production
// caller, which is precisely why it reads as dangerous — an audit sees
// SettleRoute handing out every hop's scalar and cannot tell from the function
// alone that nobody calls it.
//
// So this file does what the finding asks when a design turns out to be safe:
// it documents why, and pins the property with regression tests, so that wiring
// SettleRoute into the claim path later has to break something first.

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The production claim path must not depend on the adaptor-scalar machinery.
//
// This is the load-bearing fact of the whole finding. If SettleRoute ever gains
// a non-test caller, the reasoning above stops holding and this fails.
func TestSettleRouteIsNotOnTheProductionClaimPath(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var callers []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(body)
		// The definition itself lives in atomic.go; a CALL is what matters.
		for _, line := range strings.Split(src, "\n") {
			if !strings.Contains(line, "SettleRoute(") {
				continue
			}
			if strings.Contains(line, "func SettleRoute") {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			callers = append(callers, name+": "+trimmed)
		}
	}
	if len(callers) > 0 {
		t.Fatalf("SettleRoute now has production callers:\n  %s\n\n"+
			"The claim that a hop's upstream authorisation is contingent on its "+
			"downstream payment rests on the claim path using a VAULT PREIMAGE "+
			"(Forwarder.ClaimUpstream), not a payer-computed scalar. If scalars "+
			"are now used to claim, re-open P13.5 finding 2 before shipping.",
			strings.Join(callers, "\n  "))
	}
}

// A hop cannot claim upstream without the downstream secret.
//
// The mechanism, asserted rather than argued: ClaimUpstream consults the vault
// and refuses when the preimage is absent.
func TestAHopCannotClaimUpstreamWithoutTheDownstreamSecret(t *testing.T) {
	dir := t.TempDir()
	vault, err := OpenPreimageVault(dir)
	if err != nil {
		t.Fatalf("OpenPreimageVault: %v", err)
	}
	hub, upstream, in := wiredPair(t, anon(500))
	fwd := NewForwarder(hub.coord, vault, hub.key.address())

	pre := [32]byte{31: 0x21}
	var h [32]byte
	copy(h[:], keccak(pre[:]))

	incoming := Incoming{
		Channel: in,
		Lock:    HTLC{ID: [32]byte{31: 1}, Hash: h, Amount: anon(50), Expiry: 2_000_000_000},
	}
	// The vault has never seen the secret: the downstream payment has not
	// settled, so there is nothing to claim with.
	if _, err := fwd.ClaimUpstream(context.Background(), incoming,
		derive("p135/claim", nil), directPeer{t, upstream.coord}); err == nil {
		t.Fatal("a hop claimed upstream with no downstream secret")
	}

	// Once the downstream reveals it, the claim becomes possible — the vault is
	// the ONLY thing that changed.
	if err := vault.Learn(pre); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if _, known := vault.Lookup(h); !known {
		t.Fatal("the vault did not record the revealed preimage")
	}
}

// A blinding is drawn fresh per payment, so nothing is reused across payments.
func TestBlindingsAreFreshPerPayment(t *testing.T) {
	c := DefaultCurve()
	_, Z, err := NewSecret(c)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		chain, err := BuildLocks(c, Z, 3)
		if err != nil {
			t.Fatalf("BuildLocks: %v", err)
		}
		for hop := range chain.Locks {
			b, err := chain.BlindingFor(hop)
			if err != nil {
				t.Fatalf("BlindingFor: %v", err)
			}
			k := b.String()
			if seen[k] {
				t.Fatalf("blinding reused across payments at hop %d", hop)
			}
			seen[k] = true
		}
	}
}

// A hop receives a COMMITMENT to its lock point, never a scalar.
//
// If an onion ever carried a usable scalar, a hop could claim without the
// downstream reveal — which is the failure the finding feared.
func TestAHopsOnionInstructionCarriesNoScalar(t *testing.T) {
	req := planReq(t)
	plan, err := PlanPayment(req)
	if err != nil {
		t.Fatalf("PlanPayment: %v", err)
	}
	for i, cand := range plan.Route {
		shared := HopSharedSecret(req.Seed, plan.Packet.EphemeralPublicKey, cand.NodeID)
		hop, err := plan.Packet.Peel(shared)
		if err != nil {
			t.Fatalf("hop %d peel: %v", i, err)
		}
		// The commitment is a one-way hash of the lock point. It cannot be
		// inverted into the scalar that satisfies it.
		var zero Commitment
		if hop.OutgoingCommitment == zero {
			t.Fatalf("hop %d received no commitment", i)
		}
		blinding, err := plan.Locks.BlindingFor(i)
		if err != nil {
			t.Fatalf("BlindingFor: %v", err)
		}
		// The instruction must not contain the blinding in any form the hop
		// could read off it.
		if strings.Contains(string(hop.BlindedEndpoint), blinding.String()) {
			t.Fatalf("hop %d's instruction leaks its blinding", i)
		}
	}
}

// ---- cross-payment interference --------------------------------------------
//
// The multipath audit proved that single-payment reasoning misses attacks that
// need two payments. These exercise the pairs explicitly.

// Two payments sharing a recipient secret must not share lock points.
func TestTwoPaymentsSharingASecretDoNotShareLockPoints(t *testing.T) {
	c := DefaultCurve()
	z, Z, err := NewSecret(c)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	_ = z
	a, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatalf("BuildLocks a: %v", err)
	}
	b, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatalf("BuildLocks b: %v", err)
	}
	for i := range a.Locks {
		for j := range b.Locks {
			if a.Locks[i].Equal(b.Locks[j]) {
				t.Fatalf("payment A hop %d and payment B hop %d share a lock point "+
					"despite a fresh blinding per payment", i, j)
			}
		}
	}
}

// A scalar from payment A must not satisfy payment B's lock at the same index.
func TestAScalarFromOnePaymentDoesNotSatisfyAnother(t *testing.T) {
	c := DefaultCurve()
	z, Z, _ := NewSecret(c)
	a, _ := BuildLocks(c, Z, 3)
	b, _ := BuildLocks(c, Z, 3)

	scalarsA, err := SettleRoute(c, a, z)
	if err != nil {
		t.Fatalf("SettleRoute: %v", err)
	}
	for i := range b.Locks {
		if err := Satisfies(c, b.Locks[i], scalarsA[i]); err == nil {
			t.Fatalf("payment A's scalar for hop %d satisfied payment B's lock", i)
		}
	}
	// Sanity: A's scalars do satisfy A, so the test is not vacuous.
	for i := range a.Locks {
		if err := Satisfies(c, a.Locks[i], scalarsA[i]); err != nil {
			t.Fatalf("payment A's own scalar failed at hop %d: %v", i, err)
		}
	}
}

// Two payments over the SAME route must not produce the same onion.
//
// The ephemeral key is per-payment; reusing one would link every payment sent
// under it, which the onion header calls out explicitly.
func TestTwoPaymentsOverOneRouteProduceDifferentOnions(t *testing.T) {
	reqA := planReq(t)
	reqB := planReq(t)
	reqB.Seed = [32]byte{31: 0x99} // a different payment, same candidates
	planA, err := PlanPayment(reqA)
	if err != nil {
		t.Fatalf("PlanPayment A: %v", err)
	}
	planB, err := PlanPayment(reqB)
	if err != nil {
		t.Fatalf("PlanPayment B: %v", err)
	}
	if planA.Packet.EphemeralPublicKey == planB.Packet.EphemeralPublicKey {
		t.Fatal("two payments shared an onion ephemeral key; they would be linkable")
	}
	// And a hop's shared secret differs, so a replayed onion does not peel.
	for _, cand := range planA.Route {
		sharedA := HopSharedSecret(reqA.Seed, planA.Packet.EphemeralPublicKey, cand.NodeID)
		if _, err := planB.Packet.Peel(sharedA); err == nil {
			t.Fatal("payment A's hop secret peeled payment B's onion")
		}
	}
}

// Settlement material from payment A must not settle payment B on a channel.
//
// The channel-level statement of the same property, through the real engine:
// two locks, two preimages, no crossover.
func TestSettlementMaterialDoesNotCrossPayments(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	const now = int64(1_000_000)
	payer.clock, payee.clock = now, now

	preA := [32]byte{31: 0x31}
	preB := [32]byte{31: 0x32}
	var hA, hB [32]byte
	copy(hA[:], keccak(preA[:]))
	copy(hB[:], keccak(preB[:]))

	for i, h := range [][32]byte{hA, hB} {
		tr := StateTransition{Kind: KindLockAdd, Amount: anon(50),
			LockID: [32]byte{31: byte(i + 1)}, Hash: h, Expiry: now + 3600}
		if _, err := payer.coord.Pay(ctx, id, derive("p135/x-lock", []byte{byte(i)}),
			tr, directPeer{t, payee.coord}); err != nil {
			t.Fatalf("lock %d: %v", i, err)
		}
	}

	// Payment A's preimage against payment B's lock.
	cross := StateTransition{Kind: KindLockSettle,
		LockID: [32]byte{31: 2}, Preimage: preA}
	if _, err := payee.coord.Pay(ctx, id, derive("p135/x-settle", nil),
		cross, directPeer{t, payer.coord}); err == nil {
		t.Fatal("payment A's preimage settled payment B's lock")
	}

	// Each still settles with its own.
	own := StateTransition{Kind: KindLockSettle,
		LockID: [32]byte{31: 2}, Preimage: preB}
	if _, err := payee.coord.Pay(ctx, id, derive("p135/x-settle-own", nil),
		own, directPeer{t, payer.coord}); err != nil {
		t.Fatalf("payment B refused its own preimage: %v", err)
	}
	bal, _ := payee.coord.Balances(id)
	if bal.Mine.Cmp(anon(50)) != 0 {
		t.Fatalf("payee holds %s, want exactly one lock's 50", bal.Mine)
	}
	_ = big.NewInt
}

// ---- FINDING 3: lock-id reuse defeated the sweep's idempotency key ----------
//
// Found by adversarial review while investigating findings 1 and 2, and verified
// as a working exploit before the fix.
//
// SweepClaimable derived its claim intent from the lock ID alone. The goal was
// right — a retry after a crash must reuse the intent so it cannot claim twice —
// but a lock ID is unique only among PENDING locks: Channel.Accept builds its
// duplicate check over st.Pending, so a resolved lock's id is free again.
//
//	1. payment 1 uses lock id L, resolves. AppliedAt(intent_L) recorded.
//	2. payment 2 reuses L upstream. Accept permits it — L is not pending.
//	3. the hub forwards, pays downstream, learns the preimage.
//	4. the sweep recomputes intent_L; Pay finds it applied and returns Done
//	   WITHOUT claiming.
//	5. res.Done is true, so the sweep reports success.
//
// Hub paid downstream, never claimed upstream, and believed it had.

// Two lock instances that merely share an id must not share a claim intent.
func TestLockIDReuseDoesNotCollideTheClaimIntent(t *testing.T) {
	ch := [32]byte{31: 0xC1}
	sameID := [32]byte{31: 0x07}

	// Payment 1's lock, and payment 2's reusing the id with its own secret.
	first := Incoming{Channel: ch, Lock: HTLC{
		ID: sameID, Hash: [32]byte{31: 0xA1}, Amount: anon(100), Expiry: 2_000_000_000}}
	second := Incoming{Channel: ch, Lock: HTLC{
		ID: sameID, Hash: [32]byte{31: 0xA2}, Amount: anon(100), Expiry: 2_000_000_000}}

	if claimUpstreamIntent(first) == claimUpstreamIntent(second) {
		t.Fatal("two lock instances sharing an id derived the same claim intent; " +
			"the second claim would be answered from the first's record and the " +
			"hub would pay downstream without collecting upstream")
	}

	// The crash property must survive: the SAME lock derives the SAME intent, so
	// a restart mid-claim cannot claim twice.
	again := Incoming{Channel: ch, Lock: HTLC{
		ID: sameID, Hash: [32]byte{31: 0xA1}, Amount: anon(100), Expiry: 2_000_000_000}}
	if claimUpstreamIntent(first) != claimUpstreamIntent(again) {
		t.Fatal("the same lock derived two different intents; a retry after a crash " +
			"would claim a second time")
	}
}

// Every field that distinguishes one lock instance from another must move the
// intent, or some pair of instances collides.
func TestClaimIntentDependsOnEveryLockField(t *testing.T) {
	base := Incoming{Channel: [32]byte{31: 0xC1}, Lock: HTLC{
		ID: [32]byte{31: 0x07}, Hash: [32]byte{31: 0xA1},
		Amount: anon(100), Expiry: 2_000_000_000}}
	want := claimUpstreamIntent(base)

	alt := base
	alt.Channel = [32]byte{31: 0xC2}
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the channel does not affect the claim intent")
	}
	alt = base
	alt.Lock.ID = [32]byte{31: 0x08}
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the lock id does not affect the claim intent")
	}
	alt = base
	alt.Lock.Hash = [32]byte{31: 0xA2}
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the payment hash does not affect the claim intent")
	}
	alt = base
	alt.Lock.Amount = anon(101)
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the amount does not affect the claim intent")
	}
	alt = base
	alt.Lock.Expiry = 2_000_000_001
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the expiry does not affect the claim intent")
	}
}

// ---- FINDING 2: the eleven cross-payment attacks ---------------------------
//
// Constructed as ordered by the corrective phase. Each builds TWO independent
// payments, because the multipath audit proved that perturbing one payment
// cannot see an attack that needs two.
//
// What the binding must cover, and where each comes from:
//
//	specific payment   ephemeral key (fresh from z, crypto/rand per plan)
//	specific hop       node id in the shared secret; own lock point in the
//	                   commitment
//	specific channel   the channel id is inside every signed state digest
//	specific amount    the amount is inside the state digest and, for multipath,
//	                   inside the intent that keys the preimage
//	specific leg       per-fragment lock chains and per-leg intents
//	downstream first   the vault: no downstream reveal, no preimage, no claim

// 1. Payment A's scalar must not satisfy payment B's lock.
func TestX1ScalarFromADoesNotSatisfyB(t *testing.T) {
	c := DefaultCurve()
	zA, ZA, _ := NewSecret(c)
	_, ZB, _ := NewSecret(c)
	a, _ := BuildLocks(c, ZA, 3)
	b, _ := BuildLocks(c, ZB, 3)

	scalars, err := SettleRoute(c, a, zA)
	if err != nil {
		t.Fatalf("SettleRoute: %v", err)
	}
	for i := range b.Locks {
		if err := Satisfies(c, b.Locks[i], scalars[i]); err == nil {
			t.Fatalf("A's scalar for hop %d satisfied B's lock", i)
		}
	}
}

// 2. Payment A's onion must not peel with B's hop secrets, and vice versa —
//    INCLUDING when the payer reuses its seed.
//
// This is the attack that was live: the shared secret ignored the ephemeral key,
// so one seed gave a hop the same secret on every payment and it could peel an
// onion it was never handed.
func TestX2OnionFromADoesNotPeelWithBsSecrets(t *testing.T) {
	reqA, reqB := planReq(t), planReq(t)
	reqB.Amount = 200
	if reqA.Seed != reqB.Seed {
		t.Fatal("precondition: this test needs the SAME seed on both payments")
	}
	planA, err := PlanPayment(reqA)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	planB, err := PlanPayment(reqB)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if planA.Packet.EphemeralPublicKey == planB.Packet.EphemeralPublicKey {
		t.Fatal("two payments shared an ephemeral key")
	}
	for _, cand := range planA.Route {
		secretA := HopSharedSecret(reqA.Seed, planA.Packet.EphemeralPublicKey, cand.NodeID)
		if _, err := planB.Packet.Peel(secretA); err == nil {
			t.Fatalf("hop %s peeled payment B's onion using its payment-A secret; "+
				"the two payments are linkable and B's routing instruction is exposed",
				cand.NodeID)
		}
	}
}

// 3. Settlement material from A must not settle B, on a real channel.
func TestX3SettlementMaterialFromADoesNotSettleB(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	const now = int64(1_000_000)
	payer.clock, payee.clock = now, now

	preA, preB := [32]byte{31: 0x41}, [32]byte{31: 0x42}
	var hA, hB [32]byte
	copy(hA[:], keccak(preA[:]))
	copy(hB[:], keccak(preB[:]))
	for i, h := range [][32]byte{hA, hB} {
		tr := StateTransition{Kind: KindLockAdd, Amount: anon(50),
			LockID: [32]byte{31: byte(i + 1)}, Hash: h, Expiry: now + 3600}
		if _, err := payer.coord.Pay(ctx, id, derive("x3/lock", []byte{byte(i)}),
			tr, directPeer{t, payee.coord}); err != nil {
			t.Fatalf("lock %d: %v", i, err)
		}
	}
	cross := StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 2}, Preimage: preA}
	if _, err := payee.coord.Pay(ctx, id, derive("x3/cross", nil),
		cross, directPeer{t, payer.coord}); err == nil {
		t.Fatal("payment A's preimage settled payment B's lock")
	}
}

// 4. Same recipient secret, different payment id, must not share a hash.
func TestX4SameSecretDifferentPaymentID(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	a := f.payment(t, [32]byte{31: 0x51}, 40, 60)
	b := f.payment(t, [32]byte{31: 0x52}, 40, 60)
	for i := range a.Legs {
		if a.Legs[i].Hash == b.Legs[i].Hash {
			t.Fatalf("leg %d shares a hash across payment ids on one secret", i)
		}
		if a.Legs[i].Intent == b.Legs[i].Intent {
			t.Fatalf("leg %d shares an intent across payment ids", i)
		}
	}
}

// 5. Same route, different payment: no authorization material may repeat.
func TestX5SameRouteDifferentPayment(t *testing.T) {
	reqA, reqB := planReq(t), planReq(t)
	reqB.Amount = 300
	planA, _ := PlanPayment(reqA)
	planB, _ := PlanPayment(reqB)

	// The routes are the same candidates; the material must not be.
	seen := map[string]bool{}
	for i := range planA.Locks.Locks {
		p := planA.Locks.Locks[i]
		seen[p.X.String()+":"+p.Y.String()] = true
	}
	for i := range planB.Locks.Locks {
		p := planB.Locks.Locks[i]
		if seen[p.X.String()+":"+p.Y.String()] {
			t.Fatalf("hop %d reused a lock point across two payments on one route", i)
		}
	}
}

// 6. Same fragment index, different payment.
func TestX6SameIndexDifferentPayment(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	a := f.payment(t, [32]byte{31: 0x61}, 20, 30, 50)
	b := f.payment(t, [32]byte{31: 0x62}, 20, 30, 50)
	for i := range a.Legs {
		if a.Legs[i].LockID == b.Legs[i].LockID {
			t.Fatalf("index %d produced the same lock id in two payments", i)
		}
	}
}

// 7. A downstream FAILURE must not leave an upstream authorization usable.
func TestX7DownstreamFailureLeavesNoUpstreamAuthorization(t *testing.T) {
	vault, err := OpenPreimageVault(t.TempDir())
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	hub, upstream, in := wiredPair(t, anon(500))
	fwd := NewForwarder(hub.coord, vault, hub.key.address())

	pre := [32]byte{31: 0x71}
	var h [32]byte
	copy(h[:], keccak(pre[:]))
	incoming := Incoming{Channel: in, Lock: HTLC{
		ID: [32]byte{31: 1}, Hash: h, Amount: anon(50), Expiry: 2_000_000_000}}

	// The downstream never settled, so the vault never learned the secret.
	if _, err := fwd.ClaimUpstream(context.Background(), incoming,
		claimUpstreamIntent(incoming), directPeer{t, upstream.coord}); err == nil {
		t.Fatal("the hub claimed upstream after a downstream failure")
	}
}

// 8. Replay after a SUCCESSFUL settlement must not settle again.
func TestX8ReplayAfterSuccessfulSettlement(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 0x81}, 40, 60)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	before := f.exec.Summarise(pay).SettledAmount

	// Replay the exact settle transition on leg 0.
	leg := pay.Legs[0]
	tr := StateTransition{Kind: KindLockSettle, LockID: leg.LockID,
		Preimage: FragmentPreimage(f.secret, leg.Intent)}
	if _, err := f.payer.coord.Pay(ctx, leg.Channel, derive("x8/replay", nil),
		tr, directPeer{t, f.payees[0].coord}); err == nil {
		t.Fatal("a settled lock was settled a second time")
	}
	if f.exec.Summarise(pay).SettledAmount.Cmp(before) != 0 {
		t.Fatal("a replay moved value")
	}
}

// 9. Replay after a REFUND must not settle the refunded lock.
func TestX9ReplayAfterRefund(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 0x91}, 40, 60)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	f.advanceTo(mpExpiry + 120)
	if _, err := f.exec.Refund(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Refund: %v", err)
	}
	// The secret still exists; the lock does not.
	leg := pay.Legs[0]
	tr := StateTransition{Kind: KindLockSettle, LockID: leg.LockID,
		Preimage: FragmentPreimage(f.secret, leg.Intent)}
	if _, err := f.payer.coord.Pay(ctx, leg.Channel, derive("x9/replay", nil),
		tr, directPeer{t, f.payees[0].coord}); err == nil {
		t.Fatal("a refunded lock was then settled")
	}
	out := f.exec.Summarise(pay)
	if out.SettledAmount.Sign() != 0 {
		t.Fatalf("a refunded payment delivered %s", out.SettledAmount)
	}
}

// 10. A payer constructing INCONSISTENT blinding must not produce a chain that
//     validates, so a hop is never handed a lock it cannot satisfy.
func TestX10InconsistentBlindingDoesNotValidate(t *testing.T) {
	c := DefaultCurve()
	z, Z, _ := NewSecret(c)
	chain, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatalf("BuildLocks: %v", err)
	}
	// A well-formed chain settles at every hop.
	scalars, err := SettleRoute(c, chain, z)
	if err != nil {
		t.Fatalf("SettleRoute: %v", err)
	}
	for i := range chain.Locks {
		if err := Satisfies(c, chain.Locks[i], scalars[i]); err != nil {
			t.Fatalf("honest chain failed at hop %d: %v", i, err)
		}
	}
	// Now corrupt one hop's lock, as a malicious payer would. The scalar the
	// unwinding produces must NOT satisfy it — the mismatch has to be visible
	// to the hop before it forwards, which is what Satisfies is for.
	tampered := *chain
	tampered.Locks = append([]Point(nil), chain.Locks...)
	tampered.Locks[1] = chain.Locks[2] // hop 1 handed hop 2's point
	if err := Satisfies(c, tampered.Locks[1], scalars[1]); err == nil {
		t.Fatal("a hop's scalar satisfied a lock the payer had swapped; " +
			"the hop could not detect the mismatch")
	}
}

// 11. A malicious intermediary must not turn the mismatch into a claim.
//
// Even holding its own instruction, its own secret and a sibling's material, a
// hop cannot settle upstream without the preimage the downstream reveals.
func TestX11MaliciousHopCannotExploitAMismatch(t *testing.T) {
	vault, err := OpenPreimageVault(t.TempDir())
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	hub, upstream, in := wiredPair(t, anon(500))
	fwd := NewForwarder(hub.coord, vault, hub.key.address())

	// The hub knows a DIFFERENT payment's secret and tries to use it.
	other := [32]byte{31: 0xB1}
	if err := vault.Learn(other); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	pre := [32]byte{31: 0xB2}
	var h [32]byte
	copy(h[:], keccak(pre[:]))
	incoming := Incoming{Channel: in, Lock: HTLC{
		ID: [32]byte{31: 1}, Hash: h, Amount: anon(50), Expiry: 2_000_000_000}}

	// The vault is keyed by hash, so an unrelated secret is simply not found.
	if _, err := fwd.ClaimUpstream(context.Background(), incoming,
		claimUpstreamIntent(incoming), directPeer{t, upstream.coord}); err == nil {
		t.Fatal("a hub claimed upstream using an unrelated payment's secret")
	}
}

// 12. Within ONE payment, a hop must peel only its own instruction.
//
// Cross-payment isolation was tested and within-payment isolation was not, so
// dropping the node id from the derivation — making every hop on a route share
// one secret — survived the first mutation pass. That collapse would hand each
// hop the whole route, which is the single property onion routing exists for.
func TestX12EachHopPeelsOnlyItsOwnInstruction(t *testing.T) {
	req := planReq(t)
	plan, err := PlanPayment(req)
	if err != nil {
		t.Fatalf("PlanPayment: %v", err)
	}
	if len(plan.Route) < 2 {
		t.Fatalf("need at least two hops, got %d", len(plan.Route))
	}

	// Each hop's own secret must yield the instruction committing to ITS lock.
	for i, cand := range plan.Route {
		secret := HopSharedSecret(req.Seed, plan.Packet.EphemeralPublicKey, cand.NodeID)
		hop, err := plan.Packet.Peel(secret)
		if err != nil {
			t.Fatalf("hop %d could not peel its own instruction: %v", i, err)
		}
		want := Commitment(derive("syndichan/payment/hopcommit/v1",
			plan.Locks.Locks[i].X.Bytes(), plan.Locks.Locks[i].Y.Bytes()))
		if hop.OutgoingCommitment != want {
			t.Fatalf("hop %d peeled an instruction committing to another hop's lock", i)
		}
	}

	// And no hop's secret may yield another hop's instruction. With a shared
	// secret every hop reads every slot, so this is what collapses first.
	for i, ci := range plan.Route {
		si := HopSharedSecret(req.Seed, plan.Packet.EphemeralPublicKey, ci.NodeID)
		got, err := plan.Packet.Peel(si)
		if err != nil {
			t.Fatalf("hop %d peel: %v", i, err)
		}
		for j := range plan.Route {
			if i == j {
				continue
			}
			other := Commitment(derive("syndichan/payment/hopcommit/v1",
				plan.Locks.Locks[j].X.Bytes(), plan.Locks.Locks[j].Y.Bytes()))
			if got.OutgoingCommitment == other {
				t.Fatalf("hop %d's secret peeled hop %d's instruction; the route is "+
					"visible to every hop on it", i, j)
			}
		}
	}
}

// 13. The hop secret must depend on EVERY input that scopes it.
//
// Dropping the seed leaves derive(ephemeral, nodeID) — and the ephemeral key
// travels in the packet in clear, so anyone who observes a payment could compute
// every hop's secret and peel the whole onion. That mutation also survived the
// first pass, because nothing asserted the seed was an input at all.
//
// Tested at the derivation the way a key schedule is, rather than through a
// behaviour that happens to depend on it.
func TestX13HopSecretDependsOnEveryInput(t *testing.T) {
	seed := [32]byte{31: 0x01}
	eph := [32]byte{31: 0x02}
	const node = NodeID("hop-a")
	base := HopSharedSecret(seed, eph, node)

	if HopSharedSecret([32]byte{31: 0x09}, eph, node) == base {
		t.Fatal("the seed does not affect the hop secret; an observer with the " +
			"packet could derive it and peel the onion")
	}
	if HopSharedSecret(seed, [32]byte{31: 0x09}, node) == base {
		t.Fatal("the ephemeral key does not affect the hop secret; one seed would " +
			"give a hop the same secret on every payment")
	}
	if HopSharedSecret(seed, eph, NodeID("hop-b")) == base {
		t.Fatal("the node id does not affect the hop secret; every hop on the " +
			"route would share one and could read the whole path")
	}
	// Deterministic, or a router could never reproduce it.
	if HopSharedSecret(seed, eph, node) != base {
		t.Fatal("the hop secret derivation is not deterministic")
	}
}
