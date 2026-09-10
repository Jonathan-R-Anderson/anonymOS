package channel

// P13 — the multi-path security table, mapped row by row.
//
// Specification: doc/p13-multipath-security-table.md. Same coverage mechanism
// as the other P13 suites: the spec is data, each row registers itself, and an
// unclaimed row fails the suite.
//
// THE GAPS ARE CLOSED
// -------------------
// Ten of these rows were GAPs: SplitPlan had no executor, so everything needing
// fragments coordinated AT SETTLEMENT TIME — partial settlement, partial refund,
// aggregate replay, crash recovery — had no implementation and could not
// honestly be tested. Their tests pinned the absence instead.
//
// multipath_exec.go is that executor, and those rows are now enforced. The
// end-to-end scenarios live in multipath_exec_test.go, driven through the real
// Coordinator and SCPP/1; the rows below re-assert the specific property each
// one names, so the security table stays checkable from one place.

import (
	"math/big"
	"errors"
	"os"
	"reflect"
	"testing"
)

var p13MultipathSpec = []p13Row{
	{"mp", "plan conservation", "fragments sum to the total"},
	{"mp", "exact total", "no unit is lost to rounding"},
	{"mp", "no path creates value", "rejected at plan and at channel"},
	{"mp", "no double spend per path", "rejected per channel"},
	{"mp", "nonce monotonic per channel", "strictly increasing"},
	{"mp", "independent channel conservation", "each channel conserves alone"},
	{"mp", "aggregate conservation at plan time", "enforced before sending"},
	{"mp", "one secret settles every fragment", "one z opens all chains"},
	{"mp", "fragments carry different locks", "not linkable"},
	{"mp", "within-route expiry ladder", "outgoing shorter than incoming"},
	{"mp", "per-leg refund restores both sides", "no liquidity bleed"},
	{"mp", "cancelling one path leaves siblings intact", "no cross-path leak"},
	{"mp", "individual path replay", "refused"},
	{"mp", "duplicate claim on one fragment", "refused"},
	{"mp", "per leg unwind is independent", "one stall does not strand others"},
	{"mp", "channels survive restart independently", "latest state reloads"},
	{"mp", "fragments never share a hub", "disjoint operator sets"},
	{"mp", "hub holdings stay zero across fragments", "no custody"},
	{"mp", "signer identity per leg", "both parties or refused"},
	{"mp", "cross path state rejection", "wrong channel refused"},
	{"mp", "per leg recovery is idempotent", "re-apply is a no-op"},
	{"mp", "no aggregate write path", "Accept is the only mutator"},

	// Formerly GAPs. Closed by the executor (multipath_exec.go); each is now
	// exercised end to end in multipath_exec_test.go and re-asserted here.
	{"mp", "aggregate settlement accounting", "delivered value summed from channels"},
	{"mp", "cross-fragment expiry ordering", "every leg expires by the deadline"},
	{"mp", "partial path failure", "siblings resolve independently"},
	{"mp", "plan level replay identity", "payment id re-derives the same intents"},
	{"mp", "partial settlement", "reported as delivered, not complete"},
	{"mp", "partial refund reconciliation", "refund never touches a settled leg"},
	{"mp", "aggregate stall resolution", "unwind returns locked value"},
	{"mp", "plan is persisted", "attempt journal written before any leg commits"},
	{"mp", "resumption after restart", "state re-derived from channels"},
	{"mp", "aggregate recovery is idempotent", "resume converges"},

	// The seam that made "SplitPlan is executable" true rather than asserted.
	{"mp", "real split plan is executable", "Split output drives the engine"},
	{"mp", "expiry from the actual route", "per-fragment, scaled by hop count"},
}

// methodNames returns the exported method set of a type, for pinning an
// absence mechanically rather than by assertion in prose.
func methodNames(v any) map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumMethod(); i++ {
		out[t.Method(i).Name] = true
	}
	return out
}

func TestP13MultipathSecuritySuite(t *testing.T) {
	covered := map[string]bool{}
	cover := func(name string) { covered["mp/"+name] = true }

	newPlan := func(t *testing.T, total Amount) (*SplitPlan, Curve, *big.Int, Point) {
		t.Helper()
		c := DefaultCurve()
		z, Z, err := NewSecret(c)
		if err != nil {
			t.Fatalf("NewSecret: %v", err)
		}
		plan, err := Split(c, Z, total, threeIndependentRoutes())
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		return plan, c, z, Z
	}

	// ---- plan-layer properties -----------------------------------------

	t.Run("mp/plan conservation", func(t *testing.T) {
		cover("plan conservation")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		var sum Amount
		for _, f := range plan.Fragments {
			sum += f.Amount
		}
		if sum != plan.Total {
			t.Fatalf("fragments sum to %d, total is %d", sum, plan.Total)
		}
		// Tamper: shave one fragment. Verify must catch it — a short-paid
		// recipient is silent until somebody reconciles.
		plan.Fragments[0].Amount -= 1
		if err := plan.Verify(); err == nil {
			t.Fatal("a plan whose fragments do not sum to the total verified")
		}
	})

	t.Run("mp/exact total", func(t *testing.T) {
		cover("exact total")
		// Totals chosen to stress the rounding path: just over the floor, odd
		// values, and values where spare/n divides badly.
		for _, total := range []Amount{2 * MinFragment, 3*MinFragment + 1, 100_001, 999_997} {
			c := DefaultCurve()
			_, Z, _ := NewSecret(c)
			plan, err := Split(c, Z, total, threeIndependentRoutes())
			if err != nil {
				continue // too small to split is a legitimate refusal, not a loss
			}
			var sum Amount
			for _, f := range plan.Fragments {
				sum += f.Amount
			}
			if sum != total {
				t.Fatalf("total %d split to %d — %d units lost to rounding",
					total, sum, total-sum)
			}
		}
	})

	t.Run("mp/no path creates value", func(t *testing.T) {
		cover("no path creates value")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		plan.Fragments[0].Amount += 5_000 // inflate one leg after planning
		if err := plan.Verify(); err == nil {
			t.Fatal("an inflated fragment verified; the payer would be over-charged")
		}
		// And at the channel layer: a leg state exceeding its deposits.
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(600), anon(600)))); err == nil {
			t.Fatal("a leg state creating value was accepted")
		}
	})

	t.Run("mp/aggregate conservation at plan time", func(t *testing.T) {
		cover("aggregate conservation at plan time")
		plan, _, _, _ := newPlan(t, Amount(250_000))
		if err := plan.Verify(); err != nil {
			t.Fatalf("a well-formed plan failed verification: %v", err)
		}
		// Dropping a fragment entirely must not still verify.
		plan.Fragments = plan.Fragments[:len(plan.Fragments)-1]
		if err := plan.Verify(); err == nil {
			t.Fatal("a plan missing a fragment verified against its own total")
		}
	})

	// ---- cryptographic properties ---------------------------------------

	t.Run("mp/one secret settles every fragment", func(t *testing.T) {
		cover("one secret settles every fragment")
		plan, c, z, _ := newPlan(t, Amount(100_000))
		for i, f := range plan.Fragments {
			scalars, err := SettleRoute(c, f.Locks, z)
			if err != nil {
				t.Fatalf("fragment %d: SettleRoute: %v", i, err)
			}
			for hop, s := range scalars {
				if err := Satisfies(c, f.Locks.Locks[hop], s); err != nil {
					t.Fatalf("fragment %d hop %d not satisfied by the recipient's secret: %v",
						i, hop, err)
				}
			}
		}
		// A different secret must open nothing — otherwise fragments could be
		// claimed by someone who is not the recipient.
		other, _, _ := NewSecret(c)
		scalars, err := SettleRoute(c, plan.Fragments[0].Locks, other)
		if err != nil {
			t.Fatalf("SettleRoute: %v", err)
		}
		if err := Satisfies(c, plan.Fragments[0].Locks.Locks[0], scalars[0]); err == nil {
			t.Fatal("a wrong secret satisfied a fragment's lock")
		}
	})

	t.Run("mp/fragments carry different locks", func(t *testing.T) {
		cover("fragments carry different locks")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		seen := map[string]int{}
		for i, f := range plan.Fragments {
			for _, l := range f.Locks.Locks {
				key := l.X.String() + ":" + l.Y.String()
				if prev, dup := seen[key]; dup {
					t.Fatalf("fragments %d and %d share a lock point; "+
						"they are trivially linkable as one payment", prev, i)
				}
				seen[key] = i
			}
		}
	})

	// ---- per-channel properties, which are fragment-agnostic ------------

	t.Run("mp/nonce monotonic per channel", func(t *testing.T) {
		cover("nonce monotonic per channel")
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(4, anon(400), anon(600)))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Two fragments of one payment landing on the same channel at the same
		// nonce. The channel does not know fragments exist, which is exactly
		// why this is safe.
		if err := f.ch.Accept(f.signed(t, f.state(4, anon(350), anon(650)))); err == nil {
			t.Fatal("two legs wrote the same nonce on one channel")
		}
	})

	t.Run("mp/independent channel conservation", func(t *testing.T) {
		cover("independent channel conservation")
		// Two channels, each with its own deposits. A leg on one must not be
		// able to draw on the other's capacity.
		f1, f2 := newP13Fixture(t), newP13Fixture(t)
		if err := f1.ch.Accept(f1.signed(t, f1.state(1, anon(0), anon(1000)))); err != nil {
			t.Fatalf("f1 legitimate drain: %v", err)
		}
		// f2 is untouched and must still conserve against its OWN deposits.
		if err := f2.ch.Accept(f2.signed(t, f2.state(1, anon(1400), anon(0)))); err == nil {
			t.Fatal("a channel accepted balances exceeding its own deposits")
		}
	})

	t.Run("mp/no double spend per path", func(t *testing.T) {
		cover("no double spend per path")
		f := newP13Fixture(t)
		st := f.state(6, anon(300), anon(700))
		if err := f.ch.Accept(f.signed(t, st)); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, st)); err == nil {
			t.Fatal("the same leg state was applied twice")
		}
	})

	t.Run("mp/individual path replay", func(t *testing.T) {
		cover("individual path replay")
		f := newP13Fixture(t)
		captured := f.signed(t, f.state(3, anon(400), anon(600)))
		if err := f.ch.Accept(captured); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, f.state(9, anon(350), anon(650)))); err != nil {
			t.Fatalf("later state: %v", err)
		}
		// The captured leg is replayed after the channel has moved on.
		if err := f.ch.Accept(captured); err == nil {
			t.Fatal("a captured leg state was replayed successfully")
		}
		if f.ch.Latest.State.Nonce != 9 {
			t.Fatal("the replay rolled the channel back")
		}
	})

	t.Run("mp/duplicate claim on one fragment", func(t *testing.T) {
		cover("duplicate claim on one fragment")
		f := newP13Fixture(t)
		pre := [32]byte{31: 0x77}
		var h [32]byte
		copy(h[:], keccak(pre[:]))
		lock := HTLC{ID: [32]byte{31: 1}, Hash: h, Amount: anon(10),
			Expiry: 2_000_000_000, PayerIsA: true}
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(490), anon(500), lock))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, f.state(2, anon(490), anon(510)))); err != nil {
			t.Fatalf("first claim: %v", err)
		}
		// Claim it again at a fresh nonce: the lock is gone, so the value has
		// nothing to come from.
		if err := f.ch.Accept(f.signed(t, f.state(3, anon(490), anon(520)))); err == nil {
			t.Fatal("a fragment's lock was claimed twice")
		}
	})

	t.Run("mp/signer identity per leg", func(t *testing.T) {
		cover("signer identity per leg")
		f := newP13Fixture(t)
		outsider := newSigner(t)
		st := f.state(1, anon(400), anon(600))
		raw := st.Digest(f.chainI, f.con)
		if err := f.ch.Accept(SignedState{State: st,
			SigA: outsider.sign(raw), SigB: f.b.sign(raw)}); err == nil {
			t.Fatal("a leg signed by a non-party was accepted")
		}
		// One party signing both slots is the other identity attack.
		if err := f.ch.Accept(SignedState{State: st,
			SigA: f.b.sign(raw), SigB: f.b.sign(raw)}); err == nil {
			t.Fatal("one party signed both slots of a leg")
		}
	})

	t.Run("mp/cross path state rejection", func(t *testing.T) {
		cover("cross path state rejection")
		f1, f2 := newP13Fixture(t), newP13Fixture(t)
		// A fully valid state for f1's channel, offered to f2's.
		legA := f1.signed(t, f1.state(1, anon(400), anon(600)))
		if err := f2.ch.Accept(legA); err == nil {
			t.Fatal("one path's signed state authorised a change on another path's channel")
		}
		// And it must still work on its own channel — the rejection is about
		// identity, not about the state being malformed.
		if err := f1.ch.Accept(legA); err != nil {
			t.Fatalf("the state was rejected on its own channel too: %v", err)
		}
	})

	t.Run("mp/per leg recovery is idempotent", func(t *testing.T) {
		cover("per leg recovery is idempotent")
		f := newP13Fixture(t)
		leg := f.signed(t, f.state(5, anon(400), anon(600)))
		if err := f.ch.Accept(leg); err != nil {
			t.Fatalf("first apply: %v", err)
		}
		before := f.ch.Latest.State.BalanceA.String()
		// Recovery re-applying the same leg must change nothing.
		for i := 0; i < 3; i++ {
			if err := f.ch.Accept(leg); err == nil {
				t.Fatal("re-applying a leg succeeded; recovery would double-settle")
			}
		}
		if f.ch.Latest.State.BalanceA.String() != before {
			t.Fatal("re-application mutated the channel")
		}
	})

	t.Run("mp/channels survive restart independently", func(t *testing.T) {
		cover("channels survive restart independently")
		f := newP13Fixture(t)
		dir, err := os.MkdirTemp("", "p13mp")
		if err != nil {
			t.Fatalf("tempdir: %v", err)
		}
		defer os.RemoveAll(dir)
		store, err := OpenStore(dir)
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		occ, err := f.chain.ReadChannel(t.Context(), f.con, f.id)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := store.TrackFromChain(f.chainI, f.con, occ); err != nil {
			t.Fatalf("track: %v", err)
		}
		if err := store.Accept(f.id, f.signed(t, f.state(8, anon(325), anon(675)))); err != nil {
			t.Fatalf("accept: %v", err)
		}
		reopened, err := OpenStore(dir)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		got, ok := reopened.Get(f.id)
		if !ok || got.Latest.State.Nonce != 8 {
			t.Fatal("a committed leg did not survive restart")
		}
		// The channel survives. What does NOT survive is the knowledge that
		// this leg belonged to a multi-path payment — see the GAP rows.
	})

	// ---- hub and routing properties -------------------------------------

	t.Run("mp/fragments never share a hub", func(t *testing.T) {
		cover("fragments never share a hub")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		seen := map[string]int{}
		for i, f := range plan.Fragments {
			for _, hop := range f.Route {
				if prev, dup := seen[hop.Operator]; dup {
					t.Fatalf("fragments %d and %d both transit operator %q; "+
						"its liquidity would be double-counted and it would see both legs",
						prev, i, hop.Operator)
				}
				seen[hop.Operator] = i
			}
		}
	})

	t.Run("mp/hub holdings stay zero across fragments", func(t *testing.T) {
		cover("hub holdings stay zero across fragments")
		// One hub per fragment, each carrying its leg. No hub ever owns value,
		// at any point in any leg's life.
		hubs := []*Hub{NewHub(), NewHub(), NewHub()}
		secrets := make([]Preimage, len(hubs))
		conds := make([]Hash, len(hubs))
		for i, h := range hubs {
			if err := h.OpenReader(p13Tipper, 1000); err != nil {
				t.Fatalf("hub %d: %v", i, err)
			}
			h.FundRecipient(p13Recipient, 1000)
			secrets[i][31] = byte(i + 1)
			conds[i] = HashOf(secrets[i])
			if _, err := h.Reserve(p13Tipper, p13Recipient, 100, conds[i]); err != nil {
				t.Fatalf("hub %d reserve: %v", i, err)
			}
			if h.HubHoldings() != 0 {
				t.Fatalf("hub %d holds value mid-flight", i)
			}
		}
		// A fragment must settle ONLY against its own condition. If one
		// fragment's preimage could settle another, a recipient revealing once
		// would drain every leg — and the per-fragment lock chains that make
		// fragments unlinkable would be pointless.
		for i, h := range hubs {
			for j := range hubs {
				if i == j {
					continue
				}
				if err := h.Deliver(conds[i], secrets[j]); err == nil {
					t.Fatalf("fragment %d settled using fragment %d's preimage", i, j)
				}
			}
		}
		for i, h := range hubs {
			if err := h.Deliver(conds[i], secrets[i]); err != nil {
				t.Fatalf("hub %d deliver: %v", i, err)
			}
			if h.HubHoldings() != 0 {
				t.Fatalf("hub %d retained value after delivery", i)
			}
		}
	})

	t.Run("mp/per-leg refund restores both sides", func(t *testing.T) {
		cover("per-leg refund restores both sides")
		h := NewHub()
		if err := h.OpenReader(p13Tipper, 500); err != nil {
			t.Fatalf("OpenReader: %v", err)
		}
		h.FundRecipient(p13Recipient, 500)
		before := snapshot(h, p13Tipper, p13Recipient)
		var secret Preimage
		secret[31] = 9
		cond := HashOf(secret)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 120, cond); err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := h.Cancel(cond); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if snapshot(h, p13Tipper, p13Recipient) != before {
			t.Fatal("a leg refund did not restore both sides")
		}
	})

	t.Run("mp/cancelling one path leaves siblings intact", func(t *testing.T) {
		cover("cancelling one path leaves siblings intact")
		hubA, hubB := NewHub(), NewHub()
		for _, h := range []*Hub{hubA, hubB} {
			if err := h.OpenReader(p13Tipper, 500); err != nil {
				t.Fatalf("OpenReader: %v", err)
			}
			h.FundRecipient(p13Recipient, 500)
		}
		var sA, sB Preimage
		sA[31], sB[31] = 1, 2
		condA, condB := HashOf(sA), HashOf(sB)
		if _, err := hubA.Reserve(p13Tipper, p13Recipient, 100, condA); err != nil {
			t.Fatalf("A: %v", err)
		}
		if _, err := hubB.Reserve(p13Tipper, p13Recipient, 150, condB); err != nil {
			t.Fatalf("B: %v", err)
		}
		beforeB := snapshot(hubB, p13Tipper, p13Recipient)

		if err := hubA.Cancel(condA); err != nil {
			t.Fatalf("cancel A: %v", err)
		}
		if snapshot(hubB, p13Tipper, p13Recipient) != beforeB {
			t.Fatal("cancelling one path changed a sibling path's accounting")
		}
		// B must still settle normally afterwards.
		if err := hubB.Deliver(condB, sB); err != nil {
			t.Fatalf("sibling path could not settle after a cancel elsewhere: %v", err)
		}
		// A's cancel must not have let A settle too.
		if err := hubA.Deliver(condA, sA); err == nil {
			t.Fatal("a cancelled path settled anyway")
		}
	})

	t.Run("mp/per leg unwind is independent", func(t *testing.T) {
		cover("per leg unwind is independent")
		// A stalled leg (never delivered, never cancelled) must not block a
		// sibling from resolving.
		stalled, healthy := NewHub(), NewHub()
		for _, h := range []*Hub{stalled, healthy} {
			if err := h.OpenReader(p13Tipper, 500); err != nil {
				t.Fatalf("OpenReader: %v", err)
			}
			h.FundRecipient(p13Recipient, 500)
		}
		var s1, s2 Preimage
		s1[31], s2[31] = 3, 4
		c1, c2 := HashOf(s1), HashOf(s2)
		if _, err := stalled.Reserve(p13Tipper, p13Recipient, 100, c1); err != nil {
			t.Fatalf("stalled: %v", err)
		}
		if _, err := healthy.Reserve(p13Tipper, p13Recipient, 100, c2); err != nil {
			t.Fatalf("healthy: %v", err)
		}
		if err := healthy.Deliver(c2, s2); err != nil {
			t.Fatalf("a healthy leg could not settle while a sibling stalled: %v", err)
		}
		if stalled.InFlight() != 100 {
			t.Fatal("the stalled leg was resolved by its sibling settling")
		}
	})

	t.Run("mp/within-route expiry ladder", func(t *testing.T) {
		cover("within-route expiry ladder")
		// Exercises the REAL planner. An earlier version of this test computed
		// the ladder inline and therefore tested nothing — it would have passed
		// with the implementation deleted.
		req := planReq(t)
		plan, err := PlanPayment(req)
		if err != nil {
			t.Fatalf("PlanPayment: %v", err)
		}
		if len(plan.Route) < 2 {
			t.Fatalf("route has %d hops; the ladder needs at least 2 to mean anything",
				len(plan.Route))
		}
		// Peel each hop's instruction with the shared secret that hop would
		// hold, which is what a router actually does.
		var prev uint64
		for i, c := range plan.Route {
			shared := HopSharedSecret(req.Seed, plan.Packet.EphemeralPublicKey, c.NodeID)
			hop, err := plan.Packet.Peel(shared)
			if err != nil {
				t.Fatalf("hop %d could not peel its own instruction: %v", i, err)
			}
			if hop.OutgoingExpiry == 0 {
				t.Fatalf("hop %d has no outgoing expiry", i)
			}
			if i > 0 && hop.OutgoingExpiry >= prev {
				t.Fatalf("hop %d expiry %d is not strictly shorter than hop %d's %d; "+
					"an intermediary could be paid downstream with no time to claim upstream",
					i, hop.OutgoingExpiry, i-1, prev)
			}
			prev = hop.OutgoingExpiry
		}
	})

	t.Run("mp/no aggregate write path", func(t *testing.T) {
		cover("no aggregate write path")
		// Channel.Accept is the only mutator. If an aggregate executor is ever
		// written, it MUST go through Accept per channel rather than writing
		// balances directly — this pins that there is currently no other door.
		have := methodNames(&Channel{})
		for _, forbidden := range []string{"SetBalances", "ApplyAggregate", "ApplyPlan", "ForceState"} {
			if have[forbidden] {
				t.Fatalf("Channel.%s exists — an aggregate path can now write balances "+
					"without Accept's conservation and nonce checks", forbidden)
			}
		}
		// And the store's write surface funnels through Accept/Update only.
		st := methodNames(&Store{})
		for _, forbidden := range []string{"WritePlan", "ApplySplitPlan", "SettleMultipath"} {
			if st[forbidden] {
				t.Fatalf("Store.%s exists — see doc/p13-multipath-security-table.md row 25", forbidden)
			}
		}
	})

	// ---- formerly gaps, now enforced by the executor ---------------------

	t.Run("mp/aggregate settlement accounting", func(t *testing.T) {
		cover("aggregate settlement accounting")
		f := newMPFixture(t, 3, anon(500))
		ctx := t.Context()
		pay := f.payment(t, [32]byte{31: 100}, 20, 30, 50)
		if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		// Locked is NOT delivered. Counting a lock as settled is how a payer
		// would be told a payment succeeded while the recipient holds nothing.
		if got := f.exec.Summarise(pay).SettledAmount; got.Sign() != 0 {
			t.Fatalf("locked-but-unsettled value counted as delivered: %s", got)
		}
		if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
			t.Fatalf("Settle: %v", err)
		}
		out := f.exec.Summarise(pay)
		if out.SettledAmount.Cmp(pay.Total) != 0 {
			t.Fatalf("delivered %s, total %s", out.SettledAmount, pay.Total)
		}
		f.conserves(t, pay)
	})

	t.Run("mp/cross-fragment expiry ordering", func(t *testing.T) {
		cover("cross-fragment expiry ordering")
		f := newMPFixture(t, 2, anon(500))
		// A leg outliving the payment deadline is refused at construction, so
		// the payer's exposure across fragments is bounded by one number.
		_, err := BuildPayment([32]byte{31: 101}, f.secret, anon(100), mpDeadline,
			f.channels, []*big.Int{anon(50), anon(50)},
			[]int64{mpExpiry, mpDeadline + 1})
		if !errors.Is(err, ErrFragmentExpiryUnsafe) {
			t.Fatalf("a fragment outliving the deadline was accepted: %v", err)
		}
		// And every leg of a valid payment carries an expiry within it.
		pay := f.payment(t, [32]byte{31: 102}, 50, 50)
		for _, leg := range pay.Legs {
			if leg.Expiry <= 0 || leg.Expiry > pay.Deadline {
				t.Fatalf("leg %d expiry %d outside the deadline %d",
					leg.Index, leg.Expiry, pay.Deadline)
			}
		}
	})

	t.Run("mp/partial path failure", func(t *testing.T) {
		cover("partial path failure")
		f := newMPFixture(t, 3, anon(500))
		ctx := t.Context()
		pay := f.payment(t, [32]byte{31: 103}, 20, 30, 50)
		peers := func(ch [32]byte) (Peer, error) {
			if ch == pay.Legs[1].Channel {
				return deadPeer{}, nil
			}
			return f.peers(t)(ch)
		}
		errs, err := f.exec.Lock(ctx, pay, peers)
		if err != nil {
			t.Fatalf("Lock: %v", err)
		}
		if errs[1] == nil {
			t.Fatal("a dead counterparty reported success")
		}
		if errs[0] != nil || errs[2] != nil {
			t.Fatal("one failing path prevented its siblings")
		}
		f.conserves(t, pay)
	})

	t.Run("mp/plan level replay identity", func(t *testing.T) {
		cover("plan level replay identity")
		f := newMPFixture(t, 2, anon(500))
		id := [32]byte{31: 104}
		a := f.payment(t, id, 40, 60)
		b := f.payment(t, id, 40, 60)
		// The same payment id must re-derive identical intents — that is what
		// makes a whole-payment replay recognisable rather than a second payment.
		for i := range a.Legs {
			if a.Legs[i].Intent != b.Legs[i].Intent {
				t.Fatalf("leg %d intent is not stable across rebuilds", i)
			}
		}
		// A DIFFERENT payment id must not collide with it.
		c := f.payment(t, [32]byte{31: 105}, 40, 60)
		for i := range a.Legs {
			if a.Legs[i].Intent == c.Legs[i].Intent {
				t.Fatalf("leg %d intent collides across payments", i)
			}
		}
	})

	t.Run("mp/partial settlement", func(t *testing.T) {
		cover("partial settlement")
		f := newMPFixture(t, 2, anon(500))
		ctx := t.Context()
		pay := f.payment(t, [32]byte{31: 106}, 40, 60)
		if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		// Settle one leg only.
		leg := pay.Legs[0]
		tr := StateTransition{Kind: KindLockSettle, LockID: leg.LockID,
			Preimage: FragmentPreimage(f.secret, pay.Legs[0].Intent)}
		if _, err := f.payer.coord.Pay(ctx, leg.Channel, settleIntent(leg.Intent), tr,
			directPeer{t, f.payees[0].coord}); err != nil {
			t.Fatalf("settle one leg: %v", err)
		}
		out := f.exec.Summarise(pay)
		// It must report what was DELIVERED, and must not call itself complete.
		if out.Complete(pay) {
			t.Fatal("a partially settled payment reported itself complete")
		}
		if out.SettledAmount.Cmp(anon(40)) != 0 {
			t.Fatalf("delivered %s, want 40", out.SettledAmount)
		}
		f.conserves(t, pay)
	})

	t.Run("mp/partial refund reconciliation", func(t *testing.T) {
		cover("partial refund reconciliation")
		f := newMPFixture(t, 2, anon(500))
		ctx := t.Context()
		pay := f.payment(t, [32]byte{31: 107}, 40, 60)
		if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		leg := pay.Legs[0]
		tr := StateTransition{Kind: KindLockSettle, LockID: leg.LockID,
			Preimage: FragmentPreimage(f.secret, pay.Legs[0].Intent)}
		if _, err := f.payer.coord.Pay(ctx, leg.Channel, settleIntent(leg.Intent), tr,
			directPeer{t, f.payees[0].coord}); err != nil {
			t.Fatalf("settle leg 0: %v", err)
		}
		delivered := f.exec.Summarise(pay).SettledAmount

		f.advanceTo(mpExpiry + 120)
		if _, err := f.exec.Refund(ctx, pay, f.peers(t)); err != nil {
			t.Fatalf("Refund: %v", err)
		}
		out := f.exec.Summarise(pay)
		// Refunding must not touch the settled leg: that would pay it twice.
		if out.Settled != 1 || out.Refunded != 1 {
			t.Fatalf("expected 1 settled and 1 refunded: %+v", out)
		}
		if out.SettledAmount.Cmp(delivered) != 0 {
			t.Fatalf("a refund changed delivered value: %s -> %s", delivered, out.SettledAmount)
		}
		f.conserves(t, pay)
	})

	t.Run("mp/aggregate stall resolution", func(t *testing.T) {
		cover("aggregate stall resolution")
		f := newMPFixture(t, 2, anon(500))
		ctx := t.Context()
		pay := f.payment(t, [32]byte{31: 108}, 30, 70)
		if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		// Nobody ever settles. The locked value must not sit forever: reaching
		// the expiry lets it be unwound, and both sides get their value back.
		f.advanceTo(mpExpiry + 120)
		errs, err := f.exec.Refund(ctx, pay, f.peers(t))
		if err != nil {
			t.Fatalf("Refund: %v", err)
		}
		noErrs(t, "refund", errs)
		out := f.exec.Summarise(pay)
		if out.Refunded != 2 || out.SettledAmount.Sign() != 0 {
			t.Fatalf("stalled payment did not unwind: %+v", out)
		}
		f.conserves(t, pay)
	})

	t.Run("mp/plan is persisted", func(t *testing.T) {
		cover("plan is persisted")
		f := newMPFixture(t, 3, anon(500))
		id := [32]byte{31: 109}
		pay := f.payment(t, id, 20, 30, 50)
		// The journal must exist BEFORE any leg commits, or a crash mid-flight
		// leaves committed money with nothing recording what it belonged to.
		if _, err := f.exec.LoadJournal(id); err == nil {
			t.Fatal("a journal existed before the payment was journalled")
		}
		if err := f.exec.Journal(pay); err != nil {
			t.Fatalf("Journal: %v", err)
		}
		loaded, err := f.exec.LoadJournal(id)
		if err != nil {
			t.Fatalf("LoadJournal: %v", err)
		}
		if len(loaded.Legs) != 3 || loaded.Total.Cmp(pay.Total) != 0 {
			t.Fatalf("journal round trip lost data: %+v", loaded)
		}
		for i := range pay.Legs {
			if loaded.Legs[i].Intent != pay.Legs[i].Intent ||
				loaded.Legs[i].Amount.Cmp(pay.Legs[i].Amount) != 0 {
				t.Fatalf("leg %d did not round trip", i)
			}
		}
	})

	t.Run("mp/resumption after restart", func(t *testing.T) {
		cover("resumption after restart")
		f := newMPFixture(t, 3, anon(500))
		ctx := t.Context()
		id := [32]byte{31: 110}
		pay := f.payment(t, id, 20, 30, 50)
		// Commit one leg, then lose the process.
		peers := func(ch [32]byte) (Peer, error) {
			if ch == pay.Legs[0].Channel {
				return f.peers(t)(ch)
			}
			return deadPeer{}, nil
		}
		if _, err := f.exec.Lock(ctx, pay, peers); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		revived, err := NewMultipathExecutor(f.payer.coord, f.dir)
		if err != nil {
			t.Fatalf("revived: %v", err)
		}
		loaded, err := revived.LoadJournal(id)
		if err != nil {
			t.Fatalf("LoadJournal: %v", err)
		}
		// Recovery must read the CHANNELS: one leg really landed, two did not.
		if got := revived.Summarise(loaded).Locked; got != 1 {
			t.Fatalf("recovery trusted the previous process's intent: %d locked", got)
		}
		secret := f.secret
		out, errs, err := revived.Resume(ctx, id, &secret, f.peers(t))
		if err != nil {
			t.Fatalf("Resume: %v", err)
		}
		noErrs(t, "resume", errs)
		if !out.Complete(loaded) {
			t.Fatalf("resume did not complete: %+v", out)
		}
		f.conserves(t, loaded)
	})

	t.Run("mp/aggregate recovery is idempotent", func(t *testing.T) {
		cover("aggregate recovery is idempotent")
		f := newMPFixture(t, 2, anon(500))
		ctx := t.Context()
		id := [32]byte{31: 111}
		pay := f.payment(t, id, 45, 55)
		if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		secret := f.secret
		first, _, err := f.exec.Resume(ctx, id, &secret, f.peers(t))
		if err != nil {
			t.Fatalf("Resume: %v", err)
		}
		// Resuming repeatedly must converge on the same result, not pay again.
		for i := 0; i < 3; i++ {
			again, _, err := f.exec.Resume(ctx, id, &secret, f.peers(t))
			if err != nil {
				t.Fatalf("Resume %d: %v", i, err)
			}
			if again.SettledAmount.Cmp(first.SettledAmount) != 0 {
				t.Fatalf("resume %d moved more value: %s -> %s",
					i, first.SettledAmount, again.SettledAmount)
			}
		}
		f.conserves(t, pay)
	})

	t.Run("mp/real split plan is executable", func(t *testing.T) {
		cover("real split plan is executable")
		f := newMPFixture(t, 3, anon(500))
		ctx := t.Context()
		c := DefaultCurve()
		_, Z, err := NewSecret(c)
		if err != nil {
			t.Fatalf("NewSecret: %v", err)
		}
		plan, err := Split(c, Z, Amount(120_000), threeIndependentRoutes())
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		pay, err := PaymentFromSplitPlan(plan, [32]byte{31: 130}, f.secret,
			f.channels[:len(plan.Fragments)], mpClock, 900, mpClock+86_400)
		if err != nil {
			t.Fatalf("PaymentFromSplitPlan: %v", err)
		}
		if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
			t.Fatalf("Settle: %v", err)
		}
		if !f.exec.Summarise(pay).Complete(pay) {
			t.Fatal("a real Split plan did not settle through the executor")
		}
		f.conserves(t, pay)
	})

	t.Run("mp/expiry from the actual route", func(t *testing.T) {
		cover("expiry from the actual route")
		f := newMPFixture(t, 3, anon(500))
		c := DefaultCurve()
		_, Z, _ := NewSecret(c)
		plan, err := Split(c, Z, Amount(120_000), [][]Candidate{
			routeOf("x1", "x2"), routeOf("y1", "y2", "y3"),
		})
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		pay, err := PaymentFromSplitPlan(plan, [32]byte{31: 131}, f.secret,
			f.channels[:len(plan.Fragments)], mpClock, 900, mpClock+86_400)
		if err != nil {
			t.Fatalf("PaymentFromSplitPlan: %v", err)
		}
		// Each window must come from that fragment's own hop count, not a
		// constant and not recomputed here from the same expression: the hop
		// count is read back off the PLAN.
		for i, leg := range pay.Legs {
			hops := len(plan.Fragments[i].Route)
			if leg.Expiry != mpClock+900*int64(hops+1) {
				t.Fatalf("fragment %d (%d hops) got expiry %d", i, hops, leg.Expiry)
			}
		}
	})

	// ---- the audit ------------------------------------------------------

	t.Run("spec coverage", func(t *testing.T) {
		var missing []string
		for _, row := range p13MultipathSpec {
			if !covered["mp/"+row.name] {
				missing = append(missing, row.name+" ("+row.expected+")")
			}
		}
		if len(missing) > 0 {
			t.Fatalf("%d multi-path requirement(s) have no test:\n  %v", len(missing), missing)
		}
		var gaps int
		for _, row := range p13MultipathSpec {
			if len(row.name) > 4 && row.name[:4] == "GAP " {
				gaps++
			}
		}
		t.Logf("all %d multi-path rows exercised: %d enforced, %d gaps remaining",
			len(p13MultipathSpec), len(p13MultipathSpec)-gaps, gaps)
	})
}
