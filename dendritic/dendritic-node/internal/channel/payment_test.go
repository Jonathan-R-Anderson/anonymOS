package channel

import (
	"errors"
	"math/big"
	"testing"
	"time"
)

func planReq(t *testing.T) PlanRequest {
	t.Helper()
	inv, err := NewInvoice(InvoiceRequest{
		SettlementKey: [32]byte{0x11}, IntroductionNode: "intro",
		MinAmount: 1, MaxAmount: 1000, TTL: time.Hour,
	}, invNow)
	if err != nil {
		t.Fatal(err)
	}
	return PlanRequest{
		Invoice: inv, Amount: 100,
		Candidates: []Candidate{
			cand("a", "acme", "d1"), cand("b", "beta", "d2"), cand("c", "gamma", "d3"),
		},
		Routing: RouteRequest{Hops: 3, MinSuccessRate: 0.5, PrivacyVersion: 1},
		Curve:   EthereumCurve(),
		Now:     invNow,
	}
}

// The nine modules must actually compose. This is the test that would have
// caught them disagreeing about hop counts or ordering.
func TestPlanComposesAllTheParts(t *testing.T) {
	plan, err := PlanPayment(planReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Hops() != 3 {
		t.Errorf("hops = %d, want 3", plan.Hops())
	}
	if len(plan.Locks.Locks) != plan.Hops() {
		t.Errorf("%d locks for %d hops — the lock chain and route disagree",
			len(plan.Locks.Locks), plan.Hops())
	}
	if plan.Packet == nil || len(plan.Packet.Slots) != MaxHops {
		t.Error("packet was not built to full slot count")
	}
	if len(plan.Operators()) != 3 {
		t.Errorf("operators = %v, want 3 distinct", plan.Operators())
	}
}

// Failures must be cheap and ordered: an expired invoice must be caught before
// a route is drawn, so a caller does not leak intent to routers for a payment
// that could never have been made.
func TestExpiredInvoiceFailsBeforeRouting(t *testing.T) {
	req := planReq(t)
	req.Now = invNow.Add(2 * time.Hour)
	// No candidates at all: if routing were attempted first this would fail
	// with a routing error instead of an invoice error.
	req.Candidates = nil
	if _, err := PlanPayment(req); !errors.Is(err, ErrInvoiceExpired) {
		t.Fatalf("got %v, want the invoice error before any routing", err)
	}
}

func TestAmountOutsideTheInvoiceRangeIsRefused(t *testing.T) {
	req := planReq(t)
	req.Amount = 9999
	req.Candidates = nil
	if _, err := PlanPayment(req); !errors.Is(err, ErrAmountOutOfRange) {
		t.Fatalf("got %v, want an amount error before routing", err)
	}
}

// The diversity refusal must reach the caller intact, so it can say WHY rather
// than reporting a generic failure.
func TestDiversityRefusalIsPassedThrough(t *testing.T) {
	req := planReq(t)
	req.Candidates = []Candidate{
		cand("a", "acme", "d1"), cand("b", "acme", "d2"), cand("c", "acme", "d3"),
	}
	_, err := PlanPayment(req)
	var refusal *RouteRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("got %T, want the route refusal to survive", err)
	}
	if refusal.OperatorsFound != 1 {
		t.Errorf("refusal lost its detail: %+v", refusal)
	}
}

// A missing curve must be refused, never defaulted. A payment planned on the
// wrong curve produces locks no contract can settle.
func TestMissingCurveIsRefusedNotDefaulted(t *testing.T) {
	req := planReq(t)
	req.Curve = nil
	if _, err := PlanPayment(req); err == nil {
		t.Fatal("planned a payment with no curve — it would have silently defaulted")
	}
}

// Each hop's instruction must be readable by that hop and no other, and the
// expiries must strictly decrease outward.
func TestPlannedPacketPeelsCorrectlyPerHop(t *testing.T) {
	req := planReq(t)
	plan, err := PlanPayment(req)
	if err != nil {
		t.Fatal(err)
	}
	var previous uint64
	for i, c := range plan.Route {
		shared := HopSharedSecret(req.Seed, plan.Packet.EphemeralPublicKey, c.NodeID)
		hop, err := plan.Packet.Peel(shared)
		if err != nil {
			t.Fatalf("hop %d could not peel its own instruction: %v", i, err)
		}
		if i > 0 && hop.OutgoingExpiry >= previous {
			t.Errorf("hop %d expiry %d does not decrease from %d",
				i, hop.OutgoingExpiry, previous)
		}
		previous = hop.OutgoingExpiry
		if i+1 < len(plan.Route) && hop.NextHop != plan.Route[i+1].NodeID {
			t.Errorf("hop %d points at %q, want %q", i, hop.NextHop, plan.Route[i+1].NodeID)
		}
		if i+1 == len(plan.Route) && hop.BlindedEndpoint == "" {
			t.Error("the exit hop carries no blinded endpoint")
		}
	}
}

// The planned locks must settle on the chain's curve — the whole chain of
// modules is worthless if the composition produces locks that never open.
func TestPlannedLocksSettle(t *testing.T) {
	plan, err := PlanPayment(planReq(t))
	if err != nil {
		t.Fatal(err)
	}
	c := EthereumCurve()
	z := new(big.Int).SetBytes(plan.Secret)
	scalars, err := SettleRoute(c, plan.Locks, z)
	if err != nil {
		t.Fatal(err)
	}
	for i, lock := range plan.Locks.Locks {
		if err := Satisfies(c, lock, scalars[i]); err != nil {
			t.Fatalf("planned hop %d cannot settle: %v", i, err)
		}
	}
}
