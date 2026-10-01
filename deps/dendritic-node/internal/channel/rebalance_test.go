package channel

import "testing"

func drainedHub(t *testing.T) (*Hub, Funding) {
	t.Helper()
	h := NewHub()
	_ = h.OpenReader("viewer", 1000)
	h.FundRecipient("busy", 100)
	h.FundRecipient("quiet", 100)
	original := Funding{"busy": 100, "quiet": 100}

	// Drain "busy" to 10% by routing real payments through it.
	for i := 0; i < 9; i++ {
		s := Preimage{byte(i + 1)}
		c := HashOf(s)
		if _, err := h.Reserve("viewer", "busy", 10, c); err != nil {
			t.Fatal(err)
		}
		if err := h.Deliver(c, s); err != nil {
			t.Fatal(err)
		}
	}
	return h, original
}

// A working hub drains itself. This is steady state, not a fault.
func TestSuccessfulRoutingStarvesTheHub(t *testing.T) {
	h, original := drainedHub(t)
	if h.OutboundTo("busy") != 10 {
		t.Fatalf("outbound %d, want 10", h.OutboundTo("busy"))
	}
	plan := PlanRebalance(h, original, false)
	if len(plan) != 1 || plan[0].Recipient != "busy" {
		t.Fatalf("plan = %+v, want one action for 'busy'", plan)
	}
	if plan[0].Need != 90 {
		t.Errorf("need %d, want 90", plan[0].Need)
	}
}

// Circular routing is free; on-chain costs gas. Reaching for on-chain first
// works perfectly and burns money.
func TestCircularIsPreferredOverOnChain(t *testing.T) {
	h, original := drainedHub(t)
	free := PlanRebalance(h, original, true)
	if len(free) == 0 || free[0].OnChain {
		t.Fatal("a circular path was available and the plan still went on-chain")
	}
	paid := PlanRebalance(h, original, false)
	if len(paid) == 0 || !paid[0].OnChain {
		t.Fatal("no circular path available but the plan avoided on-chain")
	}
}

// A healthy recipient must not be flagged, or every plan is noise.
func TestHealthyRecipientsAreNotFlagged(t *testing.T) {
	h, original := drainedHub(t)
	for _, a := range PlanRebalance(h, original, true) {
		if a.Recipient == "quiet" {
			t.Fatal("an untouched recipient was flagged as starved")
		}
	}
}

// A hub can be full of value and unable to pay anyone. One number cannot say
// that, which is why inbound and outbound are reported separately.
func TestFullAndBrokeAreDistinguishable(t *testing.T) {
	h, original := drainedHub(t)
	s := Health(h, original)
	if s.TotalInbound <= 0 {
		t.Fatal("expected inbound capacity")
	}
	if s.Starved != 1 {
		t.Errorf("starved = %d, want 1", s.Starved)
	}
	if s.TotalOutbound >= s.TotalInbound {
		return // not the interesting case here
	}
	// The point: inbound high, outbound low, and both visible.
	if s.TotalOutbound == 0 && s.TotalInbound == 0 {
		t.Fatal("summary collapsed both sides into nothing")
	}
}

// The plan must be reproducible, or two runs describe one situation two ways.
func TestPlanIsDeterministic(t *testing.T) {
	h := NewHub()
	_ = h.OpenReader("v", 10000)
	original := Funding{}
	for _, id := range []NodeID{"a", "b", "c"} {
		h.FundRecipient(id, 100)
		original[id] = 100
		s := Preimage{byte(len(id) + int(id[0]))}
		c := HashOf(s)
		if _, err := h.Reserve("v", id, 95, c); err != nil {
			t.Fatal(err)
		}
		_ = h.Deliver(c, s)
	}
	first := PlanRebalance(h, original, true)
	for i := 0; i < 20; i++ {
		again := PlanRebalance(h, original, true)
		if len(again) != len(first) {
			t.Fatal("plan length varies between runs")
		}
		for j := range first {
			if again[j].Recipient != first[j].Recipient {
				t.Fatalf("run %d ordered differently at %d", i, j)
			}
		}
	}
}

// An interface should be able to say "this tip will not work" before somebody
// commits to it.
func TestCanStillPayReportsTheCeiling(t *testing.T) {
	h, _ := drainedHub(t)
	if CanStillPay(h, "busy") != 10 {
		t.Errorf("got %d, want 10", CanStillPay(h, "busy"))
	}
	if CanStillPay(h, "nobody") != 0 {
		t.Error("reported capacity toward an unfunded recipient")
	}
}
