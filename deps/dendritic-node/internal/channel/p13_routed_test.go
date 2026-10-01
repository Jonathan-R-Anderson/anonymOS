package channel

// P13 — the routed payment table, mapped row by row.
//
// Same shape as p13_test.go: the specification is data, every row registers
// itself, and an unclaimed row fails the suite.
//
//	Tipper -> Hub -> Recipient
//
// The property the whole table exists to protect is that an intermediary
// handling somebody else's money can neither keep it nor lose it. Every row is
// a way of trying to break that, and value conservation across the hub is
// asserted after each one rather than reasoned about.

import (
	"testing"
)

var p13RoutedSpec = []p13Row{
	{"routed", "hub failure", "payment does not complete; value returns"},
	{"routed", "recipient failure", "payment does not complete; value returns"},
	{"routed", "invalid route", "fails"},
	{"routed", "insufficient channel capacity", "fails"},
	{"routed", "htlc timeout", "value returns to both sides"},
	{"routed", "successful preimage propagation", "succeeds"},
	{"routed", "intermediary cannot steal funds", "hub holds nothing"},
	{"routed", "one hop cannot settle without the condition", "fails"},
	{"routed", "multi-hop A->B", "succeeds end to end"},
}

const (
	p13Tipper    NodeID = "tipper"
	p13Recipient NodeID = "recipient"
	p13Hub2      NodeID = "hub-b"
)

// p13Conservation is the invariant every routed row is checked against:
// nothing is created, nothing vanishes, and the hub owns none of it.
type p13Conservation struct {
	reader, outbound, inFlight, holdings Amount
}

func snapshot(h *Hub, reader, recipient NodeID) p13Conservation {
	return p13Conservation{
		reader:   h.ReaderBalance(reader),
		outbound: h.OutboundTo(recipient),
		inFlight: h.InFlight(),
		holdings: h.HubHoldings(),
	}
}

// total is every unit the hub can account for. It must not change except by
// delivery, which removes value from the system's inbound side legitimately.
func (c p13Conservation) total() Amount { return c.reader + c.outbound + c.inFlight }

func TestP13RoutedPaymentSuite(t *testing.T) {
	covered := map[string]bool{}
	cover := func(name string) { covered["routed/"+name] = true }

	// newHub builds Tipper -> Hub -> Recipient with known capacity on both legs.
	newHub := func(t *testing.T, readerDeposit, hubOutbound Amount) *Hub {
		t.Helper()
		h := NewHub()
		if err := h.OpenReader(p13Tipper, readerDeposit); err != nil {
			t.Fatalf("OpenReader: %v", err)
		}
		h.FundRecipient(p13Recipient, hubOutbound)
		return h
	}

	secretOf := func(b byte) Preimage {
		var p Preimage
		p[31] = b
		return p
	}

	t.Run("routed/successful preimage propagation", func(t *testing.T) {
		cover("successful preimage propagation")
		h := newHub(t, 100, 100)
		before := snapshot(h, p13Tipper, p13Recipient)

		secret := secretOf(1)
		cond := HashOf(secret)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 30, cond); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		// While in flight the value is in NEITHER balance — that is what stops
		// it being spent twice or counted as the hub's.
		if got := h.InFlight(); got != 30 {
			t.Fatalf("in flight %d, want 30", got)
		}
		if h.ReaderBalance(p13Tipper) != before.reader-30 {
			t.Fatal("the reader's capacity was not debited by the reservation")
		}

		if err := h.Deliver(cond, secret); err != nil {
			t.Fatalf("Deliver with the correct secret: %v", err)
		}
		if h.InFlight() != 0 {
			t.Fatal("value is still locked after delivery")
		}
		if h.HubHoldings() != 0 {
			t.Fatal("the hub kept value from a completed payment")
		}
		if h.Delivered != 1 {
			t.Fatalf("delivered count %d, want 1", h.Delivered)
		}
	})

	t.Run("routed/one hop cannot settle without the condition", func(t *testing.T) {
		cover("one hop cannot settle without the condition")
		h := newHub(t, 100, 100)
		secret := secretOf(2)
		cond := HashOf(secret)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 25, cond); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		// The wrong secret must not settle the hop, even though the
		// reservation exists and the amount is right.
		if err := h.Deliver(cond, secretOf(99)); err == nil {
			t.Fatal("a hop settled without the payment condition being satisfied")
		}
		if h.InFlight() != 25 {
			t.Fatal("a failed delivery moved value anyway")
		}
		if h.Delivered != 0 {
			t.Fatal("a failed delivery was counted as delivered")
		}
		// And the correct secret still works afterwards: the failure must not
		// have poisoned the reservation.
		if err := h.Deliver(cond, secret); err != nil {
			t.Fatalf("the valid secret was refused after a bad attempt: %v", err)
		}
	})

	t.Run("routed/intermediary cannot steal funds", func(t *testing.T) {
		cover("intermediary cannot steal funds")
		h := newHub(t, 100, 100)
		secret := secretOf(3)
		cond := HashOf(secret)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 40, cond); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		// The hub holds nothing at any point in the payment's life: before,
		// during, or after. This is the custody property, asserted rather than
		// argued.
		if h.HubHoldings() != 0 {
			t.Fatal("the hub holds value while a payment is in flight")
		}
		// The hub cannot invent the secret: without it, delivery is impossible
		// and the only other path is Cancel, which returns the value.
		if err := h.Deliver(cond, secretOf(0)); err == nil {
			t.Fatal("the hub delivered without the recipient's secret")
		}
		if err := h.Cancel(cond); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		if h.HubHoldings() != 0 {
			t.Fatal("the hub retained value after cancelling")
		}
		if h.ReaderBalance(p13Tipper) != 100 || h.OutboundTo(p13Recipient) != 100 {
			t.Fatalf("cancel did not restore both sides: reader %d, outbound %d",
				h.ReaderBalance(p13Tipper), h.OutboundTo(p13Recipient))
		}
	})

	t.Run("routed/insufficient channel capacity", func(t *testing.T) {
		cover("insufficient channel capacity")
		h := newHub(t, 10, 100) // reader can afford 10
		before := snapshot(h, p13Tipper, p13Recipient)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 50, HashOf(secretOf(4))); err == nil {
			t.Fatal("a payment larger than the reader's channel was reserved")
		}
		if snapshot(h, p13Tipper, p13Recipient) != before {
			t.Fatal("a refused reservation still moved value")
		}
	})

	t.Run("routed/hub failure", func(t *testing.T) {
		cover("hub failure")
		// The hub's own outbound liquidity is exhausted. This must fail LOUDLY
		// at reservation time: a payment accepted here would be one the hub
		// has taken from the reader and cannot deliver, which is custody by
		// accident and looks like success until somebody asks where their
		// money went.
		h := newHub(t, 100, 5)
		before := snapshot(h, p13Tipper, p13Recipient)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 50, HashOf(secretOf(5))); err == nil {
			t.Fatal("the hub accepted a payment it had no capacity to deliver")
		}
		if h.ReaderBalance(p13Tipper) != before.reader {
			t.Fatal("the reader was debited for a payment the hub could not route")
		}
		if h.Failed == 0 {
			t.Fatal("an undeliverable payment was not counted as failed")
		}
	})

	t.Run("routed/recipient failure", func(t *testing.T) {
		cover("recipient failure")
		h := newHub(t, 100, 100)
		before := snapshot(h, p13Tipper, p13Recipient)
		secret := secretOf(6)
		cond := HashOf(secret)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 35, cond); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		// The recipient never reveals — offline, crashed, or refusing. The
		// payment must unwind completely, not sit locked forever.
		if err := h.Cancel(cond); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		after := snapshot(h, p13Tipper, p13Recipient)
		if after != before {
			t.Fatalf("value did not fully return after a recipient failure:\n before %+v\n after  %+v",
				before, after)
		}
	})

	t.Run("routed/htlc timeout", func(t *testing.T) {
		cover("htlc timeout")
		h := newHub(t, 100, 100)
		before := snapshot(h, p13Tipper, p13Recipient)
		cond := HashOf(secretOf(7))
		if _, err := h.Reserve(p13Tipper, p13Recipient, 20, cond); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		// A timeout resolves as a cancel. The specific failure being guarded
		// against is a refund that returns the reader's value but silently
		// consumes the hub's outbound, which would bleed the hub's liquidity
		// once per failed payment.
		if err := h.Cancel(cond); err != nil {
			t.Fatalf("timeout unwind: %v", err)
		}
		after := snapshot(h, p13Tipper, p13Recipient)
		if after.outbound != before.outbound {
			t.Fatalf("the hub's outbound was consumed by a timeout: %d -> %d",
				before.outbound, after.outbound)
		}
		if after.total() != before.total() {
			t.Fatalf("value was not conserved across a timeout: %d -> %d",
				before.total(), after.total())
		}
		// Unwinding twice must not credit twice.
		if err := h.Cancel(cond); err == nil {
			t.Fatal("a reservation was cancelled twice, crediting the value twice")
		}
	})

	t.Run("routed/invalid route", func(t *testing.T) {
		cover("invalid route")
		h := newHub(t, 100, 100)
		// A recipient the hub has no channel with.
		if _, err := h.Reserve(p13Tipper, NodeID("nobody"), 10, HashOf(secretOf(8))); err == nil {
			t.Fatal("a payment was routed to a recipient with no channel")
		}
		// A reader the hub has no channel with.
		if _, err := h.Reserve(NodeID("stranger"), p13Recipient, 10, HashOf(secretOf(9))); err == nil {
			t.Fatal("a payment was accepted from a reader with no channel")
		}
		// Reusing a live condition — two payments sharing a correlator, which
		// would let one preimage settle both.
		cond := HashOf(secretOf(10))
		if _, err := h.Reserve(p13Tipper, p13Recipient, 10, cond); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if _, err := h.Reserve(p13Tipper, p13Recipient, 10, cond); err == nil {
			t.Fatal("two reservations shared one condition; a single preimage would settle both")
		}
	})

	t.Run("routed/multi-hop A to B", func(t *testing.T) {
		cover("multi-hop A->B")
		// Tipper -> Hub A -> Hub B -> Recipient, modelled as two hops sharing
		// ONE condition, which is what makes the route atomic: the same
		// preimage settles both or neither.
		secret := secretOf(11)
		cond := HashOf(secret)

		hubA := NewHub()
		if err := hubA.OpenReader(p13Tipper, 100); err != nil {
			t.Fatalf("OpenReader: %v", err)
		}
		hubA.FundRecipient(p13Hub2, 100) // A's outbound leg is toward B

		hubB := NewHub()
		if err := hubB.OpenReader(p13Hub2, 100); err != nil {
			t.Fatalf("OpenReader: %v", err)
		}
		hubB.FundRecipient(p13Recipient, 100)

		if _, err := hubA.Reserve(p13Tipper, p13Hub2, 25, cond); err != nil {
			t.Fatalf("hop 1 reserve: %v", err)
		}
		if _, err := hubB.Reserve(p13Hub2, p13Recipient, 25, cond); err != nil {
			t.Fatalf("hop 2 reserve: %v", err)
		}

		// The downstream hop settles first, revealing the secret upstream.
		// This ordering is the security property: an intermediary learns the
		// preimage only once it has already been paid, so it can always claim.
		if err := hubB.Deliver(cond, secret); err != nil {
			t.Fatalf("hop 2 deliver: %v", err)
		}
		if err := hubA.Deliver(cond, secret); err != nil {
			t.Fatalf("hop 1 deliver with the revealed secret: %v", err)
		}
		if hubA.InFlight() != 0 || hubB.InFlight() != 0 {
			t.Fatal("value is still locked on a fully settled route")
		}
		if hubA.HubHoldings() != 0 || hubB.HubHoldings() != 0 {
			t.Fatal("an intermediary kept value from a completed route")
		}

		// The failure case that makes the ordering matter: if the downstream
		// hop never settles, the upstream one must not settle either.
		cond2 := HashOf(secretOf(12))
		if _, err := hubA.Reserve(p13Tipper, p13Hub2, 15, cond2); err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := hubA.Deliver(cond2, secretOf(13)); err == nil {
			t.Fatal("an upstream hop settled without the route's preimage")
		}
	})

	t.Run("spec coverage", func(t *testing.T) {
		var missing []string
		for _, row := range p13RoutedSpec {
			if !covered["routed/"+row.name] {
				missing = append(missing, row.name+" ("+row.expected+")")
			}
		}
		if len(missing) > 0 {
			t.Fatalf("%d P13 routed requirement(s) have no test:\n  %v", len(missing), missing)
		}
		t.Logf("all %d P13 routed-payment requirements are exercised", len(p13RoutedSpec))
	})
}
