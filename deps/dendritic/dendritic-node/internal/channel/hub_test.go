package channel

import (
	"errors"
	"testing"
)

func hubWith(t *testing.T) (*Hub, Preimage, Hash) {
	t.Helper()
	h := NewHub()
	if err := h.OpenReader("reader", 100); err != nil {
		t.Fatal(err)
	}
	h.FundRecipient("streamer", 50)
	secret := Preimage{0x01}
	return h, secret, HashOf(secret)
}

func TestReaderPaysAStreamerThroughTheHub(t *testing.T) {
	h, secret, cond := hubWith(t)
	if _, err := h.Reserve("reader", "streamer", 5, cond); err != nil {
		t.Fatal(err)
	}
	if h.ReaderBalance("reader") != 95 {
		t.Errorf("reader balance %d, want 95", h.ReaderBalance("reader"))
	}
	if h.OutboundTo("streamer") != 45 {
		t.Errorf("outbound %d, want 45", h.OutboundTo("streamer"))
	}
	if h.InFlight() != 5 {
		t.Errorf("in flight %d, want 5", h.InFlight())
	}
	if err := h.Deliver(cond, secret); err != nil {
		t.Fatal(err)
	}
	if h.InFlight() != 0 || h.Delivered != 1 {
		t.Error("delivery did not clear the reservation")
	}
}

// THE property. If this is ever non-zero the hub is a custodian and the whole
// legal and trust analysis of the product changes.
func TestHubNeverHoldsFunds(t *testing.T) {
	h, secret, cond := hubWith(t)
	_, _ = h.Reserve("reader", "streamer", 20, cond)
	if h.HubHoldings() != 0 {
		t.Fatal("the hub holds funds mid-flight — it has become a custodian")
	}
	_ = h.Deliver(cond, secret)
	if h.HubHoldings() != 0 {
		t.Fatal("the hub retained funds after delivery")
	}
}

// Delivery requires the recipient's secret. The hub cannot pay itself, and
// cannot complete a payment the recipient never acted on.
func TestHubCannotDeliverWithoutTheSecret(t *testing.T) {
	h, _, cond := hubWith(t)
	if _, err := h.Reserve("reader", "streamer", 10, cond); err != nil {
		t.Fatal(err)
	}
	if err := h.Deliver(cond, Preimage{0xFF}); err == nil {
		t.Fatal("the hub delivered without the correct secret")
	}
	if h.InFlight() != 10 {
		t.Error("a failed delivery released the reservation")
	}
}

// Exhaustion must fail LOUDLY. A queued-but-undeliverable payment looks like
// success until a streamer asks where their money is.
func TestExhaustedOutboundFailsLoudly(t *testing.T) {
	h := NewHub()
	_ = h.OpenReader("reader", 1000)
	h.FundRecipient("streamer", 10)
	if _, err := h.Reserve("reader", "streamer", 50, HashOf(Preimage{1})); !errors.Is(err, ErrHubExhausted) {
		t.Fatalf("got %v, want ErrHubExhausted", err)
	}
	// The reader must not have been charged for a payment that never happened.
	if h.ReaderBalance("reader") != 1000 {
		t.Errorf("reader charged %d for an undelivered payment", 1000-h.ReaderBalance("reader"))
	}
}

// Inbound capacity is useless for paying: a reader with plenty cannot pay a
// recipient the hub has not funded. This is the asymmetry that makes routing
// capital-intensive.
func TestInboundCapacityCannotPayAnUnfundedRecipient(t *testing.T) {
	h := NewHub()
	_ = h.OpenReader("reader", 1_000_000)
	if _, err := h.Reserve("reader", "nobody", 1, HashOf(Preimage{1})); !errors.Is(err, ErrNoOutbound) {
		t.Fatalf("got %v, want ErrNoOutbound", err)
	}
}

// Cancel must return value to BOTH sides. Refunding only the reader would
// silently consume the hub's liquidity on every failed payment.
func TestCancelRestoresBothSides(t *testing.T) {
	h, _, cond := hubWith(t)
	_, _ = h.Reserve("reader", "streamer", 30, cond)
	if err := h.Cancel(cond); err != nil {
		t.Fatal(err)
	}
	if h.ReaderBalance("reader") != 100 {
		t.Errorf("reader not refunded: %d", h.ReaderBalance("reader"))
	}
	if h.OutboundTo("streamer") != 50 {
		t.Errorf("hub liquidity leaked on cancel: %d", h.OutboundTo("streamer"))
	}
	if h.InFlight() != 0 {
		t.Error("cancelled reservation still in flight")
	}
}

func TestReaderCannotOverspend(t *testing.T) {
	h, _, cond := hubWith(t)
	if _, err := h.Reserve("reader", "streamer", 500, cond); !errors.Is(err, ErrReaderShort) {
		t.Fatalf("got %v, want ErrReaderShort", err)
	}
}

func TestUnknownReaderIsRefused(t *testing.T) {
	h, _, cond := hubWith(t)
	if _, err := h.Reserve("stranger", "streamer", 1, cond); !errors.Is(err, ErrUnknownReader) {
		t.Fatalf("got %v, want ErrUnknownReader", err)
	}
}

// One condition, one payment. Reusing it would let a reservation be delivered
// twice against a single lock.
func TestConditionCannotBeReused(t *testing.T) {
	h, _, cond := hubWith(t)
	if _, err := h.Reserve("reader", "streamer", 5, cond); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Reserve("reader", "streamer", 5, cond); !errors.Is(err, ErrDoubleSpend) {
		t.Fatalf("got %v, want ErrDoubleSpend", err)
	}
}

// Many small tips must work — the whole point of a hub is that a viewer does
// not open a channel per creator.
func TestOneReaderPaysManyRecipients(t *testing.T) {
	h := NewHub()
	_ = h.OpenReader("viewer", 100)
	for _, who := range []NodeID{"streamerA", "streamerB", "gateway", "storage"} {
		h.FundRecipient(who, 100)
	}
	for i, who := range []NodeID{"streamerA", "streamerB", "gateway", "storage"} {
		secret := Preimage{byte(i + 1)}
		cond := HashOf(secret)
		if _, err := h.Reserve("viewer", who, 10, cond); err != nil {
			t.Fatalf("%s: %v", who, err)
		}
		if err := h.Deliver(cond, secret); err != nil {
			t.Fatalf("%s: %v", who, err)
		}
	}
	if h.ReaderBalance("viewer") != 60 {
		t.Errorf("viewer balance %d, want 60", h.ReaderBalance("viewer"))
	}
	if h.Delivered != 4 || h.HubHoldings() != 0 {
		t.Error("hub accounting drifted across multiple recipients")
	}
}
