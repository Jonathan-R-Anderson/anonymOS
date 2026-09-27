package channel

import (
	"fmt"
	"testing"
	"time"
)

func TestDetectorFindsALeakInAnyEncoding(t *testing.T) {
	d := NewDetector()
	d.Watch("channel", ChannelID("channel-for-alice"))

	if got := d.Scan("log", "forwarding for channel-for-alice"); len(got) == 0 {
		t.Error("missed a plaintext leak")
	}
	if got := d.Scan("log", "id=6368616e6e656c2d666f722d616c696365"); len(got) == 0 {
		t.Error("missed a hex-encoded leak")
	}
	if got := d.Scan("log", "forwarded 1 payment"); len(got) != 0 {
		t.Errorf("false positive: %v", got)
	}
}

// THE regression test. Every error this package can produce is scanned for the
// values that created it — because error messages are the single most likely
// route into a log file.
func TestNoErrorMessageLeaksItsInputs(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	d := NewDetector()

	// The values a real payment would involve.
	reader := NodeID("reader-node-identity")
	recipient := NodeID("streamer-node-identity")
	ch := ChannelID("channel-reader-to-hub")
	secret := Preimage{0xAB, 0xCD}
	amount := Amount(1234567)
	d.Watch("reader", reader)
	d.Watch("recipient", recipient)
	d.Watch("channel", ch)
	d.Watch("secret", [32]byte(secret))
	d.Watch("amount", amount)

	outputs := map[string]string{}
	record := func(where string, err error) {
		if err != nil {
			outputs[where] = err.Error()
		}
	}

	// Hub: the component most likely to know both ends.
	h := NewHub()
	_ = h.OpenReader(reader, 100)
	h.FundRecipient(recipient, 10)
	_, err := h.Reserve(reader, recipient, amount, HashOf(secret))
	record("hub.Reserve.exhausted", err)
	_, err = h.Reserve("unknown-reader", recipient, 1, HashOf(Preimage{0x02}))
	record("hub.Reserve.unknownReader", err)
	record("hub.Deliver.wrongSecret", h.Deliver(HashOf(Preimage{0x03}), Preimage{0x04}))

	// Router: the component that must forget the most.
	r := NewRouter(RouterPolicy{MinTimelockMargin: time.Hour, MaxInFlight: 1}, DeriveKey(seedA))
	hops := []HopInstruction{{NextHop: recipient, OutgoingExpiry: uint64(now.Add(time.Minute).Unix())}}
	p, buildErr := Build([32]byte{0x11}, hops, [][32]byte{{0x22}})
	record("onion.Build", buildErr)
	if p != nil {
		p.Expiry = uint64(now.Add(2 * time.Minute).Unix())
		_, _, ferr := r.Forward(p, [32]byte{0x22}, 1000, now)
		record("router.Forward.tightExpiry", ferr)
		_, _, ferr = r.Forward(p, [32]byte{0x99}, 1000, now)
		record("router.Forward.notForUs", ferr)
	}

	// Channel state machine.
	native, nerr := OpenNative(t.TempDir(), DeriveKey(seedA))
	record("native.Open", nerr)
	if native != nil {
		cid, oerr := native.Open(nil, recipient, 100)
		record("native.OpenChannel", oerr)
		_, perr := native.Pay(nil, cid, amount, "ref")
		record("native.Pay.overdraw", perr)
		_, perr = native.Pay(nil, ch, 1, "ref")
		record("native.Pay.unknownChannel", perr)
	}

	// Invoices and escrow.
	_, ierr := NewInvoice(InvoiceRequest{IntroductionNode: recipient, MaxAmount: 0, TTL: time.Hour}, now)
	record("invoice.New", ierr)
	inv, _ := NewInvoice(InvoiceRequest{SettlementKey: [32]byte(secret),
		IntroductionNode: recipient, MinAmount: 1, MaxAmount: 10, TTL: time.Hour}, now)
	if inv != nil {
		record("invoice.AcceptsAmount", inv.AcceptsAmount(amount))
		record("invoice.Validate", inv.Validate(now.Add(2*time.Hour)))
	}

	// Route selection, which knows the whole candidate set.
	_, rerr := SelectRoute([]Candidate{cand("a", "solo", "d1")},
		RouteRequest{Hops: 3, PrivacyVersion: 1}, [32]byte{1})
	record("route.Select", rerr)

	leaks := d.ScanAll(outputs)
	for _, l := range leaks {
		t.Errorf("%s", l)
	}
	if len(outputs) < 8 {
		t.Fatalf("only exercised %d error paths — the test is not covering enough", len(outputs))
	}
	t.Logf("scanned %d error messages for %d classes of secret", len(outputs), 5)
}

// A router's retained records must survive the same scan.
func TestRouterRecordsCarryNoSecrets(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	next := NodeID("downstream-node-identity")
	d := NewDetector()
	d.Watch("nextHop", next)

	r := NewRouter(RouterPolicy{MinTimelockMargin: time.Minute, MaxInFlight: 5}, DeriveKey(seedA))
	hops := []HopInstruction{{NextHop: next, OutgoingExpiry: uint64(now.Add(30 * time.Minute).Unix())}}
	p, err := Build([32]byte{0x11}, hops, [][32]byte{{0x22}})
	if err != nil {
		t.Fatal(err)
	}
	p.Expiry = uint64(now.Add(time.Hour).Unix())
	if _, _, err := r.Forward(p, [32]byte{0x22}, 1000, now); err != nil {
		t.Fatal(err)
	}
	// Everything the router kept, rendered as a human would log it.
	dump := fmt.Sprintf("%+v", r.Outstanding())
	if leaks := d.Scan("router.Outstanding", dump); len(leaks) > 0 {
		for _, l := range leaks {
			t.Errorf("%s", l)
		}
	}
}

// The hub's summary must not name anyone either.
func TestHubHealthCarriesNoIdentities(t *testing.T) {
	reader, streamer := NodeID("viewer-identity-abc"), NodeID("streamer-identity-xyz")
	d := NewDetector()
	d.Watch("reader", reader)
	d.Watch("recipient", streamer)

	h := NewHub()
	_ = h.OpenReader(reader, 100)
	h.FundRecipient(streamer, 100)
	s := Health(h, Funding{streamer: 100})
	if leaks := d.Scan("hub.Health", fmt.Sprintf("%+v", s)); len(leaks) > 0 {
		for _, l := range leaks {
			t.Errorf("%s", l)
		}
	}
}
