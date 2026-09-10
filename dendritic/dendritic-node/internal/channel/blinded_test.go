package channel

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

var invNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

func invReq() InvoiceRequest {
	return InvoiceRequest{
		SettlementKey:    [32]byte{0x11},
		IntroductionNode: "intro-node",
		MinAmount:        1, MaxAmount: 100,
		TTL: time.Hour,
	}
}

// The property everything rests on: two invoices from the SAME recipient must
// share no field. Any stable field would be the recipient's identifier under
// another name.
func TestTwoInvoicesFromOneRecipientShareNothing(t *testing.T) {
	a, err := NewInvoice(invReq(), invNow)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewInvoice(invReq(), invNow)
	if err != nil {
		t.Fatal(err)
	}
	if a.InvoiceID == b.InvoiceID {
		t.Error("invoice ids repeat — every payment to this recipient is linkable")
	}
	if a.BlindedEndpoint == b.BlindedEndpoint {
		t.Error("blinded endpoints repeat — the exit router can link payments")
	}
	if a.RecipientEphemeralKey == b.RecipientEphemeralKey {
		t.Error("the recipient key repeats across invoices")
	}
	if a.Commitment == b.Commitment {
		t.Error("commitments repeat")
	}
}

// The settlement key must never appear in the invoice — it is an input to the
// derivations, not a field.
func TestSettlementKeyNeverAppearsInTheInvoice(t *testing.T) {
	req := invReq()
	req.SettlementKey = [32]byte{0xAB, 0xCD, 0xEF}
	inv, err := NewInvoice(req, invNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][32]byte{
		inv.InvoiceID, inv.BlindedEndpoint, inv.RecipientEphemeralKey, inv.Commitment,
	} {
		if field == req.SettlementKey {
			t.Fatal("the settlement key was published in the invoice")
		}
	}
}

// The exit router must not learn the invoice id, the amount range, or the
// recipient's key — only where to deliver. Asserted against ExitView's actual
// FIELDS by reflection, so adding one is a deliberate act with a failing test
// attached rather than a convenience someone slips in.
func TestExitRouterSeesOnlyTheEndpoint(t *testing.T) {
	inv, _ := NewInvoice(invReq(), invNow)
	view := inv.ViewForExit()
	if view.BlindedEndpoint != inv.BlindedEndpoint {
		t.Error("the exit cannot deliver without the endpoint")
	}

	allowed := map[string]bool{
		"BlindedEndpoint": true, "FinalHopCiphertext": true, "Expiry": true,
	}
	typ := reflect.TypeOf(ExitView{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("ExitView gained %q — every field here is visible to the exit "+
				"router, which must not learn who it is delivering to", name)
		}
	}
	// The fields that would break blinding must be absent by name.
	for _, forbidden := range []string{"InvoiceID", "MinAmount", "MaxAmount", "Commitment", "Recipient"} {
		if _, present := typ.FieldByName(forbidden); present {
			t.Errorf("ExitView exposes %q to the exit router", forbidden)
		}
	}
}

// A single-use invoice must not be payable twice — otherwise a router can
// replay it for its own benefit.
func TestSingleUseInvoiceCannotBePaidTwice(t *testing.T) {
	inv, _ := NewInvoice(invReq(), invNow)
	ledger := NewInvoiceLedger()
	if err := ledger.Claim(inv); err != nil {
		t.Fatalf("first claim failed: %v", err)
	}
	if err := ledger.Claim(inv); !errors.Is(err, ErrInvoiceReused) {
		t.Fatalf("an invoice was paid twice: %v", err)
	}
}

// Streaming is the deliberate exception: one invoice covers many vouchers.
func TestStreamingInvoiceMayBeClaimedRepeatedly(t *testing.T) {
	req := invReq()
	req.Streaming = true
	inv, _ := NewInvoice(req, invNow)
	ledger := NewInvoiceLedger()
	for i := 0; i < 5; i++ {
		if err := ledger.Claim(inv); err != nil {
			t.Fatalf("streaming claim %d failed: %v", i, err)
		}
	}
}

// The commitment is what makes the amount range binding rather than advisory.
func TestAlteredTermsAreDetected(t *testing.T) {
	inv, _ := NewInvoice(invReq(), invNow)
	if err := inv.Validate(invNow); err != nil {
		t.Fatalf("a fresh invoice failed validation: %v", err)
	}
	inv.MaxAmount = 1_000_000 // as a router or a payer might rewrite it
	if err := inv.Validate(invNow); !errors.Is(err, ErrInvoiceMalformed) {
		t.Fatal("an altered amount range was accepted")
	}
}

func TestExpiredInvoiceIsRejected(t *testing.T) {
	inv, _ := NewInvoice(invReq(), invNow)
	if err := inv.Validate(invNow.Add(2 * time.Hour)); !errors.Is(err, ErrInvoiceExpired) {
		t.Fatal("an expired invoice was accepted")
	}
}

func TestAmountRangeIsEnforced(t *testing.T) {
	inv, _ := NewInvoice(invReq(), invNow)
	if err := inv.AcceptsAmount(50); err != nil {
		t.Errorf("rejected an in-range amount: %v", err)
	}
	for _, bad := range []Amount{0, 101, -5} {
		if err := inv.AcceptsAmount(bad); !errors.Is(err, ErrAmountOutOfRange) {
			t.Errorf("accepted out-of-range amount %d", bad)
		}
	}
}

// A range rather than an exact figure is the point: an invoice pinning one
// amount tells anyone who sees it exactly what was paid.
func TestInvoiceCarriesARangeNotAnExactAmount(t *testing.T) {
	inv, _ := NewInvoice(invReq(), invNow)
	if inv.MinAmount == inv.MaxAmount {
		t.Error("the invoice pins a single amount — the payment size is exposed")
	}
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*InvoiceRequest)
	}{
		{"no introduction node", func(r *InvoiceRequest) { r.IntroductionNode = "" }},
		{"no maximum", func(r *InvoiceRequest) { r.MaxAmount = 0 }},
		{"min above max", func(r *InvoiceRequest) { r.MinAmount = 500 }},
		{"negative min", func(r *InvoiceRequest) { r.MinAmount = -1 }},
		{"no ttl", func(r *InvoiceRequest) { r.TTL = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := invReq()
			tc.mut(&r)
			if _, err := NewInvoice(r, invNow); err == nil {
				t.Fatal("accepted a malformed invoice request")
			}
		})
	}
}

// Different recipients must not collide even with identical terms.
func TestDifferentRecipientsProduceDifferentEndpoints(t *testing.T) {
	a := invReq()
	b := invReq()
	b.SettlementKey = [32]byte{0x22}
	ia, _ := NewInvoice(a, invNow)
	ib, _ := NewInvoice(b, invNow)
	if ia.BlindedEndpoint == ib.BlindedEndpoint {
		t.Fatal("two recipients share a blinded endpoint")
	}
}
