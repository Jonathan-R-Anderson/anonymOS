package channel

import (
	"errors"
	"testing"
	"time"
)

var eNow = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
var master = [32]byte{0xAA}

func escrowFor(t *testing.T, index uint64, amount Amount) (*EscrowBook, Escrow, Disclosure) {
	t.Helper()
	opening := OpeningFor(master, index)
	ch := ChannelID("buyer-channel")
	nonce := uint64(index + 1)
	e := Escrow{
		ID: [32]byte{byte(index)}, Buyer: "buyer", Seller: "seller",
		Amount: amount, Commitment: CommitPayment(ch, nonce, amount, opening),
		Deadline: eNow.Add(48 * time.Hour),
	}
	b := NewEscrowBook("dao")
	if err := b.Open(e); err != nil {
		t.Fatal(err)
	}
	return b, e, Disclosure{Index: index, Opening: opening, Amount: amount, Channel: ch, Nonce: nonce}
}

// THE property. Disclosing one purchase must reveal nothing about the others —
// otherwise winning a dispute publishes everything you ever bought, and nobody
// disputes.
func TestDisclosingOnePaymentRevealsNoOthers(t *testing.T) {
	one := OpeningFor(master, 1)
	two := OpeningFor(master, 2)
	if one == two {
		t.Fatal("two payments share an opening secret")
	}
	// Holding opening(1), an arbiter must not be able to open payment 2.
	otherCommit := CommitPayment("buyer-channel", 3, 500, two)
	bad := Disclosure{Index: 2, Opening: one, Amount: 500, Channel: "buyer-channel", Nonce: 3}
	if err := bad.Verify(otherCommit); !errors.Is(err, ErrDisclosureBad) {
		t.Fatal("one payment's opening opened another")
	}
	// And the master must not be recoverable from a disclosed opening.
	if one == master || two == master {
		t.Fatal("an opening equals the master secret")
	}
}

func TestAValidDisclosureVerifies(t *testing.T) {
	_, e, d := escrowFor(t, 1, 250)
	if err := d.Verify(e.Commitment); err != nil {
		t.Fatalf("a genuine disclosure failed: %v", err)
	}
}

// The arbiter must be shown the payment before ruling — otherwise they could
// rule on a dispute about a payment that never happened.
func TestArbiterCannotResolveWithoutAValidDisclosure(t *testing.T) {
	b, e, _ := escrowFor(t, 1, 250)
	if err := b.Dispute(e.ID, eNow); err != nil {
		t.Fatal(err)
	}
	bogus := Disclosure{Index: 1, Opening: [32]byte{0x01}, Amount: 250,
		Channel: "buyer-channel", Nonce: 2}
	if err := b.Resolve(e.ID, "dao", bogus, true); !errors.Is(err, ErrDisclosureBad) {
		t.Fatalf("got %v, want ErrDisclosureBad", err)
	}
}

// Only the arbiter rules. If the operator could, they would be adjudicating
// disputes over payments to their own marketplace.
func TestOnlyTheArbiterMayResolve(t *testing.T) {
	b, e, d := escrowFor(t, 1, 250)
	_ = b.Dispute(e.ID, eNow)
	if err := b.Resolve(e.ID, "seller", d, false); !errors.Is(err, ErrNotTheArbiter) {
		t.Fatal("the seller resolved their own dispute")
	}
	if err := b.Resolve(e.ID, "buyer", d, true); !errors.Is(err, ErrNotTheArbiter) {
		t.Fatal("the buyer resolved their own dispute")
	}
	if err := b.Resolve(e.ID, "dao", d, true); err != nil {
		t.Fatalf("the arbiter could not resolve: %v", err)
	}
	if s, _ := b.State(e.ID); s != EscrowRefunded {
		t.Errorf("state = %d, want refunded", s)
	}
}

// Silence becomes consent. Refunding on silence would let any buyer take
// delivery and stop answering, which makes selling impossible.
func TestSilenceReleasesToTheSellerAfterTheWindow(t *testing.T) {
	b, e, _ := escrowFor(t, 1, 250)
	if err := b.Expire(e.ID, eNow); !errors.Is(err, ErrEscrowLive) {
		t.Fatal("expired an escrow inside its window")
	}
	if err := b.Expire(e.ID, eNow.Add(72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s, _ := b.State(e.ID); s != EscrowReleased {
		t.Errorf("state = %d, want released", s)
	}
}

// A dispute after the window is too late — the seller has been paid, and
// reopening settled payments indefinitely is its own attack.
func TestDisputeAfterTheWindowIsRefused(t *testing.T) {
	b, e, _ := escrowFor(t, 1, 250)
	if err := b.Dispute(e.ID, eNow.Add(72*time.Hour)); !errors.Is(err, ErrEscrowSettled) {
		t.Fatalf("got %v, want ErrEscrowSettled", err)
	}
}

func TestConfirmedEscrowCannotBeReopened(t *testing.T) {
	b, e, d := escrowFor(t, 1, 250)
	if err := b.Confirm(e.ID); err != nil {
		t.Fatal(err)
	}
	if err := b.Dispute(e.ID, eNow); !errors.Is(err, ErrEscrowSettled) {
		t.Fatal("a confirmed escrow was disputed")
	}
	if err := b.Resolve(e.ID, "dao", d, true); !errors.Is(err, ErrEscrowSettled) {
		t.Fatal("a confirmed escrow was resolved")
	}
}

// A disclosure must be bound to its exact payment, not merely to the buyer.
func TestDisclosureIsBoundToAmountAndNonce(t *testing.T) {
	_, e, d := escrowFor(t, 1, 250)
	wrongAmount := d
	wrongAmount.Amount = 251
	if err := wrongAmount.Verify(e.Commitment); err == nil {
		t.Error("a disclosure verified against the wrong amount")
	}
	wrongNonce := d
	wrongNonce.Nonce = 99
	if err := wrongNonce.Verify(e.Commitment); err == nil {
		t.Error("a disclosure verified against the wrong nonce")
	}
}
