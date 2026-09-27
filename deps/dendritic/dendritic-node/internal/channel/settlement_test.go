package channel

import (
	"errors"
	"testing"
)

var secretS = [32]byte{0x77}

// THE property. A channel's pseudonym must differ every epoch, or a public
// receipt lets anyone follow that channel through time.
func TestPseudonymRotatesEveryEpoch(t *testing.T) {
	a := NewReceiptLink("ch1", 100, 1, 50, secretS, SettlePrivateChannel)
	b := NewReceiptLink("ch1", 101, 2, 50, secretS, SettlePrivateChannel)
	if Linkable(a, b) {
		t.Fatal("the same channel is linkable across epochs")
	}
	// Within one epoch it is stable, which is what makes the audit possible.
	c := NewReceiptLink("ch1", 100, 3, 10, secretS, SettlePrivateChannel)
	if !Linkable(a, c) {
		t.Fatal("the same channel is not recognisable within one epoch")
	}
}

func TestDifferentChannelsNeverShareAPseudonym(t *testing.T) {
	a := NewReceiptLink("ch1", 100, 1, 50, secretS, SettlePrivateChannel)
	b := NewReceiptLink("ch2", 100, 1, 50, secretS, SettlePrivateChannel)
	if Linkable(a, b) {
		t.Fatal("two channels collide in one epoch")
	}
}

// Two identical payments must not produce identical commitments, or an observer
// can count how often a job recurs.
func TestIdenticalPaymentsProduceDifferentCommitments(t *testing.T) {
	a := NewReceiptLink("ch1", 100, 1, 50, secretS, SettlePrivateChannel)
	b := NewReceiptLink("ch1", 100, 2, 50, secretS, SettlePrivateChannel)
	if a.PaymentCommitment == b.PaymentCommitment {
		t.Fatal("two payments of the same amount share a commitment")
	}
}

// Only the parties can open it. An auditor holding the receipt cannot.
func TestOnlyThePartiesCanOpenTheCommitment(t *testing.T) {
	link := NewReceiptLink("ch1", 100, 7, 250, secretS, SettlePrivateChannel)
	if err := OpenPayment(link, "ch1", 7, 250, secretS); err != nil {
		t.Fatalf("the parties could not open their own commitment: %v", err)
	}
	// Wrong secret, wrong amount, wrong nonce — all must fail.
	if err := OpenPayment(link, "ch1", 7, 250, [32]byte{0x01}); !errors.Is(err, ErrCommitmentBad) {
		t.Error("opened with the wrong secret")
	}
	if err := OpenPayment(link, "ch1", 7, 999, secretS); !errors.Is(err, ErrCommitmentBad) {
		t.Error("opened with the wrong amount")
	}
	if err := OpenPayment(link, "ch1", 8, 250, secretS); !errors.Is(err, ErrCommitmentBad) {
		t.Error("opened with the wrong nonce")
	}
}

// Double-settlement must be caught within the epoch — the window that matters.
func TestDoubleSettlementIsCaughtInEpoch(t *testing.T) {
	audit := NewSettlementAudit(100)
	link := NewReceiptLink("ch1", 100, 1, 50, secretS, SettlePrivateChannel)
	if err := audit.Record(link, "ch1"); err != nil {
		t.Fatal(err)
	}
	if err := audit.Record(link, "ch1"); !errors.Is(err, ErrDoubleSettled) {
		t.Fatalf("got %v, want ErrDoubleSettled", err)
	}
	if audit.Settled() != 1 {
		t.Errorf("settled = %d, want 1", audit.Settled())
	}
}

// A receipt from another epoch must not be replayable into this one's books.
func TestReceiptFromAnotherEpochIsRefused(t *testing.T) {
	audit := NewSettlementAudit(100)
	old := NewReceiptLink("ch1", 99, 1, 50, secretS, SettlePrivateChannel)
	if err := audit.Record(old, "ch1"); !errors.Is(err, ErrWrongEpoch) {
		t.Fatalf("got %v, want ErrWrongEpoch", err)
	}
}

// The audit is deliberately forgetful: a new epoch's audit knows nothing of the
// last, so it cannot rebuild the channel history rotation exists to break.
func TestAuditDoesNotCarryAcrossEpochs(t *testing.T) {
	a := NewSettlementAudit(100)
	link := NewReceiptLink("ch1", 100, 1, 50, secretS, SettlePrivateChannel)
	_ = a.Record(link, "ch1")

	b := NewSettlementAudit(101)
	if b.Settled() != 0 {
		t.Fatal("a new epoch's audit inherited state")
	}
	// And the old link cannot be recorded into the new epoch.
	if err := b.Record(link, "ch1"); !errors.Is(err, ErrWrongEpoch) {
		t.Error("an old link was accepted into a new epoch")
	}
}

// The epoch path must keep working untouched — privacy is additive.
func TestEpochModeIsStillRepresentable(t *testing.T) {
	link := NewReceiptLink("", 100, 0, 0, [32]byte{}, SettleEpoch)
	if link.Mode != SettleEpoch {
		t.Fatal("epoch settlement mode was not preserved")
	}
}

// The receipt link must carry nothing that names a party.
func TestLinkCarriesNoIdentifiers(t *testing.T) {
	ch := ChannelID("channel-belonging-to-alice")
	link := NewReceiptLink(ch, 100, 1, 50, secretS, SettlePrivateChannel)
	raw := append(link.PaymentCommitment[:], link.SettlementPseudonym[:]...)
	if containsBytes(raw, []byte(ch)) {
		t.Fatal("the channel id is recoverable from the receipt link")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
