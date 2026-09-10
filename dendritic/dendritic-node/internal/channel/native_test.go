package channel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func native(t *testing.T) (*Native, string) {
	t.Helper()
	dir := t.TempDir()
	n, err := OpenNative(dir, DeriveKey(seedA))
	if err != nil {
		t.Fatal(err)
	}
	return n, dir
}

func TestPaymentMovesValueAndSignsIt(t *testing.T) {
	n, _ := native(t)
	ch, err := n.Open(nil, "peer", 1000)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := n.Pay(nil, ch, 250, "ref")
	if err != nil {
		t.Fatal(err)
	}
	bal, _ := n.Balance(ch)
	if bal.Outbound != 750 || bal.Inbound != 250 || bal.Nonce != 1 {
		t.Fatalf("balance = %+v", bal)
	}
	// The proof must verify against exactly the balances it covers.
	if err := VerifyBalance(n.key.PublicKey(), proof, 750, 250); err != nil {
		t.Fatalf("the signed proof does not verify: %v", err)
	}
}

// A node cannot spend what it does not have, and Locked is already excluded
// from Outbound — subtracting it twice would under-spend.
func TestCannotOverdraw(t *testing.T) {
	n, _ := native(t)
	ch, _ := n.Open(nil, "peer", 100)
	if _, err := n.Pay(nil, ch, 101, "r"); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("overdrew the channel: %v", err)
	}
	if _, err := n.Pay(nil, ch, 100, "r"); err != nil {
		t.Fatalf("the exact balance should be spendable: %v", err)
	}
	if _, err := n.Pay(nil, ch, 1, "r"); !errors.Is(err, ErrInsufficient) {
		t.Fatal("spent from an emptied channel")
	}
}

// THE durability test. State written before acknowledging must survive a
// restart — a payment reported successful and then forgotten is money the
// counterparty keeps.
func TestStateSurvivesRestart(t *testing.T) {
	n, dir := native(t)
	ch, _ := n.Open(nil, "peer", 1000)
	if _, err := n.Pay(nil, ch, 400, "r"); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenNative(dir, DeriveKey(seedA))
	if err != nil {
		t.Fatal(err)
	}
	bal, err := reopened.Balance(ch)
	if err != nil {
		t.Fatalf("the channel did not survive a restart: %v", err)
	}
	if bal.Outbound != 600 || bal.Inbound != 400 || bal.Nonce != 1 {
		t.Fatalf("state after restart = %+v", bal)
	}
}

// A nullifier spent before a crash must stay spent after it, or a note becomes
// spendable again by restarting the process.
func TestSpentNullifiersSurviveRestart(t *testing.T) {
	n, dir := native(t)
	nf := Nullifier{0xAB}
	if err := n.Spend(nf); err != nil {
		t.Fatal(err)
	}
	if err := n.Spend(nf); !errors.Is(err, ErrDoubleSpend) {
		t.Fatal("a nullifier was spent twice in one process")
	}

	reopened, err := OpenNative(dir, DeriveKey(seedA))
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Spent(nf) {
		t.Fatal("a spent nullifier was forgotten across a restart")
	}
	if err := reopened.Spend(nf); !errors.Is(err, ErrDoubleSpend) {
		t.Fatal("a note became spendable again after a restart")
	}
}

// An unreadable nullifier set must STOP the node, not start it with an empty
// one — silently forgetting spends re-enables double spending.
func TestUnreadableNullifierSetRefusesToStart(t *testing.T) {
	n, dir := native(t)
	if err := n.Spend(Nullifier{0x01}); err != nil {
		t.Fatal(err)
	}
	// Make it unreadable.
	if err := os.Chmod(filepath.Join(dir, "nullifiers"), 0o000); err != nil {
		t.Skip("cannot chmod in this environment")
	}
	defer os.Chmod(filepath.Join(dir, "nullifiers"), 0o600)

	if _, err := OpenNative(dir, DeriveKey(seedA)); err == nil {
		t.Fatal("started with an unreadable nullifier set — spends would be forgotten")
	}
}

func TestClosedChannelRefusesPayment(t *testing.T) {
	n, _ := native(t)
	ch, _ := n.Open(nil, "peer", 500)
	if err := n.Close(nil, ch, true); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Pay(nil, ch, 10, "r"); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("paid through a closed channel: %v", err)
	}
}

// Nonces must increase monotonically, or an old state can be presented as new.
func TestNonceIncreasesWithEveryPayment(t *testing.T) {
	n, _ := native(t)
	ch, _ := n.Open(nil, "peer", 1000)
	var previous uint64
	for i := 0; i < 5; i++ {
		if _, err := n.Pay(nil, ch, 10, "r"); err != nil {
			t.Fatal(err)
		}
		bal, _ := n.Balance(ch)
		if bal.Nonce <= previous {
			t.Fatalf("nonce did not increase: %d then %d", previous, bal.Nonce)
		}
		previous = bal.Nonce
	}
}

// This backend must claim no privacy — the capability checks then refuse every
// claim automatically, so a UI on top cannot say "private".
func TestNativeBackendClaimsNoPrivacy(t *testing.T) {
	n, _ := native(t)
	c := n.Capabilities()
	if err := c.Validate(); err != nil {
		t.Fatalf("its capability report is inconsistent: %v", err)
	}
	for _, p := range []string{"onion_routing", "confidential_amounts",
		"confidential_recipient", "private_notes"} {
		if MayClaim(c, p) {
			t.Errorf("the native backend claimed %q", p)
		}
	}
}

func TestUnknownChannelIsRefused(t *testing.T) {
	n, _ := native(t)
	if _, err := n.Pay(nil, "nope", 1, "r"); !errors.Is(err, ErrChannelUnknown) {
		t.Fatal("paid into a channel that does not exist")
	}
	if _, err := n.Balance("nope"); !errors.Is(err, ErrChannelUnknown) {
		t.Fatal("read a balance for a channel that does not exist")
	}
}
