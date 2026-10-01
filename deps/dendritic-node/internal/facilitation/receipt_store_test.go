package facilitation

import (
	"crypto/ed25519"
	"testing"
)

func testStore(t *testing.T) *ReceiptStore {
	t.Helper()
	store, err := OpenReceiptStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func mkReceipt(t *testing.T, epoch uint64, nonce uint64) (SignedReceipt, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	return NewSignedReceipt(pub, priv, ServiceReceipt{
		ServiceType: ServiceStorage, Epoch: epoch, Quantity: 10, Quality: 1, Nonce: nonce,
	}), pub, priv
}

func TestPutGetListRoundTrip(t *testing.T) {
	store := testStore(t)
	sr, _, _ := mkReceipt(t, 5, 1)
	if err := store.Put(sr); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, found, err := store.Get(5, sr.Hash())
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if got.Hash() != sr.Hash() {
		t.Fatal("round-tripped receipt has a different canonical hash")
	}
	if !VerifyReceiptSignature(got.ProviderPub, got.Receipt, got.ProviderSig) {
		t.Fatal("signature does not survive the round trip")
	}
}

// A receipt gains witnesses after it is first written. Re-putting it must
// UPDATE the row, not create a second one — the aggregator rejects duplicates.
func TestReputUpdatesInsteadOfDuplicating(t *testing.T) {
	store := testStore(t)
	sr, _, _ := mkReceipt(t, 7, 2)
	if err := store.Put(sr); err != nil {
		t.Fatal(err)
	}

	h := sr.Hash()
	wpub, wpriv, _ := ed25519.GenerateKey(nil)
	if !sr.AddWitness(wpub, ed25519.Sign(wpriv, h[:])) {
		t.Fatal("witness not added")
	}
	if err := store.Put(sr); err != nil {
		t.Fatal(err)
	}

	rows, err := store.ListEpoch(7)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after re-put, got %d", len(rows))
	}
	if len(rows[0].Witnesses) != 1 {
		t.Fatalf("witness not persisted on update: %d", len(rows[0].Witnesses))
	}
}

func TestListEpochIsolatesEpochs(t *testing.T) {
	store := testStore(t)
	for i := 0; i < 3; i++ {
		sr, _, _ := mkReceipt(t, 10, uint64(i))
		if err := store.Put(sr); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		sr, _, _ := mkReceipt(t, 11, uint64(i))
		if err := store.Put(sr); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := store.Count(10); n != 3 {
		t.Errorf("epoch 10: got %d want 3", n)
	}
	if n, _ := store.Count(11); n != 2 {
		t.Errorf("epoch 11: got %d want 2", n)
	}
	if n, _ := store.Count(12); n != 0 {
		t.Errorf("empty epoch returned %d", n)
	}
	epochs, err := store.Epochs()
	if err != nil {
		t.Fatal(err)
	}
	if len(epochs) != 2 || epochs[0] != 10 || epochs[1] != 11 {
		t.Fatalf("epochs: %v want [10 11]", epochs)
	}
}

func TestPruneBeforeKeepsCurrentEpochs(t *testing.T) {
	store := testStore(t)
	for _, epoch := range []uint64{1, 2, 3} {
		sr, _, _ := mkReceipt(t, epoch, epoch)
		if err := store.Put(sr); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := store.PruneBefore(3)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed %d, want 2", removed)
	}
	if n, _ := store.Count(3); n != 1 {
		t.Fatal("pruning took the epoch it was told to keep")
	}
	if n, _ := store.Count(1); n != 0 {
		t.Fatal("old epoch survived pruning")
	}
}

// Receipts are earnings evidence: losing them to a restart means losing the
// window's pay, so persistence is the point of this store existing.
func TestReceiptsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenReceiptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sr, _, _ := mkReceipt(t, 42, 9)
	if err := store.Put(sr); err != nil {
		t.Fatal(err)
	}
	store.Close()

	reopened, err := OpenReceiptStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	rows, err := reopened.ListEpoch(42)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Hash() != sr.Hash() {
		t.Fatal("receipt did not survive a restart")
	}
}
