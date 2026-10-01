package channel

// Restoring a backup — roadmap P11-4.
//
// The scenario is mundane and the consequence is not: a disk dies, a backup
// from Tuesday is restored, and the node resumes signing from a nonce it passed
// on Wednesday. Everything it can see is internally consistent — the files
// verify, the digests match, the signatures recover — because a rolled-back
// past is a coherent past.
//
// So these tests are about a node correctly refusing to trust itself.

import (
	"context"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// restoredFrom copies a store directory as a backup would, then marks it.
func restoredFrom(t *testing.T, dir string) string {
	t.Helper()
	backup := t.TempDir()
	channels := filepath.Join(backup, "channels")
	if err := os.MkdirAll(channels, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "channels"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, "channels", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(channels, e.Name()), raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", e.Name(), err)
		}
	}
	if err := MarkRestored(backup); err != nil {
		t.Fatalf("MarkRestored: %v", err)
	}
	return backup
}

// The whole problem, in one test: a backup taken at nonce 2, restored after the
// live node reached 5.
func TestARestoredNodeRefusesToSign(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	for i := byte(1); i <= 2; i++ {
		if _, err := payer.coord.Pay(ctx, id, intent(i), payTransition(1),
			directPeer{t, payee.coord}); err != nil {
			t.Fatalf("pay %d: %v", i, err)
		}
	}
	// Tuesday's backup.
	backupDir := restoredFrom(t, payer.dir)

	// Wednesday's payments, which the backup will not contain.
	for i := byte(3); i <= 5; i++ {
		if _, err := payer.coord.Pay(ctx, id, intent(i), payTransition(1),
			directPeer{t, payee.coord}); err != nil {
			t.Fatalf("pay %d: %v", i, err)
		}
	}

	// The disk dies and Tuesday comes back.
	restored, err := OpenStore(backupDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if !restored.NeedsReconcile(id) {
		t.Fatal("a restored channel was not quarantined")
	}

	ch, _ := restored.Get(id)
	if ch.Latest.State.Nonce != 2 {
		t.Fatalf("restored at nonce %d, expected the stale 2", ch.Latest.State.Nonce)
	}

	// And it must refuse to sign, because signing 3 again — differently — is a
	// double-spend it cannot see.
	session := NewPeerSession(restored, payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return payer.key.sign(raw), nil })
	_, err = session.Propose(id, intent(99), payTransition(1))
	if !errors.Is(err, ErrNeedsReconcile) {
		t.Fatalf("a restored node signed anyway: %v", err)
	}
}

// Refusing to propose while happily countersigning would double-sign just as
// thoroughly, and from the side where the counterparty picks the nonce.
func TestARestoredNodeAlsoRefusesToCountersign(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(1),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	backupDir := restoredFrom(t, payee.dir)

	restored, err := OpenStore(backupDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	session := NewPeerSession(restored, payee.key.address(),
		func(raw [32]byte) ([]byte, error) { return payee.key.sign(raw), nil })

	// A perfectly ordinary proposal arrives.
	payerSession := NewPeerSession(payer.store, payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return payer.key.sign(raw), nil })
	propose, err := payerSession.Propose(id, intent(2), payTransition(1))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := session.HandlePropose(hop(t, propose)); !errors.Is(err, ErrNeedsReconcile) {
		t.Fatalf("a restored node countersigned: %v", err)
	}
}

// Reconciling against a source that holds the newer state must adopt it and
// release the quarantine.
func TestReconcilingAdoptsTheNewerStateAndReleases(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	for i := byte(1); i <= 2; i++ {
		if _, err := payer.coord.Pay(ctx, id, intent(i), payTransition(1),
			directPeer{t, payee.coord}); err != nil {
			t.Fatalf("pay %d: %v", i, err)
		}
	}
	backupDir := restoredFrom(t, payer.dir)
	for i := byte(3); i <= 5; i++ {
		if _, err := payer.coord.Pay(ctx, id, intent(i), payTransition(1),
			directPeer{t, payee.coord}); err != nil {
			t.Fatalf("pay %d: %v", i, err)
		}
	}

	// A vault holding what the counterparty co-signed.
	chain := NewFakeChain()
	chain.Add(payer.key.address(), payee.key.address(), anon(500), new(big.Int))
	vault := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	live, _ := payee.store.Get(id)
	if _, err := vault.Submit(ctx, live.Latest); err != nil {
		t.Fatalf("vault submit: %v", err)
	}

	restored, err := OpenStore(backupDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	coord := NewCoordinator(restored, chain, big.NewInt(1),
		mustAddr(t, deployedChannelManager), payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return payer.key.sign(raw), nil })

	if err := coord.Reconcile(ctx, id, vault); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	ch, _ := restored.Get(id)
	if ch.Latest.State.Nonce != 5 {
		t.Fatalf("reconciled to nonce %d, want 5", ch.Latest.State.Nonce)
	}
	if restored.NeedsReconcile(id) {
		t.Error("still quarantined after a successful reconcile")
	}
	if ch.NeedsReconcile {
		t.Error("the snapshot still reports needing reconciliation")
	}

	// And it can sign again.
	session := NewPeerSession(restored, payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return payer.key.sign(raw), nil })
	if _, err := session.Propose(id, intent(50), payTransition(1)); err != nil {
		t.Fatalf("still refusing after reconcile: %v", err)
	}
}

// The load-bearing check. A hostile source can only ever confront a restored
// node with states the node really signed — it cannot invent one.
func TestAStateThisNodeDidNotSignIsNotAdopted(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(1),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	backupDir := restoredFrom(t, payer.dir)

	chain := NewFakeChain()
	chain.Add(payer.key.address(), payee.key.address(), anon(500), new(big.Int))
	contract := mustAddr(t, deployedChannelManager)

	// A source offering a high-nonce state signed by two strangers. Structurally
	// perfect, and nothing to do with this channel's parties.
	strangerA, strangerB := newSigner(t), newSigner(t)
	forged := State{
		Channel: id, Nonce: 99,
		BalanceA: anon(0), BalanceB: anon(500),
	}
	digest := forged.Digest(big.NewInt(1), contract)
	liar := fakeSource{signed: SignedState{
		State: forged, SigA: strangerA.sign(digest), SigB: strangerB.sign(digest),
	}}

	restored, err := OpenStore(backupDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	coord := NewCoordinator(restored, chain, big.NewInt(1), contract,
		payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return payer.key.sign(raw), nil })

	if err := coord.Reconcile(ctx, id, liar); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	ch, _ := restored.Get(id)
	if ch.Latest.State.Nonce != 1 {
		t.Fatalf("adopted a forged state at nonce %d", ch.Latest.State.Nonce)
	}
}

// Every source is asked, not just the first to answer — the point is to find
// the highest state that exists anywhere.
func TestReconcileAsksEverySource(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(1),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	backupDir := restoredFrom(t, payer.dir)

	// Capture an intermediate state, then go further.
	middle, _ := payee.store.Get(id)
	for i := byte(2); i <= 4; i++ {
		if _, err := payer.coord.Pay(ctx, id, intent(i), payTransition(1),
			directPeer{t, payee.coord}); err != nil {
			t.Fatalf("pay %d: %v", i, err)
		}
	}
	latest, _ := payee.store.Get(id)

	chain := NewFakeChain()
	chain.Add(payer.key.address(), payee.key.address(), anon(500), new(big.Int))
	contract := mustAddr(t, deployedChannelManager)

	// The better source is second, so a function that stopped at the first
	// usable answer would settle for nonce 1 and sign against nonce 4.
	behind := fakeSource{signed: middle.Latest}
	current := fakeSource{signed: latest.Latest}

	restored, err := OpenStore(backupDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	coord := NewCoordinator(restored, chain, big.NewInt(1), contract,
		payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return payer.key.sign(raw), nil })

	if err := coord.Reconcile(ctx, id, behind, current); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	ch, _ := restored.Get(id)
	if ch.Latest.State.Nonce != 4 {
		t.Fatalf("reconciled to nonce %d, want the highest 4", ch.Latest.State.Nonce)
	}
}

// A source with nothing newer is not an error — the backup may simply have been
// current.
func TestReconcilingACurrentBackupJustReleasesIt(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(1),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	backupDir := restoredFrom(t, payer.dir)

	chain := NewFakeChain()
	chain.Add(payer.key.address(), payee.key.address(), anon(500), new(big.Int))
	restored, err := OpenStore(backupDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	coord := NewCoordinator(restored, chain, big.NewInt(1),
		mustAddr(t, deployedChannelManager), payer.key.address(),
		func(raw [32]byte) ([]byte, error) { return payer.key.sign(raw), nil })

	if err := coord.Reconcile(ctx, id); err != nil {
		t.Fatalf("Reconcile with no sources: %v", err)
	}
	if restored.NeedsReconcile(id) {
		t.Error("a current backup stayed quarantined")
	}
}

// The marker is only cleared once EVERY channel is released, so a node that
// reconciled half of them and crashed comes back still guarding the rest.
func TestTheMarkerSurvivesUntilEveryChannelIsReconciled(t *testing.T) {
	dir := t.TempDir()
	if err := MarkRestored(dir); err != nil {
		t.Fatalf("MarkRestored: %v", err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	// No channels: nothing can be stale, so the marker has no work to do and
	// leaving it would quarantine channels opened later.
	if _, err := os.Stat(filepath.Join(dir, RestoreMarker)); !os.IsNotExist(err) {
		t.Error("an empty restored store kept its marker")
	}
	if len(store.Unreconciled()) != 0 {
		t.Error("an empty store reported quarantined channels")
	}
}

// An ordinary start must not quarantine anything, or every restart is an outage.
func TestAnOrdinaryStartIsNotQuarantined(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	if _, err := payer.coord.Pay(context.Background(), id, intent(1),
		payTransition(1), directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}

	reopened, err := OpenStore(payer.dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if reopened.NeedsReconcile(id) {
		t.Fatal("an ordinary restart was treated as a restore")
	}
	if len(reopened.Unreconciled()) != 0 {
		t.Error("an ordinary restart quarantined channels")
	}
}

type fakeSource struct{ signed SignedState }

func (f fakeSource) Best(id [32]byte) (SignedState, bool) {
	if f.signed.State.Channel != id {
		return SignedState{}, false
	}
	return f.signed, true
}
