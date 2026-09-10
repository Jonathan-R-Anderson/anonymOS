package channel

// State availability — roadmap P11.
//
// The vault holds somebody else's money-bearing states, and its address is
// public by necessity: a party who cannot reach it cannot be defended by it. So
// every test here is written from the position that the submitter is hostile
// until the checks say otherwise, and the property being defended is that a
// party is never worse off for having used one.

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"
)

// vaulted builds a vault, a funded channel and a pair of nodes to sign with.
func vaulted(t *testing.T) (*Vault, *FakeChain, *wiredNode, *wiredNode, [32]byte) {
	t.Helper()
	payer, payee, id := wiredPair(t, anon(500))

	chain := NewFakeChain()
	chain.Add(payer.key.address(), payee.key.address(), anon(500), new(big.Int))

	// The deployment the wired nodes sign for. Taken from the same constants
	// they were built with rather than from a channel record, which does not
	// exist until the first payment adopts it.
	vault := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	return vault, chain, payer, payee, id
}

// payTo advances the channel and returns the fully signed state.
func payTo(t *testing.T, payer, payee *wiredNode, id [32]byte, nonce uint64) SignedState {
	t.Helper()
	for i := uint64(1); i <= nonce; i++ {
		if _, err := payer.coord.Pay(context.Background(), id, intent(byte(i)),
			payTransition(1), directPeer{t, payee.coord}); err != nil {
			t.Fatalf("pay %d: %v", i, err)
		}
	}
	ch, ok := payee.store.Get(id)
	if !ok {
		t.Fatal("no channel")
	}
	return cloneSigned(ch.Latest)
}

func TestAVaultKeepsAValidState(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 3)

	entry, err := vault.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if entry.Nonce() != 3 {
		t.Errorf("held nonce %d, want 3", entry.Nonce())
	}
	best, ok := vault.Best(id)
	if !ok || best.State.Nonce != 3 {
		t.Fatalf("Best() = %d/%v", best.State.Nonce, ok)
	}
}

// The ordering rule. A vault that could be walked backwards would hold an old
// state at exactly the moment somebody closed on it.
func TestAVaultOnlyMovesForward(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	ctx := context.Background()

	third := payTo(t, payer, payee, id, 3)
	if _, err := vault.Submit(ctx, third); err != nil {
		t.Fatalf("submit 3: %v", err)
	}

	fifth := payTo(t, payer, payee, id, 5)
	if _, err := vault.Submit(ctx, fifth); err != nil {
		t.Fatalf("submit 5: %v", err)
	}

	// Now replay the old one, as an attacker would just before closing on it.
	entry, err := vault.Submit(ctx, third)
	if !errors.Is(err, ErrStaleDeposit) {
		t.Fatalf("replaying nonce 3 over 5 returned %v, want ErrStaleDeposit", err)
	}
	if entry.Nonce() != 5 {
		t.Errorf("the vault moved back to %d", entry.Nonce())
	}
	if best, _ := vault.Best(id); best.State.Nonce != 5 {
		t.Errorf("Best() went backwards to %d", best.State.Nonce)
	}
}

// An equal nonce is not better, matching the contract's `challenge`.
func TestAnEqualNonceIsRefused(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	ctx := context.Background()
	signed := payTo(t, payer, payee, id, 4)

	if _, err := vault.Submit(ctx, signed); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := vault.Submit(ctx, signed); !errors.Is(err, ErrStaleDeposit) {
		t.Fatalf("resubmitting the same state returned %v, want ErrStaleDeposit", err)
	}
	// Re-sending the latest state is ordinary, not an attack, so the entry must
	// survive it intact.
	if best, _ := vault.Best(id); best.State.Nonce != 4 {
		t.Errorf("a duplicate submission damaged the entry: %d", best.State.Nonce)
	}
}

// One signature proves somebody PROPOSED a state. Value moves when both agree.
func TestAHalfSignedStateIsRefused(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 2)

	for name, broken := range map[string]SignedState{
		"no A": {State: signed.State, SigB: signed.SigB},
		"no B": {State: signed.State, SigA: signed.SigA},
	} {
		if _, err := vault.Submit(context.Background(), broken); err == nil {
			t.Errorf("%s: a half-signed state was kept", name)
		}
	}
}

// The forgery that matters: change a balance after signing.
func TestATamperedBalanceIsRefused(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 2)

	// Move value to party A without re-signing. The digest no longer matches, so
	// the signatures recover to somebody else entirely.
	tampered := cloneSigned(signed)
	tampered.State.BalanceA = new(big.Int).Add(tampered.State.BalanceA, anon(100))
	tampered.State.BalanceB = new(big.Int).Sub(tampered.State.BalanceB, anon(100))

	if _, err := vault.Submit(context.Background(), tampered); err == nil {
		t.Fatal("a tampered state was kept")
	}
}

// A state that creates value could never be honoured by the contract, so
// holding it would mean holding something unusable and believing otherwise.
func TestAStateThatCreatesValueIsRefused(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 2)

	inflated := cloneSigned(signed)
	inflated.State.BalanceA = new(big.Int).Add(inflated.State.BalanceA, anon(1000))

	if _, err := vault.Submit(context.Background(), inflated); err == nil {
		t.Fatal("a state creating value out of nothing was kept")
	}
}

// Signatures from a real key that is not a party to this channel.
func TestAStateSignedByStrangersIsRefused(t *testing.T) {
	vault, chain, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 2)

	// A different pair entirely, signing a structurally perfect state.
	outsiderA, outsiderB := newSigner(t), newSigner(t)
	digest := signed.State.Digest(vault.ChainID, vault.Contract)
	forged := SignedState{
		State: cloneState(signed.State),
		SigA:  outsiderA.sign(digest),
		SigB:  outsiderB.sign(digest),
	}
	_ = chain

	if _, err := vault.Submit(context.Background(), forged); err == nil {
		t.Fatal("a state signed by two strangers was kept")
	}
}

// A channel the chain does not know cannot be verified at all — and inventing
// one would let anybody fill the vault with fiction.
func TestAnUnknownChannelIsRefused(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 2)

	// Same signed state, aimed at an id the chain has never heard of.
	elsewhere := cloneSigned(signed)
	elsewhere.State.Channel = [32]byte{31: 0xEE}

	if _, err := vault.Submit(context.Background(), elsewhere); !errors.Is(err, ErrNotVerifiable) {
		t.Fatalf("an unknown channel returned %v, want ErrNotVerifiable", err)
	}
}

// A vault that cannot check anything must refuse everything. Storing the
// unverifiable would be worse than storing nothing: it would look defended.
func TestAVaultWithoutAChainRefusesEverything(t *testing.T) {
	_, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 2)

	blind := NewVault(nil, big.NewInt(1), mustAddr(t, deployedChannelManager))

	if _, err := blind.Submit(context.Background(), signed); !errors.Is(err, ErrNotVerifiable) {
		t.Fatalf("a blind vault returned %v, want ErrNotVerifiable", err)
	}
}

// Rejections are counted. An operator watching this climb on one channel is
// watching somebody probe the vault.
func TestRejectionsAreCounted(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	ctx := context.Background()
	signed := payTo(t, payer, payee, id, 3)

	if _, err := vault.Submit(ctx, signed); err != nil {
		t.Fatalf("submit: %v", err)
	}
	for i := 0; i < 3; i++ {
		_, _ = vault.Submit(ctx, signed)
	}
	entry, _ := vault.Entry(id)
	if entry.Accepted != 1 {
		t.Errorf("accepted %d, want 1", entry.Accepted)
	}
	if entry.Rejected != 3 {
		t.Errorf("rejected %d, want 3", entry.Rejected)
	}
}

// What the vault hands out must not be a window into what it holds.
func TestWhatTheVaultReturnsCannotMutateIt(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 3)
	if _, err := vault.Submit(context.Background(), signed); err != nil {
		t.Fatalf("submit: %v", err)
	}

	best, _ := vault.Best(id)
	best.State.Nonce = 99
	best.State.BalanceA = anon(9999)
	if best.SigA != nil {
		best.SigA[0] ^= 0xFF
	}

	after, _ := vault.Best(id)
	if after.State.Nonce != 3 {
		t.Errorf("a caller rewrote the vault's nonce to %d", after.State.Nonce)
	}
	if after.SigA[0] == best.SigA[0] {
		t.Error("a caller shares the vault's signature bytes")
	}
}

// ---- the whole point: a vault defending a channel it is not party to --------

func TestAVaultBackedWatchtowerBeatsAStaleClose(t *testing.T) {
	vault, chain, payer, payee, id := vaulted(t)
	ctx := context.Background()

	// The party hands its latest state to a vault it does not control, then
	// stops paying attention — the browser-tab case.
	signed := payTo(t, payer, payee, id, 6)
	if _, err := vault.Submit(ctx, signed); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// The counterparty closes on an old state.
	chain.StartClose(id, 2, 1_000_000+RecommendedChallengePeriod())

	sender := &recordingSender{hash: "0xfeed"}
	tower := &Watchtower{
		Store: VaultStore{vault}, Chain: chain, Sender: sender,
		Contract: vault.Contract,
		Now:      func() time.Time { return time.Unix(1_000_000, 0) },
	}

	got := tower.Check(ctx, id)
	if got.Outcome != WatchChallenged {
		t.Fatalf("outcome %q (%v), want challenged", got.Outcome, got.Err)
	}
	if sender.sent[0].State.Nonce != 6 {
		t.Errorf("challenged with nonce %d, want 6", sender.sent[0].State.Nonce)
	}
}

// The invariant, stated as a test: everything a vault can submit is something
// both parties already signed. It has no key and cannot make one.
func TestAVaultCanOnlySubmitWhatBothPartiesSigned(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	signed := payTo(t, payer, payee, id, 4)
	if _, err := vault.Submit(context.Background(), signed); err != nil {
		t.Fatalf("submit: %v", err)
	}

	best, _ := vault.Best(id)
	entry, _ := vault.Entry(id)
	digest := best.State.Digest(vault.ChainID, vault.Contract)

	gotA, err := RecoverSigner(digest, best.SigA)
	if err != nil || gotA != entry.PartyA {
		t.Fatalf("signature A recovers to %s (%v), want party A %s", gotA, err, entry.PartyA)
	}
	gotB, err := RecoverSigner(digest, best.SigB)
	if err != nil || gotB != entry.PartyB {
		t.Fatalf("signature B recovers to %s (%v), want party B %s", gotB, err, entry.PartyB)
	}
}
