package channel

// These tests are about the three ways a store loses money: signing something
// the chain will not accept, forgetting part of what was signed, and letting an
// older state come back.

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tipState(t *testing.T, ch *Channel, nonce uint64, tipper *signer, paid int64, deposit int64) State {
	t.Helper()
	st := State{Channel: ch.ID, Nonce: nonce}
	remaining, received := anon(deposit-paid), anon(paid)
	if ch.IsA(tipper.address()) {
		st.BalanceA, st.BalanceB = remaining, received
	} else {
		st.BalanceA, st.BalanceB = received, remaining
	}
	return st
}

func storeWithChannel(t *testing.T) (*Store, *Channel, *signer, *signer, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	tipper, recipient := newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))
	trackViaChain(t, s, ch)
	return s, ch, tipper, recipient, dir
}

// ---- 1. exactly the V2 digest, and nothing else --------------------------

func TestStoreAcceptsOnlyTheV2Digest(t *testing.T) {
	s, ch, tipper, recipient, _ := storeWithChannel(t)
	st := tipState(t, ch, 1, tipper, 5, 500)

	// Signed over V1's digest — the six-field one the currently-deployed
	// contract uses. Structurally plausible, and worthless: it commits to no
	// lock root, so accepting it would be the second interpretation this
	// package is not allowed to have.
	v1 := StateDigestV1(ch.ChainID, ch.Contract, st.Channel, st.Nonce, st.BalanceA, st.BalanceB)
	wrong := SignedState{State: st}
	for _, who := range []*signer{tipper, recipient} {
		if ch.IsA(who.address()) {
			wrong.SigA = who.sign(v1)
		} else {
			wrong.SigB = who.sign(v1)
		}
	}
	if err := s.Accept(ch.ID, wrong); err == nil {
		t.Fatal("a state signed over the V1 digest was accepted")
	}

	// The V2 digest is accepted.
	if err := s.Accept(ch.ID, signState(t, ch, st, tipper, recipient)); err != nil {
		t.Fatalf("V2-signed state refused: %v", err)
	}
}

// ---- 2. persistence must reproduce what was signed -----------------------

func TestLocksSurviveARestart(t *testing.T) {
	s, ch, tipper, recipient, dir := storeWithChannel(t)

	// 400 spendable, 50 already tipped, 50 committed to a lock.
	st := State{Channel: ch.ID, Nonce: 1, Pending: []HTLC{{
		ID: [32]byte{31: 7}, Hash: [32]byte{31: 9},
		Amount: anon(50), Expiry: 1 << 40, PayerIsA: ch.IsA(tipper.address()),
	}}}
	remaining, received := anon(400), anon(50)
	if ch.IsA(tipper.address()) {
		st.BalanceA, st.BalanceB = remaining, received
	} else {
		st.BalanceA, st.BalanceB = received, remaining
	}
	if err := s.Accept(ch.ID, signState(t, ch, st, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// The restart. This is the catastrophe being tested for: a node that comes
	// back believing the locked 50 is spendable will sign it away.
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Get(ch.ID)
	if !ok {
		t.Fatal("channel vanished across the restart")
	}
	if len(got.Latest.State.Pending) != 1 {
		t.Fatalf("locks after restart: %d, want 1", len(got.Latest.State.Pending))
	}
	lock := got.Latest.State.Pending[0]
	if lock.Amount.Cmp(anon(50)) != 0 {
		t.Fatalf("lock amount %s, want 50 ANON", lock.Amount)
	}
	if lock.Expiry != 1<<40 || lock.PayerIsA != ch.IsA(tipper.address()) {
		t.Fatal("lock expiry or payer did not survive")
	}
	// And the reloaded record still reproduces the digest it was signed over.
	if err := verifyLoaded(got); err != nil {
		t.Fatalf("reloaded state does not reproduce its signatures: %v", err)
	}
}

// If the record is not sufficient to rebuild the signed state, the signatures
// stop verifying and the node must refuse to start rather than run on a state
// it cannot prove.
func TestATamperedRecordStopsTheNode(t *testing.T) {
	cases := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"a lock is dropped", func(m map[string]any) {
			st := m["state"].(map[string]any)
			delete(st, "pending")
		}},
		{"a lock amount is changed", func(m map[string]any) {
			st := m["state"].(map[string]any)
			locks := st["pending"].([]any)
			locks[0].(map[string]any)["amount"] = anon(1).String()
		}},
		{"a lock expiry is changed", func(m map[string]any) {
			st := m["state"].(map[string]any)
			locks := st["pending"].([]any)
			locks[0].(map[string]any)["expiry"] = float64(1234)
		}},
		{"the payer is flipped", func(m map[string]any) {
			st := m["state"].(map[string]any)
			locks := st["pending"].([]any)
			l := locks[0].(map[string]any)
			l["payer_is_a"] = !l["payer_is_a"].(bool)
		}},
		{"a balance is changed", func(m map[string]any) {
			st := m["state"].(map[string]any)
			st["balance_a"] = anon(499).String()
		}},
		{"the nonce is changed", func(m map[string]any) {
			st := m["state"].(map[string]any)
			st["nonce"] = float64(99)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ch, tipper, recipient, dir := storeWithChannel(t)
			st := State{Channel: ch.ID, Nonce: 1, Pending: []HTLC{{
				ID: [32]byte{31: 7}, Hash: [32]byte{31: 9},
				Amount: anon(50), Expiry: 1 << 40, PayerIsA: true,
			}}}
			st.BalanceA, st.BalanceB = anon(400), anon(50)
			if !ch.IsA(tipper.address()) {
				st.BalanceA, st.BalanceB = anon(50), anon(400)
			}
			if err := s.Accept(ch.ID, signState(t, ch, st, tipper, recipient)); err != nil {
				t.Fatalf("accept: %v", err)
			}

			path := filepath.Join(dir, "channels", hexOf(ch.ID[:])+".json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			tc.edit(m)
			edited, _ := json.Marshal(m)
			if err := os.WriteFile(path, edited, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			_, err = OpenStore(dir)
			if err == nil {
				t.Fatal("the node started on a record that cannot reproduce its signatures")
			}
			if !strings.Contains(err.Error(), "does not reproduce its signatures") {
				t.Fatalf("wrong failure: %v", err)
			}
		})
	}
}

// A balance of 1e20 wei must come back exactly. Stored as a JSON number it
// would be a float on the way through some parsers, and 100 ANON is past the
// point where that is lossless.
func TestLargeAmountsRoundTripExactly(t *testing.T) {
	s, ch, tipper, recipient, dir := storeWithChannel(t)
	st := tipState(t, ch, 1, tipper, 100, 500) // a gold award
	if err := s.Accept(ch.ID, signState(t, ch, st, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "channels", hexOf(ch.ID[:])+".json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), `"100000000000000000000"`) {
		t.Fatal("amounts are not stored as decimal strings")
	}

	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, _ := reopened.Get(ch.ID)
	if got.BalanceOf(recipient.address()).Cmp(anon(100)) != 0 {
		t.Fatalf("recipient balance came back as %s", got.BalanceOf(recipient.address()))
	}
}

// ---- 3. state must never move backward -----------------------------------

func TestStoredNonceIsMonotonicAcrossRestart(t *testing.T) {
	s, ch, tipper, recipient, dir := storeWithChannel(t)

	for _, n := range []uint64{1, 2, 100} {
		st := tipState(t, ch, n, tipper, int64(n), 500)
		if err := s.Accept(ch.ID, signState(t, ch, st, tipper, recipient)); err != nil {
			t.Fatalf("nonce %d: %v", n, err)
		}
	}

	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	live, _ := reopened.Get(ch.ID)

	// 99: older. 100: the same one again. Both refused, and refused for the
	// nonce rather than for anything about their signatures.
	for _, n := range []uint64{99, 100} {
		st := tipState(t, ch, n, tipper, int64(n), 500)
		if err := reopened.Accept(ch.ID, signState(t, live, st, tipper, recipient)); err != ErrNonceRegressed {
			t.Fatalf("nonce %d: got %v, want ErrNonceRegressed", n, err)
		}
	}

	st := tipState(t, ch, 101, tipper, 101, 500)
	if err := reopened.Accept(ch.ID, signState(t, live, st, tipper, recipient)); err != nil {
		t.Fatalf("nonce 101: %v", err)
	}
}

// A higher nonce is not on its own enough. The locks presented must be the ones
// the signature actually committed to, which the digest enforces because it
// covers the root.
func TestAHigherNonceCannotCarrySubstitutedLocks(t *testing.T) {
	s, ch, tipper, recipient, _ := storeWithChannel(t)

	payerIsA := ch.IsA(tipper.address())
	agreed := State{Channel: ch.ID, Nonce: 1, Pending: []HTLC{{
		ID: [32]byte{31: 7}, Hash: [32]byte{31: 9},
		Amount: anon(50), Expiry: 1 << 40, PayerIsA: payerIsA,
	}}}
	agreed.BalanceA, agreed.BalanceB = anon(400), anon(50)
	if !payerIsA {
		agreed.BalanceA, agreed.BalanceB = anon(50), anon(400)
	}
	signed := signState(t, ch, agreed, tipper, recipient)

	// Same nonce, same balances, same signatures — a different secret. If this
	// were accepted, the payer could redirect a payment in flight to a hash
	// only they know the preimage of.
	swapped := signed
	swapped.State.Pending = []HTLC{{
		ID: [32]byte{31: 7}, Hash: [32]byte{31: 0xff},
		Amount: anon(50), Expiry: 1 << 40, PayerIsA: payerIsA,
	}}
	if err := s.Accept(ch.ID, swapped); err == nil {
		t.Fatal("a state was accepted with its locks substituted")
	}

	if err := s.Accept(ch.ID, signed); err != nil {
		t.Fatalf("the agreed state was refused: %v", err)
	}
}

// ---- the write ordering ---------------------------------------------------

// A payment that cannot be written is not a payment. If the store advanced in
// memory and only then failed to persist, the counterparty would hold a state
// this node forgets on restart.
func TestAFailedWriteLeavesNothingBehind(t *testing.T) {
	s, ch, tipper, recipient, dir := storeWithChannel(t)
	good := tipState(t, ch, 1, tipper, 5, 500)
	if err := s.Accept(ch.ID, signState(t, ch, good, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	channelsDir := filepath.Join(dir, "channels")
	if err := os.Chmod(channelsDir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	defer os.Chmod(channelsDir, 0o700)

	next := tipState(t, ch, 2, tipper, 30, 500)
	if err := s.Accept(ch.ID, signState(t, ch, next, tipper, recipient)); err == nil {
		t.Skip("the filesystem allowed the write anyway; nothing to assert")
	}

	// In memory, the channel is still at the state that IS on disk.
	got, _ := s.Get(ch.ID)
	if got.Latest.State.Nonce != 1 {
		t.Fatalf("nonce advanced to %d despite the write failing", got.Latest.State.Nonce)
	}
	if got.BalanceOf(recipient.address()).Cmp(anon(5)) != 0 {
		t.Fatalf("balance advanced to %s despite the write failing",
			got.BalanceOf(recipient.address()))
	}
}

func TestGetReturnsACopy(t *testing.T) {
	s, ch, tipper, recipient, _ := storeWithChannel(t)
	st := tipState(t, ch, 1, tipper, 5, 500)
	if err := s.Accept(ch.ID, signState(t, ch, st, tipper, recipient)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	got, _ := s.Get(ch.ID)
	got.Latest.State.BalanceA = anon(9999)
	got.Latest.State.Nonce = 4242

	again, _ := s.Get(ch.ID)
	if again.Latest.State.Nonce != 1 {
		t.Fatal("mutating a returned channel changed the store")
	}
	if again.Latest.State.BalanceA.Cmp(anon(9999)) == 0 {
		t.Fatal("mutating a returned balance changed the store")
	}
}

func TestTrackRefusesADuplicate(t *testing.T) {
	s, ch, _, _, _ := storeWithChannel(t)
	chain := NewFakeChain()
	chain.Add(ch.PartyA, ch.PartyB, ch.DepositA, ch.DepositB)
	occ, err := chain.ReadChannel(context.Background(), ch.Contract, ch.ID)
	if err != nil {
		t.Fatalf("chain read: %v", err)
	}
	if err := s.TrackFromChain(ch.ChainID, ch.Contract, occ); err != ErrChannelExists {
		t.Fatalf("got %v, want ErrChannelExists", err)
	}
}

// Invariant P5-1, as a test rather than a comment: a channel whose deposits did
// not come from a chain read cannot be registered.
//
// The struct literal below is what an attacker's code path looks like — and
// outside this package it does not even compile, because the guard field is
// unexported. This test can only be written from inside.
func TestAHandBuiltChannelIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	tipper, recipient := newSigner(t), newSigner(t)
	a, b := SortParties(tipper.address(), recipient.address())

	forged := OnChainChannel{
		ID: DeriveChannelID(a, b), PartyA: a, PartyB: b,
		DepositA: anon(1000), DepositB: new(big.Int),
		Status: StatusOpen,
		// fromChain deliberately absent — this is peer-supplied collateral.
	}
	if err := s.TrackFromChain(big.NewInt(1), Address{}, forged); err != ErrNotFromChain {
		t.Fatalf("got %v, want ErrNotFromChain", err)
	}
	if len(s.IDs()) != 0 {
		t.Fatal("a channel with fabricated collateral was registered")
	}
}

// The deposit the store uses is the chain's, not the one anybody hoped for.
func TestTheChainsDepositIsTheOneThatCounts(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	tipper, recipient := newSigner(t), newSigner(t)

	// The chain says 10.
	chain := NewFakeChain()
	id := chain.Add(tipper.address(), recipient.address(), anon(10), new(big.Int))
	occ, err := chain.ReadChannel(context.Background(), Address{}, id)
	if err != nil {
		t.Fatalf("chain read: %v", err)
	}
	if err := s.TrackFromChain(big.NewInt(1), Address{}, occ); err != nil {
		t.Fatalf("track: %v", err)
	}

	ch, _ := s.Get(id)
	total := new(big.Int).Add(ch.DepositA, ch.DepositB)
	if total.Cmp(anon(10)) != 0 {
		t.Fatalf("the store holds a deposit of %s, want the chain's 10", total)
	}

	// A state conserving a 1,000 deposit — signed by both, and worthless.
	fabricated := State{Channel: id, Nonce: 1, BalanceA: anon(900), BalanceB: anon(100)}
	if err := ch.Accept(signState(t, ch, fabricated, tipper, recipient)); err != ErrNotConserved {
		t.Fatalf("got %v, want ErrNotConserved — a fabricated deposit was believed", err)
	}
}

// A channel the chain has never heard of is not a channel, however plausible
// the id looks.
func TestAnUnknownChannelCannotBeTracked(t *testing.T) {
	chain := NewFakeChain()
	if _, err := chain.ReadChannel(context.Background(), Address{}, [32]byte{0xde, 0xad}); err != ErrChannelNotOnChain {
		t.Fatalf("got %v, want ErrChannelNotOnChain", err)
	}
}

func TestAcceptOnAnUnknownChannel(t *testing.T) {
	s, _, _, _, _ := storeWithChannel(t)
	if err := s.Accept([32]byte{0xde, 0xad}, SignedState{}); err != ErrNoSuchChannel {
		t.Fatalf("got %v, want ErrNoSuchChannel", err)
	}
}

func TestEmptyStoreOpensClean(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if len(s.IDs()) != 0 {
		t.Fatal("a fresh store is not empty")
	}
}

func TestUnparseableRecordStopsTheNode(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "channels"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "channels", strings.Repeat("ab", 32)+".json")
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Skipping the bad file is right for a cache and wrong for money: carrying
	// on means operating without a balance the node is supposed to have.
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("the node started despite an unreadable channel record")
	}
}

// A channel that has been tracked but never used has no signatures to check,
// and must not be mistaken for a corrupt one.
func TestAFreshChannelHasNothingToVerify(t *testing.T) {
	_, ch, _, _, dir := storeWithChannel(t)
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Get(ch.ID)
	if !ok {
		t.Fatal("the channel did not survive")
	}
	if got.Latest.Complete() {
		t.Fatal("a fresh channel came back with signatures")
	}
	if got.DepositA.Cmp(ch.DepositA) != 0 || got.DepositB.Cmp(ch.DepositB) != 0 {
		t.Fatal("deposits did not survive")
	}
}

func TestIDsAreStable(t *testing.T) {
	s, ch, _, _, _ := storeWithChannel(t)
	ids := s.IDs()
	if len(ids) != 1 || ids[0] != ch.ID {
		t.Fatalf("IDs() = %v", ids)
	}
	_ = big.NewInt(0)
}

func TestPreimageMatchesTheContractsHashing(t *testing.T) {
	var preimage [32]byte
	copy(preimage[:], []byte("routed tip"))
	var hash [32]byte
	copy(hash[:], keccak(preimage[:]))

	lock := HTLC{Hash: hash}
	if !lock.Matches(preimage) {
		t.Fatal("the correct preimage did not open the lock")
	}
	var wrong [32]byte
	wrong[0] = 0xff
	if lock.Matches(wrong) {
		t.Fatal("a wrong preimage opened the lock")
	}
}

// trackViaChain registers a channel the only way the store allows: from facts a
// chain read established.
func trackViaChain(t *testing.T, s *Store, ch *Channel) {
	t.Helper()
	chain := NewFakeChain()
	chain.Add(ch.PartyA, ch.PartyB, ch.DepositA, ch.DepositB)
	occ, err := chain.ReadChannel(context.Background(), ch.Contract, ch.ID)
	if err != nil {
		t.Fatalf("chain read: %v", err)
	}
	if err := s.TrackFromChain(ch.ChainID, ch.Contract, occ); err != nil {
		t.Fatalf("TrackFromChain: %v", err)
	}
}
