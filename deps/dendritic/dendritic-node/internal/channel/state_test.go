package channel

// None of the golden vectors here were computed by this package. Two sources,
// both outside it:
//
//   - V1: eth_call against the DEPLOYED ChannelManager at
//     0xae70526931FF460894133201f6C8cA91bbA0E177 on mainnet, 2026-08-11.
//   - V2: `npx hardhat run scripts/v2-golden-vectors.ts` in
//     proof-of-facilitation — the Solidity compiler and the EVM.
//
// That matters more than it looks. A test that checks this package against
// itself proves the encoding is self-consistent, which is exactly what a wrong
// encoding also is. The only question worth answering is whether a state signed
// in somebody's browser will settle on chain, and the contract is the only
// authority on that.
//
// The V1 vector is kept although V2 supersedes it: it is the one value here
// confirmed against a real chain rather than a local EVM, so it anchors the
// abi.encode/keccak machinery that V2 reuses.
//
// Regenerate the V2 vectors whenever ChannelManagerV2 changes, and note they
// carry the local chain id (31337) and the deterministic hardhat deploy
// address — both are inside the digest, deliberately.

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	deployedChannelManager = "0xae70526931FF460894133201f6C8cA91bbA0E177"

	// channelId(0x1111…11, 0x2222…22). Identical in V1 and V2 — the derivation
	// did not change — so this one value is checked against both authorities.
	goldenChannelID = "1bbe365357fe28ec15df954baa1b29fb309dd0e8a21208d768bce9ab1c0c4fd0"

	// V1's stateDigest(goldenChannelID, 5, 340e18, 160e18) on chain 1, from
	// mainnet. The only encoding here confirmed against a real chain, which is
	// why it stays after V2 replaced it: V2 adds one word using the same
	// machinery, so this anchors that machinery to reality.
	goldenDigestV1 = "8765fe541624334ed869c7bf01146a298f9c27460902053a0e4c279fd68cbf39"
)

// V2 vectors, from `npx hardhat run scripts/v2-golden-vectors.ts` in
// proof-of-facilitation. The Solidity compiler and the EVM are the authority;
// the Go below is what is being checked.
const (
	v2ChainID  = 31337
	v2Contract = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

	// htlcRoot over the two locks built in goldenLocks.
	goldenHTLCRoot = "e8303e521e3d9771a180e3f13b1f2d3b27ff1255adf20442232588b9528d6fa2"

	// stateDigest(OP_STATE, id, 5, 340e18, 160e18, root) with an empty root and
	// with the root above. The two must differ, or the locks are not being
	// committed to.
	//
	// Regenerated when the operation domain became the digest's first word:
	// `npx hardhat run scripts/p15-golden-digest.ts` (no --network, so the chain
	// is fresh and the contract lands at v2Contract deterministically).
	goldenDigestNoLocks = "a7695ffb8fb18ef9c3376a798b7d47c8de0d05bb7ec6286c8b5ab8a77057e045"
	goldenDigestLocked  = "b06719805839bfcc1f2bdbd5f6558731193fb40f3c19213b2f84a7f2abc32729"

	// THE SAME ECONOMIC STATE under the other two domains. From the same
	// contract call, so these are the EVM's answer and not this package's.
	//
	// Before the domain existed, goldenDigestCoopClose and goldenDigestNoLocks
	// were the same 32 bytes: signing "the balance is 340/160" was also signing
	// "settle this channel now". These three constants differing is the whole
	// property this phase adds.
	goldenDigestCoopClose  = "c3634a77abeb6717aea850cd2b7fc92578ebdba4250a208973682221f8e42ca2"
	goldenDigestCheckpoint = "f9a394ec0af645242bea7544dc3e419ba2cad6bfc1e9c25d554388d2b562db27"

	// stateDigest(id, 5, 340e18, 160e18, emptyRoot, 0, 75e18) — a checkpoint.
	goldenDigestDraw    = "72f7ab6a1b41016b823e352f7473ab60f204057d911e1395670758d79d08ea5e"
)

// goldenLocks mirrors the lock set in scripts/v2-golden-vectors.ts exactly.
func goldenLocks() []HTLC {
	return []HTLC{
		{ID: [32]byte{31: 0x01}, Hash: [32]byte{31: 0x09}, Amount: anon(5), Expiry: 100, PayerIsA: true},
		{ID: [32]byte{31: 0x02}, Hash: [32]byte{31: 0x08}, Amount: anon(7), Expiry: 200, PayerIsA: false},
	}
}

func mustAddr(t *testing.T, s string) Address {
	t.Helper()
	a, err := ParseAddress(s)
	if err != nil {
		t.Fatalf("ParseAddress(%s): %v", s, err)
	}
	return a
}

func anon(n int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
}

// signer is a test wallet standing in for MetaMask.
type signer struct{ priv *secp256k1.PrivateKey }

func newSigner(t *testing.T) *signer {
	t.Helper()
	p, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &signer{priv: p}
}

func (s *signer) address() Address {
	pub := s.priv.PubKey().SerializeUncompressed()
	var a Address
	copy(a[:], keccak(pub[1:])[12:])
	return a
}

// sign produces r||s||v over the EIP-191 wrapping of raw, which is the layout
// personal_sign returns.
func (s *signer) sign(raw [32]byte) []byte {
	d := PersonalDigest(raw)
	compact := ecdsa.SignCompact(s.priv, d[:], false) // v||r||s
	out := make([]byte, 65)
	copy(out[0:32], compact[1:33])
	copy(out[32:64], compact[33:65])
	out[64] = compact[0]
	return out
}

func TestChannelIDMatchesDeployedContract(t *testing.T) {
	a := mustAddr(t, "0x1111111111111111111111111111111111111111")
	b := mustAddr(t, "0x2222222222222222222222222222222222222222")

	got := DeriveChannelID(a, b)
	if hexOf(got[:]) != goldenChannelID {
		t.Fatalf("channelId\n got  %s\n want %s", hexOf(got[:]), goldenChannelID)
	}

	// The sort is the point: either argument order names one channel. Without
	// it a pair could hold two, and each could settle whichever suited them.
	if DeriveChannelID(b, a) != got {
		t.Fatal("channelId is not symmetric; the sort is broken")
	}
}

func TestStateDigestV1MatchesTheChain(t *testing.T) {
	contract := mustAddr(t, deployedChannelManager)
	var id [32]byte
	copy(id[:], mustHex(t, goldenChannelID))

	got := StateDigestV1(big.NewInt(1), contract, id, 5, anon(340), anon(160))
	if hexOf(got[:]) != goldenDigestV1 {
		t.Fatalf("V1 stateDigest disagrees with mainnet\n got  %s\n want %s",
			hexOf(got[:]), goldenDigestV1)
	}
}

func TestHTLCRootMatchesTheContract(t *testing.T) {
	got := State{Pending: goldenLocks()}.HTLCRoot()
	if hexOf(got[:]) != goldenHTLCRoot {
		t.Fatalf("HTLCRoot disagrees with ChannelManagerV2.htlcRoot\n got  %s\n want %s",
			hexOf(got[:]), goldenHTLCRoot)
	}
	// The contract returns bytes32(0) for an empty set; anything else here and
	// a lock-free state would fail to verify on chain.
	if (State{}).HTLCRoot() != ([32]byte{}) {
		t.Fatal("an empty lock set must hash to the zero root")
	}
}

func TestStateDigestMatchesTheContract(t *testing.T) {
	contract := mustAddr(t, v2Contract)
	var id [32]byte
	copy(id[:], mustHex(t, goldenChannelID))

	bare := State{Channel: id, Nonce: 5, BalanceA: anon(340), BalanceB: anon(160)}
	if got := bare.Digest(big.NewInt(v2ChainID), contract); hexOf(got[:]) != goldenDigestNoLocks {
		t.Fatalf("digest without locks\n got  %s\n want %s", hexOf(got[:]), goldenDigestNoLocks)
	}

	locked := bare
	locked.Pending = goldenLocks()
	got := locked.Digest(big.NewInt(v2ChainID), contract)
	if hexOf(got[:]) != goldenDigestLocked {
		t.Fatalf("digest with locks\n got  %s\n want %s", hexOf(got[:]), goldenDigestLocked)
	}

	// The point of the whole phase: the same balances at the same nonce sign to
	// a DIFFERENT value once locks exist, so a signed state cannot be presented
	// with its locks stripped off.
	if goldenDigestNoLocks == goldenDigestLocked {
		t.Fatal("locks do not change the digest; they are not being committed to")
	}

	// And the same again for a withdrawal: a state that takes 75 out signs to a
	// different value than one that takes nothing, so a checkpoint cannot be
	// submitted asking for an amount nobody agreed to.
	draw := bare
	draw.WithdrawB = anon(75)
	if got := draw.Digest(big.NewInt(v2ChainID), contract); hexOf(got[:]) != goldenDigestDraw {
		t.Fatalf("digest with a withdrawal\n got  %s\n want %s", hexOf(got[:]), goldenDigestDraw)
	}
	if goldenDigestDraw == goldenDigestNoLocks {
		t.Fatal("withdrawals do not change the digest; they are not being committed to")
	}
}

// TestOperationDomainsSeparateTheDigest pins the property this phase adds.
//
// Before it, closeCooperative and an ordinary lock-free state signed THE SAME
// BYTES. A party agreeing a balance was unknowingly also authorising an
// immediate settlement, and once a delegate may sign that becomes an authority
// nobody granted. The three constants below are the same economics under the
// three domains, taken from the contract itself.
func TestOperationDomainsSeparateTheDigest(t *testing.T) {
	contract := mustAddr(t, v2Contract)
	var id [32]byte
	copy(id[:], mustHex(t, goldenChannelID))
	base := State{Channel: id, Nonce: 5, BalanceA: anon(340), BalanceB: anon(160)}

	seen := map[string]string{}
	for _, tc := range []struct {
		name string
		op   uint8
		want string
	}{
		{"state", OpState, goldenDigestNoLocks},
		{"cooperative close", OpCoopClose, goldenDigestCoopClose},
		{"checkpoint", OpCheckpoint, goldenDigestCheckpoint},
	} {
		st := base
		st.Op = tc.op
		d := st.Digest(big.NewInt(v2ChainID), contract)
		got := hexOf(d[:])
		if got != tc.want {
			t.Fatalf("%s domain\n got  %s\n want %s", tc.name, got, tc.want)
		}
		if prev, clash := seen[got]; clash {
			t.Fatalf("%s and %s produce the SAME digest; a signature for one "+
				"authorises the other", prev, tc.name)
		}
		seen[got] = tc.name
	}

	// The default must be the least powerful domain: a state that somehow
	// arrived without one is a payment, never an authority to close.
	undeclared := base
	ud := undeclared.Digest(big.NewInt(v2ChainID), contract)
	if hexOf(ud[:]) != goldenDigestNoLocks {
		t.Fatal("a state with no declared domain must hash as an ordinary state")
	}
}

// A gold award is 100 ANON = 1e20 wei, which does not fit in an int64. If these
// balances are ever narrowed to Amount, this is the test that catches it.
func TestTopTierAmountExceedsInt64(t *testing.T) {
	gold := anon(100)
	if gold.IsInt64() {
		t.Fatal("100 ANON now fits in an int64; the *big.Int reasoning has changed")
	}
}

// The ordering trap: A and B are decided by address value, never by who opened
// the channel or who is paying.
func TestPartyOrderIsByAddressNotRole(t *testing.T) {
	low := mustAddr(t, "0x0000000000000000000000000000000000000001")
	high := mustAddr(t, "0xffffffffffffffffffffffffffffffffffffffff")

	// The high-addressed party opens and tips; they are still B.
	ch := NewChannel(big.NewInt(1), mustAddr(t, deployedChannelManager), high, low)
	if ch.PartyA != low || ch.PartyB != high {
		t.Fatalf("party order ignored address value: A=%s B=%s", ch.PartyA.Hex(), ch.PartyB.Hex())
	}
	if ch.IsA(high) {
		t.Fatal("the higher address was reported as party A")
	}
}

func TestRecoverSignerRoundTrip(t *testing.T) {
	s := newSigner(t)
	var raw [32]byte
	copy(raw[:], mustHex(t, goldenDigestV1))

	got, err := RecoverSigner(raw, s.sign(raw))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got != s.address() {
		t.Fatalf("recovered %s, signed by %s", got.Hex(), s.address().Hex())
	}
}

// A signature over the RAW digest, without the EIP-191 wrapping, must not be
// accepted: the contract would reject it, so accepting it here would record a
// payment that can never settle.
func TestRecoverRejectsUnwrappedSignature(t *testing.T) {
	s := newSigner(t)
	var raw [32]byte
	copy(raw[:], mustHex(t, goldenDigestV1))

	compact := ecdsa.SignCompact(s.priv, raw[:], false) // signed the raw digest
	sig := make([]byte, 65)
	copy(sig[0:32], compact[1:33])
	copy(sig[32:64], compact[33:65])
	sig[64] = compact[0]

	got, err := RecoverSigner(raw, sig)
	if err == nil && got == s.address() {
		t.Fatal("a signature missing the EIP-191 prefix was accepted")
	}
}

func TestRecoverRejectsHighS(t *testing.T) {
	s := newSigner(t)
	var raw [32]byte
	copy(raw[:], mustHex(t, goldenDigestV1))
	sig := s.sign(raw)

	// Flip s to n-s, the other valid-looking half. The contract refuses it, so
	// this package must too or it will accept states that settle nowhere.
	order := new(big.Int).Add(new(big.Int).Mul(halfOrder, big.NewInt(2)), big.NewInt(1))
	high := new(big.Int).Sub(order, new(big.Int).SetBytes(sig[32:64]))
	copy(sig[32:64], word(high.Bytes()))

	if _, err := RecoverSigner(raw, sig); err != ErrHighS {
		t.Fatalf("high-s signature: got %v, want ErrHighS", err)
	}
}

// openChannel deposits, then five tips, exactly as the roadmap describes.
func newFundedChannel(t *testing.T, a, b *signer, deposit *big.Int) *Channel {
	t.Helper()
	ch := NewChannel(big.NewInt(1), mustAddr(t, deployedChannelManager), a.address(), b.address())
	if ch.IsA(a.address()) {
		ch.DepositA = new(big.Int).Set(deposit)
	} else {
		ch.DepositB = new(big.Int).Set(deposit)
	}
	return ch
}

// signState has both parties sign, in the contract's A/B order rather than the
// order the callers were passed in.
func signState(t *testing.T, ch *Channel, st State, x, y *signer) SignedState {
	t.Helper()
	raw := st.Digest(ch.ChainID, ch.Contract)
	ss := SignedState{State: st}
	for _, s := range []*signer{x, y} {
		if ch.IsA(s.address()) {
			ss.SigA = s.sign(raw)
		} else {
			ss.SigB = s.sign(raw)
		}
	}
	return ss
}

func TestAcceptWalksTipsWithoutTouchingTheChain(t *testing.T) {
	tipper, recipient := newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))

	tips := []int64{5, 25, 100, 5, 25}
	paid := int64(0)
	for i, tip := range tips {
		paid += tip
		st := State{Channel: ch.ID, Nonce: uint64(i + 1)}
		remaining, received := anon(500-paid), anon(paid)
		if ch.IsA(tipper.address()) {
			st.BalanceA, st.BalanceB = remaining, received
		} else {
			st.BalanceA, st.BalanceB = received, remaining
		}
		if err := ch.Accept(signState(t, ch, st, tipper, recipient)); err != nil {
			t.Fatalf("tip %d of %d ANON: %v", i+1, tip, err)
		}
	}

	if got := ch.BalanceOf(recipient.address()); got.Cmp(anon(160)) != 0 {
		t.Fatalf("recipient holds %s, want 160 ANON", got)
	}
	if got := ch.BalanceOf(tipper.address()); got.Cmp(anon(340)) != 0 {
		t.Fatalf("tipper holds %s, want 340 ANON", got)
	}
	if ch.Latest.State.Nonce != 5 {
		t.Fatalf("nonce %d, want 5", ch.Latest.State.Nonce)
	}
}

func TestAcceptRefusesReplayedAndRegressedNonces(t *testing.T) {
	tipper, recipient := newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))

	first := State{Channel: ch.ID, Nonce: 4}
	second := State{Channel: ch.ID, Nonce: 9}
	for _, st := range []*State{&first, &second} {
		if ch.IsA(tipper.address()) {
			st.BalanceA, st.BalanceB = anon(450), anon(50)
		} else {
			st.BalanceA, st.BalanceB = anon(50), anon(450)
		}
	}
	if err := ch.Accept(signState(t, ch, second, tipper, recipient)); err != nil {
		t.Fatalf("nonce 9: %v", err)
	}
	// Older, and equal, are both refused. Two different states at one nonce is
	// what a double spend looks like.
	if err := ch.Accept(signState(t, ch, first, tipper, recipient)); err != ErrNonceRegressed {
		t.Fatalf("stale nonce 4: got %v, want ErrNonceRegressed", err)
	}
	if err := ch.Accept(signState(t, ch, second, tipper, recipient)); err != ErrNonceRegressed {
		t.Fatalf("replayed nonce 9: got %v, want ErrNonceRegressed", err)
	}
}

func TestAcceptRefusesInventedMoney(t *testing.T) {
	tipper, recipient := newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))

	// Both parties happily sign a state paying out 600 from a 500 deposit.
	// Signatures are not the safeguard here; conservation is.
	st := State{Channel: ch.ID, Nonce: 1, BalanceA: anon(300), BalanceB: anon(300)}
	if err := ch.Accept(signState(t, ch, st, tipper, recipient)); err != ErrNotConserved {
		t.Fatalf("got %v, want ErrNotConserved", err)
	}
}

func TestAcceptRefusesOneSidedAndForeignSignatures(t *testing.T) {
	tipper, recipient, stranger := newSigner(t), newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))

	st := State{Channel: ch.ID, Nonce: 1}
	if ch.IsA(tipper.address()) {
		st.BalanceA, st.BalanceB = anon(495), anon(5)
	} else {
		st.BalanceA, st.BalanceB = anon(5), anon(495)
	}

	// One signature is a claim, not an agreement.
	half := signState(t, ch, st, tipper, recipient)
	half.SigB = nil
	if err := ch.Accept(half); err != ErrBadStateSignature {
		t.Fatalf("one-sided: got %v, want ErrBadStateSignature", err)
	}

	// A stranger's perfectly valid signature is still the wrong party's.
	forged := signState(t, ch, st, tipper, stranger)
	if err := ch.Accept(forged); err == nil {
		t.Fatal("a state signed by a non-party was accepted")
	}
}

func TestAcceptRefusesAnotherChannelsState(t *testing.T) {
	tipper, recipient := newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))

	st := State{Channel: [32]byte{0xaa}, Nonce: 1, BalanceA: anon(500), BalanceB: new(big.Int)}
	if err := ch.Accept(SignedState{State: st, SigA: make([]byte, 65), SigB: make([]byte, 65)}); err != ErrWrongChannel {
		t.Fatalf("got %v, want ErrWrongChannel", err)
	}
}

// Locked value belongs to neither balance. Counting it inside the payer's
// balance would let them sign it away twice.
func TestConservationCountsLockedValueOutsideBalances(t *testing.T) {
	st := State{
		BalanceA: anon(300), BalanceB: anon(150),
		Pending: []HTLC{{ID: [32]byte{1}, Amount: anon(50), Expiry: 1, PayerIsA: true}},
	}
	if !st.Conserved(anon(500), new(big.Int)) {
		t.Fatal("300 + 150 + 50 locked should conserve a 500 deposit")
	}
	// The same numbers without the lock do not add up, which is the point.
	bare := State{BalanceA: anon(300), BalanceB: anon(150)}
	if bare.Conserved(anon(500), new(big.Int)) {
		t.Fatal("300 + 150 should not conserve 500")
	}
}

// A state signed with locks must not verify once the locks are removed. This is
// the off-chain half of the contract test "will not let a signed state be
// presented with its locks removed".
func TestAcceptRefusesAStateStrippedOfItsLocks(t *testing.T) {
	tipper, recipient := newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))

	withLocks := State{
		Channel: ch.ID, Nonce: 1, BalanceA: anon(400), BalanceB: anon(50),
		Pending: []HTLC{{ID: [32]byte{1}, Hash: [32]byte{2}, Amount: anon(50), Expiry: 1 << 40, PayerIsA: true}},
	}
	if !ch.IsA(tipper.address()) {
		withLocks.BalanceA, withLocks.BalanceB = anon(50), anon(400)
	}
	signed := signState(t, ch, withLocks, tipper, recipient)

	// Same balances, same nonce, same signatures — locks gone. 50 ANON would
	// cease to exist if this were accepted.
	stripped := signed
	stripped.State.Pending = nil
	if err := ch.Accept(stripped); err == nil {
		t.Fatal("a state was accepted with its locks removed")
	}

	// Intact, it is fine.
	if err := ch.Accept(signed); err != nil {
		t.Fatalf("the intact state was refused: %v", err)
	}
}

func TestHTLCRootIsOrderIndependent(t *testing.T) {
	one := HTLC{ID: [32]byte{1}, Hash: [32]byte{9}, Amount: anon(5), Expiry: 100}
	two := HTLC{ID: [32]byte{2}, Hash: [32]byte{8}, Amount: anon(7), Expiry: 200}

	a := State{Pending: []HTLC{one, two}}.HTLCRoot()
	b := State{Pending: []HTLC{two, one}}.HTLCRoot()
	if a != b {
		t.Fatal("HTLCRoot depends on slice order; two nodes would disagree")
	}
	if (State{}).HTLCRoot() != ([32]byte{}) {
		t.Fatal("no locks should give the zero root")
	}
}

func TestAcceptRefusesDuplicateAndExpiredLocks(t *testing.T) {
	tipper, recipient := newSigner(t), newSigner(t)
	ch := newFundedChannel(t, tipper, recipient, anon(500))

	dup := SignedState{State: State{
		Channel: ch.ID, Nonce: 1, BalanceA: anon(400), BalanceB: new(big.Int),
		Pending: []HTLC{
			{ID: [32]byte{7}, Amount: anon(50), Expiry: 10},
			{ID: [32]byte{7}, Amount: anon(50), Expiry: 10},
		},
	}, SigA: make([]byte, 65), SigB: make([]byte, 65)}
	if err := ch.Accept(dup); err != ErrDuplicateHTLC {
		t.Fatalf("duplicate lock id: got %v, want ErrDuplicateHTLC", err)
	}

	stale := SignedState{State: State{
		Channel: ch.ID, Nonce: 1, BalanceA: anon(450), BalanceB: new(big.Int),
		Pending: []HTLC{{ID: [32]byte{7}, Amount: anon(50), Expiry: 0}},
	}, SigA: make([]byte, 65), SigB: make([]byte, 65)}
	if err := ch.Accept(stale); err != ErrHTLCExpiryPast {
		t.Fatalf("expired lock: got %v, want ErrHTLCExpiryPast", err)
	}
}

func TestReplayKeyIsChannelAndNonce(t *testing.T) {
	id := [32]byte{0xab, 0xcd}
	if ReplayKey(id, 7) == ReplayKey(id, 8) {
		t.Fatal("two nonces share a replay key")
	}
	if ReplayKey(id, 7) != ReplayKey(id, 7) {
		t.Fatal("replay key is not stable")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = digits[c>>4], digits[c&0x0f]
	}
	return string(out)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | (c - 'a' + 10)
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		out[i] = v
	}
	if bytes.Equal(out, nil) {
		t.Fatal("empty hex")
	}
	return out
}
