package facilitation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func addressOf(pub *secp256k1.PublicKey) string {
	u := pub.SerializeUncompressed()
	h := keccak256(u[1:])
	return "0x" + hex.EncodeToString(h[12:])
}

func TestWalletPersistsAndSignRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.key")
	w, err := LoadOrCreateWallet(path)
	if err != nil {
		t.Fatal(err)
	}
	// A reload must yield the same address (the key persisted).
	w2, err := LoadOrCreateWallet(path)
	if err != nil {
		t.Fatal(err)
	}
	if w.AddressHex() != w2.AddressHex() {
		t.Fatalf("wallet not persisted: %s != %s", w.AddressHex(), w2.AddressHex())
	}
	if len(w.AddressHex()) != 42 {
		t.Fatalf("bad address: %s", w.AddressHex())
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	digest := RegistrationDigest(big.NewInt(300), [20]byte{19: 0x42}, pub,
		CapDHT|CapStorage, EndpointCommitment("http://x", "secret", 7), big.NewInt(1))
	v, r, s := w.SignDigest(digest)
	if v != 27 && v != 28 {
		t.Fatalf("recovery id not 27/28 (Solidity ecrecover needs that): %d", v)
	}

	// Recover exactly as Solidity ecrecover(digest, v, r, s) would: the recovered
	// address must equal the signing wallet's address.
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:33], r[:])
	copy(compact[33:65], s[:])
	recPub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := addressOf(recPub); got != w.AddressHex() {
		t.Fatalf("recovered %s != wallet %s", got, w.AddressHex())
	}
}

func TestRegistrationDigestDeterministic(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	reg := [20]byte{0: 0xab}
	a := RegistrationDigest(big.NewInt(300), reg, pub, CapGateway, [32]byte{}, big.NewInt(2))
	b := RegistrationDigest(big.NewInt(300), reg, pub, CapGateway, [32]byte{}, big.NewInt(2))
	if a != b {
		t.Fatal("digest not deterministic")
	}
	// Changing the nonce changes the digest.
	c := RegistrationDigest(big.NewInt(300), reg, pub, CapGateway, [32]byte{}, big.NewInt(3))
	if a == c {
		t.Fatal("digest ignored the nonce")
	}
}

func TestNodeID(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if NodeID(pub) != NodeID(pub) {
		t.Fatal("nodeId not deterministic")
	}
	if NodeID(pub) == ([32]byte{}) {
		t.Fatal("nodeId is zero")
	}
}

func TestBuildRegisterIntent(t *testing.T) {
	w, _ := LoadOrCreateWallet(filepath.Join(t.TempDir(), "w.key"))
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	intent := w.BuildRegisterIntent(big.NewInt(300), [20]byte{}, pub, CapGateway|CapWitness, [32]byte{}, big.NewInt(1))
	if intent.Owner != w.AddressHex() {
		t.Fatalf("owner mismatch: %s", intent.Owner)
	}
	if intent.Capabilities != (CapGateway | CapWitness) {
		t.Fatal("capabilities mismatch")
	}
	if len(intent.R) != 66 || len(intent.S) != 66 { // 0x + 64 hex
		t.Fatalf("bad r/s hex length: %d/%d", len(intent.R), len(intent.S))
	}
}

// The channel seed must not expose the wallet key. A routing node's hot key is
// derived from this, so a leak here would cost the operator everything the node
// has earned rather than only what is committed to channels.
func TestChannelSeedDoesNotRevealTheWalletKey(t *testing.T) {
	dir := t.TempDir()
	w, err := LoadOrCreateWallet(dir + "/key")
	if err != nil {
		t.Fatal(err)
	}
	seed := w.ChannelSeed()
	raw := w.priv.Serialize()
	if bytes.Equal(seed[:], raw) {
		t.Fatal("the channel seed IS the wallet key")
	}
	if bytes.Contains(seed[:], raw[:8]) {
		t.Fatal("the channel seed leaks wallet key material")
	}
	// Deterministic, or the node cannot re-derive its own channel identity.
	if again := w.ChannelSeed(); again != seed {
		t.Fatal("channel seed derivation is not deterministic")
	}
}

func TestDifferentWalletsGiveDifferentChannelSeeds(t *testing.T) {
	a, _ := LoadOrCreateWallet(t.TempDir() + "/a")
	b, _ := LoadOrCreateWallet(t.TempDir() + "/b")
	if a.ChannelSeed() == b.ChannelSeed() {
		t.Fatal("two wallets share a channel seed")
	}
}
