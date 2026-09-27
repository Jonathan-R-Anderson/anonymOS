package channel

import (
	"bytes"
	"errors"
	"testing"
)

var seedA = [32]byte{0x01}
var seedB = [32]byte{0x02}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	k := DeriveKey(seedA)
	proof, err := k.SignBalance("ch1", 5, 100, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBalance(k.PublicKey(), proof, 100, 50); err != nil {
		t.Fatalf("a valid proof failed verification: %v", err)
	}
}

// THE property. A signature must not verify against balances the signer never
// agreed to, or a peer signs one state and claims another.
func TestSignatureDoesNotCoverOtherBalances(t *testing.T) {
	k := DeriveKey(seedA)
	proof, _ := k.SignBalance("ch1", 5, 100, 50)
	for _, tc := range []struct{ out, in Amount }{
		{101, 50}, {100, 51}, {50, 100}, {0, 0},
	} {
		if err := VerifyBalance(k.PublicKey(), proof, tc.out, tc.in); err == nil {
			t.Errorf("a proof for (100,50) verified against (%d,%d)", tc.out, tc.in)
		}
	}
}

// A proof for one nonce must not verify at another, or an old state replays.
func TestSignatureIsBoundToTheNonce(t *testing.T) {
	k := DeriveKey(seedA)
	proof, _ := k.SignBalance("ch1", 5, 100, 50)
	proof.Nonce = 6
	if err := VerifyBalance(k.PublicKey(), proof, 100, 50); err == nil {
		t.Fatal("a proof verified at a different nonce")
	}
}

// And to the channel, or a proof moves between channels.
func TestSignatureIsBoundToTheChannel(t *testing.T) {
	k := DeriveKey(seedA)
	proof, _ := k.SignBalance("ch1", 5, 100, 50)
	proof.Channel = "ch2"
	if err := VerifyBalance(k.PublicKey(), proof, 100, 50); err == nil {
		t.Fatal("a proof verified against a different channel")
	}
}

// Length-prefixing: ("ab", nonce 1) and ("a", nonce ...) must not collide.
// Without it one signature authorises two different states.
func TestEncodingIsUnambiguous(t *testing.T) {
	a := proofDigest("ab", 1, 10, 20)
	b := proofDigest("a", 1, 10, 20)
	if a == b {
		t.Fatal("channel ids of different lengths collide")
	}
	if proofDigest("ch", 1, 10, 20) == proofDigest("ch", 1, 20, 10) {
		t.Fatal("swapping the balances produces the same digest")
	}
}

// The channel key must NOT be the payout key. One leaked hot key should cost
// what is committed to channels, not the address earnings accumulate in.
func TestChannelKeyIsNotTheSeed(t *testing.T) {
	k := DeriveKey(seedA)
	pub := k.PublicKey()
	if bytes.Contains(pub, seedA[:]) {
		t.Fatal("the seed is recoverable from the channel public key")
	}
	// Different seeds must give different keys, or every node shares an identity.
	if bytes.Equal(DeriveKey(seedA).PublicKey(), DeriveKey(seedB).PublicKey()) {
		t.Fatal("two seeds produced the same channel key")
	}
	// Derivation must be deterministic, or a node cannot verify its own history.
	if !bytes.Equal(DeriveKey(seedA).PublicKey(), DeriveKey(seedA).PublicKey()) {
		t.Fatal("key derivation is not deterministic")
	}
}

func TestAnotherKeyCannotForgeAProof(t *testing.T) {
	victim := DeriveKey(seedA)
	attacker := DeriveKey(seedB)
	forged, _ := attacker.SignBalance("ch1", 5, 100, 50)
	if err := VerifyBalance(victim.PublicKey(), forged, 100, 50); err == nil {
		t.Fatal("a proof signed by another key verified")
	}
}

func TestUnsignedProofIsRejected(t *testing.T) {
	k := DeriveKey(seedA)
	if err := VerifyBalance(k.PublicKey(), BalanceProof{Channel: "ch1"}, 1, 1); !errors.Is(err, ErrNotSigned) {
		t.Fatal("an unsigned proof was accepted")
	}
}

func TestMalformedInputsAreRejectedNotPanicking(t *testing.T) {
	k := DeriveKey(seedA)
	proof, _ := k.SignBalance("ch1", 5, 100, 50)
	if err := VerifyBalance([]byte{1, 2, 3}, proof, 100, 50); !errors.Is(err, ErrBadSignature) {
		t.Error("a malformed public key was not rejected cleanly")
	}
	proof.Signature = []byte{9, 9, 9}
	if err := VerifyBalance(k.PublicKey(), proof, 100, 50); !errors.Is(err, ErrBadSignature) {
		t.Error("a malformed signature was not rejected cleanly")
	}
}

func TestNilKeyRefusesToSign(t *testing.T) {
	var k *Key
	if _, err := k.SignBalance("ch1", 1, 1, 1); !errors.Is(err, ErrNoKey) {
		t.Fatal("a nil key signed something")
	}
}
