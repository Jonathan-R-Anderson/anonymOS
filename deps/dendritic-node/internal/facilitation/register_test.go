package facilitation

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// The proof message is built independently in Go (here) and Python (the site's
// PofRegistration.proof_message). If they disagree by one byte the site rejects
// every honest node's registration, so the exact bytes are pinned.
func TestProofMessageBytesMatchTheServer(t *testing.T) {
	wallet := "0xB2b36AaD18d7be5d4016267BC4cCec2f12a64b6e"
	caps := uint64(0b0000101)
	commitment := "0xAABBCC0000000000000000000000000000000000000000000000000000000000"
	nonce := big.NewInt(7)

	// Mirrors the server's join order and lowercasing exactly.
	want := strings.Join([]string{
		"syndichan-pof-register:v1",
		"0xb2b36aad18d7be5d4016267bc4ccec2f12a64b6e",
		"5",
		"0xaabbcc0000000000000000000000000000000000000000000000000000000000",
		"7",
	}, "\n")

	pub, priv, _ := ed25519.GenerateKey(nil)
	sigHex := P2PRegistrationProof(priv, wallet, caps, commitment, nonce)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(want), sig) {
		t.Fatal("proof does not verify against the message the server rebuilds — " +
			"field order, lowercasing or separators have drifted")
	}
}

// A captured proof must not be replayable to point the same node at a different
// payout address; that is the entire attack it exists to stop.
func TestProofIsBoundToTheWallet(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	commitment := "0x" + strings.Repeat("11", 32)
	honest := P2PRegistrationProof(priv, "0xaaaa000000000000000000000000000000000000", 1, commitment, big.NewInt(1))

	// The same signature offered for an attacker's wallet must not verify.
	attackerMsg := strings.Join([]string{
		"syndichan-pof-register:v1",
		"0xbbbb000000000000000000000000000000000000",
		"1", commitment, "1",
	}, "\n")
	sig, _ := hex.DecodeString(honest)
	if ed25519.Verify(pub, []byte(attackerMsg), sig) {
		t.Fatal("a proof for one wallet verified for another — node identities could be hijacked")
	}
}

func TestBuildRegistrationRequestCarriesBothSignatures(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	intent := RegisterIntent{
		P2PPublicKey:       hex.EncodeToString(pub),
		Capabilities:       CapStorage,
		EndpointCommitment: "0x" + strings.Repeat("22", 32),
		Nonce:              "42",
		Owner:              "0xCCCC000000000000000000000000000000000000",
		V:                  27,
		R:                  "0x" + strings.Repeat("33", 32),
		S:                  "0x" + strings.Repeat("44", 32),
	}
	req, err := BuildRegistrationRequest(intent, priv)
	if err != nil {
		t.Fatal(err)
	}
	if req.P2PProof == "" || req.R == "" || req.V == 0 {
		t.Fatal("request is missing one of the two signatures")
	}
	if req.Wallet != strings.ToLower(intent.Owner) {
		t.Fatal("wallet was not normalised — the server lowercases before verifying")
	}
	if req.Nonce != 42 {
		t.Fatalf("nonce %d, want 42", req.Nonce)
	}
	// And the proof must verify against what the server will rebuild.
	msg := strings.Join([]string{
		"syndichan-pof-register:v1", req.Wallet, "4",
		strings.ToLower(intent.EndpointCommitment), "42",
	}, "\n")
	sig, _ := hex.DecodeString(req.P2PProof)
	if !ed25519.Verify(pub, []byte(msg), sig) {
		t.Fatal("built proof does not verify")
	}
}
