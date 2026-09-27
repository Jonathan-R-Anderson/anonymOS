package dcs

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// These fixtures were produced by the Python coordinator
// (backend/services/content_keys.py) so this test proves the Go worker decodes
// exactly what the server encrypts -- the byte-level contract between the two
// implementations. Regenerate them if the blob format ever changes.
const (
	fixtureBlobHex      = "5343453100106c61622f696e7465726f702d746573740258df754b9cf2d87821be1ef8a1a3ad14b426fc152667f3e6e5b2969a1aaa4f3bbacc138e2ef9aaa9e84e5b16003038599babca55d7f72944fa6eeddaf0d9e1fd8c21989c31e63462f566216093bdd3fb9e469c53190c3b0f49a592ade4052b03d6de8fb19e4dd2140f06548bc80334d866bd8cab1719d61bd7c4dc996b170ed5af8acc28f11e15ffce10f694c977d90e3e4508e759efd70c93df"
	fixtureSealedB64    = "1n0kujjEq+qwQLCv3oqER0WuBGA+cTq5QnM1X2qog3XtYSr4LAwX38mNKzHuw25DH0LYcjqWOsRa98uEOO2wF/EACGr4aL5fvmjSWwOZpwQ="
	fixtureWorkerPriv   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	fixturePlaintextHex = "76756c68756220636f6d706f736520696e7465726f7020636865636b200001fe"
)

func TestDecryptContentFromPythonCoordinator(t *testing.T) {
	blob, _ := hex.DecodeString(fixtureBlobHex)
	sealed, _ := base64.StdEncoding.DecodeString(fixtureSealedB64)
	privBytes, _ := hex.DecodeString(fixtureWorkerPriv)
	wantPlaintext, _ := hex.DecodeString(fixturePlaintextHex)

	// Reconstruct the worker's Curve25519 keypair and open the sealed grant the
	// same way the running node does.
	var priv, pub [32]byte
	copy(priv[:], privBytes)
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], derived)

	contentKey, ok := box.OpenAnonymous(nil, sealed, &pub, &priv)
	if !ok {
		t.Fatal("could not open the sealed content key produced by the coordinator")
	}
	if len(contentKey) != 32 {
		t.Fatalf("content key length = %d, want 32", len(contentKey))
	}

	plaintext, err := DecryptContent(blob, contentKey)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if !bytes.Equal(plaintext, wantPlaintext) {
		t.Fatalf("decrypted %q, want %q", plaintext, wantPlaintext)
	}
}

// A grant sealed to one worker must not open with another worker's key.
func TestSealedGrantIsRecipientOnly(t *testing.T) {
	recipientPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intruderPub, intruderPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sealedB64, err := SealContentKey([]byte("0123456789abcdef0123456789abcdef"), base64.StdEncoding.EncodeToString(recipientPub[:]))
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := base64.StdEncoding.DecodeString(sealedB64)

	if _, ok := box.OpenAnonymous(nil, sealed, intruderPub, intruderPriv); ok {
		t.Fatal("a non-recipient opened the grant")
	}
}
