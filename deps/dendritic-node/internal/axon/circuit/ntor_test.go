package circuit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// newRelayStatic generates a relay's RoutingIdentity material and its static
// X25519 private key.
func newRelayStatic(t *testing.T) (RelayStatic, [32]byte) {
	t.Helper()
	var rid, b [32]byte
	if _, err := rand.Read(rid[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(b[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var static RelayStatic
	static.RID = rid
	copy(static.B[:], pub)
	static.Epoch = 42
	return static, b
}

// TestHandshakeAgrees is the basic property: both sides derive the same keys.
func TestHandshakeAgrees(t *testing.T) {
	static, b := newRelayStatic(t)

	h, createBody, err := NewClientHandshake(rand.Reader, static)
	if err != nil {
		t.Fatal(err)
	}
	if len(createBody) != CreateBodySize {
		t.Fatalf("CREATE body is %d bytes, section 8.2 says %d", len(createBody), CreateBodySize)
	}

	relayKeys, reply, err := ServerHandshake(rand.Reader, static, b, createBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != CreatedBodySize {
		t.Fatalf("CREATED body is %d bytes, section 8.2 says %d", len(reply), CreatedBodySize)
	}

	clientKeys, err := h.Complete(reply)
	if err != nil {
		t.Fatal(err)
	}
	if clientKeys != relayKeys {
		t.Fatal("client and relay derived different keys")
	}
	// Every derived value must be distinct: a KDF bug that returned the same
	// 32 bytes four times would still "agree".
	seen := map[string]string{}
	for name, k := range map[string][]byte{
		"Kf": clientKeys.Kf[:], "Kb": clientKeys.Kb[:],
		"Af": clientKeys.Af[:], "Ab": clientKeys.Ab[:],
	} {
		s := hex.EncodeToString(k)
		if prev, dup := seen[s]; dup {
			t.Fatalf("%s and %s are the same key material", name, prev)
		}
		seen[s] = name
	}
	if clientKeys.NPf == clientKeys.NPb {
		t.Fatal("forward and backward nonce prefixes are identical")
	}
}

// TestWrongStaticKeyCostsNoScalarMultiplication is section 8.2's first line of
// handshake DoS defence: a relay that does not hold B answers without doing any
// cryptography, so a client with a stale descriptor costs one comparison rather
// than one scalar multiplication.
func TestWrongStaticKeyCostsNoScalarMultiplication(t *testing.T) {
	static, b := newRelayStatic(t)
	other, _ := newRelayStatic(t)

	_, createBody, err := NewClientHandshake(rand.Reader, other) // aimed elsewhere
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ServerHandshake(rand.Reader, static, b, createBody); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("err = %v, want ErrWrongKey", err)
	}

	// A body naming the right ID but the wrong B is refused too: both halves of
	// the check matter, since the ID alone does not pin the epoch's static key.
	_, good, err := NewClientHandshake(rand.Reader, static)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), good...)
	tampered[32] ^= 0xFF
	if _, _, err := ServerHandshake(rand.Reader, static, b, tampered); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("err = %v, want ErrWrongKey for a wrong B", err)
	}
}

// TestForgedAuthIsRejected: AUTH is a MAC keyed by material derived from
// EXP(X,b), so a relay cannot be impersonated without the static private key.
// This is the entire security of telescoping.
func TestForgedAuthIsRejected(t *testing.T) {
	static, b := newRelayStatic(t)
	h, createBody, err := NewClientHandshake(rand.Reader, static)
	if err != nil {
		t.Fatal(err)
	}
	_, reply, err := ServerHandshake(rand.Reader, static, b, createBody)
	if err != nil {
		t.Fatal(err)
	}

	forged := append([]byte(nil), reply...)
	forged[CreatedBodySize-1] ^= 0x01
	if _, err := h.Complete(forged); !errors.Is(err, ErrAuthMismatch) {
		t.Fatalf("err = %v, want ErrAuthMismatch", err)
	}
}

// TestImpersonationWithoutTheStaticKeyFails: an intermediate hop forwarding an
// EXTEND sees X and Y in the clear and still cannot produce a valid AUTH.
func TestImpersonationWithoutTheStaticKeyFails(t *testing.T) {
	static, _ := newRelayStatic(t)
	// The impostor knows the descriptor (RID, B) but not b, so it substitutes
	// its own static key.
	_, impostorPriv := newRelayStatic(t)

	h, createBody, err := NewClientHandshake(rand.Reader, static)
	if err != nil {
		t.Fatal(err)
	}
	// It answers as though it were the relay, using its own private key.
	_, reply, err := ServerHandshake(rand.Reader, static, impostorPriv, createBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Complete(reply); !errors.Is(err, ErrAuthMismatch) {
		t.Fatalf("an impostor without b produced an accepted AUTH (err = %v)", err)
	}
}

// TestLowOrderPointRejected: a low-order point produces a zero shared secret
// for any private key, so an attacker sending one would drive both sides to a
// predictable key.
func TestLowOrderPointRejected(t *testing.T) {
	static, b := newRelayStatic(t)
	_, createBody, err := NewClientHandshake(rand.Reader, static)
	if err != nil {
		t.Fatal(err)
	}
	// Replace X with the all-zero point.
	body := append([]byte(nil), createBody...)
	for i := 64; i < 96; i++ {
		body[i] = 0
	}
	if _, _, err := ServerHandshake(rand.Reader, static, b, body); !errors.Is(err, ErrLowOrderPoint) {
		t.Fatalf("err = %v, want ErrLowOrderPoint", err)
	}
}

// TestEphemeralIsZeroedAfterCompletion backs the forward-secrecy claim at the
// process level, not only the protocol level: an adversary who obtains b later
// recovers EXP(X,b) and nothing else, which requires x to be gone.
func TestEphemeralIsZeroedAfterCompletion(t *testing.T) {
	static, b := newRelayStatic(t)
	h, createBody, err := NewClientHandshake(rand.Reader, static)
	if err != nil {
		t.Fatal(err)
	}
	_, reply, err := ServerHandshake(rand.Reader, static, b, createBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Complete(reply); err != nil {
		t.Fatal(err)
	}
	var zero [32]byte
	if h.x != zero {
		t.Fatal("the client ephemeral survived key derivation")
	}
}

// TestKeyScheduleGoldenVectors is T5.4: golden vectors so a KDF label change
// fails the build rather than silently producing circuits the deployed network
// cannot talk to.
//
// The vectors are derived from FIXED inputs, so they pin the exact label
// strings, the exact secret_input concatenation order, and the exact 136-byte
// split. Changing any one of them changes these digests.
func TestKeyScheduleGoldenVectors(t *testing.T) {
	// Fixed, non-random inputs.
	var expXy, expXb, id, B, X, Y [32]byte
	for i := 0; i < 32; i++ {
		expXy[i] = byte(i)
		expXb[i] = byte(0x40 + i)
		id[i] = byte(0x80 + i)
		B[i] = byte(0xC0 + i)
		X[i] = byte(0x10 + i)
		Y[i] = byte(0x20 + i)
	}
	secret := secretInput(expXy, expXb, id, B, X, Y)
	ks, auth, err := deriveAndAuth(secret, id, B, Y, X)
	if err != nil {
		t.Fatal(err)
	}

	// Compared as one concatenation so a mismatch is one failure line rather
	// than seven, and so a reordering of the 136-byte split is caught too.
	all := make([]byte, 0, 136+32)
	all = append(all, ks.Kf[:]...)
	all = append(all, ks.Kb[:]...)
	all = append(all, ks.Af[:]...)
	all = append(all, ks.Ab[:]...)
	all = append(all, ks.NPf[:]...)
	all = append(all, ks.NPb[:]...)
	all = append(all, auth[:]...)

	const want = goldenKeySchedule
	if got := hex.EncodeToString(all); got != want {
		t.Fatalf("T5.4: key schedule changed.\n got %s\nwant %s\n"+
			"If this was intentional, the wire protocol changed and every deployed "+
			"relay must be updated in lockstep.", got, want)
	}

	// And the labels themselves are pinned, so a rename cannot slip through by
	// coincidentally producing the same digest.
	if protoID != "axon-ntor-v1" || tKey != "axon-ntor-v1:key_extract" ||
		tVerify != "axon-ntor-v1:verify" || tMAC != "axon-ntor-v1:mac" ||
		mExpand != "axon-ntor-v1:key_expand" {
		t.Fatal("T5.4: a domain-separation label was renamed")
	}
}

// TestSecretInputIsFixedLength: every field is 32 bytes and the PROTOID tail is
// constant, so no byte can shift from one field into the next.
func TestSecretInputIsFixedLength(t *testing.T) {
	var a, b2, c, d, e, f [32]byte
	s := secretInput(a, b2, c, d, e, f)
	if len(s) != 32*6+len(protoID) {
		t.Fatalf("secret_input is %d bytes, want %d", len(s), 32*6+len(protoID))
	}
	if !bytes.HasSuffix(s, []byte(protoID)) {
		t.Fatal("secret_input does not end with PROTOID")
	}
}

// TestHandshakeBodySizesMatchTheSpec.
func TestHandshakeBodySizesMatchTheSpec(t *testing.T) {
	if CreateBodySize != 96 {
		t.Errorf("CREATE body = %d, section 8.2 says 96", CreateBodySize)
	}
	if CreatedBodySize != 64 {
		t.Errorf("CREATED body = %d, section 8.2 says 64", CreatedBodySize)
	}
	if KeyMaterialSize != 136 {
		t.Errorf("key material = %d, section 8.2 says 136", KeyMaterialSize)
	}
	if HTypeNtorV1 != 0x0001 || HTypeNtorHybrid != 0x0002 {
		t.Error("handshake type codes do not match section 8.2")
	}
}
