// Package circuit is AXON's L4: telescoping onion circuits over the L2 link.
//
// Three hops by default. Each hop shares an AEAD key with the client and nobody
// else, so no relay learns more than its two neighbours, and forging a layer is
// forging an AEAD.
//
// WHAT THIS PACKAGE DOES NOT DO, per P5's "must NOT be built yet": path
// SELECTION (P12 -- Build takes an explicit path and must keep taking one),
// guards and tunnel pools (P7), rendezvous (P6), and padding schedules (P13).
// The terminal hop never reaches clearnet; there is no exit role in v1.
package circuit

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HTYPE 0x0001 -- axon-ntor-v1 (X25519), section 8.2.
//
// One round trip, ntor-style, against the RoutingIdentity -- NEVER
// NodeIdentity. RoutingIdentity is epoch-scoped, which is what makes the
// forward-secrecy boundary meaningful and lets a relay rotate circuit keys
// without losing its bond or its reputation.

// Handshake type codes.
const (
	HTypeNtorV1     uint16 = 0x0001 // X25519
	HTypeNtorHybrid uint16 = 0x0002 // X25519 + ML-KEM-768; reserved, not implemented in v1
)

// The four domain-separation strings. They are constants rather than parameters
// because T5.4 pins them: a KDF label change must fail the build, not silently
// produce circuits that cannot talk to the deployed network.
const (
	protoID  = "axon-ntor-v1"
	tKey     = protoID + ":key_extract"
	tVerify  = protoID + ":verify"
	tMAC     = protoID + ":mac"
	mExpand  = protoID + ":key_expand"
	authTail = "Server"
)

// Wire sizes, section 8.2.
const (
	// CreateBodySize is ID(32) ‖ B(32) ‖ X(32).
	CreateBodySize = 96
	// CreatedBodySize is Y(32) ‖ AUTH(32).
	CreatedBodySize = 64
	// KeyMaterialSize is the 136 bytes HKDF-Expand produces.
	KeyMaterialSize = 136
)

var (
	ErrBadHandshakeSize = errors.New("axon/circuit: handshake body is the wrong size")
	ErrWrongKey         = errors.New("axon/circuit: handshake names a static key this relay does not hold")
	ErrLowOrderPoint    = errors.New("axon/circuit: X25519 output is all-zero (low-order point)")
	ErrAuthMismatch     = errors.New("axon/circuit: CREATED auth does not verify")
)

// RelayStatic is a relay's published RoutingIdentity material, from its
// RelayDescriptor (L3).
type RelayStatic struct {
	// RID is the Ed25519 RoutingIdentity signing key.
	RID [32]byte
	// B is the X25519 RoutingIdentity static DH key.
	B [32]byte
	// Epoch scopes both.
	Epoch uint64
}

// ID is SHA-256(RID) -- the 32-byte relay identifier carried in EXTEND.
func (r RelayStatic) ID() [32]byte { return sha256.Sum256(r.RID[:]) }

// KeySet is one hop's derived key material, section 8.2's 136-byte layout.
//
// Af/Ab do NOT authenticate the data path -- the AEAD tags do. Tor needs
// separate digest keys because a stream cipher has no authenticator; we do not.
// They serve the control plane: authenticated SENDME proof-of-delivery and hop
// receipts. Deriving them here costs 64 bytes of KDF output and avoids a second
// key exchange later.
type KeySet struct {
	Kf  [32]byte // forward AEAD key, client -> relay
	Kb  [32]byte // backward AEAD key
	Af  [32]byte // forward authentication key (control plane only)
	Ab  [32]byte // backward authentication key (control plane only)
	NPf [4]byte  // forward nonce prefix
	NPb [4]byte  // backward nonce prefix
}

// splitKeys carves the 136-byte KDF output into the section 8.2 layout.
func splitKeys(k []byte) (KeySet, error) {
	if len(k) != KeyMaterialSize {
		return KeySet{}, fmt.Errorf("%w: key material is %d bytes, want %d",
			ErrBadHandshakeSize, len(k), KeyMaterialSize)
	}
	var ks KeySet
	copy(ks.Kf[:], k[0:32])
	copy(ks.Kb[:], k[32:64])
	copy(ks.Af[:], k[64:96])
	copy(ks.Ab[:], k[96:128])
	copy(ks.NPf[:], k[128:132])
	copy(ks.NPb[:], k[132:136])
	return ks, nil
}

// ClientHandshake is the client's in-flight state for one hop.
type ClientHandshake struct {
	static RelayStatic
	x      [32]byte // ephemeral private; discarded once keys are derived
	X      [32]byte // ephemeral public
}

// NewClientHandshake generates the client half and returns the 96-byte CREATE
// body.
func NewClientHandshake(rnd io.Reader, static RelayStatic) (*ClientHandshake, []byte, error) {
	h := &ClientHandshake{static: static}
	if _, err := io.ReadFull(rnd, h.x[:]); err != nil {
		return nil, nil, fmt.Errorf("axon/circuit: ephemeral key: %w", err)
	}
	pub, err := curve25519.X25519(h.x[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("axon/circuit: ephemeral public: %w", err)
	}
	copy(h.X[:], pub)

	id := static.ID()
	body := make([]byte, 0, CreateBodySize)
	body = append(body, id[:]...)
	body = append(body, static.B[:]...)
	body = append(body, h.X[:]...)
	return h, body, nil
}

// Public returns the client's ephemeral public key.
func (h *ClientHandshake) Public() [32]byte { return h.X }

// ServerHandshake answers a CREATE.
//
// A relay that does not recognise ID, or whose current static key is not B,
// answers with ErrWrongKey and DOES NO CRYPTOGRAPHY. A client with a stale
// descriptor then costs the relay one comparison, not one scalar
// multiplication -- the first line of handshake DoS defence, and the reason
// this check precedes every other step.
func ServerHandshake(rnd io.Reader, static RelayStatic, b [32]byte, createBody []byte) (KeySet, []byte, error) {
	if len(createBody) != CreateBodySize {
		return KeySet{}, nil, fmt.Errorf("%w: CREATE body is %d bytes, want %d",
			ErrBadHandshakeSize, len(createBody), CreateBodySize)
	}
	var gotID, gotB, X [32]byte
	copy(gotID[:], createBody[0:32])
	copy(gotB[:], createBody[32:64])
	copy(X[:], createBody[64:96])

	wantID := static.ID()
	// Compared before any scalar multiplication. See the doc comment.
	if !hmac.Equal(gotID[:], wantID[:]) || !hmac.Equal(gotB[:], static.B[:]) {
		return KeySet{}, nil, ErrWrongKey
	}

	var y [32]byte
	if _, err := io.ReadFull(rnd, y[:]); err != nil {
		return KeySet{}, nil, fmt.Errorf("axon/circuit: ephemeral key: %w", err)
	}
	Ybytes, err := curve25519.X25519(y[:], curve25519.Basepoint)
	if err != nil {
		return KeySet{}, nil, fmt.Errorf("axon/circuit: ephemeral public: %w", err)
	}
	var Y [32]byte
	copy(Y[:], Ybytes)

	expXy, err := x25519(y[:], X[:]) // EXP(X,y)
	if err != nil {
		return KeySet{}, nil, err
	}
	expXb, err := x25519(b[:], X[:]) // EXP(X,b)
	if err != nil {
		return KeySet{}, nil, err
	}

	secret := secretInput(expXy, expXb, wantID, static.B, X, Y)
	ks, auth, err := deriveAndAuth(secret, wantID, static.B, Y, X)
	if err != nil {
		return KeySet{}, nil, err
	}

	reply := make([]byte, 0, CreatedBodySize)
	reply = append(reply, Y[:]...)
	reply = append(reply, auth[:]...)
	return ks, reply, nil
}

// Complete finishes the client side against a 64-byte CREATED reply.
//
// The AUTH check is what makes telescoping secure: AUTH is a MAC keyed by
// material derived from EXP(X,b), which requires the relay's static private
// key. An intermediate hop forwarding an EXTEND sees X and Y in the clear and
// still cannot produce a valid AUTH.
//
// What it does NOT give: possession of b allows impersonation going forward.
// Compromise of b does not open PAST circuits, because KEY_SEED depends on
// EXP(X,y) and both ephemerals are discarded once K is derived.
func (h *ClientHandshake) Complete(reply []byte) (KeySet, error) {
	if len(reply) != CreatedBodySize {
		return KeySet{}, fmt.Errorf("%w: CREATED body is %d bytes, want %d",
			ErrBadHandshakeSize, len(reply), CreatedBodySize)
	}
	var Y, gotAuth [32]byte
	copy(Y[:], reply[0:32])
	copy(gotAuth[:], reply[32:64])

	expXy, err := x25519(h.x[:], Y[:]) // EXP(X,y)
	if err != nil {
		return KeySet{}, err
	}
	expXb, err := x25519(h.x[:], h.static.B[:]) // EXP(X,b)
	if err != nil {
		return KeySet{}, err
	}

	id := h.static.ID()
	secret := secretInput(expXy, expXb, id, h.static.B, h.X, Y)
	ks, wantAuth, err := deriveAndAuth(secret, id, h.static.B, Y, h.X)
	if err != nil {
		return KeySet{}, err
	}
	// Constant time: a variable-time compare here leaks how many leading bytes
	// of a forged AUTH were right, which is a forgery oracle.
	if !hmac.Equal(gotAuth[:], wantAuth[:]) {
		return KeySet{}, ErrAuthMismatch
	}

	// The ephemeral is dead the moment the keys exist. Zeroing it is what makes
	// the forward-secrecy claim above true of the process and not only of the
	// protocol.
	for i := range h.x {
		h.x[i] = 0
	}
	return ks, nil
}

// x25519 performs the DH and rejects an all-zero output.
//
// A low-order point produces a zero shared secret for any private key, so an
// attacker sending one would drive both sides to a key they can predict.
// curve25519.X25519 already errors on this; the check is restated because
// section 8.2 states it as a MUST and a future swap of the primitive must not
// silently drop it.
func x25519(scalar, point []byte) ([32]byte, error) {
	out, err := curve25519.X25519(scalar, point)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrLowOrderPoint, err)
	}
	var zero, res [32]byte
	copy(res[:], out)
	if res == zero {
		return [32]byte{}, ErrLowOrderPoint
	}
	return res, nil
}

// secretInput is EXP(X,y) ‖ EXP(X,b) ‖ ID ‖ B ‖ X ‖ Y ‖ PROTOID.
//
// Every input is fixed-length, so no length prefixes are needed or used --
// there is no way to shift a byte from one field into the next.
func secretInput(expXy, expXb, id, B, X, Y [32]byte) []byte {
	out := make([]byte, 0, 32*6+len(protoID))
	out = append(out, expXy[:]...)
	out = append(out, expXb[:]...)
	out = append(out, id[:]...)
	out = append(out, B[:]...)
	out = append(out, X[:]...)
	out = append(out, Y[:]...)
	return append(out, []byte(protoID)...)
}

// deriveAndAuth computes AUTH and the key set from the secret input.
func deriveAndAuth(secret []byte, id, B, Y, X [32]byte) (KeySet, [32]byte, error) {
	vm := hmac.New(sha256.New, []byte(tVerify))
	vm.Write(secret)
	verify := vm.Sum(nil)

	// auth_input = verify ‖ ID ‖ B ‖ Y ‖ X ‖ PROTOID ‖ "Server"
	authInput := make([]byte, 0, len(verify)+32*4+len(protoID)+len(authTail))
	authInput = append(authInput, verify...)
	authInput = append(authInput, id[:]...)
	authInput = append(authInput, B[:]...)
	authInput = append(authInput, Y[:]...)
	authInput = append(authInput, X[:]...)
	authInput = append(authInput, []byte(protoID)...)
	authInput = append(authInput, []byte(authTail)...)

	am := hmac.New(sha256.New, []byte(tMAC))
	am.Write(authInput)
	var auth [32]byte
	copy(auth[:], am.Sum(nil))

	r := hkdf.New(sha256.New, secret, []byte(tKey), []byte(mExpand))
	k := make([]byte, KeyMaterialSize)
	if _, err := io.ReadFull(r, k); err != nil {
		return KeySet{}, [32]byte{}, fmt.Errorf("axon/circuit: key expand: %w", err)
	}
	ks, err := splitKeys(k)
	return ks, auth, err
}
