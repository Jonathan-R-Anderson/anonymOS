package identity

import (
	"crypto/ed25519"
	"fmt"
)

// Raw key access, for the AXON runtime (internal/axon/runtime) and nothing else.
//
// Every identity type keeps its private key unexported and offers only a
// domain-separated Sign. That is the right default and it stays the default.
// But four consumers take a key in a form Sign cannot provide: the libp2p host
// authenticating links (an Ed25519 private key), the ntor responder (the X25519
// static private scalar), dht record signing (raw Ed25519 over a canonical
// encoding, no label), and per-period blinding (BlindSigner needs the service's
// private key). Before these accessors the only way to run any of them was the
// tests' in-package reach into the private field.

// PrivateKey is the NodeIdentity's Ed25519 private key: the libp2p host key
// that authenticates links, and the signer of the node's RelayDescriptor.
func (n NodeIdentity) PrivateKey() ed25519.PrivateKey { return n.private }

// StaticPrivate is the RoutingIdentity's X25519 static private scalar -- the
// ntor responder's `b` (circuit.RelayEndpoint.B). Already clamped.
func (r RoutingIdentity) StaticPrivate() [32]byte { return r.xPrivate }

// EdPrivateKey is the RoutingIdentity's Ed25519 private key, which signs
// epoch-scoped records such as an IntroPointRecord.
func (r RoutingIdentity) EdPrivateKey() ed25519.PrivateKey { return r.edPrivate }

// PrivateKey is the ServiceIdentity's Ed25519 private key, for BlindSigner.
func (s ServiceIdentity) PrivateKey() ed25519.PrivateKey { return s.private }

// Seed is what persists a ServiceIdentity: the 32-byte Ed25519 seed.
func (s ServiceIdentity) Seed() [32]byte {
	var out [32]byte
	copy(out[:], s.private.Seed())
	return out
}

// ServiceIdentityFromSeed reloads a ServiceIdentity saved with Seed. A service
// that cannot do this gets a new address at every restart.
func ServiceIdentityFromSeed(seed [32]byte) (ServiceIdentity, error) {
	if seed == ([32]byte{}) {
		return ServiceIdentity{}, fmt.Errorf("identity: zero service seed")
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	return ServiceIdentity{Public: priv.Public().(ed25519.PublicKey), private: priv}, nil
}
