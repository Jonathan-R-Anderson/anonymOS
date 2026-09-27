package p2p

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// loadOrCreateContentKey loads (or creates) the node's Curve25519 content key.
// The coordinator seals a per-object content key to the public half so only this
// node can open it; the ed25519 libp2p identity cannot be used for that because
// it is a signing key, not an ECDH key.
func loadOrCreateContentKey(path string) (priv, pub [32]byte, err error) {
	data, rerr := os.ReadFile(path)
	if rerr == nil {
		if len(data) != 32 {
			return priv, pub, errors.New("content.key has invalid length")
		}
		copy(priv[:], data)
	} else if errors.Is(rerr, os.ErrNotExist) {
		if _, err = rand.Read(priv[:]); err != nil {
			return priv, pub, err
		}
		if err = os.WriteFile(path, priv[:], 0600); err != nil {
			return priv, pub, err
		}
	} else {
		return priv, pub, rerr
	}
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], derived)
	return priv, pub, nil
}

// ContentPublicKey is the base64 Curve25519 public key this node advertises so
// the coordinator can seal per-object content keys to it.
func (n *Node) ContentPublicKey() string {
	return base64.StdEncoding.EncodeToString(n.contentPub[:])
}

// OpenSealedContentKey opens a libsodium sealed box (PyNaCl SealedBox on the
// server) and returns the enclosed content key. Only this node's content private
// key can open it, which is exactly the per-object access grant.
func (n *Node) OpenSealedContentKey(sealed []byte) ([]byte, error) {
	out, ok := box.OpenAnonymous(nil, sealed, &n.contentPub, &n.contentPriv)
	if !ok {
		return nil, errors.New("could not open sealed content key")
	}
	return out, nil
}
