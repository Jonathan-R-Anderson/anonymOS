package p2p

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"
)

// The scheduler addresses nodes by Proof-of-Facilitation id; libp2p addresses
// them by peer id. They must be two views of ONE key, or a peer could answer
// challenges as somebody else.
func TestNodeIDFromPeerMatchesKeccakOfTheKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := libp2pcrypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := peer.IDFromPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	got, err := NodeIDFromPeer(pid)
	if err != nil {
		t.Fatalf("NodeIDFromPeer: %v", err)
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(pub)
	var want [32]byte
	copy(want[:], h.Sum(nil))

	if got != want {
		t.Fatalf("node id does not match keccak256(pubkey)\n got: %s\nwant: %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}
}

// Distinct keys must give distinct ids — otherwise two nodes would collide and
// one could collect the other's receipts.
func TestDistinctPeersGetDistinctNodeIDs(t *testing.T) {
	seen := map[[32]byte]bool{}
	for i := 0; i < 8; i++ {
		_, priv, _ := ed25519.GenerateKey(nil)
		sk, _ := libp2pcrypto.UnmarshalEd25519PrivateKey(priv)
		pid, _ := peer.IDFromPrivateKey(sk)
		id, err := NodeIDFromPeer(pid)
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatal("two peers derived the same node id")
		}
		seen[id] = true
	}
}
