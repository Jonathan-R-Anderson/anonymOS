package identity

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/syndichan/maniwani/storage-client/internal/facilitation"
)

// Migration from the existing node's p2p.key.
//
// The requirement that shapes this file, from P1's exit criterion E1.1: a node
// started from an existing syndichan-node data directory must report a Proof of
// Facilitation nodeId identical to its pre-migration value, byte for byte. The
// nodeId is bonded on-chain. A migration that silently mints a new one abandons
// the bond, and the failure is invisible until a payout does not arrive.
//
// PoF computes nodeId = keccak256(ed25519 public key). That derivation is
// reproduced here rather than imported, because the two live in different
// repositories and the test pins them together.

// PoFNodeID is the 32-byte identifier the NodeRegistry contract keys on.
type PoFNodeID [32]byte

// DerivePoFNodeID computes keccak256 over the raw 32-byte Ed25519 public key.
//
// It delegates to facilitation.NodeID rather than reimplementing the hash. That
// is the whole point: the nodeId is bonded on-chain, and a second copy of the
// derivation is a place for the two to silently drift and abandon a bond. There
// is one implementation, and this is a typed alias over it.
func DerivePoFNodeID(pub ed25519.PublicKey) PoFNodeID {
	return PoFNodeID(facilitation.NodeID(pub))
}

// LegacyNodeKey is an existing p2p.key: a raw 64-byte Ed25519 private key, or a
// 32-byte seed. Both forms are accepted because the on-disk format has varied.
type LegacyNodeKey struct {
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// PoFNodeID returns the identifier this key already has on-chain.
func (k LegacyNodeKey) PoFNodeID() PoFNodeID { return DerivePoFNodeID(k.Public) }

// Sign signs with the legacy key, so a migrating node can prove possession of
// the identity its bond is attached to.
func (k LegacyNodeKey) Sign(label string, message []byte) []byte {
	return signPrefixed(k.private, label, message)
}

// LoadLegacyNodeKey reads an existing p2p.key.
//
// It deliberately does NOT rewrite the file, derive a new key, or migrate
// anything on its own. Adopting a new identity is a decision with an on-chain
// consequence, so it belongs to an explicit operator action rather than to a
// loader that runs at startup.
func LoadLegacyNodeKey(path string) (LegacyNodeKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LegacyNodeKey{}, fmt.Errorf("identity: read legacy key: %w", err)
	}
	switch len(raw) {
	case ed25519.PrivateKeySize: // 64: full private key
		priv := ed25519.PrivateKey(raw)
		return LegacyNodeKey{
			Public:  priv.Public().(ed25519.PublicKey),
			private: priv,
		}, nil
	case ed25519.SeedSize: // 32: seed only
		priv := ed25519.NewKeyFromSeed(raw)
		return LegacyNodeKey{
			Public:  priv.Public().(ed25519.PublicKey),
			private: priv,
		}, nil
	default:
		return LegacyNodeKey{}, fmt.Errorf(
			"identity: legacy key %s is %d bytes, want %d or %d",
			path, len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// MigrationPlan describes what adopting AXON identities would do to a node that
// already has a bonded identity. It computes and reports; it changes nothing.
type MigrationPlan struct {
	LegacyPublic ed25519.PublicKey
	LegacyNodeID PoFNodeID
	AxonPublic   ed25519.PublicKey
	AxonNodeID   PoFNodeID
	// PreservesBond is true when adopting the AXON identity would keep the
	// on-chain nodeId, and therefore the bond, unchanged.
	PreservesBond bool
}

// PlanMigration compares an existing key against what a fresh AXON seed would
// produce.
//
// The expected answer is PreservesBond == false, and that is not a bug: a new
// seed is a new identity. The plan exists so the consequence is stated before
// an operator acts, and so the supported path -- keep the legacy key as the
// NodeIdentity, derive only the epoch-scoped routing keys from a new seed --
// is the one that gets chosen deliberately rather than by default.
func PlanMigration(legacy LegacyNodeKey, seed NodeSeed) MigrationPlan {
	axon := DeriveNodeIdentity(seed)
	legacyID := legacy.PoFNodeID()
	axonID := DerivePoFNodeID(axon.Public)
	return MigrationPlan{
		LegacyPublic:  legacy.Public,
		LegacyNodeID:  legacyID,
		AxonPublic:    axon.Public,
		AxonNodeID:    axonID,
		PreservesBond: legacyID == axonID,
	}
}

// AdoptLegacyIdentity is the bond-preserving path: the existing Ed25519 key
// remains the NodeIdentity, so keccak256(pub) and therefore the on-chain nodeId
// are unchanged, while everything epoch-scoped is derived from the new seed.
func AdoptLegacyIdentity(legacy LegacyNodeKey) NodeIdentity {
	return NodeIdentity{Public: legacy.Public, private: legacy.private}
}
