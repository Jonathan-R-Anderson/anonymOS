// Package aggregator builds the epoch commitments the EpochManager /
// RewardDistributor contracts settle. This file is the reward Merkle tree: it
// produces a root + per-leaf proofs that Solidity's MerkleProof.verify accepts,
// using the same double-hashed leaf as RewardDistributor.leafHash and the same
// commutative (sorted-pair) node hashing OpenZeppelin uses. The contract only
// verifies that a proof folds to the root, so any self-consistent sorted-pair
// tree is accepted — no dependence on a specific tree-construction library.
package aggregator

import (
	"math/big"

	"golang.org/x/crypto/sha3"
)

func keccak(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// left32 left-pads to a 32-byte ABI word.
func left32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// RewardLeaf matches RewardDistributor.leafHash:
//
//	keccak256(bytes.concat(keccak256(abi.encode(nodeId, recipient, amount, svc))))
func RewardLeaf(nodeID [32]byte, recipient [20]byte, amount *big.Int, svc [32]byte) [32]byte {
	enc := make([]byte, 0, 4*32)
	enc = append(enc, nodeID[:]...)          // bytes32
	enc = append(enc, left32(recipient[:])...) // address (left-padded)
	enc = append(enc, left32(amount.Bytes())...) // uint256
	enc = append(enc, svc[:]...)             // bytes32
	inner := keccak(enc)
	return keccak(inner[:])
}

func less(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// hashPair is OpenZeppelin's commutative hash: keccak256 of the two nodes in
// ascending byte order.
func hashPair(a, b [32]byte) [32]byte {
	if less(a, b) {
		return keccak(a[:], b[:])
	}
	return keccak(b[:], a[:])
}

// Tree is a sorted-pair Merkle tree over reward leaves.
type Tree struct {
	Root   [32]byte
	levels [][][32]byte // levels[0] = leaves … top = root
}

// BuildTree builds a tree; a lone node at any level is carried up unchanged.
func BuildTree(leaves [][32]byte) *Tree {
	if len(leaves) == 0 {
		return &Tree{}
	}
	levels := [][][32]byte{leaves}
	cur := leaves
	for len(cur) > 1 {
		next := make([][32]byte, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 < len(cur) {
				next = append(next, hashPair(cur[i], cur[i+1]))
			} else {
				next = append(next, cur[i]) // carry the lone node up
			}
		}
		levels = append(levels, next)
		cur = next
	}
	return &Tree{Root: cur[0], levels: levels}
}

// Proof returns the sibling path for the leaf at index (empty at a level where
// the node was carried up without a sibling).
func (t *Tree) Proof(index int) [][32]byte {
	proof := make([][32]byte, 0)
	idx := index
	for level := 0; level+1 < len(t.levels); level++ {
		nodes := t.levels[level]
		var sib int
		if idx%2 == 0 {
			sib = idx + 1
		} else {
			sib = idx - 1
		}
		if sib >= 0 && sib < len(nodes) {
			proof = append(proof, nodes[sib])
		}
		idx /= 2
	}
	return proof
}

// Verify replicates Solidity MerkleProof.verify (sorted-pair folding).
func Verify(proof [][32]byte, root, leaf [32]byte) bool {
	computed := leaf
	for _, p := range proof {
		computed = hashPair(computed, p)
	}
	return computed == root
}
