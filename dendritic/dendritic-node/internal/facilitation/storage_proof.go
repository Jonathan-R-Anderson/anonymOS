package facilitation

import "math/big"

// Proof of storage — the node's side.
//
// A stored shard is split into fixed-size chunks; each chunk is a Merkle leaf,
// and the shard's committed root is the tree over those leaves. A verifier
// derives unpredictable chunk indices from epoch randomness bound to the
// assignment and this node, so the node cannot know in advance which chunks it
// will be asked for — holding the root is not enough, it must still hold the
// data.
//
// Like the receipt encoding, this mirrors proof-of-facilitation/aggregator
// across a module boundary: the aggregator (and any witness) recomputes the
// same indices and folds the same proofs. Every constant here — chunk size
// default, the sorted-pair hash, the lone-node carry rule, the index
// derivation — is part of that contract. TestStorageProofGoldenVectors pins it.

// ChunkShard splits data into chunkSize pieces and returns the chunks plus
// their Merkle leaves (keccak256 of each chunk).
func ChunkShard(data []byte, chunkSize int) ([][]byte, [][32]byte) {
	if chunkSize <= 0 {
		chunkSize = 4096
	}
	var chunks [][]byte
	var leaves [][32]byte
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		c := data[off:end]
		chunks = append(chunks, c)
		leaves = append(leaves, keccak32(c))
	}
	if len(chunks) == 0 { // empty shard: one empty chunk so a root still exists
		chunks = [][]byte{{}}
		leaves = [][32]byte{keccak32([]byte{})}
	}
	return chunks, leaves
}

// ShardRoot is the committed Merkle root over a shard's chunks.
func ShardRoot(data []byte, chunkSize int) [32]byte {
	_, leaves := ChunkShard(data, chunkSize)
	return BuildTree(leaves).Root
}

// DeriveStorageChallenge derives the chunk indices a verifier will ask for.
// The node runs this to know what to prove; the verifier runs it to know what
// to expect. Both must land on the same indices from public inputs alone.
func DeriveStorageChallenge(seed, assignmentID, nodeID [32]byte, count, numChunks int) []int {
	if numChunks <= 0 {
		return nil
	}
	idxs := make([]int, 0, count)
	mod := big.NewInt(int64(numChunks))
	for i := 0; i < count; i++ {
		h := keccak32(seed[:], assignmentID[:], nodeID[:], be64(uint64(i)))
		n := new(big.Int).SetBytes(h[:])
		idxs = append(idxs, int(new(big.Int).Mod(n, mod).Int64()))
	}
	return idxs
}

// ChunkProof is one challenged chunk plus its Merkle proof to the shard root.
type ChunkProof struct {
	Index int        `json:"index"`
	Chunk []byte     `json:"chunk"`
	Proof [][32]byte `json:"proof"`
}

// BuildStorageProof answers a challenge with the requested chunks and proofs.
func BuildStorageProof(chunks [][]byte, tree *Tree, indices []int) []ChunkProof {
	out := make([]ChunkProof, 0, len(indices))
	for _, i := range indices {
		if i < 0 || i >= len(chunks) {
			continue
		}
		out = append(out, ChunkProof{Index: i, Chunk: chunks[i], Proof: tree.Proof(i)})
	}
	return out
}

// VerifyStorageProof checks a peer returned exactly the challenged chunks and
// that each folds to the committed root. The node needs this as a WITNESS, not
// just as a provider: attesting to a proof it has not checked is what gets a
// witness slashed.
func VerifyStorageProof(shardRoot [32]byte, resp []ChunkProof, challenged []int) bool {
	if len(resp) != len(challenged) {
		return false
	}
	for k, cp := range resp {
		if cp.Index != challenged[k] {
			return false
		}
		if !VerifyMerkle(cp.Proof, shardRoot, keccak32(cp.Chunk)) {
			return false
		}
	}
	return true
}

// --- Merkle (sorted-pair, matching OpenZeppelin MerkleProof.verify) ---

func keccak32(parts ...[]byte) [32]byte {
	var out [32]byte
	copy(out[:], keccak256(parts...))
	return out
}

func lessBytes(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// hashPair is the commutative hash: keccak256 of the two nodes in ascending
// byte order. Commutative so a proof need not say which side each sibling was.
func hashPair(a, b [32]byte) [32]byte {
	if lessBytes(a, b) {
		return keccak32(a[:], b[:])
	}
	return keccak32(b[:], a[:])
}

// Tree is a sorted-pair Merkle tree over chunk leaves.
type Tree struct {
	Root   [32]byte
	levels [][][32]byte
}

// BuildTree builds the tree; a lone node at any level is carried up unchanged
// (not duplicated — duplicating would change every root the aggregator expects).
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
				next = append(next, cur[i])
			}
		}
		levels = append(levels, next)
		cur = next
	}
	return &Tree{Root: cur[0], levels: levels}
}

// Proof returns the sibling path for the leaf at index.
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

// VerifyMerkle folds a proof to a root, exactly as the Solidity verifier does.
func VerifyMerkle(proof [][32]byte, root, leaf [32]byte) bool {
	computed := leaf
	for _, p := range proof {
		computed = hashPair(computed, p)
	}
	return computed == root
}
