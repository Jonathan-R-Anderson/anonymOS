package aggregator

import "math/big"

// Proof of storage. A stored shard is split into fixed-size chunks; each chunk is
// a Merkle leaf and the shard's committed root is BuildTree(leaves).Root. To
// challenge a node, the verifier derives unpredictable chunk indices from the
// epoch randomness (a node cannot precompute which chunks it will be asked for),
// and the node must return those chunks plus Merkle proofs to the committed root.
// This mirrors the roadmap's storage proof and reuses the same Merkle machinery
// the reward tree uses.

// ChunkShard splits data into chunkSize pieces and returns the chunks + their
// Merkle leaves (keccak256 of each chunk).
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
		leaves = append(leaves, keccak(c))
	}
	if len(chunks) == 0 { // empty shard: one empty chunk so a root exists
		chunks = [][]byte{{}}
		leaves = [][32]byte{keccak([]byte{})}
	}
	return chunks, leaves
}

// ShardRoot is the committed Merkle root over a shard's chunks.
func ShardRoot(data []byte, chunkSize int) [32]byte {
	_, leaves := ChunkShard(data, chunkSize)
	return BuildTree(leaves).Root
}

// DeriveStorageChallenge derives `count` chunk indices to ask for, from an
// unpredictable seed (epoch randomness) bound to the assignment + node, so the
// challenge cannot be anticipated or shared.
func DeriveStorageChallenge(seed, assignmentID, nodeID [32]byte, count, numChunks int) []int {
	if numChunks <= 0 {
		return nil
	}
	idxs := make([]int, 0, count)
	mod := big.NewInt(int64(numChunks))
	for i := 0; i < count; i++ {
		h := keccak(seed[:], assignmentID[:], nodeID[:], be64(uint64(i)))
		n := new(big.Int).SetBytes(h[:])
		idxs = append(idxs, int(new(big.Int).Mod(n, mod).Int64()))
	}
	return idxs
}

// ChunkProof is one challenged chunk plus its Merkle proof to the shard root.
type ChunkProof struct {
	Index int
	Chunk []byte
	Proof [][32]byte
}

// BuildStorageProof answers a challenge: the requested chunks + their proofs.
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

// VerifyStorageProof checks the node returned exactly the challenged chunks and
// that each hashes to a leaf whose Merkle proof folds to the committed shardRoot.
func VerifyStorageProof(shardRoot [32]byte, resp []ChunkProof, challenged []int) bool {
	if len(resp) != len(challenged) {
		return false
	}
	for k, cp := range resp {
		if cp.Index != challenged[k] {
			return false
		}
		if !Verify(cp.Proof, shardRoot, keccak(cp.Chunk)) {
			return false
		}
	}
	return true
}
