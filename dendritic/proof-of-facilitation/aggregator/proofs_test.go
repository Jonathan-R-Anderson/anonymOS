package aggregator

import (
	"bytes"
	"testing"
)

func TestStorageProofRoundTrip(t *testing.T) {
	// A 10 KiB shard split into 1 KiB chunks -> 10 chunks.
	data := bytes.Repeat([]byte("syndichan-shard-"), 640) // 10240 bytes
	chunks, leaves := ChunkShard(data, 1024)
	if len(chunks) != 10 {
		t.Fatalf("expected 10 chunks, got %d", len(chunks))
	}
	tree := BuildTree(leaves)
	root := ShardRoot(data, 1024)
	if root != tree.Root {
		t.Fatal("ShardRoot must match the tree root")
	}

	seed := nodeID(0x5e)
	assignment := nodeID(0xa5)
	node := nodeID(0x0d)
	challenge := DeriveStorageChallenge(seed, assignment, node, 4, len(chunks))
	if len(challenge) != 4 {
		t.Fatalf("expected 4 challenge indices, got %d", len(challenge))
	}
	// Deterministic for the same inputs.
	if again := DeriveStorageChallenge(seed, assignment, node, 4, len(chunks)); !equalInts(challenge, again) {
		t.Fatal("challenge must be deterministic for the same seed/assignment/node")
	}
	// Different node -> (almost surely) different challenge.
	if other := DeriveStorageChallenge(seed, assignment, nodeID(0x0e), 4, len(chunks)); equalInts(challenge, other) {
		t.Fatal("challenge should depend on the node id")
	}

	proof := BuildStorageProof(chunks, tree, challenge)
	if !VerifyStorageProof(root, proof, challenge) {
		t.Fatal("honest storage proof must verify")
	}

	// A node that lost/corrupted a challenged chunk cannot produce a valid proof.
	tampered := make([]ChunkProof, len(proof))
	copy(tampered, proof)
	tampered[0].Chunk = append([]byte("x"), tampered[0].Chunk...)
	if VerifyStorageProof(root, tampered, challenge) {
		t.Fatal("tampered chunk must NOT verify")
	}
	// Answering a different index than challenged fails.
	wrong := DeriveStorageChallenge(seed, assignment, node, 4, len(chunks))
	wrong[0] = (wrong[0] + 1) % len(chunks)
	if VerifyStorageProof(root, proof, wrong) && !equalInts(wrong, challenge) {
		t.Fatal("proof for the wrong indices must NOT verify")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
