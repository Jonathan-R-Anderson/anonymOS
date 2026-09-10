package facilitation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

func newAgent(t *testing.T) *Agent {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	return NewAgent(pub, priv)
}

func shardFixture() ([]byte, int) {
	data := make([]byte, 40*1024)
	for i := range data {
		data[i] = byte(i * 7)
	}
	return data, 4096
}

// The full loop: a verifier challenges, the provider proves, a third node
// witnesses, and the receipt carries a quorum-eligible attestation.
func TestStorageChallengeRoundTrip(t *testing.T) {
	verifier, provider, witness := newAgent(t), newAgent(t), newAgent(t)
	data, chunkSize := shardFixture()
	chunks, leaves := ChunkShard(data, chunkSize)
	root := BuildTree(leaves).Root

	var assignment, seed [32]byte
	assignment[0], seed[0] = 9, 3

	c := verifier.IssueStorageChallenge(provider.NodeID(), assignment, root, seed, 12, len(chunks), 4)
	if !c.VerifySignature() {
		t.Fatal("issued challenge does not verify")
	}
	resp, err := provider.AnswerStorageChallenge(c, data, chunkSize)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	if len(resp.Proofs) != 4 {
		t.Fatalf("expected 4 chunk proofs, got %d", len(resp.Proofs))
	}
	if err := verifier.VerifyStorageResponse(c, resp); err != nil {
		t.Fatalf("verifier rejected a correct answer: %v", err)
	}

	sr, err := provider.BuildReceipt(c, resp, uint64(len(data)))
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if sr.Receipt.Quantity != uint64(len(data)) {
		t.Fatal("quantity is not the proven byte count")
	}
	if err := witness.Attest(&sr, c, resp); err != nil {
		t.Fatalf("witness attestation: %v", err)
	}
	if len(sr.Witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(sr.Witnesses))
	}
}

// Holding the root but not the data must fail — that is the whole point of
// asking for unpredictable chunks rather than a root the node could cache.
func TestCannotProveWithoutTheData(t *testing.T) {
	verifier, provider := newAgent(t), newAgent(t)
	data, chunkSize := shardFixture()
	chunks, leaves := ChunkShard(data, chunkSize)
	root := BuildTree(leaves).Root

	var assignment, seed [32]byte
	seed[0] = 11
	c := verifier.IssueStorageChallenge(provider.NodeID(), assignment, root, seed, 1, len(chunks), 3)

	// The node kept the right shape of data but not the bytes.
	wrong := make([]byte, len(data))
	resp, err := provider.AnswerStorageChallenge(c, wrong, chunkSize)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := verifier.VerifyStorageResponse(c, resp); err != ErrProofFailed {
		t.Fatalf("wrong data accepted (err=%v)", err)
	}
	if _, err := provider.BuildReceipt(c, resp, 1); err != ErrProofFailed {
		t.Fatal("a receipt was minted from a failed proof")
	}
}

// A provider must not be able to answer a challenge aimed at someone else, or
// re-point one at itself — the target is inside the signed bytes.
func TestChallengeIsBoundToItsTarget(t *testing.T) {
	verifier, provider, other := newAgent(t), newAgent(t), newAgent(t)
	data, chunkSize := shardFixture()
	_, leaves := ChunkShard(data, chunkSize)
	root := BuildTree(leaves).Root
	var assignment, seed [32]byte

	c := verifier.IssueStorageChallenge(other.NodeID(), assignment, root, seed, 1, len(leaves), 2)
	if _, err := provider.AnswerStorageChallenge(c, data, chunkSize); err != ErrWrongTarget {
		t.Fatalf("answered a challenge for another node: %v", err)
	}
	// Rewriting the target invalidates the issuer signature.
	tampered := c
	tampered.TargetNodeID = provider.NodeID()
	if tampered.VerifySignature() {
		t.Fatal("target could be rewritten after signing")
	}
	if _, err := provider.AnswerStorageChallenge(tampered, data, chunkSize); err != ErrIssuerSignature {
		t.Fatalf("tampered challenge accepted: %v", err)
	}
}

// Re-seeding after signing would let a provider shop for indices it can pass.
func TestSeedIsCoveredBySignature(t *testing.T) {
	verifier, provider := newAgent(t), newAgent(t)
	data, chunkSize := shardFixture()
	_, leaves := ChunkShard(data, chunkSize)
	var assignment, seed, evil [32]byte
	seed[0], evil[0] = 1, 2
	c := verifier.IssueStorageChallenge(provider.NodeID(), assignment, BuildTree(leaves).Root, seed, 1, len(leaves), 3)

	tampered := c
	tampered.Seed = evil
	if tampered.VerifySignature() {
		t.Fatal("seed could be swapped after signing")
	}
	if bytes.Equal(intsToBytes(c.Indices()), intsToBytes(tampered.Indices())) {
		t.Fatal("a different seed produced the same indices")
	}
	_ = data
	_ = chunkSize
}

func intsToBytes(in []int) []byte {
	out := make([]byte, 0, len(in)*8)
	for _, v := range in {
		out = append(out, be64(uint64(v))...)
	}
	return out
}

// Stale answers are refused: without a TTL a node could fetch the data back
// from a peer after being asked and still pass.
func TestExpiredChallengeRefused(t *testing.T) {
	verifier, provider := newAgent(t), newAgent(t)
	data, chunkSize := shardFixture()
	_, leaves := ChunkShard(data, chunkSize)
	var assignment, seed [32]byte
	c := verifier.IssueStorageChallenge(provider.NodeID(), assignment, BuildTree(leaves).Root, seed, 1, len(leaves), 2)

	provider.Now = func() time.Time { return time.Now().Add(ChallengeTTL + time.Minute) }
	if _, err := provider.AnswerStorageChallenge(c, data, chunkSize); err != ErrChallengeExpired {
		t.Fatalf("expired challenge answered: %v", err)
	}
}

func TestWitnessCannotAttestOwnWork(t *testing.T) {
	verifier, provider := newAgent(t), newAgent(t)
	data, chunkSize := shardFixture()
	chunks, leaves := ChunkShard(data, chunkSize)
	var assignment, seed [32]byte
	c := verifier.IssueStorageChallenge(provider.NodeID(), assignment, BuildTree(leaves).Root, seed, 4, len(chunks), 2)
	resp, err := provider.AnswerStorageChallenge(c, data, chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := provider.BuildReceipt(c, resp, uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Attest(&sr, c, resp); err != ErrSelfWitness {
		t.Fatalf("provider witnessed its own receipt: %v", err)
	}
	if len(sr.Witnesses) != 0 {
		t.Fatal("self-attestation was recorded")
	}
}

// Cross-module vectors for the storage proof. The aggregator derives the same
// indices and folds the same roots; if either side moves, honest proofs start
// being rejected as fraud.
func TestStorageProofGoldenVectors(t *testing.T) {
	data := make([]byte, 16*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	// Both values produced by proof-of-facilitation/aggregator and pinned there
	// too. The shard root covers chunking, leaf hashing, the sorted-pair hash
	// and the lone-node carry rule in one number.
	const wantRoot = "fda9428ffbd0ced439d2af56358b50265ff3b529f4758ac0376dd86707a744e8"
	root := ShardRoot(data, 4096)
	if hex.EncodeToString(root[:]) != wantRoot {
		t.Fatalf("shard root drifted from the aggregator\n got: %s\nwant: %s\n"+
			"Chunk size, leaf hashing or the Merkle rules no longer match; "+
			"honest proofs would be rejected as fraud.",
			hex.EncodeToString(root[:]), wantRoot)
	}

	var seed, assignment, node [32]byte
	for i := 0; i < 32; i++ {
		seed[i], assignment[i], node[i] = byte(i), byte(i*2), byte(i*3)
	}
	idx := DeriveStorageChallenge(seed, assignment, node, 5, 4)
	want := []int{2, 2, 3, 3, 2}
	if !bytes.Equal(intsToBytes(idx), intsToBytes(want)) {
		t.Fatalf("challenge indices drifted from the aggregator\n got: %v\nwant: %v\n"+
			"Provider and verifier would demand different chunks.", idx, want)
	}
	// Repeats are expected and fine: indices are drawn independently, so the
	// same chunk can be asked for twice. Deduplicating would silently weaken
	// the challenge relative to what the verifier expects.
}
