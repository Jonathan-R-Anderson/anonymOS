package aggregator

import (
	"encoding/hex"
	"testing"
)

// Cross-module contract with the node.
//
// The node that produces receipts lives in a different repository
// (storage-client, package internal/facilitation) and a different Go module, so
// it cannot import these types — it re-implements the canonical encoding. This
// vector is pinned identically on both sides.
//
// Failing here means the aggregator's encoding moved. Do not "fix" the test by
// updating the constant: that would make the aggregator stop recognising every
// receipt the fleet is already signing, and nothing would crash — nodes would
// simply stop being paid. Change the encoding on both sides deliberately, or
// not at all.

const goldenReceiptHash = "76a75cf1dc27ff24c1827a1b8cc21cd354bdb1c7200e41c89ab677902a554bc7"

func goldenReceipt() ServiceReceipt {
	var provider, verifier, job, challenge, result [32]byte
	for i := 0; i < 32; i++ {
		provider[i] = byte(i)
		verifier[i] = byte(0x40 + i)
		job[i] = byte(0x80 + i)
		challenge[i] = byte(0xC0 + i)
		result[i] = byte(0xE0 - i)
	}
	return ServiceReceipt{
		ProviderNodeID: provider, VerifierNodeID: verifier,
		ServiceType: ServiceStorage, JobID: job,
		ChallengeHash: challenge, ResultHash: result,
		Epoch: 1234567890, StartedAt: 1700000000, CompletedAt: 1700000123,
		Quantity: 987654321, Quality: 4242, Nonce: 42,
	}
}

func TestCanonicalReceiptHashMatchesNodeVector(t *testing.T) {
	got := CanonicalReceiptHash(goldenReceipt())
	if hex.EncodeToString(got[:]) != goldenReceiptHash {
		t.Fatalf("canonical receipt hash drifted from storage-client\n got: %s\nwant: %s\n"+
			"The node signs the other encoding; receipts would stop being recognised.",
			hex.EncodeToString(got[:]), goldenReceiptHash)
	}
}

// NodeID must agree too: it is keccak256(ed25519 pubkey) on both sides, and a
// mismatch would make every receipt unattributable to a registered node. The
// hazard is specific — SHA3-256 and legacy Keccak-256 are different functions
// with the same output size, so a wrong-but-plausible id would sail through.
const goldenNodeID = "8ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd2d"

func TestNodeIDVectorMatchesNode(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	got := NodeIDOf(pub)
	if hex.EncodeToString(got[:]) != goldenNodeID {
		t.Fatalf("node id derivation drifted\n got: %s\nwant: %s",
			hex.EncodeToString(got[:]), goldenNodeID)
	}
}

// Storage-proof vectors, pinned identically in storage-client. The shard root
// covers chunk size, leaf hashing, the sorted-pair hash and the lone-node carry
// rule in a single number; the indices cover the challenge derivation. If either
// drifts, a node that genuinely holds the data produces proofs this side rejects
// — an honest operator would be treated as a fraud.
const goldenShardRoot = "fda9428ffbd0ced439d2af56358b50265ff3b529f4758ac0376dd86707a744e8"

func TestStorageProofVectorsMatchNode(t *testing.T) {
	data := make([]byte, 16*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	root := ShardRoot(data, 4096)
	if hex.EncodeToString(root[:]) != goldenShardRoot {
		t.Fatalf("shard root drifted from the node\n got: %s\nwant: %s",
			hex.EncodeToString(root[:]), goldenShardRoot)
	}

	var seed, assignment, node [32]byte
	for i := 0; i < 32; i++ {
		seed[i], assignment[i], node[i] = byte(i), byte(i*2), byte(i*3)
	}
	got := DeriveStorageChallenge(seed, assignment, node, 5, 4)
	want := []int{2, 2, 3, 3, 2}
	if len(got) != len(want) {
		t.Fatalf("indices: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("challenge indices drifted from the node\n got: %v\nwant: %v", got, want)
		}
	}
}
