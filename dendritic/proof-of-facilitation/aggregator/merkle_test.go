package aggregator

import (
	"math/big"
	"testing"
)

func nodeID(b byte) [32]byte { var x [32]byte; x[0] = b; x[31] = b; return x }
func addr(b byte) [20]byte   { var x [20]byte; x[19] = b; return x }

func TestSingleLeafTree(t *testing.T) {
	leaf := RewardLeaf(nodeID(1), addr(1), big.NewInt(5), [32]byte{})
	tree := BuildTree([][32]byte{leaf})
	if tree.Root != leaf {
		t.Fatal("single-leaf root must equal the leaf")
	}
	if !Verify(tree.Proof(0), tree.Root, leaf) {
		t.Fatal("single-leaf proof (empty) must verify")
	}
}

func TestRewardTreeProofsVerify(t *testing.T) {
	rows := []RewardRow{
		{NodeID: nodeID(3), Recipient: addr(3), Amount: big.NewInt(40), Service: [32]byte{}},
		{NodeID: nodeID(1), Recipient: addr(1), Amount: big.NewInt(60), Service: [32]byte{}},
		{NodeID: nodeID(2), Recipient: addr(2), Amount: big.NewInt(25), Service: [32]byte{}},
	}
	tree, sorted := RewardTree(rows)
	if len(sorted) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(sorted))
	}
	// Sorted by nodeId (deterministic root).
	if !(less(sorted[0].NodeID, sorted[1].NodeID) && less(sorted[1].NodeID, sorted[2].NodeID)) {
		t.Fatal("rows not sorted by nodeId")
	}
	// Every row's proof must fold to the root (exactly what the contract checks).
	for i, r := range sorted {
		leaf := RewardLeaf(r.NodeID, r.Recipient, r.Amount, r.Service)
		if !Verify(tree.Proof(i), tree.Root, leaf) {
			t.Fatalf("row %d proof failed to verify", i)
		}
		// A tampered amount must NOT verify against the committed proof.
		bad := RewardLeaf(r.NodeID, r.Recipient, new(big.Int).Add(r.Amount, big.NewInt(1)), r.Service)
		if Verify(tree.Proof(i), tree.Root, bad) {
			t.Fatalf("row %d verified a tampered amount", i)
		}
	}
}

func TestDeterministicRoot(t *testing.T) {
	rows := []RewardRow{
		{NodeID: nodeID(1), Recipient: addr(1), Amount: big.NewInt(60)},
		{NodeID: nodeID(2), Recipient: addr(2), Amount: big.NewInt(40)},
	}
	shuffled := []RewardRow{rows[1], rows[0]}
	a, _ := RewardTree(rows)
	b, _ := RewardTree(shuffled)
	if a.Root != b.Root {
		t.Fatal("root must not depend on input order (rows are sorted by nodeId)")
	}
}
