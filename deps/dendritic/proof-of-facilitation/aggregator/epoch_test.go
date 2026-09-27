package aggregator

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"testing"
)

// node is a test identity: keys plus the candidate record the registry would
// hold for it.
type testNode struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   [32]byte
	cand Candidate
}

func newTestNode(group string, stakeEth int64) testNode {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id := NodeIDOf(pub)
	return testNode{pub: pub, priv: priv, id: id, cand: Candidate{
		NodeID:        id,
		Stake:         new(big.Int).Mul(big.NewInt(stakeEth), big.NewInt(1e18)),
		ReputationBps: 10000,
		Group:         group,
	}}
}

// network builds n nodes, each in its own independence group, plus the
// recipients map NodeRegistry would supply.
func network(n int) ([]testNode, []Candidate, map[[32]byte][20]byte) {
	nodes := make([]testNode, 0, n)
	cands := make([]Candidate, 0, n)
	recips := make(map[[32]byte][20]byte, n)
	for i := 0; i < n; i++ {
		nd := newTestNode(fmt.Sprintf("group%d", i), 100)
		var addr [20]byte
		addr[0], addr[19] = byte(i+1), byte(i+1)
		nodes = append(nodes, nd)
		cands = append(cands, nd.cand)
		recips[nd.id] = addr
	}
	return nodes, cands, recips
}

func testPolicy() Policy {
	var split [7]uint16
	split[ServiceDHT] = 5000
	split[ServiceStorage] = 5000
	return Policy{
		EpochBudget:   new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)),
		SplitBps:      split,
		PerNodeCapBps: 5000,
	}
}

// attest builds a receipt signed by the provider and countersigned by the
// witnesses the protocol actually drew for it — i.e. an honest receipt.
func attest(t *testing.T, provider testNode, svc ServiceType, epoch uint64, qty uint64, nonce uint64,
	randomness [32]byte, all []testNode, cands []Candidate) SignedReceipt {
	t.Helper()
	r := ServiceReceipt{
		ProviderNodeID: provider.id,
		ServiceType:    svc,
		Epoch:          epoch,
		Quantity:       qty,
		Quality:        1,
		Nonce:          nonce,
	}
	sr := SignedReceipt{Receipt: r, ProviderPub: provider.pub, ProviderSig: SignReceipt(provider.priv, r)}

	th := ThresholdFor(svc)
	selected := SelectWitnesses(randomness, provider.id, svc, ChallengeIndexOf(r), th, cands)
	if len(selected) < th.Of {
		t.Fatalf("witness pool too small: drew %d of %d", len(selected), th.Of)
	}
	byID := map[[32]byte]testNode{}
	for _, nd := range all {
		byID[nd.id] = nd
	}
	for i := 0; i < th.Need; i++ { // exactly the quorum signs
		w := byID[selected[i].NodeID]
		sr.Witnesses = append(sr.Witnesses, WitnessAttestation{Pub: w.pub, Sig: SignReceipt(w.priv, r)})
	}
	return sr
}

func TestSettleEpochHappyPath(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 42
	nodes, cands, recips := network(12)

	var receipts []SignedReceipt
	for i := 0; i < 3; i++ {
		receipts = append(receipts, attest(t, nodes[i], ServiceDHT, 7, uint64(10*(i+1)), uint64(i), rnd, nodes, cands))
	}
	c := SettleEpoch(EpochInput{
		Epoch: 7, Randomness: rnd, Receipts: receipts,
		Candidates: cands, Policy: testPolicy(), Recipients: recips,
	})

	if len(c.Accepted) != 3 {
		t.Fatalf("accepted %d of 3: %v", len(c.Accepted), c.Rejections)
	}
	if len(c.Rejections) != 0 {
		t.Fatalf("unexpected rejections: %v", c.Rejections)
	}
	if c.ReceiptRoot == ([32]byte{}) || c.RewardRoot == ([32]byte{}) {
		t.Fatal("roots not set")
	}
	if c.TotalRewards.Sign() == 0 {
		t.Fatal("nothing paid out")
	}
	if !c.WithinBudget(testPolicy()) {
		t.Fatalf("total %s exceeds the epoch budget", c.TotalRewards)
	}
	// Rewards must be proportional: node 2 did 3x node 0's work.
	r0, _, ok0 := c.ProofForNode(nodes[0].id)
	r2, _, ok2 := c.ProofForNode(nodes[2].id)
	if !ok0 || !ok2 {
		t.Fatal("missing reward rows")
	}
	ratio := new(big.Int).Div(r2.Amount, r0.Amount)
	if ratio.Int64() != 3 {
		t.Fatalf("want 3x reward for 3x work, got %sx", ratio)
	}
}

// The claim path: every paid node's proof must verify against the posted root,
// because that is literally what RewardDistributor.claim checks on-chain.
func TestEveryPaidNodeCanClaim(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 5
	nodes, cands, recips := network(14)
	var receipts []SignedReceipt
	for i := 0; i < 5; i++ {
		receipts = append(receipts, attest(t, nodes[i], ServiceStorage, 3, uint64(i+1), uint64(i), rnd, nodes, cands))
	}
	c := SettleEpoch(EpochInput{
		Epoch: 3, Randomness: rnd, Receipts: receipts,
		Candidates: cands, Policy: testPolicy(), Recipients: recips,
	})
	if len(c.Rows) == 0 {
		t.Fatalf("no rows; rejections: %v", c.Rejections)
	}
	for _, row := range c.Rows {
		_, proof, ok := c.ProofForNode(row.NodeID)
		if !ok {
			t.Fatalf("no proof for a row that exists")
		}
		leaf := RewardLeaf(row.NodeID, row.Recipient, row.Amount, row.Service)
		if !Verify(proof, c.RewardRoot, leaf) {
			t.Fatalf("claim proof does not verify for %x", row.NodeID[:4])
		}
	}
}

// A planted fraudulent receipt — witnesses the provider chose itself — must not
// be paid. This is the Phase 1 exit criterion in miniature.
func TestFraudulentReceiptIsRejected(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 11
	nodes, cands, recips := network(12)
	honest := attest(t, nodes[0], ServiceDHT, 1, 10, 0, rnd, nodes, cands)

	// The fraudster signs a receipt and has two accomplices countersign it —
	// a valid 2-of-3 by count, but not the drawn set.
	fraud := ServiceReceipt{ProviderNodeID: nodes[5].id, ServiceType: ServiceDHT, Epoch: 1, Quantity: 1_000_000, Quality: 1, Nonce: 99}
	sf := SignedReceipt{Receipt: fraud, ProviderPub: nodes[5].pub, ProviderSig: SignReceipt(nodes[5].priv, fraud)}
	th := ThresholdFor(ServiceDHT)
	drawn := SelectedIDs(SelectWitnesses(rnd, nodes[5].id, ServiceDHT, ChallengeIndexOf(fraud), th, cands))
	accomplices := 0
	for _, nd := range nodes {
		if nd.id == nodes[5].id || drawn[nd.id] {
			continue // pick only nodes the protocol did NOT select
		}
		sf.Witnesses = append(sf.Witnesses, WitnessAttestation{Pub: nd.pub, Sig: SignReceipt(nd.priv, fraud)})
		if accomplices++; accomplices == 2 {
			break
		}
	}

	c := SettleEpoch(EpochInput{
		Epoch: 1, Randomness: rnd, Receipts: []SignedReceipt{honest, sf},
		Candidates: cands, Policy: testPolicy(), Recipients: recips,
	})
	if len(c.Accepted) != 1 {
		t.Fatalf("want only the honest receipt, accepted %d", len(c.Accepted))
	}
	if c.Accepted[0].Receipt.ProviderNodeID != nodes[0].id {
		t.Fatal("the wrong receipt survived")
	}
	if _, _, ok := c.ProofForNode(nodes[5].id); ok {
		t.Fatal("fraudster got paid")
	}
	if len(c.Rejections) != 1 || c.Rejections[0].Reason != RejectNotSelected {
		t.Fatalf("want a not-selected rejection, got %v", c.Rejections)
	}
}

func TestDuplicateAndWrongEpochRejected(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 2
	nodes, cands, recips := network(12)
	good := attest(t, nodes[1], ServiceDHT, 4, 5, 1, rnd, nodes, cands)
	stale := attest(t, nodes[2], ServiceDHT, 3, 5, 2, rnd, nodes, cands) // epoch 3, settling 4

	c := SettleEpoch(EpochInput{
		Epoch: 4, Randomness: rnd, Receipts: []SignedReceipt{good, good, stale},
		Candidates: cands, Policy: testPolicy(), Recipients: recips,
	})
	if len(c.Accepted) != 1 {
		t.Fatalf("want 1 accepted, got %d", len(c.Accepted))
	}
	reasons := map[RejectReason]int{}
	for _, r := range c.Rejections {
		reasons[r.Reason]++
	}
	if reasons[RejectDuplicate] != 1 {
		t.Errorf("duplicate not rejected: %v", c.Rejections)
	}
	if reasons[RejectWrongEpoch] != 1 {
		t.Errorf("wrong-epoch receipt not rejected: %v", c.Rejections)
	}
}

func TestUnregisteredProviderRejected(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 8
	nodes, cands, recips := network(12)
	stranger := newTestNode("outside", 100)
	cands = append(cands, stranger.cand) // known to the network, but no payout address
	sr := attest(t, stranger, ServiceDHT, 2, 5, 0, rnd, append(nodes, stranger), cands)

	c := SettleEpoch(EpochInput{
		Epoch: 2, Randomness: rnd, Receipts: []SignedReceipt{sr},
		Candidates: cands, Policy: testPolicy(), Recipients: recips,
	})
	if len(c.Accepted) != 0 {
		t.Fatal("paid a node with no registered recipient")
	}
	if len(c.Rejections) != 1 || c.Rejections[0].Reason != RejectUnregistered {
		t.Fatalf("want unregistered rejection, got %v", c.Rejections)
	}
}

func TestTooSmallWitnessPoolIsCalledOut(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 6
	// 3 nodes total: a 3-of-5 storage claim cannot draw a legitimate set.
	nodes, cands, recips := network(3)
	r := ServiceReceipt{ProviderNodeID: nodes[0].id, ServiceType: ServiceStorage, Epoch: 1, Quantity: 1, Quality: 1}
	sr := SignedReceipt{Receipt: r, ProviderPub: nodes[0].pub, ProviderSig: SignReceipt(nodes[0].priv, r)}
	for _, nd := range nodes[1:] {
		sr.Witnesses = append(sr.Witnesses, WitnessAttestation{Pub: nd.pub, Sig: SignReceipt(nd.priv, r)})
	}
	c := SettleEpoch(EpochInput{
		Epoch: 1, Randomness: rnd, Receipts: []SignedReceipt{sr},
		Candidates: cands, Policy: testPolicy(), Recipients: recips,
	})
	if len(c.Accepted) != 0 {
		t.Fatal("settled a claim that could not be properly witnessed")
	}
	if c.Rejections[0].Reason != RejectNoWitnessPool {
		t.Fatalf("want a pool-size rejection, got %v", c.Rejections[0].Reason)
	}
}

// Reproducibility is the security property of the whole optimistic scheme: a
// challenger re-running settlement on the same receipts, in any order, must get
// byte-identical roots or an honest aggregator could be slashed.
func TestSettlementIsReproducibleRegardlessOfArrivalOrder(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 77
	nodes, cands, recips := network(12)
	var receipts []SignedReceipt
	for i := 0; i < 6; i++ {
		receipts = append(receipts, attest(t, nodes[i], ServiceDHT, 9, uint64(i+1), uint64(i), rnd, nodes, cands))
	}
	in := EpochInput{Epoch: 9, Randomness: rnd, Receipts: receipts,
		Candidates: cands, Policy: testPolicy(), Recipients: recips}
	first := SettleEpoch(in)

	shuffled := make([]SignedReceipt, len(receipts))
	for i, sr := range receipts { // deterministic reversal, not rand
		shuffled[len(receipts)-1-i] = sr
	}
	in2 := in
	in2.Receipts = shuffled
	second := SettleEpoch(in2)

	if first.ReceiptRoot != second.ReceiptRoot {
		t.Error("receiptRoot depends on arrival order")
	}
	if first.RewardRoot != second.RewardRoot {
		t.Error("rewardRoot depends on arrival order")
	}
	if first.TotalRewards.Cmp(second.TotalRewards) != 0 {
		t.Error("totalRewards depends on arrival order")
	}
}

func TestOverBudgetEpochIsDetectable(t *testing.T) {
	p := testPolicy()
	c := EpochCommitment{TotalRewards: new(big.Int).Add(p.EpochBudget, big.NewInt(1))}
	if c.WithinBudget(p) {
		t.Fatal("an over-budget epoch must be detectable — that is currency inflation")
	}
}
