package aggregator

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"testing"
)

func cand(seed byte, stakeEth int64, repBps uint32, group string) Candidate {
	var id [32]byte
	id[0], id[31] = seed, seed
	stake := new(big.Int).Mul(big.NewInt(stakeEth), big.NewInt(1e18))
	return Candidate{NodeID: id, Stake: stake, ReputationBps: repBps, Group: group}
}

func pool(n int) []Candidate {
	out := make([]Candidate, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, cand(byte(i+1), 100, 10000, fmt.Sprintf("g%d", i)))
	}
	return out
}

func TestSelectIsDeterministic(t *testing.T) {
	var rnd, prov [32]byte
	rnd[0], prov[0] = 7, 200
	a := SelectWitnesses(rnd, prov, ServiceStorage, 3, ThresholdFor(ServiceStorage), pool(20))
	b := SelectWitnesses(rnd, prov, ServiceStorage, 3, ThresholdFor(ServiceStorage), pool(20))
	if len(a) != 5 {
		t.Fatalf("want 5 witnesses for storage, got %d", len(a))
	}
	for i := range a {
		if a[i].NodeID != b[i].NodeID {
			t.Fatalf("selection not deterministic at %d", i)
		}
	}
	// Candidate ordering must not change the outcome — an aggregator that reads
	// the registry in a different order must still agree.
	rev := pool(20)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	c := SelectWitnesses(rnd, prov, ServiceStorage, 3, ThresholdFor(ServiceStorage), rev)
	for i := range a {
		if a[i].NodeID != c[i].NodeID {
			t.Fatalf("selection depends on candidate order at %d", i)
		}
	}
}

func TestSelectVariesWithSeedInputs(t *testing.T) {
	var rnd, prov [32]byte
	rnd[0], prov[0] = 7, 200
	base := SelectWitnesses(rnd, prov, ServiceStorage, 0, ThresholdFor(ServiceStorage), pool(30))
	diffIdx := SelectWitnesses(rnd, prov, ServiceStorage, 1, ThresholdFor(ServiceStorage), pool(30))
	var rnd2 [32]byte
	rnd2[0] = 8
	diffRnd := SelectWitnesses(rnd2, prov, ServiceStorage, 0, ThresholdFor(ServiceStorage), pool(30))

	same := func(x, y []Candidate) bool {
		for i := range x {
			if x[i].NodeID != y[i].NodeID {
				return false
			}
		}
		return true
	}
	if same(base, diffIdx) {
		t.Fatal("challengeIndex does not affect the draw — one draw could be replayed onto another claim")
	}
	if same(base, diffRnd) {
		t.Fatal("epoch randomness does not affect the draw — witnesses would be predictable")
	}
}

func TestProviderNeverWitnessesItself(t *testing.T) {
	var rnd [32]byte
	rnd[0] = 1
	cands := pool(6)
	prov := cands[2].NodeID
	sel := SelectWitnesses(rnd, prov, ServiceDHT, 0, ThresholdFor(ServiceDHT), cands)
	for _, c := range sel {
		if c.NodeID == prov {
			t.Fatal("provider selected as its own witness")
		}
	}
}

func TestIndependenceOneSeatPerGroup(t *testing.T) {
	var rnd, prov [32]byte
	rnd[0], prov[0] = 9, 250
	// 10 nodes, only 5 distinct groups: a 5-seat set must use each group once.
	cands := make([]Candidate, 0, 10)
	for i := 0; i < 10; i++ {
		cands = append(cands, cand(byte(i+1), 100, 10000, fmt.Sprintf("subnet%d", i%5)))
	}
	sel := SelectWitnesses(rnd, prov, ServiceStorage, 0, ThresholdFor(ServiceStorage), cands)
	if len(sel) != 5 {
		t.Fatalf("want 5, got %d", len(sel))
	}
	seen := map[string]bool{}
	for _, c := range sel {
		if seen[c.Group] {
			t.Fatalf("two witnesses from group %s — one operator could hold the quorum", c.Group)
		}
		seen[c.Group] = true
	}
}

func TestShortPoolReturnsShortSet(t *testing.T) {
	var rnd, prov [32]byte
	rnd[0], prov[0] = 3, 99
	sel := SelectWitnesses(rnd, prov, ServiceStorage, 0, ThresholdFor(ServiceStorage), pool(2))
	if len(sel) != 2 {
		t.Fatalf("want the 2 available, got %d", len(sel))
	}
	// And a short set must not be settleable.
	if err := ValidateAttested(SignedReceipt{}, SelectedIDs(sel), ThresholdFor(ServiceStorage)); err != ErrWitnessThreshold {
		t.Fatalf("short set should be rejected, got %v", err)
	}
}

func TestZeroReputationExcludedEvenDuringBootstrap(t *testing.T) {
	// The bootstrap floor lets an unstaked node be drawn. It does not rescue a
	// node the network has already judged: reputation zero is an earned verdict,
	// not a starting condition, and it stays disqualifying.
	var rnd, prov [32]byte
	rnd[0], prov[0] = 4, 77
	cands := []Candidate{
		cand(1, 100, 10000, "a"),
		cand(2, 0, 10000, "b"), // unstaked: eligible while bootstrapping
		cand(3, 100, 0, "c"),   // zero reputation: never eligible
		cand(4, 100, 10000, "d"),
	}
	sel := SelectWitnesses(rnd, prov, ServiceDHT, 0, ThresholdFor(ServiceDHT), cands)
	if len(sel) != 3 {
		t.Fatalf("want 3 eligible, got %d", len(sel))
	}
	for _, c := range sel {
		if c.NodeID == cands[2].NodeID {
			t.Fatal("a zero-reputation candidate was selected")
		}
	}
}

func TestUnstakedExcludedOnceTheBootstrapFloorIsLifted(t *testing.T) {
	// Setting the floor to zero restores the original rule with nothing else
	// changed, which is the whole point of expressing bootstrap as a floor
	// rather than as a special case scattered through the selection.
	saved := BootstrapStakeFloorWei
	BootstrapStakeFloorWei = big.NewInt(0)
	defer func() { BootstrapStakeFloorWei = saved }()

	var rnd, prov [32]byte
	rnd[0], prov[0] = 4, 77
	cands := []Candidate{
		cand(1, 100, 10000, "a"),
		cand(2, 0, 10000, "b"), // no stake: nothing to slash
		cand(3, 100, 0, "c"),   // zero reputation
		cand(4, 100, 10000, "d"),
	}
	sel := SelectWitnesses(rnd, prov, ServiceDHT, 0, ThresholdFor(ServiceDHT), cands)
	if len(sel) != 2 {
		t.Fatalf("want 2 eligible, got %d", len(sel))
	}
	for _, c := range sel {
		if c.NodeID == cands[1].NodeID || c.NodeID == cands[2].NodeID {
			t.Fatal("ineligible candidate selected")
		}
	}
}

func TestRealStakeStillOutweighsTheBootstrapFloor(t *testing.T) {
	// The floor must let unstaked nodes in without letting them compete. One
	// wei against 10^18 wei is a factor of 10^9 in stake and 10^4.5 in weight
	// after the square root, so the staked node should take nearly every seat.
	var rnd, prov [32]byte
	prov[0] = 9
	staked := cand(1, 0, 10000, "a")
	staked.Stake = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	floored := cand(2, 0, 10000, "b")

	wins := 0
	const draws = 200
	for i := 0; i < draws; i++ {
		rnd[0] = byte(i)
		rnd[1] = byte(i >> 8)
		sel := SelectWitnesses(rnd, prov, ServiceDHT, 0, Threshold{Need: 1, Of: 1},
			[]Candidate{staked, floored})
		if len(sel) == 1 && sel[0].NodeID == staked.NodeID {
			wins++
		}
	}
	if wins < draws*9/10 {
		t.Fatalf("staked node won %d/%d draws; the floor is competing with real stake", wins, draws)
	}
}

// sqrt(stake) must damp wealth: 100x the stake buys ~10x the selection share,
// not 100x. Measured over many independent draws.
func TestSqrtStakeDampsWhaleShare(t *testing.T) {
	var prov [32]byte
	prov[0] = 250
	whale := cand(1, 1_000_000, 10000, "whale")
	cands := []Candidate{whale}
	for i := 2; i <= 11; i++ {
		cands = append(cands, cand(byte(i), 10_000, 10000, fmt.Sprintf("small%d", i)))
	}
	// One seat, so each draw is a clean weighted sample.
	one := Threshold{Need: 1, Of: 1}
	whaleWins, rounds := 0, 400
	for i := 0; i < rounds; i++ {
		var rnd [32]byte
		rnd[0], rnd[1] = byte(i), byte(i>>8)
		sel := SelectWitnesses(rnd, prov, ServiceDHT, uint32(i), one, cands)
		if len(sel) == 1 && sel[0].NodeID == whale.NodeID {
			whaleWins++
		}
	}
	// Linear weighting would give 1M/(1M+100k) ≈ 91%. sqrt gives
	// 1000/(1000+10*100) ≈ 50%.
	share := float64(whaleWins) / float64(rounds)
	if share > 0.65 {
		t.Fatalf("whale share %.2f — stake does not look sqrt-damped", share)
	}
	if share < 0.35 {
		t.Fatalf("whale share %.2f — weighting looks broken in the other direction", share)
	}
}

func TestThresholdTableMatchesRoadmap(t *testing.T) {
	for _, tc := range []struct {
		svc  ServiceType
		want Threshold
	}{
		{ServiceDHT, Threshold{2, 3}},
		{ServiceGateway, Threshold{3, 5}},
		{ServiceStorage, Threshold{3, 5}},
		{ServiceDockerWorker, Threshold{4, 7}},
		{ServiceDockerController, Threshold{4, 7}},
	} {
		if got := ThresholdFor(tc.svc); got != tc.want {
			t.Errorf("service %d: got %v want %v", tc.svc, got, tc.want)
		}
	}
	if got := DisputeThreshold(); got != (Threshold{7, 11}) {
		t.Errorf("dispute: got %v want 7-of-11", got)
	}
}

// The point of the whole exercise: signatures from witnesses the protocol did
// not select must not settle a receipt.
func TestValidateAttestedRejectsUnselectedWitnesses(t *testing.T) {
	provPub, provPriv, _ := ed25519.GenerateKey(nil)
	r := ServiceReceipt{ProviderNodeID: NodeIDOf(provPub), ServiceType: ServiceDHT, Epoch: 4, Quantity: 10}
	sr := SignedReceipt{Receipt: r, ProviderPub: provPub, ProviderSig: SignReceipt(provPriv, r)}

	// Three friends of the provider, none of them selected.
	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		sr.Witnesses = append(sr.Witnesses, WitnessAttestation{Pub: pub, Sig: SignReceipt(priv, r)})
	}
	// The set the protocol actually drew is three other nodes.
	selected := map[[32]byte]bool{}
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(nil)
		selected[NodeIDOf(pub)] = true
	}
	if err := ValidateAttested(sr, selected, ThresholdFor(ServiceDHT)); err != ErrWitnessNotSelected {
		t.Fatalf("hand-picked witnesses accepted: %v", err)
	}
	// The old count-anything check passes the same receipt — which is exactly
	// the hole ValidateAttested closes.
	if err := ValidateReceipt(sr, 2); err != nil {
		t.Fatalf("baseline sanity: %v", err)
	}
}

func TestValidateAttestedAcceptsSelectedQuorum(t *testing.T) {
	provPub, provPriv, _ := ed25519.GenerateKey(nil)
	r := ServiceReceipt{ProviderNodeID: NodeIDOf(provPub), ServiceType: ServiceStorage, Epoch: 9, Quantity: 1}
	sr := SignedReceipt{Receipt: r, ProviderPub: provPub, ProviderSig: SignReceipt(provPriv, r)}

	selected := map[[32]byte]bool{}
	for i := 0; i < 5; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		selected[NodeIDOf(pub)] = true
		if i < 3 { // exactly the 3-of-5 quorum signs
			sr.Witnesses = append(sr.Witnesses, WitnessAttestation{Pub: pub, Sig: SignReceipt(priv, r)})
		}
	}
	if err := ValidateAttested(sr, selected, ThresholdFor(ServiceStorage)); err != nil {
		t.Fatalf("valid 3-of-5 rejected: %v", err)
	}
	// Drop to two and it must fail.
	sr.Witnesses = sr.Witnesses[:2]
	if err := ValidateAttested(sr, selected, ThresholdFor(ServiceStorage)); err != ErrWitnessThreshold {
		t.Fatalf("2-of-5 accepted for a 3-of-5 service: %v", err)
	}
}
