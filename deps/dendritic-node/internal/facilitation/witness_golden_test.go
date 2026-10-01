package facilitation

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// Cross-module golden vectors.
//
// These outputs were produced by proof-of-facilitation/aggregator's
// SelectWitnesses, which is a separate Go module this one cannot import. They
// are the contract between the two: the provider asks the witnesses named here,
// and settlement accepts exactly the witnesses named here.
//
// A failure means the two implementations have drifted, and the visible symptom
// in production would NOT look like drift — it would look like every node in
// the network suddenly attesting fraudulently. Fix the divergence; do not
// re-baseline the vectors unless the aggregator was changed in the same commit
// and produced the new values itself.

func goldenCandidates() []Candidate {
	mk := func(b byte, stake int64, rep uint32, group string) Candidate {
		var id [32]byte
		for i := range id {
			id[i] = b
		}
		return Candidate{NodeID: id, Stake: big.NewInt(stake), ReputationBps: rep, Group: group}
	}
	return []Candidate{
		mk(0x11, 0, 10000, ""),       // unstaked: eligible via the bootstrap floor
		mk(0x22, 0, 10000, ""),       // unstaked
		mk(0x33, 1000000, 10000, ""), // real stake: outweighs the floored ones
		mk(0x44, 0, 10000, "shared"), // same operator as 0x55
		mk(0x55, 0, 10000, "shared"), //
		mk(0x66, 0, 5000, ""),        // half reputation
		mk(0x77, 0, 0, ""),           // zero reputation: never selectable
	}
}

func goldenSeeds(t *testing.T) (randomness, provider [32]byte) {
	t.Helper()
	// The randomness derived for genesis epoch 0 from the live seed, so the
	// vectors exercise a value the network actually uses.
	raw, err := hex.DecodeString(
		"9d4f28eecbdebf3d8ca76d60cad02e618238cd83fed29521d71d3552a05a10f3")
	if err != nil {
		t.Fatal(err)
	}
	copy(randomness[:], raw)
	for i := range provider {
		provider[i] = 0xAA
	}
	return randomness, provider
}

func TestSelectWitnessesMatchesTheAggregator(t *testing.T) {
	randomness, provider := goldenSeeds(t)
	cands := goldenCandidates()

	cases := []struct {
		svc  ServiceType
		idx  uint32
		want string
	}{
		{ServiceStorage, 0, "33 11 55 66 22"},
		{ServiceStorage, 7, "33 44 11 22 66"},
		{ServiceDHT, 0, "33 22 11"},
		{ServiceDHT, 7, "33 11 22"},
	}
	for _, tc := range cases {
		sel := SelectWitnesses(randomness, provider, tc.svc, tc.idx, ThresholdFor(tc.svc), cands)
		got := ""
		for i, c := range sel {
			if i > 0 {
				got += " "
			}
			got += fmt.Sprintf("%02x", c.NodeID[0])
		}
		if got != tc.want {
			t.Errorf("service %d, challenge %d: drew [%s], the aggregator draws [%s]",
				tc.svc, tc.idx, got, tc.want)
		}
	}
}

func TestZeroReputationIsNeverDrawn(t *testing.T) {
	randomness, provider := goldenSeeds(t)
	for idx := uint32(0); idx < 40; idx++ {
		for _, c := range SelectWitnesses(randomness, provider, ServiceStorage, idx,
			ThresholdFor(ServiceStorage), goldenCandidates()) {
			if c.NodeID[0] == 0x77 {
				t.Fatalf("challenge %d drew the zero-reputation candidate", idx)
			}
		}
	}
}

func TestOneSeatPerGroupWhileIndependentsRemain(t *testing.T) {
	// 0x44 and 0x55 are the same operator. With five seats and six eligible
	// candidates there is no need to seat both, so it must not.
	randomness, provider := goldenSeeds(t)
	for idx := uint32(0); idx < 40; idx++ {
		sel := SelectWitnesses(randomness, provider, ServiceStorage, idx,
			ThresholdFor(ServiceStorage), goldenCandidates())
		shared := 0
		for _, c := range sel {
			if c.Group == "shared" {
				shared++
			}
		}
		if shared > 1 {
			t.Fatalf("challenge %d seated %d witnesses from one operator", idx, shared)
		}
	}
}

func TestAProviderNeverWitnessesItself(t *testing.T) {
	randomness, _ := goldenSeeds(t)
	cands := goldenCandidates()
	for _, self := range cands {
		for idx := uint32(0); idx < 20; idx++ {
			for _, c := range SelectWitnesses(randomness, self.NodeID, ServiceStorage, idx,
				ThresholdFor(ServiceStorage), cands) {
				if c.NodeID == self.NodeID {
					t.Fatalf("node %02x was drawn to witness its own receipt", self.NodeID[0])
				}
			}
		}
	}
}

func TestShortPoolReturnsAShortSetRatherThanPadding(t *testing.T) {
	randomness, provider := goldenSeeds(t)
	only := goldenCandidates()[:2]
	sel := SelectWitnesses(randomness, provider, ServiceStorage, 0, ThresholdFor(ServiceStorage), only)
	if len(sel) != 2 {
		t.Fatalf("drew %d witnesses from a pool of 2; a short set must stay short", len(sel))
	}
}
