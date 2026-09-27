package aggregator

import (
	"encoding/hex"
	"testing"
)

// The vectors here are shared with backend/tests/test_pof_randomness.py. They
// use the network's real genesis seed, and they are the only thing keeping a
// node's witness set and settlement's witness set from being different sets.
//
// If these two implementations ever disagree, every honest receipt is rejected
// for carrying attestations from "witnesses the protocol did not select" —
// which is indistinguishable, from the outside, from fraud.
const liveGenesisSeed = "b7aa0996eef912b1b3fed14b5edb9687ea08054d98690a2fcfbad362be8f575d"

func seedFor(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad test seed %q", s)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func TestDeriveEpochRandomnessMatchesThePythonImplementation(t *testing.T) {
	seed := seedFor(t, liveGenesisSeed)
	cases := map[uint64]string{
		0: "9d4f28eecbdebf3d8ca76d60cad02e618238cd83fed29521d71d3552a05a10f3",
		1: "6e5aebe8c181aa62d40d4f096d3fccf0958a9a9f96728d61c3ffc3eea7211130",
		4: "ffe297c6cbb73886b04c465578258d99193147e34ed15b4a03e55df96e090db1",
	}
	for epoch, want := range cases {
		value := DeriveEpochRandomness(seed, epoch)
		got := hex.EncodeToString(value[:])
		if got != want {
			t.Errorf("epoch %d: derived %s, want %s (the site derives the latter)",
				epoch, got, want)
		}
	}
}

func TestEachEpochGetsItsOwnRandomness(t *testing.T) {
	seed := seedFor(t, liveGenesisSeed)
	seen := map[[32]byte]uint64{}
	for epoch := uint64(0); epoch < 64; epoch++ {
		value := DeriveEpochRandomness(seed, epoch)
		if prev, clash := seen[value]; clash {
			t.Fatalf("epochs %d and %d derive the same randomness", prev, epoch)
		}
		seen[value] = epoch
	}
}

func TestADifferentSeedIsADifferentSchedule(t *testing.T) {
	a := DeriveEpochRandomness(seedFor(t, liveGenesisSeed), 7)
	b := DeriveEpochRandomness(seedFor(t,
		"0000000000000000000000000000000000000000000000000000000000000001"), 7)
	if a == b {
		t.Fatal("the seed does not affect the derivation")
	}
}
