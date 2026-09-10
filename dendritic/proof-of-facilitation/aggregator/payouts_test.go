package aggregator

import "testing"

func TestDeclarationOverridesRegistryOwner(t *testing.T) {
	var node [32]byte
	node[0] = 9
	var owner, declared [20]byte
	owner[19], declared[19] = 1, 2

	got := ResolveRecipients(
		map[[32]byte][20]byte{node: owner},
		map[[32]byte][20]byte{node: declared},
	)
	if got[node] != declared {
		t.Fatal("the node's declared payout did not win over the registry owner")
	}
}

func TestRegistryOwnerUsedWhenNothingDeclared(t *testing.T) {
	var node [32]byte
	var owner [20]byte
	owner[19] = 7
	got := ResolveRecipients(map[[32]byte][20]byte{node: owner}, map[[32]byte][20]byte{})
	if got[node] != owner {
		t.Fatal("registry owner should be the fallback")
	}
}

// A node with no payout anywhere must be absent, not zero-addressed: settlement
// skips who it cannot pay, but a zero recipient would burn the reward.
func TestUnknownNodeIsOmitted(t *testing.T) {
	var node [32]byte
	node[0] = 3
	got := ResolveRecipients(map[[32]byte][20]byte{}, map[[32]byte][20]byte{})
	if _, present := got[node]; present {
		t.Fatal("a node with no payout address appeared in the recipients map")
	}
}

func TestZeroAddressIsRejected(t *testing.T) {
	if _, ok := parseAddress20("0x" + "00000000000000000000000000000000000000" + "00"); ok {
		t.Fatal("the zero address was accepted as a payout target")
	}
	if _, ok := parseAddress20("0xB2b36AaD18d7be5d4016267BC4cCec2f12a64b6e"); !ok {
		t.Fatal("a valid address was rejected")
	}
}
