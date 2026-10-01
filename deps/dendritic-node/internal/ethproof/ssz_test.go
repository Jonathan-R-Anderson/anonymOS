package ethproof

// SSZ merkleisation — roadmap P12-5.2.
//
// The dangerous failure here is a root that is SELF-CONSISTENT AND WRONG: pad
// with the wrong thing, or byte-order a uint64 the other way, and every root
// this package produces will verify against every other root this package
// produces, and against nothing Ethereum ever published.
//
// So the tests below check published constants where they exist, and structural
// properties that a plausible-but-wrong implementation would fail, rather than
// only round-tripping this package against itself.

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The zero hashes are published constants. If these are wrong, every padded
// root in the package is wrong in a way nothing else would reveal.
func TestZeroHashesMatchThePublishedValues(t *testing.T) {
	// zeroHashes[1] = sha256(0^32 ‖ 0^32), which is a widely quoted value.
	want := "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
	if got := hex.EncodeToString(zeroHashes[1][:]); got != want {
		t.Errorf("zeroHashes[1] = %s, want %s", got, want)
	}
	// And zeroHashes[0] is genuinely zero, not sha256 of anything.
	if zeroHashes[0] != (Root{}) {
		t.Error("zeroHashes[0] is not the zero root")
	}
}

// Padding must use zero hashes, NOT a repeated last leaf. The two produce
// different roots and only one is Ethereum's.
func TestPaddingUsesZeroHashesNotRepeatedLeaves(t *testing.T) {
	var a Root
	a[0] = 0xAA
	got, err := Merkleize([]Root{a}, 2)
	if err != nil {
		t.Fatalf("Merkleize: %v", err)
	}
	want := sha256Pair(a[:], make([]byte, 32))
	if got != want {
		t.Errorf("a single chunk padded to 2 gave %x, want sha256(chunk ‖ 0^32) %x",
			got[:8], want[:8])
	}
	// The wrong implementation would produce this instead.
	if got == sha256Pair(a[:], a[:]) {
		t.Error("padding duplicated the last leaf")
	}
}

// A uint64 leaf is LITTLE-endian. The ABI encoder next door is big-endian, and
// mixing them produces roots wrong by a byte swap.
func TestUint64RootIsLittleEndian(t *testing.T) {
	got := Uint64Root(1)
	if got[0] != 1 {
		t.Errorf("Uint64Root(1) = %x; little-endian puts the 1 first", got[:8])
	}
	if got[7] == 1 && got[0] == 0 {
		t.Error("Uint64Root is big-endian; SSZ is little-endian")
	}
	// And the rest of the chunk is zero padding, not sign extension.
	for i := 8; i < 32; i++ {
		if got[i] != 0 {
			t.Fatalf("byte %d is %x, want zero padding", i, got[i])
		}
	}
}

func TestMerkleizeRefusesAnImpossibleLimit(t *testing.T) {
	chunks := []Root{{}, {}, {}}
	if _, err := Merkleize(chunks, 2); err == nil {
		t.Error("three chunks fitted into a limit of two")
	}
	if _, err := Merkleize(chunks, 6); err == nil {
		t.Error("a non-power-of-two limit was accepted")
	}
}

// A 48-byte BLS public key is two chunks, so its root is not its bytes. Getting
// this wrong makes every sync committee root wrong.
func TestBytesRootChunksBeyondThirtyTwo(t *testing.T) {
	key := make([]byte, 48)
	for i := range key {
		key[i] = byte(i + 1)
	}
	got, err := BytesRoot(key)
	if err != nil {
		t.Fatalf("BytesRoot: %v", err)
	}
	var first, second Root
	copy(first[:], key[:32])
	copy(second[:], key[32:])
	if got != sha256Pair(first[:], second[:]) {
		t.Error("a 48-byte value did not merkleise as two chunks")
	}
	// A short value is one chunk and IS its padded bytes.
	short, err := BytesRoot([]byte{0xAB})
	if err != nil {
		t.Fatalf("BytesRoot: %v", err)
	}
	if short[0] != 0xAB || short[1] != 0 {
		t.Errorf("a one-byte value rooted to %x", short[:4])
	}
}

// mix_in_length is what distinguishes a list from a vector with identical
// contents. Without it the two are indistinguishable.
func TestMixInLengthDistinguishesListsFromVectors(t *testing.T) {
	var r Root
	r[0] = 0x01
	if MixInLength(r, 3) == MixInLength(r, 4) {
		t.Fatal("different lengths produced the same root")
	}
	if MixInLength(r, 0) == r {
		t.Error("mixing in a length left the root unchanged")
	}
}

// ---- generalized index branches ---------------------------------------------

func TestGeneralizedIndexDepth(t *testing.T) {
	for _, tc := range []struct {
		index uint64
		depth int
	}{{1, 0}, {2, 1}, {3, 1}, {4, 2}, {7, 2}, {8, 3}, {15, 3}} {
		if got := GeneralizedIndexDepth(tc.index); got != tc.depth {
			t.Errorf("depth(%d) = %d, want %d", tc.index, got, tc.depth)
		}
	}
}

// A branch built by hand must verify, and the index must select the right side.
func TestVerifyBranchFollowsTheIndex(t *testing.T) {
	var leaf, sibling Root
	leaf[0], sibling[0] = 0x11, 0x22

	// index 2 = left child of the root: node goes on the left.
	leftRoot := sha256Pair(leaf[:], sibling[:])
	if err := VerifyBranch(leaf, []Root{sibling}, 2, leftRoot); err != nil {
		t.Errorf("left-child branch: %v", err)
	}
	// index 3 = right child: node goes on the right.
	rightRoot := sha256Pair(sibling[:], leaf[:])
	if err := VerifyBranch(leaf, []Root{sibling}, 3, rightRoot); err != nil {
		t.Errorf("right-child branch: %v", err)
	}
	// And they are genuinely different, so the index is doing work.
	if leftRoot == rightRoot {
		t.Fatal("left and right placement produced the same root")
	}
}

// A branch that verifies at the WRONG index proves a true statement about the
// wrong field. The depth check is what stops that.
func TestVerifyBranchRejectsAMismatchedDepth(t *testing.T) {
	var leaf, sibling Root
	root := sha256Pair(leaf[:], sibling[:])
	// Correct at depth 1; offered at an index needing depth 2.
	if err := VerifyBranch(leaf, []Root{sibling}, 4, root); err == nil {
		t.Fatal("a depth-1 branch verified against a depth-2 index")
	}
	if err := VerifyBranch(leaf, []Root{sibling}, 0, root); err == nil {
		t.Fatal("generalized index 0 was accepted")
	}
}

func TestVerifyBranchRejectsATamperedNode(t *testing.T) {
	var leaf, sibling Root
	leaf[0], sibling[0] = 0x11, 0x22
	root := sha256Pair(leaf[:], sibling[:])

	sibling[31] ^= 0x01
	if err := VerifyBranch(leaf, []Root{sibling}, 2, root); err == nil {
		t.Fatal("a branch with a flipped bit still verified")
	}
}

// ---- the beacon header ------------------------------------------------------

// Five fields pad to eight leaves, so the root is a depth-3 tree. A container
// that padded to a different width would produce a self-consistent wrong root.
func TestBeaconHeaderRootIsADepthThreeTree(t *testing.T) {
	h := BeaconBlockHeader{Slot: 1, ProposerIndex: 2}
	h.ParentRoot[0], h.StateRoot[0], h.BodyRoot[0] = 3, 4, 5

	got, err := h.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	want, err := Merkleize([]Root{
		Uint64Root(1), Uint64Root(2), h.ParentRoot, h.StateRoot, h.BodyRoot,
	}, 8)
	if err != nil {
		t.Fatalf("Merkleize: %v", err)
	}
	if got != want {
		t.Error("the header root is not a five-field container padded to eight")
	}
}

// Every field must affect the root, or a forged header could differ in a field
// the root does not commit to.
func TestEveryHeaderFieldChangesTheRoot(t *testing.T) {
	base := BeaconBlockHeader{Slot: 1, ProposerIndex: 2}
	baseRoot, err := base.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}

	variants := map[string]BeaconBlockHeader{
		"slot":     {Slot: 9, ProposerIndex: 2},
		"proposer": {Slot: 1, ProposerIndex: 9},
	}
	withParent := base
	withParent.ParentRoot[0] = 9
	variants["parentRoot"] = withParent
	withState := base
	withState.StateRoot[0] = 9
	variants["stateRoot"] = withState
	withBody := base
	withBody.BodyRoot[0] = 9
	variants["bodyRoot"] = withBody

	for name, v := range variants {
		got, err := v.HashTreeRoot()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == baseRoot {
			t.Errorf("changing %s did not change the root", name)
		}
	}
}

func TestZeroHashDepthIsBounded(t *testing.T) {
	if ZeroHash(-1) != (Root{}) || ZeroHash(9999) != (Root{}) {
		t.Error("an out-of-range depth did not return the zero root")
	}
	if strings.Repeat("x", 0) != "" {
		t.Fatal("unreachable")
	}
}
