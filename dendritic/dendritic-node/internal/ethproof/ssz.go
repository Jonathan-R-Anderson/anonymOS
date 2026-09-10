package ethproof

// SSZ merkleisation, the minimum the light client needs — roadmap P12-5.2.
//
// SCOPE
// -----
// Not Ethereum's SSZ ecosystem. Four things, and only because the light client
// cannot authenticate a header without them:
//
//	hash_tree_root of a fixed container      beacon headers, sync committees
//	merkleise a chunk list to a power of two the padding rule everything uses
//	mix_in_length                            lists, where the length is committed
//	generalized-index branch verification    "this field is in that root"
//
// Serialisation is deliberately absent. Nothing here needs to PRODUCE SSZ, only
// to reproduce roots and check branches, and an encoder would be surface with
// no caller.
//
// WHY HAND-WRITTEN
// ----------------
// Same reasoning as the RLP decoder and the MPT verifier next door: this is a
// simple, deterministic, fully specified encoding with no secret material, it
// is checkable against published roots, and its failure mode is a root that
// does not match. Pulling in a consensus client to obtain it would import a
// great deal we would then be trusting without having read.
//
// That reasoning covers encodings. It does NOT extend to pairing cryptography —
// see bls.go for where the line is and why it is drawn differently there.
//
// THE PADDING RULE
// ---------------
// Every merkleisation pads with ZERO HASHES to the next power of two, where the
// zero hash at depth d is the root of a subtree of that depth containing
// nothing. Getting this wrong produces roots that are self-consistent and wrong
// — they will verify against each other and against nothing Ethereum published,
// which is the most confusing failure available. Hence zeroHashes below, and
// tests that check specific published constants rather than only round trips.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Root is a 32-byte SSZ hash tree root.
type Root [32]byte

// BytesPerChunk is SSZ's leaf size.
const BytesPerChunk = 32

// sha256Pair hashes two chunks, which is every internal node in an SSZ tree.
func sha256Pair(left, right []byte) Root {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	var out Root
	copy(out[:], h.Sum(nil))
	return out
}

// zeroHashes[d] is the root of an empty subtree of depth d.
//
// Precomputed because padding uses them constantly and recomputing a depth-40
// zero subtree per call would dominate the cost of verifying anything.
var zeroHashes = func() [64]Root {
	var out [64]Root
	for i := 1; i < len(out); i++ {
		out[i] = sha256Pair(out[i-1][:], out[i-1][:])
	}
	return out
}()

// ZeroHash returns the root of an empty subtree of the given depth.
func ZeroHash(depth int) Root {
	if depth < 0 || depth >= len(zeroHashes) {
		return Root{}
	}
	return zeroHashes[depth]
}

// Merkleize computes the root of a chunk list padded to `limit` leaves.
//
// limit must be a power of two and at least len(chunks); pass 0 to pad to the
// next power of two above the chunk count, which is what a fixed container
// wants.
//
// Padding uses zero hashes rather than repeated leaves. That distinction is the
// whole of the rule: a tree padded by duplicating the last chunk produces a
// different, wrong root that nothing will ever agree with.
func Merkleize(chunks []Root, limit int) (Root, error) {
	if limit == 0 {
		limit = nextPowerOfTwo(len(chunks))
	}
	if limit < len(chunks) {
		return Root{}, fmt.Errorf(
			"ethproof: %d chunks do not fit a limit of %d", len(chunks), limit)
	}
	if limit&(limit-1) != 0 {
		return Root{}, fmt.Errorf("ethproof: merkleise limit %d is not a power of two", limit)
	}
	if limit == 0 {
		return Root{}, nil
	}
	if limit == 1 {
		if len(chunks) == 0 {
			return Root{}, nil
		}
		return chunks[0], nil
	}

	layer := make([]Root, len(chunks))
	copy(layer, chunks)

	width := limit
	depth := 0
	for width > 1 {
		next := make([]Root, 0, (width+1)/2)
		for i := 0; i < width; i += 2 {
			left, right := ZeroHash(depth), ZeroHash(depth)
			if i < len(layer) {
				left = layer[i]
			}
			if i+1 < len(layer) {
				right = layer[i+1]
			}
			next = append(next, sha256Pair(left[:], right[:]))
		}
		layer = next
		width /= 2
		depth++
	}
	return layer[0], nil
}

// MixInLength commits a list's length alongside its root, which is how SSZ
// distinguishes a list from a vector with the same contents.
func MixInLength(root Root, length uint64) Root {
	var lengthChunk [32]byte
	binary.LittleEndian.PutUint64(lengthChunk[:8], length)
	return sha256Pair(root[:], lengthChunk[:])
}

// Uint64Root is the leaf for a uint64 — little-endian, right-padded.
//
// Little-endian is SSZ's convention and the opposite of the ABI's, which is a
// standing trap when both encodings are in one codebase: a big-endian slot here
// produces a root that is wrong by a byte swap and matches nothing.
func Uint64Root(v uint64) Root {
	var out Root
	binary.LittleEndian.PutUint64(out[:8], v)
	return out
}

// BytesRoot chunks arbitrary bytes and merkleises them.
//
// For fixed-size byte vectors — public keys, roots. A 48-byte BLS key becomes
// two chunks, which is why a pubkey's root is not simply its bytes.
func BytesRoot(b []byte) (Root, error) {
	chunks := make([]Root, 0, (len(b)+BytesPerChunk-1)/BytesPerChunk)
	for i := 0; i < len(b); i += BytesPerChunk {
		var chunk Root
		copy(chunk[:], b[i:])
		chunks = append(chunks, chunk)
	}
	if len(chunks) == 0 {
		chunks = append(chunks, Root{})
	}
	return Merkleize(chunks, 0)
}

// ContainerRoot merkleises a container's field roots.
//
// A container's limit is its field count padded to a power of two, which
// Merkleize(chunks, 0) does — stated here because the alternative reading, that
// containers pad to some fixed width, produces roots that verify against
// nothing.
func ContainerRoot(fields []Root) (Root, error) {
	return Merkleize(fields, 0)
}

// ---- generalized index proofs -----------------------------------------------

var (
	// ErrBranchInvalid means the branch does not connect the leaf to the root.
	ErrBranchInvalid = errors.New("ethproof: merkle branch does not produce the root")
	// ErrBranchLength means the branch is the wrong depth for its index.
	ErrBranchLength = errors.New("ethproof: merkle branch length does not match the generalized index")
)

// GeneralizedIndexDepth is how many branch nodes an index needs.
//
// A generalized index numbers nodes as 1 for the root, 2n and 2n+1 for
// children; the depth is the position of its highest set bit.
func GeneralizedIndexDepth(index uint64) int {
	depth := 0
	for i := index; i > 1; i >>= 1 {
		depth++
	}
	return depth
}

// VerifyBranch checks that `leaf` sits at `index` beneath `root`.
//
// The one operation the light client performs on every update: "the finalised
// checkpoint is at this position in that beacon state", "the execution payload
// header is at this position in that block body". The index is what pins WHICH
// field — a branch that verifies at the wrong index proves a true statement
// about the wrong thing, which is why the depth check is not optional.
func VerifyBranch(leaf Root, branch []Root, index uint64, root Root) error {
	if index == 0 {
		return fmt.Errorf("%w: generalized index 0 does not exist", ErrBranchLength)
	}
	depth := GeneralizedIndexDepth(index)
	if len(branch) != depth {
		return fmt.Errorf("%w: %d nodes for a depth-%d index", ErrBranchLength, len(branch), depth)
	}

	node := leaf
	for i, sibling := range branch {
		// Bit i of the index says whether this node is a right child.
		if index>>(uint(i))&1 == 1 {
			node = sha256Pair(sibling[:], node[:])
		} else {
			node = sha256Pair(node[:], sibling[:])
		}
	}
	if node != root {
		return fmt.Errorf("%w: computed %x, want %x", ErrBranchInvalid, node[:8], root[:8])
	}
	return nil
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// ---- the containers the light client authenticates --------------------------

// BeaconBlockHeader is the consensus header a sync committee signs over.
//
// Five fields, all one chunk each, so its root is a four-level tree over eight
// leaves (five fields padded to eight).
type BeaconBlockHeader struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    Root
	StateRoot     Root
	BodyRoot      Root
}

// HashTreeRoot is what everything else refers to a header by.
func (h BeaconBlockHeader) HashTreeRoot() (Root, error) {
	return ContainerRoot([]Root{
		Uint64Root(h.Slot),
		Uint64Root(h.ProposerIndex),
		h.ParentRoot,
		h.StateRoot,
		h.BodyRoot,
	})
}
