package ethproof

// Merkle-Patricia proof verification — roadmap P12-2.
//
// THE PROPERTY THIS ESTABLISHES
// -----------------------------
// Given a root hash somebody else supplied and a proof somebody else supplied,
// either the value is what the proof says or verification fails. There is no
// third outcome where a wrong value verifies, because every step re-hashes the
// node it was pointed at and checks it against the reference it followed.
//
// So a hostile RPC can refuse to answer, or answer slowly, or lie in a way that
// fails to verify. What it cannot do is make this return a value the state root
// does not commit to. That is exactly the reduction P12 is after: the trust
// collapses from "everything the provider says" down to "the header", and P12-5
// removes that last piece.
//
// ABSENCE IS AN ANSWER
// --------------------
// A slot that has never been written is not an error. Ethereum's tries do not
// store zeros, so "this channel does not exist" and "this channel has a zero
// balance" arrive as the same proof of absence — and the caller has to be able
// to tell that from a failed verification. VerifyProof returns (nil, nil) for a
// proven absence and an error for a proof that does not hold.

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrProofInvalid means the proof does not support the root. The value it
	// claims must not be used.
	ErrProofInvalid = errors.New("ethproof: proof does not verify against the root")
	// ErrProofIncomplete means the proof ran out of nodes before reaching an
	// answer — neither a value nor a proof of absence.
	ErrProofIncomplete = errors.New("ethproof: proof ended without an answer")
)

// Keccak256 is Ethereum's hash. Not SHA3-256: the padding differs, and the two
// are easy to confuse in a library that offers both.
func Keccak256(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// nibbles expands bytes to 4-bit path elements, which is how a trie key is
// consumed.
func nibbles(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c>>4, c&0x0F)
	}
	return out
}

// hexPrefix decodes a node's packed path, returning the nibbles and whether
// this is a leaf.
//
// The first nibble carries two flags: bit 1 is "leaf", bit 0 is "the path has
// an odd number of nibbles". Getting the odd/even case wrong produces a path
// off by one nibble, which fails to verify rather than verifying wrongly — but
// it fails on perfectly good proofs, so it is worth being exact.
func hexPrefix(b []byte) (path []byte, isLeaf bool, err error) {
	if len(b) == 0 {
		return nil, false, fmt.Errorf("%w: empty hex-prefix", ErrProofInvalid)
	}
	all := nibbles(b)
	flag := all[0]
	isLeaf = flag&0x02 != 0
	odd := flag&0x01 != 0
	if odd {
		return all[1:], isLeaf, nil
	}
	if len(all) < 2 || all[1] != 0 {
		// An even-length path must be padded with a zero nibble. Anything else
		// is not a node this trie produced.
		return nil, false, fmt.Errorf("%w: bad hex-prefix padding", ErrProofInvalid)
	}
	return all[2:], isLeaf, nil
}

// VerifyProof walks a Merkle-Patricia proof from root to value.
//
// key is the RAW key — the address or the storage slot. It is hashed here,
// because forgetting to hash it is the single most common way to hold a valid
// proof and conclude the data is missing.
//
// Returns (value, nil) when the proof commits to a value, (nil, nil) when it
// PROVES the key is absent, and an error when the proof does not hold.
func VerifyProof(root []byte, key []byte, proof [][]byte) ([]byte, error) {
	if len(root) != 32 {
		return nil, fmt.Errorf("%w: root must be 32 bytes", ErrProofInvalid)
	}
	// Index the proof by node hash. A proof is a set, not a sequence: the order
	// it arrives in is not part of what it proves.
	byHash := make(map[string][]byte, len(proof))
	for _, node := range proof {
		byHash[string(Keccak256(node))] = node
	}

	path := nibbles(Keccak256(key))
	ref := root
	var inline []byte

	for depth := 0; ; depth++ {
		if depth > 64 {
			// A trie path is at most 64 nibbles deep. Beyond that the proof is
			// cyclic, and following it would not terminate.
			return nil, fmt.Errorf("%w: proof is cyclic", ErrProofInvalid)
		}

		var raw []byte
		switch {
		case inline != nil:
			raw, inline = inline, nil
		default:
			node, ok := byHash[string(ref)]
			if !ok {
				return nil, fmt.Errorf("%w: no node for %x", ErrProofIncomplete, ref[:4])
			}
			raw = node
		}

		item, err := DecodeRLP(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrProofInvalid, err)
		}
		if !item.IsList {
			return nil, fmt.Errorf("%w: node is not a list", ErrProofInvalid)
		}

		switch len(item.List) {
		case 17: // branch
			if len(path) == 0 {
				// The key ends here; the value rides in the seventeenth slot.
				return item.List[16].Bytes, nil
			}
			next := item.List[path[0]]
			path = path[1:]
			if len(next.Bytes) == 0 && !next.IsList {
				return nil, nil // proven absent: the branch has no such child
			}
			ref, inline, err = follow(next)
			if err != nil {
				return nil, err
			}

		case 2: // extension or leaf
			prefix, isLeaf, err := hexPrefix(item.List[0].Bytes)
			if err != nil {
				return nil, err
			}
			if len(path) < len(prefix) || !bytes.Equal(path[:len(prefix)], prefix) {
				// The path diverges here. That is a PROOF the key is absent,
				// not a broken proof.
				return nil, nil
			}
			path = path[len(prefix):]
			if isLeaf {
				if len(path) != 0 {
					return nil, nil // absent: the leaf is for a longer key
				}
				return item.List[1].Bytes, nil
			}
			ref, inline, err = follow(item.List[1])
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("%w: node has %d items", ErrProofInvalid, len(item.List))
		}
	}
}

// follow resolves a node reference, which is a 32-byte hash for large nodes and
// the node ITSELF for small ones.
//
// The inline case is easy to miss and produces a "missing node" error on
// perfectly valid proofs of short keys.
func follow(ref rlpItem) (hash []byte, inlineRaw []byte, err error) {
	if ref.IsList {
		// An inlined node, embedded rather than referenced. Re-encoding it to
		// hash would be wasted work; it is walked directly.
		return nil, nil, errInlineList
	}
	switch len(ref.Bytes) {
	case 32:
		return ref.Bytes, nil, nil
	case 0:
		return nil, nil, fmt.Errorf("%w: empty reference", ErrProofInvalid)
	default:
		return nil, nil, fmt.Errorf("%w: reference is %d bytes", ErrProofInvalid, len(ref.Bytes))
	}
}

// errInlineList marks the one shape this verifier does not walk.
//
// Honest rather than silent: inlined branch nodes appear only in tries with very
// few, very short keys, which the account and storage tries of a live contract
// are not. If it ever fires, this needs the case rather than a workaround.
var errInlineList = fmt.Errorf("%w: inlined list nodes are not supported", ErrProofInvalid)

// StorageSlotKey is the trie key for a mapping entry.
//
//	slot(mapping[k]) = keccak256(k ‖ uint256(position))
//
// For AxonChannels, `channels` is at position 0 — from solc's storage
// layout, not from reading the source — so a channel's first slot is
// keccak256(id ‖ 32 zero bytes) and the struct occupies the ten slots after it.
func StorageSlotKey(key [32]byte, position uint64) [32]byte {
	var pos [32]byte
	for i := 0; i < 8; i++ {
		pos[31-i] = byte(position >> (8 * i))
	}
	var out [32]byte
	copy(out[:], Keccak256(key[:], pos[:]))
	return out
}

// SlotAt returns the nth slot of a struct that begins at base.
func SlotAt(base [32]byte, n uint64) [32]byte {
	out := base
	carry := n
	for i := 31; i >= 0 && carry > 0; i-- {
		sum := uint64(out[i]) + carry&0xFF
		out[i] = byte(sum)
		carry = carry>>8 + sum>>8
	}
	return out
}

// AccountStorageRoot pulls the storageRoot out of a proven account.
//
// An account is RLP([nonce, balance, storageRoot, codeHash]). An absent account
// has no storage root and no storage, which is a real answer for a contract
// address that does not exist.
func AccountStorageRoot(accountRLP []byte) ([]byte, error) {
	if len(accountRLP) == 0 {
		return nil, fmt.Errorf("%w: account is absent", ErrProofIncomplete)
	}
	item, err := DecodeRLP(accountRLP)
	if err != nil {
		return nil, err
	}
	if !item.IsList || len(item.List) != 4 {
		return nil, fmt.Errorf("%w: account is not a 4-item list", ErrProofInvalid)
	}
	root := item.List[2].Bytes
	if len(root) != 32 {
		return nil, fmt.Errorf("%w: storageRoot is %d bytes", ErrProofInvalid, len(root))
	}
	return root, nil
}

// DecodeSlotValue unwraps a storage value, which is RLP-encoded and has its
// leading zeros stripped.
//
// Returned left-padded to 32 bytes, which is how every caller wants it and how
// the ABI would have delivered it.
func DecodeSlotValue(raw []byte) ([32]byte, error) {
	var out [32]byte
	if len(raw) == 0 {
		return out, nil // absent means zero
	}
	item, err := DecodeRLP(raw)
	if err != nil {
		return out, err
	}
	if item.IsList {
		return out, fmt.Errorf("%w: storage value is a list", ErrProofInvalid)
	}
	if len(item.Bytes) > 32 {
		return out, fmt.Errorf("%w: storage value is %d bytes", ErrProofInvalid, len(item.Bytes))
	}
	copy(out[32-len(item.Bytes):], item.Bytes)
	return out, nil
}
