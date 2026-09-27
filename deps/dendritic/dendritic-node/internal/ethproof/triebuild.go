package ethproof

// Merkle-Patricia trie CONSTRUCTION — roadmap P14.5.
//
// WHY proof.go IS NOT ENOUGH
// --------------------------
// proof.go verifies: it walks one path a provider chose, re-hashing each node
// against the reference that pointed at it. That answers "is this value in that
// trie", and it is exactly the wrong tool for "what root does this whole set
// produce".
//
// The difference is omission. A proof of one key says nothing about the keys
// that were not mentioned, so a provider can omit a receipt and hand over a
// perfectly valid proof of every receipt it did send. Rebuilding the trie from
// the complete set and comparing the ROOT is what makes an omission change the
// answer — and that is the property the whole authenticated-receipts design
// rests on.
//
// KEYS ARE NOT HASHED HERE
// ------------------------
// The account and storage tries are "secure" tries keyed by keccak(key), which
// is why VerifyProof hashes what it is given. The transaction and receipts tries
// are NOT: their keys are RLP(index), used raw. Hashing them here would produce
// a self-consistent trie matching nothing, so BuildMPT takes the final key bytes
// and hashes nothing.

import (
	"bytes"
	"sort"
)

// TrieEntry is one key/value pair. Key is the FINAL trie key — already hashed if
// the trie in question is a secure one, and raw for the receipts trie.
type TrieEntry struct {
	Key   []byte
	Value []byte
}

// EmptyTrieRoot is keccak(rlp("")), the root of a trie with nothing in it.
//
// A real value, not a sentinel: an Ethereum block with no transactions really
// does carry this as its receiptsRoot, so a rebuild that produced zeros for an
// empty block would fail to match a perfectly ordinary block.
func EmptyTrieRoot() []byte { return Keccak256([]byte{0x80}) }

// BuildMPT returns the root hash of a trie containing exactly these entries.
//
// Duplicate keys are a caller error and are not silently merged — two receipts
// claiming the same transaction index is a provider anomaly, and collapsing them
// would hide it behind a root that happens not to match.
func BuildMPT(entries []TrieEntry) []byte {
	if len(entries) == 0 {
		return EmptyTrieRoot()
	}
	nodes := make([]triePath, 0, len(entries))
	for _, e := range entries {
		nodes = append(nodes, triePath{path: nibbles(e.Key), value: e.Value})
	}
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].path, nodes[j].path) < 0
	})
	return Keccak256(encodeTrieSubtree(nodes, 0))
}

// triePath is an entry expanded to nibbles, which is how a trie consumes a key.
type triePath struct {
	path  []byte
	value []byte
}

// packHexPrefix is the ENCODER matching proof.go's hexPrefix decoder.
//
// The first nibble carries two flags — bit 1 "leaf", bit 0 "odd length" — and an
// even-length path is padded with a zero nibble. Written forwards from the
// specification rather than derived from the decoder, for the reason rlpencode.go
// gives.
func packHexPrefix(path []byte, isLeaf bool) []byte {
	flag := byte(0)
	if isLeaf {
		flag = 2
	}
	var nib []byte
	if len(path)%2 == 1 {
		nib = make([]byte, 0, len(path)+1)
		nib = append(nib, flag+1)
	} else {
		nib = make([]byte, 0, len(path)+2)
		nib = append(nib, flag, 0)
	}
	nib = append(nib, path...)
	out := make([]byte, len(nib)/2)
	for i := range out {
		out[i] = nib[2*i]<<4 | nib[2*i+1]
	}
	return out
}

// trieNodeRef is how a parent points at a child.
//
// Nodes of 32 bytes or more are referenced by hash; SMALLER ONES ARE INLINED
// WHOLE. proof.go's `follow` documents the same asymmetry from the reading side
// and refuses inlined lists as unsupported — here it must be produced, because a
// receipts trie with few entries contains them and a rebuild that always hashed
// would not match.
func trieNodeRef(encoded []byte) []byte {
	if len(encoded) < 32 {
		return encoded
	}
	return EncodeRLPBytes(Keccak256(encoded))
}

// encodeTrieSubtree encodes the subtree covering nodes, all of which share their
// first `depth` nibbles. nodes must be sorted by path and non-empty.
func encodeTrieSubtree(nodes []triePath, depth int) []byte {
	if len(nodes) == 1 {
		n := nodes[0]
		return EncodeRLPList(
			EncodeRLPBytes(packHexPrefix(n.path[depth:], true)),
			EncodeRLPBytes(n.value),
		)
	}

	// How far does the shared prefix run past depth? An extension node exists
	// precisely to skip that stretch without a branch per nibble.
	end := depth
	for end < len(nodes[0].path) {
		c := nodes[0].path[end]
		same := true
		for _, n := range nodes[1:] {
			if end >= len(n.path) || n.path[end] != c {
				same = false
				break
			}
		}
		if !same {
			break
		}
		end++
	}
	if end > depth {
		child := encodeTrieSubtree(nodes, end)
		return EncodeRLPList(
			EncodeRLPBytes(packHexPrefix(nodes[0].path[depth:end], false)),
			trieNodeRef(child),
		)
	}

	// A branch: sixteen children and a seventeenth slot for a value whose key
	// ends exactly here.
	var items [17][]byte
	for i := range items {
		items[i] = []byte{0x80}
	}
	var groups [16][]triePath
	for _, n := range nodes {
		if len(n.path) == depth {
			items[16] = EncodeRLPBytes(n.value)
			continue
		}
		groups[n.path[depth]] = append(groups[n.path[depth]], n)
	}
	for i := range groups {
		if len(groups[i]) > 0 {
			items[i] = trieNodeRef(encodeTrieSubtree(groups[i], depth+1))
		}
	}
	return EncodeRLPList(items[:]...)
}
