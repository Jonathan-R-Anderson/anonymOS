// Package swarm is how a release reaches every computer quickly: a file is cut
// into pieces, and every node that holds a piece serves it to the others while
// it is still downloading the rest. The origin server is the first source, not
// the only one -- the more computers fetch an update at once, the more sources
// there are, which is the opposite of what happens to a server.
//
// Trust does not come from the peer. A file is named by the root of a Merkle tree
// over its pieces (the locator the wallet records on chain), and every piece
// arrives with the path that proves it belongs under that root. A hostile peer
// can waste bandwidth; it cannot get one wrong byte into a download.
//
// Anonymity comes from the carrier. Every peer connection is a stream on an AXON
// session (internal/axon/session) in the BULK class, so a peer learns that some
// node wanted a piece of a public release, and not which node or where it is.
// This package needs only net.Conn and does not know how sessions are built.
package swarm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

// The tree:
//
//	leaf(i)    = SHA256(0x00 ‖ LE64(i) ‖ piece_i)
//	node(l, r) = SHA256(0x01 ‖ l ‖ r)
//
// over the leaves padded with zero hashes to a power of two. The index is in the
// leaf so a piece cannot verify at another position; the 0x00/0x01 prefixes keep
// a leaf from being passed off as an internal node (the second-preimage trick
// against unprefixed Merkle trees). A proof is the sibling at each level, leaf
// upward: 13 hashes, 416 bytes, for a 2 GiB image at 256 KiB pieces.

// DefaultPieceSize is the piece size releases are cut into.
const DefaultPieceSize = 256 << 10

// MaxPieceSize bounds what a peer may claim, so a forged Meta cannot make a node
// allocate a gigabyte for one piece.
const MaxPieceSize = 4 << 20

var (
	ErrBadMeta    = errors.New("axon/swarm: malformed file description")
	ErrBadProof   = errors.New("axon/swarm: piece does not verify against the root")
	ErrBadLocator = errors.New("axon/swarm: malformed swarm locator")
)

// Meta names one file: everything a node needs to fetch and verify it.
type Meta struct {
	Root      [32]byte
	Size      int64
	PieceSize int
}

// Validate refuses a description no honest publisher produces.
func (m Meta) Validate() error {
	switch {
	case m.Size <= 0:
		return fmt.Errorf("%w: size %d", ErrBadMeta, m.Size)
	case m.PieceSize < 1024 || m.PieceSize > MaxPieceSize || m.PieceSize&(m.PieceSize-1) != 0:
		return fmt.Errorf("%w: piece size %d", ErrBadMeta, m.PieceSize)
	case m.Size/int64(m.PieceSize) > 1<<24:
		return fmt.Errorf("%w: %d pieces", ErrBadMeta, m.Size/int64(m.PieceSize))
	}
	return nil
}

// Pieces is how many pieces the file has.
func (m Meta) Pieces() int { return int((m.Size + int64(m.PieceSize) - 1) / int64(m.PieceSize)) }

// PieceLen is piece i's length (the last is short).
func (m Meta) PieceLen(i int) int {
	if i == m.Pieces()-1 {
		if r := int(m.Size % int64(m.PieceSize)); r != 0 {
			return r
		}
	}
	return m.PieceSize
}

// depth is the number of hashes in a proof.
func (m Meta) depth() int {
	d := 0
	for 1<<d < m.Pieces() {
		d++
	}
	return d
}

// Locator renders the file as a URI to record on chain and hand to clients:
//
//	axon-swarm:<root hex>?size=<bytes>&piece=<bytes>
//
// It is the magnet link of this network: content-addressed, and enough by
// itself to find peers (by root) and to verify what they send.
func (m Meta) Locator() string {
	return fmt.Sprintf("axon-swarm:%s?size=%d&piece=%d", hex.EncodeToString(m.Root[:]), m.Size, m.PieceSize)
}

// ParseLocator is Locator's inverse.
func ParseLocator(s string) (Meta, error) {
	var m Meta
	rest, ok := strings.CutPrefix(s, "axon-swarm:")
	if !ok {
		return m, ErrBadLocator
	}
	root, query, _ := strings.Cut(rest, "?")
	b, err := hex.DecodeString(root)
	if err != nil || len(b) != 32 {
		return m, ErrBadLocator
	}
	copy(m.Root[:], b)
	q, err := url.ParseQuery(query)
	if err != nil {
		return m, ErrBadLocator
	}
	if m.Size, err = strconv.ParseInt(q.Get("size"), 10, 64); err != nil {
		return m, ErrBadLocator
	}
	if m.PieceSize, err = strconv.Atoi(q.Get("piece")); err != nil {
		return m, ErrBadLocator
	}
	if err := m.Validate(); err != nil {
		return m, err
	}
	return m, nil
}

func leafHash(i int, data []byte) [32]byte {
	h := sha256.New()
	var hdr [9]byte
	binary.LittleEndian.PutUint64(hdr[1:], uint64(i))
	h.Write(hdr[:])
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(l, r [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = 1
	copy(buf[1:], l[:])
	copy(buf[33:], r[:])
	return sha256.Sum256(buf[:])
}

// Tree is the whole tree, held by a node that has the whole file.
type Tree struct {
	meta   Meta
	levels [][][32]byte // levels[0] = padded leaves, last = [root]
}

// BuildTree hashes a complete file.
func BuildTree(r io.ReaderAt, size int64, pieceSize int) (*Tree, error) {
	m := Meta{Size: size, PieceSize: pieceSize}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	n := m.Pieces()
	leaves := make([][32]byte, 1<<m.depth())
	buf := make([]byte, pieceSize)
	for i := 0; i < n; i++ {
		l := m.PieceLen(i)
		if _, err := r.ReadAt(buf[:l], int64(i)*int64(pieceSize)); err != nil && !(err == io.EOF && i == n-1) {
			return nil, err
		}
		leaves[i] = leafHash(i, buf[:l])
	}
	t := &Tree{meta: m, levels: [][][32]byte{leaves}}
	for lv := leaves; len(lv) > 1; {
		next := make([][32]byte, len(lv)/2)
		for i := range next {
			next[i] = nodeHash(lv[2*i], lv[2*i+1])
		}
		t.levels = append(t.levels, next)
		lv = next
	}
	t.meta.Root = t.levels[len(t.levels)-1][0]
	return t, nil
}

// Meta is the file's description, root included.
func (t *Tree) Meta() Meta { return t.meta }

// Proof is piece i's path to the root.
func (t *Tree) Proof(i int) [][32]byte {
	out := make([][32]byte, 0, len(t.levels)-1)
	for lv := 0; lv < len(t.levels)-1; lv++ {
		out = append(out, t.levels[lv][i^1])
		i >>= 1
	}
	return out
}

// Verify checks that data is piece i of the file m names.
func Verify(m Meta, i int, data []byte, proof [][32]byte) error {
	if i < 0 || i >= m.Pieces() || len(data) != m.PieceLen(i) || len(proof) != m.depth() {
		return ErrBadProof
	}
	h := leafHash(i, data)
	for _, sib := range proof {
		if i&1 == 0 {
			h = nodeHash(h, sib)
		} else {
			h = nodeHash(sib, h)
		}
		i >>= 1
	}
	if h != m.Root {
		return ErrBadProof
	}
	return nil
}
