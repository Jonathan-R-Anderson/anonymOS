package circuit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// P5a: the wide-block construction that replaces the withdrawn tag stack.
//
// WHY THIS AND NOT THE OTHER TWO CANDIDATES. §81.1 admitted two options and the
// analysis collapsed them into one:
//
//	nested AEAD (the obvious third option) -- layer i's AEAD covers layer i+1's
//	  ciphertext AND its tag, which closes the channel, but an AEAD expands by 16
//	  bytes per layer. So the ciphertext length differs per layer: hop 1 opens
//	  over 992 bytes, hop 2 over 976, hop 3 over 960, and EACH HOP MUST KNOW ITS
//	  OWN INDEX to know how many bytes to open. That is a position leak at every
//	  hop -- worse than the defect being repaired.
//
//	Sphinx -- its precomputed filler solves the HEADER. Its payload is handled by
//	  a wide-block permutation (LIONESS) precisely because nothing else gives
//	  non-malleability at zero expansion. Sphinx does not avoid this primitive; it
//	  contains it.
//
// So: zero expansion, per-hop non-malleability, and no external mutable field are
// jointly satisfiable ONLY by a wide-block pseudorandom permutation. §8.3's own
// alternatives table called this "the right long-term answer" and deferred it to
// v2. PAR-01 makes it v1, because the construction it was deferred in favour of
// does not work.
//
// THE CONSTRUCTION. LIONESS (Anderson & Biham, 1996): an unbalanced four-round
// Feistel network over an arbitrary-length block, built from a stream cipher and
// a keyed hash. Four rounds of Feistel with independent pseudorandom round
// functions give a STRONG pseudorandom permutation -- secure against
// chosen-ciphertext attack -- by the Luby-Rackoff result. That is the security
// argument E5a.2 requires, and it is a citation rather than an assertion.
//
// WHAT THIS BUYS
//   - No tags, therefore no mutable unauthenticated field, therefore no
//     cross-hop channel. PAR-01 closed by construction rather than by policy.
//   - Every hop performs the IDENTICAL operation over the IDENTICAL 1008 bytes,
//     so the format carries no evidence of circuit length or hop position --
//     strictly better than the rotating stack it replaces, which only hid the
//     slot index.
//   - Zero expansion, so the relay payload grows from 944 to 1008 bytes.
//
// WHAT THIS COSTS, stated plainly because it retracts two claims §8.3 and §8.9
// make:
//   - A PRP has no authenticator. An intermediate hop can no longer DETECT that
//     a cell was corrupted upstream; it forwards randomised bytes and the
//     terminal's end-to-end check catches it. §8.3's "hop i+1 finds out
//     immediately and tears the circuit down" no longer holds.
//   - Corruption is no longer LOCALISED. §8.9's property that the client learns
//     the deepest layer at which the chain broke is lost, because there are no
//     per-layer checks to fail. The client learns that something broke.
//
// Both losses are real and are the price of closing the channel. The trade is
// worth taking because a tagging channel is a confirmation oracle between
// colluding relays, while per-hop corruption detection is a diagnostic: the
// first breaks anonymity, the second improves attribution. When they conflict,
// anonymity wins.

// BlockSize is the whole cell body: everything after the 16-byte header.
//
// There is no tag region any more, so the relay payload is the entire body.
const BlockSize = params.CellSize - params.CellHeaderSize

// lSize is the Feistel network's short branch. It is exactly a ChaCha20 key,
// because the short branch is used AS the stream-cipher key in rounds 1 and 3.
const lSize = chacha20.KeySize

// rSize is the long branch.
const rSize = BlockSize - lSize

// Round-key labels. Each round function must be keyed independently, or the
// Luby-Rackoff argument does not apply -- four rounds of the SAME function is
// not four independent rounds.
const wideBlockLabel = "AXON-wideblock-lioness-v1"

var (
	ErrBlockSize    = errors.New("axon/circuit: block is not the fixed cell-body size")
	ErrIntegrity    = errors.New("axon/circuit: end-to-end authenticator does not verify")
	ErrTooManyHops  = errors.New("axon/circuit: more hops than MaxHops permits")
	ErrCounterLimit = errors.New("axon/circuit: per-direction cell counter reached its limit")
)

// MaxHops bounds path length. It no longer sizes a tag stack -- there is none --
// but it still bounds how many layers a client may apply, and P22 draws its
// variable path length from [PathLengthMin, MaxHops].
const MaxHops = params.MaxHops

// MaxCellsPerDirection is the hard tweak limit: 2^32 cells per direction per hop
// (about 4 TB). The counter is the permutation's tweak as well as its nonce, so
// exhausting it would repeat a permutation. The 10-minute circuit lifetime makes
// it unreachable; the check exists so a bug cannot make it reachable.
const MaxCellsPerDirection = uint64(1) << 32

// WideBlock is one hop's permutation state for one direction.
type WideBlock struct {
	k1, k2, k3, k4 [32]byte
}

// NewWideBlock derives the four independent round keys from a hop's directional
// key.
func NewWideBlock(key [32]byte) (*WideBlock, error) {
	r := hkdf.New(sha256.New, key[:], nil, []byte(wideBlockLabel))
	var w WideBlock
	for _, k := range []*[32]byte{&w.k1, &w.k2, &w.k3, &w.k4} {
		if _, err := io.ReadFull(r, k[:]); err != nil {
			return nil, fmt.Errorf("axon/circuit: round key: %w", err)
		}
	}
	return &w, nil
}

// nonceFor builds the 12-byte ChaCha20 nonce from the tweak.
//
// THE TWEAK IS NOT OPTIONAL. Without it the permutation is fixed for the life of
// the circuit, so identical plaintexts produce identical ciphertexts and a relay
// can recognise a repeated cell -- which is a correlation channel of exactly the
// kind this file exists to remove. The tweak is the per-direction cell counter,
// the same value that made the old nonce discipline work.
func nonceFor(tweak uint64, round byte) [chacha20.NonceSize]byte {
	var n [chacha20.NonceSize]byte
	binary.BigEndian.PutUint64(n[0:8], tweak)
	n[8] = round
	return n
}

// stream XORs len(dst) bytes of ChaCha20 keystream into dst, keyed by key.
func stream(key []byte, tweak uint64, round byte, dst []byte) error {
	if len(key) != chacha20.KeySize {
		return fmt.Errorf("axon/circuit: stream key is %d bytes", len(key))
	}
	n := nonceFor(tweak, round)
	c, err := chacha20.NewUnauthenticatedCipher(key, n[:])
	if err != nil {
		return fmt.Errorf("axon/circuit: stream cipher: %w", err)
	}
	c.XORKeyStream(dst, dst)
	return nil
}

// mac is the keyed hash used as the Feistel round function on the short branch.
func mac(key [32]byte, tweak uint64, round byte, msg []byte) [lSize]byte {
	h := hmac.New(sha256.New, key[:])
	var t [9]byte
	binary.BigEndian.PutUint64(t[0:8], tweak)
	t[8] = round
	h.Write(t[:])
	h.Write(msg)
	var out [lSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

func xorInto(dst []byte, src [lSize]byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}

// xorKey returns L XOR k, the derived stream key for rounds 1 and 3.
func xorKey(l []byte, k [32]byte) []byte {
	out := make([]byte, lSize)
	for i := range out {
		out[i] = l[i] ^ k[i]
	}
	return out
}

// Encipher applies the permutation in place.
//
//	R ^= S(L ^ k1)
//	L ^= H(k2, R)
//	R ^= S(L ^ k3)
//	L ^= H(k4, R)
func (w *WideBlock) Encipher(block []byte, tweak uint64) error {
	if len(block) != BlockSize {
		return fmt.Errorf("%w: %d != %d", ErrBlockSize, len(block), BlockSize)
	}
	L, R := block[:lSize], block[lSize:]

	if err := stream(xorKey(L, w.k1), tweak, 1, R); err != nil {
		return err
	}
	xorInto(L, mac(w.k2, tweak, 2, R))
	if err := stream(xorKey(L, w.k3), tweak, 3, R); err != nil {
		return err
	}
	xorInto(L, mac(w.k4, tweak, 4, R))
	return nil
}

// Decipher inverts Encipher in place, running the same rounds backwards.
func (w *WideBlock) Decipher(block []byte, tweak uint64) error {
	if len(block) != BlockSize {
		return fmt.Errorf("%w: %d != %d", ErrBlockSize, len(block), BlockSize)
	}
	L, R := block[:lSize], block[lSize:]

	xorInto(L, mac(w.k4, tweak, 4, R))
	if err := stream(xorKey(L, w.k3), tweak, 3, R); err != nil {
		return err
	}
	xorInto(L, mac(w.k2, tweak, 2, R))
	if err := stream(xorKey(L, w.k1), tweak, 1, R); err != nil {
		return err
	}
	return nil
}

// -----------------------------------------------------------------------------
// Per-hop layer state
// -----------------------------------------------------------------------------

// HopWide is a hop's forward and backward permutations plus its counters.
//
// The counter rules from §8.3 survive unchanged and matter more here, because
// the counter is now the permutation's tweak as well as its nonce: one counter
// per (circuit, hop, direction), never reset, never rewound, incremented only
// after a successful operation.
type HopWide struct {
	fwd, bwd   *WideBlock
	ctrF, ctrB uint64
}

// NewHopWide builds the permutation pair from a completed handshake.
func NewHopWide(ks KeySet) (*HopWide, error) {
	f, err := NewWideBlock(ks.Kf)
	if err != nil {
		return nil, err
	}
	b, err := NewWideBlock(ks.Kb)
	if err != nil {
		return nil, err
	}
	return &HopWide{fwd: f, bwd: b}, nil
}

// Counters reports the forward and backward counters.
func (h *HopWide) Counters() (fwd, bwd uint64) { return h.ctrF, h.ctrB }

// WrapForward applies one forward layer.
func (h *HopWide) WrapForward(block []byte) error {
	if h.ctrF >= MaxCellsPerDirection {
		return ErrCounterLimit
	}
	if err := h.fwd.Encipher(block, h.ctrF); err != nil {
		return err
	}
	h.ctrF++
	return nil
}

// UnwrapForward peels one forward layer.
func (h *HopWide) UnwrapForward(block []byte) error {
	if h.ctrF >= MaxCellsPerDirection {
		return ErrCounterLimit
	}
	if err := h.fwd.Decipher(block, h.ctrF); err != nil {
		return err
	}
	h.ctrF++
	return nil
}

// WrapBackward applies one backward layer.
func (h *HopWide) WrapBackward(block []byte) error {
	if h.ctrB >= MaxCellsPerDirection {
		return ErrCounterLimit
	}
	if err := h.bwd.Encipher(block, h.ctrB); err != nil {
		return err
	}
	h.ctrB++
	return nil
}

// UnwrapBackward peels one backward layer.
func (h *HopWide) UnwrapBackward(block []byte) error {
	if h.ctrB >= MaxCellsPerDirection {
		return ErrCounterLimit
	}
	if err := h.bwd.Decipher(block, h.ctrB); err != nil {
		return err
	}
	h.ctrB++
	return nil
}

// -----------------------------------------------------------------------------
// End-to-end authentication
// -----------------------------------------------------------------------------

// AuthTagSize is the end-to-end authenticator carried INSIDE the innermost
// plaintext.
//
// It sits inside because a tag outside the permutation would be a mutable
// unauthenticated field -- the exact defect being repaired. Inside, any
// modification by any hop randomises the whole block and the check fails.
const AuthTagSize = 16

// InnerSize is the innermost plaintext region: everything the end-to-end
// authenticator covers.
//
// The relay header (§8.6) lives at the front of it and owns the length field.
// There is deliberately NO second length prefix here: two length authorities
// that can disagree is a parsing bug waiting to be found by somebody hostile,
// and the relay header's RLEN is the one the receiver must honour anyway.
const InnerSize = BlockSize - AuthTagSize

// SealInnermost places the inner region and its end-to-end authenticator into a
// full block.
//
// The authenticator is keyed under the terminal's Af -- the control-plane key
// the handshake already derives -- and lives INSIDE the permutation. A tag
// outside would be a mutable unauthenticated field, which is the defect PAR-01
// found. Inside, any modification by any hop randomises the whole block and this
// check fails.
func SealInnermost(af [32]byte, inner []byte) ([]byte, error) {
	if len(inner) != InnerSize {
		return nil, fmt.Errorf("axon/circuit: inner region is %d bytes, want %d",
			len(inner), InnerSize)
	}
	block := make([]byte, BlockSize)
	copy(block, inner)
	t := mac(af, 0, 0, block[:InnerSize])
	copy(block[InnerSize:], t[:AuthTagSize])
	return block, nil
}

// OpenInnermost verifies the end-to-end authenticator and returns the inner
// region.
func OpenInnermost(af [32]byte, block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, ErrBlockSize
	}
	want := mac(af, 0, 0, block[:InnerSize])
	if !hmac.Equal(want[:AuthTagSize], block[InnerSize:]) {
		return nil, ErrIntegrity
	}
	return block[:InnerSize], nil
}

// -----------------------------------------------------------------------------
// Path operations
// -----------------------------------------------------------------------------

// WideSealForward applies every hop's layer, innermost first.
//
// Compare SealForward, which it replaces: there is no tag stack to fill, no
// filler to generate, and no random source needed at all. The absence of the
// random source is the point -- randomness a hop chooses was the channel.
func WideSealForward(hops []*HopWide, block []byte) error {
	if len(hops) == 0 || len(hops) > MaxHops {
		return fmt.Errorf("%w: %d hops", ErrTooManyHops, len(hops))
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if err := hops[i].WrapForward(block); err != nil {
			return err
		}
	}
	return nil
}

// WideOpenForwardAtHop peels this hop's layer.
//
// Every hop calls exactly this, over exactly BlockSize bytes, with no index and
// no knowledge of the path. That uniformity is the position-hiding property, and
// it is now structural rather than defended by a rotation.
func WideOpenForwardAtHop(h *HopWide, block []byte) error { return h.UnwrapForward(block) }

// WideSealBackwardAtHop wraps a cell travelling toward the client.
func WideSealBackwardAtHop(h *HopWide, block []byte) error { return h.WrapBackward(block) }

// WideOpenBackwardAtClient peels layers 1..H.
//
// It returns no "broke at" index, unlike OpenBackwardAtClient. §8.9's
// localisation property does not survive the move to a PRP: there are no
// per-layer checks to fail, so the client learns that the chain broke and not
// where. That is a real regression and it is recorded here rather than in a
// changelog nobody reads.
func WideOpenBackwardAtClient(hops []*HopWide, block []byte) error {
	for i := range hops {
		if err := hops[i].UnwrapBackward(block); err != nil {
			return err
		}
	}
	return nil
}
