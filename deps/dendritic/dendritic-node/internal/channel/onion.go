package channel

// The three-hop onion.
//
// THE CONSTRUCTION, AND WHY IT IS NOT SPHINX
// ------------------------------------------
// Sphinx keeps a packet constant-size by having each hop peel a layer and
// append deterministic filler, so the packet never shrinks as it travels. It is
// the right long-term answer and it is fiddly: the filler has to be computable
// at build time for the MACs to close, and a subtle error there is a hole
// nobody notices because the packet still routes.
//
// This is a FIXED-SLOT construction instead. The packet always carries
// MaxHops slots of identical size; a hop finds its own by trying to
// authenticate each in turn, and forwards the packet unchanged in size.
//
// What that buys: constant size is structural rather than something the filler
// logic has to maintain, and there is no build-time/forward-time asymmetry to
// get wrong. What it costs: the packet is always MaxHops slots even for a
// shorter route, so it is larger than Sphinx. For three hops that is a few
// kilobytes and worth paying for a construction that can be reasoned about.
//
// WHY SLOT ORDER IS SHUFFLED
// --------------------------
// If hop i always occupied slot i, a router would learn its position from the
// index that decrypted — and position is one of the first things the onion
// exists to hide, because knowing you are the entry means knowing your
// predecessor is the payer. So slot assignment is permuted per payment from the
// ephemeral key, and every hop scans all slots. A hop learns only that one slot
// was for it.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// MaxHops is the route length this packet format carries. Three by default:
// two gives the middle no cover, and more multiplies I2P latency for a gain
// dwarfed by the operator-diversity problem.
const MaxHops = 3

// SlotSize is the fixed size of every encrypted slot, before the AEAD overhead.
// Every hop instruction is padded to exactly this, so a slot's length says
// nothing about what it holds.
//
// 1 KiB rather than 512 B because encoding/json renders a [32]byte as a decimal
// ARRAY — `[161,42,...]`, up to ~160 characters for 32 bytes. Three commitment
// fields plus a hex endpoint clear 512 comfortably. The honest fix is a compact
// encoding rather than a bigger slot, but the size must be right first: a slot
// too small is a payment that cannot be built at all, which is how this was
// found.
const SlotSize = 1024

// Onion key domains, separate from the note domains so a key recovered in one
// role cannot be used in the other.
const (
	domainHopKey     = "syndichan/onion/hopkey/v1"
	domainReplay     = "syndichan/onion/replay/v1"
	domainPermute    = "syndichan/onion/permute/v1"
	domainFailureKey = "syndichan/onion/failure/v1"
)

var (
	ErrNotForUs       = errors.New("channel: no onion slot authenticates with this key")
	ErrTooManyHops    = errors.New("channel: route longer than the packet format allows")
	ErrHopTooLarge    = errors.New("channel: hop instruction does not fit its slot")
	ErrExpiryOrdering = errors.New("channel: hop expiries are not strictly decreasing")
	ErrBadPacket      = errors.New("channel: malformed onion packet")
)

// HopInstruction is what one router learns. Nothing else.
type HopInstruction struct {
	// NextHop is the following router, or empty at the exit — where the blinded
	// recipient path takes over.
	NextHop NodeID `json:"next_hop,omitempty"`
	// BlindedEndpoint is set only for the exit hop.
	BlindedEndpoint string `json:"blinded_endpoint,omitempty"`

	OutgoingCommitment Commitment `json:"outgoing_commitment"`
	FeeCommitment      Commitment `json:"fee_commitment"`
	// OutgoingExpiry must be strictly less than the incoming one, by a bounded
	// amount — unbounded deltas let a router infer its distance from an end.
	OutgoingExpiry uint64 `json:"outgoing_expiry"`
	// ReplayGuard is per-hop and per-payment. NOT a route identifier: one value
	// shared across hops would be a correlation handle by construction.
	ReplayGuard [32]byte `json:"replay_guard"`
}

// Packet is what travels. Fixed size for a given MaxHops.
type Packet struct {
	// EphemeralPublicKey is fresh per payment. Reusing one links every payment
	// sent under it, which would undo the whole construction in a single field.
	EphemeralPublicKey [32]byte
	// Slots are all identical in size and indistinguishable to anyone without
	// the matching key.
	Slots [][]byte
	// PaymentCommitment and ProofReference are visible to every hop, which is
	// why neither may carry anything identifying.
	PaymentCommitment Commitment
	ProofReference    [32]byte
	Expiry            uint64
}

// hopKey derives the AEAD key for one hop from its shared secret.
func hopKey(shared [32]byte) [32]byte { return derive(domainHopKey, shared[:]) }

// replayGuardFor derives a per-hop, per-payment guard.
func replayGuardFor(shared [32]byte, ephemeral [32]byte) [32]byte {
	return derive(domainReplay, shared[:], ephemeral[:])
}

// permutation assigns hops to slots, deterministically from the ephemeral key.
//
// Fisher-Yates driven by a hash stream, so the mapping is reproducible by the
// builder and unpredictable to anyone without the ephemeral key. A fixed
// mapping would tell every router its position for free.
func permutation(ephemeral [32]byte, n int) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	stream := derive(domainPermute, ephemeral[:])
	for i := n - 1; i > 0; i-- {
		// Re-derive as needed so the stream never runs short.
		if i%8 == 0 {
			stream = derive(domainPermute, stream[:])
		}
		j := int(binary.BigEndian.Uint32(stream[(i%8)*4:])) % (i + 1)
		order[i], order[j] = order[j], order[i]
	}
	return order
}

func seal(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key [32]byte, sealed []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < gcm.NonceSize() {
		return nil, false
	}
	out, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil {
		return nil, false
	}
	return out, true
}

// padTo makes every slot's plaintext the same length, so a slot reveals nothing
// by its size.
func padTo(data []byte, size int) ([]byte, error) {
	if len(data)+4 > size {
		return nil, ErrHopTooLarge
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], data)
	return out, nil
}

func unpad(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, ErrBadPacket
	}
	n := binary.BigEndian.Uint32(padded[:4])
	if int(n) > len(padded)-4 {
		return nil, ErrBadPacket
	}
	return padded[4 : 4+n], nil
}

// Build assembles a packet for a route.
//
// sharedSecrets[i] is the secret this payer shares with hop i — derived by
// ECDH outside this file, so the curve choice stays out of the packet format
// exactly as the commitment scheme stays out of the note format.
func Build(ephemeral [32]byte, hops []HopInstruction, sharedSecrets [][32]byte) (*Packet, error) {
	if len(hops) > MaxHops || len(hops) != len(sharedSecrets) {
		return nil, ErrTooManyHops
	}
	if len(hops) == 0 {
		return nil, ErrBadPacket
	}
	// Expiries must strictly decrease along the route, so an upstream lock
	// always outlives the downstream one it depends on. Without this a stall
	// unwinds in the wrong order and a router can be left holding value it
	// cannot recover.
	for i := 1; i < len(hops); i++ {
		if hops[i].OutgoingExpiry >= hops[i-1].OutgoingExpiry {
			return nil, ErrExpiryOrdering
		}
	}

	packet := &Packet{
		EphemeralPublicKey: ephemeral,
		Slots:              make([][]byte, MaxHops),
	}
	order := permutation(ephemeral, MaxHops)

	for i, hop := range hops {
		hop.ReplayGuard = replayGuardFor(sharedSecrets[i], ephemeral)
		encoded, err := json.Marshal(hop)
		if err != nil {
			return nil, err
		}
		padded, err := padTo(encoded, SlotSize)
		if err != nil {
			return nil, err
		}
		sealedSlot, err := seal(hopKey(sharedSecrets[i]), padded)
		if err != nil {
			return nil, err
		}
		packet.Slots[order[i]] = sealedSlot
	}

	// Unused slots are filled with random bytes of the SAME length as a real
	// slot. A short route must be indistinguishable from a full one, or the
	// number of hops leaks — and on a three-hop default, knowing a route is
	// two hops tells a router almost everything.
	for i := range packet.Slots {
		if packet.Slots[i] != nil {
			continue
		}
		filler := make([]byte, len(packet.Slots[order[0]]))
		if _, err := io.ReadFull(rand.Reader, filler); err != nil {
			return nil, err
		}
		packet.Slots[i] = filler
	}
	return packet, nil
}

// Peel finds and decrypts this hop's instruction.
//
// Scans every slot rather than indexing one, so a router cannot learn its
// position from which slot was its own. The scan is cheap — three AEAD
// attempts — and the alternative leaks the thing the permutation exists to
// hide.
func (p *Packet) Peel(shared [32]byte) (HopInstruction, error) {
	if p == nil || len(p.Slots) == 0 {
		return HopInstruction{}, ErrBadPacket
	}
	key := hopKey(shared)
	for _, slot := range p.Slots {
		plaintext, ok := open(key, slot)
		if !ok {
			continue
		}
		encoded, err := unpad(plaintext)
		if err != nil {
			return HopInstruction{}, err
		}
		var hop HopInstruction
		if err := json.Unmarshal(encoded, &hop); err != nil {
			return HopInstruction{}, ErrBadPacket
		}
		// The guard must match what the builder derived, which ties this
		// instruction to this ephemeral key. A replayed packet under a new
		// ephemeral key fails here rather than being forwarded again.
		if hop.ReplayGuard != replayGuardFor(shared, p.EphemeralPublicKey) {
			return HopInstruction{}, ErrBadPacket
		}
		return hop, nil
	}
	return HopInstruction{}, ErrNotForUs
}

// Size is the packet's wire size, which must not depend on route length.
func (p *Packet) Size() int {
	if p == nil {
		return 0
	}
	total := len(p.EphemeralPublicKey) + len(p.PaymentCommitment) +
		len(p.ProofReference) + 8
	for _, s := range p.Slots {
		total += len(s)
	}
	return total
}

// SealFailure encrypts an error for the payer, to be re-encrypted at each hop
// on the way back.
//
// Encrypted rather than plain because an error message says where it came from,
// and "insufficient liquidity at hop 2" tells the payer — and anyone watching —
// something about a stranger's channel balance.
func SealFailure(shared [32]byte, reason string) ([]byte, error) {
	return seal(derive(domainFailureKey, shared[:]), []byte(reason))
}

// OpenFailure decrypts one layer of a failure message.
func OpenFailure(shared [32]byte, sealed []byte) (string, bool) {
	out, ok := open(derive(domainFailureKey, shared[:]), sealed)
	return string(out), ok
}
