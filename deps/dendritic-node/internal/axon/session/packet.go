package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/circuit"
)

// The session packet: one per SESSION relay cell, always exactly PacketSize.
//
//	 0  1  version         = 1
//	 1  2  gen   (LE)      root generation; +1 at every case-B ratchet
//	 3  2  epoch (LE)      symmetric rekey count within the generation
//	 5  8  pn    (LE)      packet number: the AEAD nonce, never reused
//	13  …  ChaCha20-Poly1305(K_dir(gen, epoch), nonce = LE64(pn) ‖ 0⁴,
//	                         AAD = bytes 0..13, plaintext) ‖ tag(16)
//
// plaintext, always PlainSize bytes:
//
//	 0  8  ack    highest contiguous reliable seq received from the peer
//	 8  8  seq    reliable sequence number; 0 = not reliable (ACK, PING)
//	16  1  type
//	17  4  stream
//	21  2  len
//	23  …  data (len bytes), then zero fill
//
// WHY A PACKET NUMBER SEPARATE FROM THE SEQUENCE NUMBER. §9.8 gives the session
// seq_f/seq_b and nothing else. A frame that is retransmitted after a carrier
// dies carries a NEWER ack than it did the first time, so if seq were the nonce
// the retransmission would be a second plaintext under the same key and nonce
// -- the one mistake ChaCha20-Poly1305 does not survive. Every transmission
// therefore gets a fresh pn; seq is what reliability is about and lives inside
// the AEAD where the rendezvous point cannot read it.
//
// WHY THE PACKET IS ALWAYS FULL. The relay cell is fixed-size on the wire
// either way, but RLEN is readable by whoever terminates the circuit, and the
// rendezvous point terminates two. A packet sized to its payload would tell the
// RP every write size; a full one tells it only that a cell went by, which it
// knew. The zero fill is inside the AEAD, so it is not a channel either.

const (
	packetVersion = 1
	headerSize    = 13
	tagSize       = chacha20poly1305.Overhead

	// PacketSize fills the relay cell's data region exactly.
	PacketSize = circuit.RelayDataSize
	// PlainSize is what is left inside the AEAD.
	PlainSize = PacketSize - headerSize - tagSize

	frameHeaderSize = 23
	// MaxData is the most stream data one packet carries.
	MaxData = PlainSize - frameHeaderSize
)

// Frame types.
type frameType uint8

const (
	ftAck    frameType = 0x00 // nothing but the ack field (unreliable)
	ftPing   frameType = 0x01 // "I attached a new carrier": ACK now, resend what is unacked
	ftOpen   frameType = 0x10 // open a stream; data = the caller's open metadata
	ftData   frameType = 0x11
	ftFin    frameType = 0x12 // the sender will write no more on this stream
	ftReset  frameType = 0x13 // abort the stream; data = code (u16)
	ftWindow frameType = 0x14 // data = new absolute receive limit (u64)
	ftClose  frameType = 0x20 // SESSION_CLOSE; data = reason (u8) ‖ retry_after (u32, s)
)

func (t frameType) reliable() bool { return t >= ftOpen }

func (t frameType) valid() bool {
	switch t {
	case ftAck, ftPing, ftOpen, ftData, ftFin, ftReset, ftWindow, ftClose:
		return true
	}
	return false
}

// frame is one decoded plaintext.
type frame struct {
	ack    uint64
	seq    uint64
	typ    frameType
	stream uint32
	data   []byte
}

var (
	ErrPacketSize    = errors.New("axon/session: packet is not PacketSize")
	ErrPacketVersion = errors.New("axon/session: unknown packet version")
	ErrAuth          = errors.New("axon/session: packet failed session authentication (CARRIER_HOSTILE)")
	ErrReplay        = errors.New("axon/session: packet number already seen")
	ErrStaleKey      = errors.New("axon/session: packet sealed under a retired key")
	ErrFrame         = errors.New("axon/session: malformed frame")
)

// header is the cleartext prefix of a packet.
type header struct {
	gen   uint16
	epoch uint16
	pn    uint64
}

func parseHeader(p []byte) (header, error) {
	if len(p) != PacketSize {
		return header{}, fmt.Errorf("%w: %d", ErrPacketSize, len(p))
	}
	if p[0] != packetVersion {
		return header{}, fmt.Errorf("%w: %d", ErrPacketVersion, p[0])
	}
	return header{
		gen:   binary.LittleEndian.Uint16(p[1:3]),
		epoch: binary.LittleEndian.Uint16(p[3:5]),
		pn:    binary.LittleEndian.Uint64(p[5:13]),
	}, nil
}

func nonceFor(pn uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(n, pn)
	return n
}

// seal encrypts one frame into a full packet.
func seal(aead cipher.AEAD, h header, f *frame) ([]byte, error) {
	if len(f.data) > MaxData {
		return nil, fmt.Errorf("%w: %d bytes of data", ErrFrame, len(f.data))
	}
	plain := make([]byte, PlainSize)
	binary.LittleEndian.PutUint64(plain[0:8], f.ack)
	binary.LittleEndian.PutUint64(plain[8:16], f.seq)
	plain[16] = byte(f.typ)
	binary.LittleEndian.PutUint32(plain[17:21], f.stream)
	binary.LittleEndian.PutUint16(plain[21:23], uint16(len(f.data)))
	copy(plain[frameHeaderSize:], f.data)

	out := make([]byte, headerSize, PacketSize)
	out[0] = packetVersion
	binary.LittleEndian.PutUint16(out[1:3], h.gen)
	binary.LittleEndian.PutUint16(out[3:5], h.epoch)
	binary.LittleEndian.PutUint64(out[5:13], h.pn)
	out = aead.Seal(out, nonceFor(h.pn), plain, out[:headerSize])
	wipe(plain)
	return out, nil
}

// open authenticates and decodes a packet whose header has been parsed.
func open(aead cipher.AEAD, h header, p []byte) (*frame, error) {
	plain, err := aead.Open(nil, nonceFor(h.pn), p[headerSize:], p[:headerSize])
	if err != nil {
		return nil, ErrAuth
	}
	f := &frame{
		ack:    binary.LittleEndian.Uint64(plain[0:8]),
		seq:    binary.LittleEndian.Uint64(plain[8:16]),
		typ:    frameType(plain[16]),
		stream: binary.LittleEndian.Uint32(plain[17:21]),
	}
	n := int(binary.LittleEndian.Uint16(plain[21:23]))
	// Authenticated, so these are the PEER's mistakes, not an injector's; they
	// are still refused rather than interpreted generously.
	if n > MaxData || !f.typ.valid() || f.typ.reliable() != (f.seq != 0) {
		return nil, ErrFrame
	}
	f.data = append([]byte(nil), plain[frameHeaderSize:frameHeaderSize+n]...)
	return f, nil
}

func newAEAD(k [32]byte) cipher.AEAD {
	a, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(err) // only fails on a wrong key length, which [32]byte rules out
	}
	return a
}

// replayWindow refuses a packet number seen before.
//
// Cells on one carrier arrive in order, but a migration can deliver a late
// packet from the old carrier after the first from the new one, so a strict
// "greater than the last" rule would drop honest traffic. A 1024-wide window
// behind the highest number seen admits that and nothing older.
type replayWindow struct {
	top  uint64 // highest pn accepted; 0 = none yet (pn starts at 1)
	bits [16]uint64
}

const replayWidth = 1024

func (w *replayWindow) check(pn uint64) error {
	if pn == 0 {
		return ErrReplay
	}
	if pn > w.top {
		return nil
	}
	d := w.top - pn
	if d >= replayWidth {
		return ErrReplay
	}
	if w.bits[d/64]&(1<<(d%64)) != 0 {
		return ErrReplay
	}
	return nil
}

// mark records pn as seen. Call only after authentication succeeds, so an
// injector cannot burn the numbers an honest peer is about to use.
func (w *replayWindow) mark(pn uint64) {
	if pn > w.top {
		shift := pn - w.top
		if shift >= replayWidth {
			w.bits = [16]uint64{}
		} else {
			w.shift(shift)
		}
		w.top = pn
		w.bits[0] |= 1
		return
	}
	d := w.top - pn
	w.bits[d/64] |= 1 << (d % 64)
}

// shift moves the window by n bit positions (bit d means "top-d was seen").
func (w *replayWindow) shift(n uint64) {
	words, bits := n/64, n%64
	var out [16]uint64
	for i := 15; i >= 0; i-- {
		src := i - int(words)
		if src < 0 {
			continue
		}
		v := w.bits[src] << bits
		if bits != 0 && src-1 >= 0 {
			v |= w.bits[src-1] >> (64 - bits)
		}
		out[i] = v
	}
	w.bits = out
}
