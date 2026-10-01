package swarm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The peer protocol: one stream per peer pair, each message
//
//	len u32 (BE, type + body) ‖ type u8 ‖ body
//
//	HELLO          root(32) ‖ bitfield            first message, both directions
//	HAVE           index u32                      a piece just verified
//	INTERESTED     -                              you have something I lack
//	NOT_INTERESTED -
//	CHOKE          -                              I will not serve you now
//	UNCHOKE        -
//	REQUEST        index u32
//	PIECE          index u32 ‖ n u8 ‖ proof(32n) ‖ data
//	REJECT         index u32                      choked, or I do not have it
//	CANCEL         index u32                      someone else delivered it
//
// Whole pieces are requested, not blocks: the carrier is a session stream with
// its own flow control and reordering, so the sub-piece blocks BitTorrent uses
// to pipeline over raw TCP would add bookkeeping and buy nothing. Every length is
// bounded before it is used -- a peer is somebody else's code.

type msgType uint8

const (
	msgHello msgType = iota + 1
	msgHave
	msgInterested
	msgNotInterested
	msgChoke
	msgUnchoke
	msgRequest
	msgPiece
	msgReject
	msgCancel
)

var ErrWire = errors.New("axon/swarm: malformed peer message")

type message struct {
	typ   msgType
	index int
	root  [32]byte
	bits  []byte
	proof [][32]byte
	data  []byte
}

func maxFrame(m Meta) int { return 1 + 32 + (m.Pieces()+7)/8 + 4 + 1 + 32*64 + m.PieceSize + 16 }

func encode(m *message) []byte {
	var body []byte
	switch m.typ {
	case msgHello:
		body = append(append(body, m.root[:]...), m.bits...)
	case msgHave, msgRequest, msgReject, msgCancel:
		body = binary.BigEndian.AppendUint32(body, uint32(m.index))
	case msgPiece:
		body = binary.BigEndian.AppendUint32(body, uint32(m.index))
		body = append(body, byte(len(m.proof)))
		for _, p := range m.proof {
			body = append(body, p[:]...)
		}
		body = append(body, m.data...)
	}
	out := make([]byte, 5, 5+len(body))
	binary.BigEndian.PutUint32(out, uint32(1+len(body)))
	out[4] = byte(m.typ)
	return append(out, body...)
}

// readMessage reads one message, refusing anything longer than limit.
func readMessage(r io.Reader, limit int) (*message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 1 || n > limit {
		return nil, fmt.Errorf("%w: frame of %d bytes", ErrWire, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	m := &message{typ: msgType(buf[0])}
	body := buf[1:]
	idx := func() error {
		if len(body) < 4 {
			return ErrWire
		}
		m.index = int(binary.BigEndian.Uint32(body))
		return nil
	}
	switch m.typ {
	case msgHello:
		if len(body) < 32 {
			return nil, ErrWire
		}
		copy(m.root[:], body)
		m.bits = body[32:]
	case msgHave, msgRequest, msgReject, msgCancel:
		if err := idx(); err != nil || len(body) != 4 {
			return nil, ErrWire
		}
	case msgInterested, msgNotInterested, msgChoke, msgUnchoke:
		if len(body) != 0 {
			return nil, ErrWire
		}
	case msgPiece:
		if err := idx(); err != nil || len(body) < 5 {
			return nil, ErrWire
		}
		np := int(body[4])
		if len(body) < 5+32*np {
			return nil, ErrWire
		}
		for k := 0; k < np; k++ {
			var h [32]byte
			copy(h[:], body[5+32*k:])
			m.proof = append(m.proof, h)
		}
		m.data = body[5+32*np:]
	default:
		return nil, fmt.Errorf("%w: type %d", ErrWire, m.typ)
	}
	return m, nil
}

// bitfield helpers: bit i of byte i/8, most significant first.
type bitfield []byte

func newBitfield(n int) bitfield  { return make(bitfield, (n+7)/8) }
func (b bitfield) has(i int) bool { return b[i/8]&(0x80>>(i%8)) != 0 }
func (b bitfield) set(i int)      { b[i/8] |= 0x80 >> (i % 8) }
