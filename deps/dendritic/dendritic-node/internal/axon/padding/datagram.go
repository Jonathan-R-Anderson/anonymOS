package padding

import (
	"errors"
	"fmt"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// M2 — fixed datagrams. §16.3: "pad every overlay QUIC packet to 1200 B".
//
// WHY THE CELL IS NOT ENOUGH. M1 makes every CELL 1024 B, so no single message's
// length is visible. It does not make every PACKET a constant, and a packet
// carrying a partly-filled cell boundary is a shorter packet. §16.8's first row
// is explicit that the datagram padding exists "so the cell boundary is not
// visible in packet lengths" — the two mechanisms defend different layers and
// neither substitutes for the other.
//
// WHAT IS NOT DONE, AND WHY IT CANNOT BE DONE HERE.
//
// The link currently runs cells over libp2p STREAMS over QUIC. On that path the
// packetiser belongs to quic-go: it coalesces and splits stream data according
// to its own MTU discovery, and nothing at this layer can make a packet a
// constant length. So **M2 is not in force on the deployed transport**, and a
// link capture of it still shows quic-go's packet-length distribution.
//
// The framing below is M2's actual mechanism and is exercised by its own tests,
// but it takes effect only when the link is moved to QUIC datagram mode, where
// one datagram is one write. That move is P11's transport work and has not
// happened. Stating this is the point: §56.2's failure mode is a defence that
// reports success while measuring nothing, and a padding package that quietly
// did nothing on the real transport would be exactly that.

var (
	// ErrDatagramTooLarge means the payload cannot fit a fixed datagram.
	ErrDatagramTooLarge = errors.New("axon/padding: payload exceeds the fixed datagram")
	// ErrDatagramSize means a received datagram was not the constant size. It
	// is an error rather than a tolerated variation: accepting a short datagram
	// would let a peer choose its own packet lengths, which is the leak.
	ErrDatagramSize = errors.New("axon/padding: datagram is not the fixed size")
	// ErrDatagramPadding means the padding bytes were not zero.
	ErrDatagramPadding = errors.New("axon/padding: datagram padding is not zero")
)

// DatagramHeaderSize is the 2-byte payload length prefix.
const DatagramHeaderSize = 2

// MaxDatagramPayload is what one fixed datagram can carry.
const MaxDatagramPayload = params.DatagramSize - DatagramHeaderSize

// PackDatagram renders a payload as one constant-size datagram.
//
// The buffer is allocated fresh every call rather than reused. A reused buffer
// carries the previous datagram's bytes in the region this one does not fill,
// and that is a disclosure bug no test of the payload would ever catch — the
// same reasoning as link.WriteCell's.
func PackDatagram(payload []byte) ([]byte, error) {
	if len(payload) > MaxDatagramPayload {
		return nil, fmt.Errorf("%w: %d > %d", ErrDatagramTooLarge, len(payload), MaxDatagramPayload)
	}
	out := make([]byte, params.DatagramSize)
	out[0] = byte(len(payload) >> 8)
	out[1] = byte(len(payload))
	copy(out[DatagramHeaderSize:], payload)
	return out, nil
}

// UnpackDatagram recovers the payload, refusing anything that is not exactly
// one well-formed fixed datagram.
func UnpackDatagram(d []byte) ([]byte, error) {
	if len(d) != params.DatagramSize {
		return nil, fmt.Errorf("%w: %d != %d", ErrDatagramSize, len(d), params.DatagramSize)
	}
	n := int(d[0])<<8 | int(d[1])
	if n > MaxDatagramPayload {
		return nil, fmt.Errorf("%w: declared %d", ErrDatagramTooLarge, n)
	}
	// The padding must be zero for the same reason the cell's must be: any
	// non-zero region an implementation is free to fill is free capacity, and
	// free capacity in a fixed-size frame is a covert channel with the exact
	// bandwidth of the padding.
	for i := DatagramHeaderSize + n; i < len(d); i++ {
		if d[i] != 0 {
			return nil, fmt.Errorf("%w: offset %d", ErrDatagramPadding, i)
		}
	}
	out := make([]byte, n)
	copy(out, d[DatagramHeaderSize:DatagramHeaderSize+n])
	return out, nil
}
