// Package link is AXON's L1/L2: an authenticated link between two nodes, and
// the fixed-size cell framing that every layer above it speaks.
//
// Scope, from the roadmap's P2: this package knows about links, streams and
// cells. It does NOT know what a hop is, does not layer encryption, and does
// not schedule padding. A link that understands hops has the wrong abstraction
// -- P5 owns the key schedule, section 16/P13 owns padding schedules, and this
// package builds only the mechanism they use.
package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Wire layout of a cell (section 8.1). Every cell is exactly params.CellSize
// bytes on every link, regardless of payload length or how many hops remain:
//
//	offset  size  field
//	0       8     circuit id
//	8       1     command
//	9       1     flags
//	10      2     payload length (big endian)
//	12      4     reserved (must be zero)
//	16      …     payload, then zero padding to CellSize
//
// The constant size is the property, not a convenience. A cell whose length
// varied with its contents would leak message size to every relay on the path,
// and a cell whose size varied with hop count would leak path length -- which is
// why params.AEADTagSize is reserved for MaxHops positions whether or not those
// hops exist.
// Field offsets, from section 8.1's cell diagram.
//
//	 0  8  CIRCID       link-local; different on every link the circuit crosses
//	 8  1  CMD          link command, not onion-encrypted
//	 9  1  FLAGS
//	10  2  LENGTH       meaningful only for non-onioned cells
//	12  4  RESERVED     must be zero and must be checked
//	16 1008 BODY        one wide-block permuted block (P5a), or cleartext
//	                    handshake material for non-onioned commands
//
// THE TAG STACK IS GONE. Section 8.1 originally placed four 16-byte Poly1305
// slots at offset 16, rotated one slot per hop. PAR-01 found that construction
// to be a cross-hop tagging channel -- 16 unauthenticated hop-chosen bytes per
// cell, carried downstream unchanged -- and section 81.1 withdrew it. P5a
// replaced it with a wide-block permutation over the whole body, which has no
// tags, no filler and no mutable unauthenticated field of any kind.
//
// The 64 bytes are reclaimed: the body is 1008 bytes rather than 944.
const (
	offCircuitID = 0
	offCommand   = 8
	offFlags     = 9
	offLength    = 10
	offReserved  = 12
	offPayload   = params.CellHeaderSize
)

// MaxPayload is the usable payload once the header and a tag for every possible
// hop position are reserved. Derived from params, never written as a literal.
const MaxPayload = params.MaxPayload

// Command identifies what a cell carries. Values are explicit because they are
// wire format: renumbering them is a protocol break.
type Command uint8

const (
	CmdPadding    Command = 0x00 // carries nothing; link-local filler, never forwarded
	CmdCreate     Command = 0x01 // begin a circuit to this hop
	CmdCreated    Command = 0x02 // …accepted
	CmdRelay      Command = 0x03 // onion-layered relay message; EXTEND inside is refused
	CmdRelayBuild Command = 0x04 // as RELAY, but EXTEND/EXTENDED permitted; budget-limited
	CmdCreateFrag Command = 0x05 // continuation of an oversized CREATE (hybrid handshake)
	CmdDestroy    Command = 0x06 // tear the circuit down; never onioned, never forwarded verbatim
	CmdVersions   Command = 0x07 // link protocol version list; first cell, CIRCID = 0
	CmdNetInfo    Command = 0x08 // clock and observed-address exchange, CIRCID = 0
)

var commandNames = map[Command]string{
	CmdPadding: "PADDING", CmdCreate: "CREATE", CmdCreated: "CREATED",
	CmdRelay: "RELAY", CmdRelayBuild: "RELAY_BUILD", CmdCreateFrag: "CREATE_FRAG",
	CmdDestroy: "DESTROY", CmdVersions: "VERSIONS", CmdNetInfo: "NETINFO",
}

// Onioned reports whether the payload region is onion ciphertext.
//
// It decides two things a decoder cannot get right by guessing: whether LENGTH
// carries meaning (it does not for onioned cells -- the real length lives inside
// the onion where an observer cannot read it), and whether the tail after the
// declared payload can be checked for zeros. For ciphertext it cannot be, since
// every byte of the 944-byte region is meaningful to whoever holds the key.
func (c Command) Onioned() bool {
	return c == CmdRelay || c == CmdRelayBuild
}

func (c Command) String() string {
	if n, ok := commandNames[c]; ok {
		return n
	}
	return fmt.Sprintf("Command(0x%02x)", uint8(c))
}

// Valid reports whether c is a command this version understands. Unknown
// commands are rejected rather than ignored: a relay that silently drops what
// it does not understand cannot be upgraded safely, because the sender has no
// way to learn the message went nowhere.
func (c Command) Valid() bool {
	_, ok := commandNames[c]
	return ok
}

// CircuitID identifies a circuit on ONE link. It is link-local: the same
// circuit has different ids on each hop, which is what stops a relay
// correlating its predecessor and successor by identifier alone.
type CircuitID uint64

// Flags is a bitfield of per-cell hints. Bits are reserved rather than invented
// as needed, so an old relay can reject a cell using a bit it does not know.
type Flags uint8

const (
	// FlagEarly marks a cell permitted to carry circuit-extension requests.
	// Bounding these is what stops an endless extension attack (P5 enforces the
	// count; the flag is defined here because it lives in the header).
	FlagEarly Flags = 1 << 0
	// FlagPriority marks INTERACTIVE traffic, served ahead of BULK by the link
	// scheduler. It changes scheduling only -- never cell size, which is what
	// keeps the two classes indistinguishable to a capture (E5.4).
	FlagPriority Flags = 1 << 1
)

const flagsKnown = FlagEarly | FlagPriority

// Cell is one fixed-size frame.
//
// Payload is a slice of the caller's data and is NOT copied by Encode; it is
// copied by Decode. Length is implied by len(Payload) and is never stored
// separately, so the two cannot disagree.
type Cell struct {
	Circuit CircuitID
	Command Command
	Flags   Flags
	Payload []byte
}

var (
	ErrPayloadTooLarge = errors.New("axon/link: payload exceeds cell capacity")
	ErrShortBuffer     = errors.New("axon/link: buffer smaller than a cell")
	ErrBadLength       = errors.New("axon/link: declared payload length exceeds capacity")
	ErrBadCommand      = errors.New("axon/link: unknown cell command")
	ErrBadFlags        = errors.New("axon/link: unknown flag bits set")
	ErrReservedNonZero = errors.New("axon/link: reserved header bytes are not zero")
	ErrPaddingNonZero  = errors.New("axon/link: cell padding is not zero")
)

// Encode writes c into dst, which must be at least params.CellSize bytes.
//
// The whole cell is written every time, including the padding: reusing a buffer
// without clearing the tail would leak the previous cell's plaintext into the
// padding of this one, which is a disclosure bug that no test of the payload
// would ever catch.
func (c *Cell) Encode(dst []byte) error {
	if len(dst) < params.CellSize {
		return ErrShortBuffer
	}
	if len(c.Payload) > MaxPayload {
		return fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, len(c.Payload), MaxPayload)
	}
	if !c.Command.Valid() {
		return fmt.Errorf("%w: 0x%02x", ErrBadCommand, uint8(c.Command))
	}
	if c.Flags&^flagsKnown != 0 {
		return fmt.Errorf("%w: 0x%02x", ErrBadFlags, uint8(c.Flags))
	}

	cell := dst[:params.CellSize]
	binary.BigEndian.PutUint64(cell[offCircuitID:], uint64(c.Circuit))
	cell[offCommand] = byte(c.Command)
	cell[offFlags] = byte(c.Flags)
	// LENGTH is meaningful only for non-onioned cells. For RELAY/RELAY_BUILD it
	// MUST be zero: the real length lives inside the onion, where an observer
	// cannot read it. Writing the true length here would hand every relay on the
	// path the plaintext size of a message it is not supposed to be able to size.
	if c.Command.Onioned() {
		binary.BigEndian.PutUint16(cell[offLength:], 0)
	} else {
		binary.BigEndian.PutUint16(cell[offLength:], uint16(len(c.Payload)))
	}
	// Reserved bytes are zeroed explicitly rather than assumed zero.
	cell[offReserved+0], cell[offReserved+1] = 0, 0
	cell[offReserved+2], cell[offReserved+3] = 0, 0

	n := copy(cell[offPayload:], c.Payload)
	// Zero the remainder. See the doc comment: this is a disclosure control,
	// not tidiness.
	tail := cell[offPayload+n:]
	for i := range tail {
		tail[i] = 0
	}
	return nil
}

// Decode parses one cell from src, which must be at least params.CellSize bytes.
// The returned Cell owns its payload.
func Decode(src []byte) (*Cell, error) {
	if len(src) < params.CellSize {
		return nil, ErrShortBuffer
	}
	cell := src[:params.CellSize]

	// Reserved-must-be-zero is enforced, not ignored. Accepting arbitrary bytes
	// in a reserved field creates a covert channel through every relay on the
	// path and forecloses ever using those bits for anything.
	if cell[offReserved] != 0 || cell[offReserved+1] != 0 ||
		cell[offReserved+2] != 0 || cell[offReserved+3] != 0 {
		return nil, ErrReservedNonZero
	}

	cmd := Command(cell[offCommand])
	if !cmd.Valid() {
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadCommand, uint8(cmd))
	}
	flags := Flags(cell[offFlags])
	if flags&^flagsKnown != 0 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadFlags, uint8(flags))
	}
	length := int(binary.BigEndian.Uint16(cell[offLength:]))
	if length > MaxPayload {
		return nil, fmt.Errorf("%w: %d > %d", ErrBadLength, length, MaxPayload)
	}
	// An onioned cell must declare zero length, or the sender is leaking the
	// inner message size into a field every relay can read.
	if cmd.Onioned() {
		if length != 0 {
			return nil, fmt.Errorf("%w: onioned cell declares length %d", ErrBadLength, length)
		}
		length = MaxPayload
	}

	// Padding must be zero, for the same reason the reserved bytes must be:
	// otherwise every relay on the path forwards attacker-chosen bytes in the
	// space after the payload, which is a covert channel with a cell's worth of
	// capacity per cell. Found by FuzzDecode, which produced a valid PADDING
	// cell whose tail was 0x30 throughout.
	//
	// The limit worth stating: this is enforceable only where the cell is seen
	// in plaintext. Once a payload is onion-encrypted (P5) the tail is
	// ciphertext to intermediate hops, and only the endpoint that decrypts can
	// apply this check. It closes the channel for link-level cells and at the
	// endpoint, not for relays carrying encrypted layers.
	if !cmd.Onioned() {
		for i := offPayload + length; i < params.CellSize; i++ {
			if cell[i] != 0 {
				return nil, fmt.Errorf("%w: offset %d", ErrPaddingNonZero, i)
			}
		}
	}

	payload := make([]byte, length)
	copy(payload, cell[offPayload:offPayload+length])

	return &Cell{
		Circuit: CircuitID(binary.BigEndian.Uint64(cell[offCircuitID:])),
		Command: cmd,
		Flags:   flags,
		Payload: payload,
	}, nil
}

// WriteCell encodes c and writes exactly one cell to w.
//
// It writes through a caller-independent buffer so a short write cannot leave a
// partial cell on the wire: a stream carrying half a cell is unrecoverable,
// because the reader has no framing to resynchronise against.
func WriteCell(w io.Writer, c *Cell) error {
	var buf [params.CellSize]byte
	if err := c.Encode(buf[:]); err != nil {
		return err
	}
	n, err := w.Write(buf[:])
	if err != nil {
		return err
	}
	if n != params.CellSize {
		return fmt.Errorf("axon/link: short cell write: %d of %d", n, params.CellSize)
	}
	return nil
}

// ReadCell reads exactly one cell from r.
//
// io.ReadFull is deliberate: a cell is a fixed-size frame, so a partial read is
// an error rather than something to accumulate. Returning io.EOF unwrapped lets
// callers distinguish a clean close from a truncated cell (io.ErrUnexpectedEOF).
func ReadCell(r io.Reader) (*Cell, error) {
	var buf [params.CellSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	return Decode(buf[:])
}

// PaddingCell is a cell that carries nothing. The link-padding mechanism emits
// these; the schedule that decides when belongs to section 16 and is not here.
func PaddingCell(circuit CircuitID) *Cell {
	return &Cell{Circuit: circuit, Command: CmdPadding}
}
