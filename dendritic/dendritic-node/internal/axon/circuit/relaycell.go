package circuit

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The relay cell (§8.6) — the structure inside the fully-peeled onion.
//
//	 0  2  STREAMID   0 = circuit-scoped. The initiator uses ODD ids, the other
//	                  end EVEN, so the two cannot collide on a rendezvous-joined
//	                  circuit.
//	 2  1  RCMD       relay command
//	 3  1  RFLAGS     bit0 FRAG_MORE, bit1 ACK_REQ, bits 2-7 reserved, MUST be zero
//	 4  2  RLEN       0..RelayDataSize; above it is a protocol violation
//	 6  2  RESERVED   MUST be zero; aligns RDATA to 8 bytes
//	 8  n  RDATA      RLEN bytes, remainder zero-filled before encryption
//
// The remainder after RLEN is zero-filled before encryption and **MUST NOT be
// checked on receipt**. It is inside the permutation, so it cannot be a channel,
// and checking it costs a pass over a kilobyte for nothing. This is the one place
// where the cell-padding rule from P2 deliberately does NOT apply, and §8.6 says
// so explicitly.

// Relay header layout.
const (
	offStreamID  = 0
	offRCmd      = 2
	offRFlags    = 3
	offRLen      = 4
	offRReserved = 6
	offRData     = 8

	// RelayHeaderSize is the fixed header inside the onion.
	RelayHeaderSize = offRData
)

// RelayDataSize is the usable relay payload.
//
// It is 984 bytes: the 1008-byte cell body, less the 16-byte end-to-end
// authenticator, less the 8-byte relay header. The withdrawn tag-stack format
// allowed 936, so PAR-01's repair returned 48 bytes per cell as well as closing
// the channel.
const RelayDataSize = InnerSize - RelayHeaderSize

// StreamID identifies a stream within a circuit. Zero is circuit-scoped.
type StreamID uint16

// IsInitiator reports whether an id belongs to the circuit's initiator.
//
// The initiator uses odd ids and the other end even, which is what stops the two
// colliding on a circuit joined at a rendezvous point — where both ends allocate
// independently and neither can see the other's table.
func (s StreamID) IsInitiator() bool { return s%2 == 1 }

// RCmd is a relay command (§8.1's RCMD table).
type RCmd uint8

const (
	RCmdBegin      RCmd = 0x01
	RCmdData       RCmd = 0x02
	RCmdEnd        RCmd = 0x03
	RCmdConnected  RCmd = 0x04
	RCmdSendme     RCmd = 0x05
	RCmdExtend     RCmd = 0x06
	RCmdExtended   RCmd = 0x07
	RCmdTruncate   RCmd = 0x08
	RCmdTruncated  RCmd = 0x09
	RCmdDrop       RCmd = 0x0A
	RCmdResolve    RCmd = 0x0B
	RCmdResolved   RCmd = 0x0C
	RCmdLookup     RCmd = 0x0D
	RCmdLookupRepl RCmd = 0x0E
	RCmdError      RCmd = 0x0F

	// L5 rendezvous commands (§8.1). §8 owns their codes and their circuit
	// scope; internal/axon/rendez owns their bodies. Keeping the codes here is
	// what stops a body being confused with stream traffic -- scope is checked
	// by this package, not by the layer that fills them in.
	RCmdEstablishIntro        RCmd = 0x10
	RCmdIntroEstablished      RCmd = 0x11
	RCmdIntroduce1            RCmd = 0x12
	RCmdIntroduce2            RCmd = 0x13
	RCmdIntroduceAck          RCmd = 0x14
	RCmdEstablishRendezvous   RCmd = 0x18
	RCmdRendezvousEstablished RCmd = 0x19
	RCmdRendezvous1           RCmd = 0x1A
	RCmdRendezvous2           RCmd = 0x1B
)

var rcmdNames = map[RCmd]string{
	RCmdBegin: "BEGIN", RCmdData: "DATA", RCmdEnd: "END", RCmdConnected: "CONNECTED",
	RCmdSendme: "SENDME", RCmdExtend: "EXTEND", RCmdExtended: "EXTENDED",
	RCmdTruncate: "TRUNCATE", RCmdTruncated: "TRUNCATED", RCmdDrop: "DROP",
	RCmdResolve: "RESOLVE", RCmdResolved: "RESOLVED", RCmdLookup: "LOOKUP",
	RCmdLookupRepl: "LOOKUP_REPLY", RCmdError: "ERROR",
	RCmdEstablishIntro: "ESTABLISH_INTRO", RCmdIntroEstablished: "INTRO_ESTABLISHED",
	RCmdIntroduce1: "INTRODUCE1", RCmdIntroduce2: "INTRODUCE2",
	RCmdIntroduceAck:          "INTRODUCE_ACK",
	RCmdEstablishRendezvous:   "ESTABLISH_RENDEZVOUS",
	RCmdRendezvousEstablished: "RENDEZVOUS_ESTABLISHED",
	RCmdRendezvous1:           "RENDEZVOUS1", RCmdRendezvous2: "RENDEZVOUS2",
}

func (r RCmd) String() string {
	if n, ok := rcmdNames[r]; ok {
		return n
	}
	return fmt.Sprintf("RCmd(0x%02x)", uint8(r))
}

func (r RCmd) Valid() bool { _, ok := rcmdNames[r]; return ok }

// CircuitScoped reports whether a command must carry STREAMID = 0.
//
// Scope is not decoration: §8.1 states that circuit scope "is what stops them
// being confused with stream traffic". A control command arriving with a stream
// id, or a stream command with none, is a protocol violation rather than
// something to interpret generously.
func (r RCmd) CircuitScoped() bool {
	switch r {
	case RCmdExtend, RCmdExtended, RCmdTruncate, RCmdTruncated, RCmdDrop,
		// Every L5 command is circuit-scoped: an introduction or a rendezvous
		// is a property of the circuit, not of a stream on it, and §8.1 says so.
		RCmdEstablishIntro, RCmdIntroEstablished, RCmdIntroduce1, RCmdIntroduce2,
		RCmdIntroduceAck, RCmdEstablishRendezvous, RCmdRendezvousEstablished,
		RCmdRendezvous1, RCmdRendezvous2:
		return true
	default:
		return false
	}
}

// ExtensionCommand reports whether a command may travel only in RELAY_BUILD.
func (r RCmd) ExtensionCommand() bool {
	return r == RCmdExtend || r == RCmdExtended
}

// RFlags is the relay-header bitfield.
type RFlags uint8

const (
	// RFlagFragMore marks a message continued in the next cell.
	RFlagFragMore RFlags = 1 << 0
	// RFlagAckReq requests an acknowledgement.
	RFlagAckReq RFlags = 1 << 1
)

const rflagsKnown = RFlagFragMore | RFlagAckReq

var (
	ErrRelayShort    = errors.New("axon/circuit: relay region shorter than the header")
	ErrRelayBadCmd   = errors.New("axon/circuit: unknown relay command")
	ErrRelayBadFlags = errors.New("axon/circuit: unknown relay flag bits set")
	ErrRelayReserved = errors.New("axon/circuit: relay reserved bytes are not zero")
	ErrRelayBadLen   = errors.New("axon/circuit: relay length exceeds capacity")
	ErrRelayScope    = errors.New("axon/circuit: relay command used at the wrong scope")
	ErrRelayNotBuild = errors.New("axon/circuit: extension command outside a RELAY_BUILD cell")
	ErrRelayBudget   = errors.New("axon/circuit: RELAY_BUILD budget exhausted")
)

// RelayCell is one relay message.
type RelayCell struct {
	Stream StreamID
	Cmd    RCmd
	Flags  RFlags
	Data   []byte
}

// Encode writes the relay cell into a full-size inner region.
//
// The whole region is written every time, including the zero fill: reusing a
// buffer without clearing the tail would carry the previous message's plaintext
// into this one's padding. It is inside the permutation so it is not a channel
// to a relay, but it IS a disclosure to the terminal, which is worse.
func (r *RelayCell) Encode() ([]byte, error) {
	if len(r.Data) > RelayDataSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrRelayBadLen, len(r.Data), RelayDataSize)
	}
	if !r.Cmd.Valid() {
		return nil, fmt.Errorf("%w: 0x%02x", ErrRelayBadCmd, uint8(r.Cmd))
	}
	if r.Flags&^rflagsKnown != 0 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrRelayBadFlags, uint8(r.Flags))
	}
	if err := checkScope(r.Cmd, r.Stream); err != nil {
		return nil, err
	}

	inner := make([]byte, InnerSize)
	binary.BigEndian.PutUint16(inner[offStreamID:], uint16(r.Stream))
	inner[offRCmd] = byte(r.Cmd)
	inner[offRFlags] = byte(r.Flags)
	binary.BigEndian.PutUint16(inner[offRLen:], uint16(len(r.Data)))
	// RESERVED is zeroed explicitly rather than assumed zero.
	inner[offRReserved], inner[offRReserved+1] = 0, 0
	copy(inner[offRData:], r.Data)
	return inner, nil
}

// DecodeRelay parses a relay cell from a fully-peeled inner region.
func DecodeRelay(inner []byte) (*RelayCell, error) {
	if len(inner) < RelayHeaderSize {
		return nil, ErrRelayShort
	}
	if inner[offRReserved] != 0 || inner[offRReserved+1] != 0 {
		return nil, ErrRelayReserved
	}
	cmd := RCmd(inner[offRCmd])
	if !cmd.Valid() {
		return nil, fmt.Errorf("%w: 0x%02x", ErrRelayBadCmd, uint8(cmd))
	}
	flags := RFlags(inner[offRFlags])
	if flags&^rflagsKnown != 0 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrRelayBadFlags, uint8(flags))
	}
	n := int(binary.BigEndian.Uint16(inner[offRLen:]))
	if n > RelayDataSize || offRData+n > len(inner) {
		return nil, fmt.Errorf("%w: %d > %d", ErrRelayBadLen, n, RelayDataSize)
	}
	stream := StreamID(binary.BigEndian.Uint16(inner[offStreamID:]))
	if err := checkScope(cmd, stream); err != nil {
		return nil, err
	}

	data := make([]byte, n)
	copy(data, inner[offRData:offRData+n])
	// The tail after RLEN is deliberately NOT checked. See the file comment.
	return &RelayCell{Stream: stream, Cmd: cmd, Flags: flags, Data: data}, nil
}

func checkScope(cmd RCmd, stream StreamID) error {
	if cmd.CircuitScoped() && stream != 0 {
		return fmt.Errorf("%w: %s is circuit-scoped but carries stream %d",
			ErrRelayScope, cmd, stream)
	}
	// SENDME is the one command valid at either scope (§8.1).
	if !cmd.CircuitScoped() && cmd != RCmdSendme && stream == 0 {
		return fmt.Errorf("%w: %s is stream-scoped but carries no stream id",
			ErrRelayScope, cmd)
	}
	return nil
}
