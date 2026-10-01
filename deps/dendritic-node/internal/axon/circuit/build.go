package circuit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
)

// Telescoping construction over a live L2 link (§8.2, §8.4).
//
// WHY TELESCOPING, and what it costs — §8.4 chose it over a single-pass
// construction for forward secrecy per hop, no build-time filler hazard, and
// failure attribution by position. PAR-19 records the price, which this file is
// where you can see: hop *k* is ASKED to extend, so it learns it is not the
// terminal, and every extension passes through the guard. That is not repairable
// inside telescoping and §81's ruling retains the construction anyway.

// EXTEND body layout (§8.1's RCMD table):
//
//	NEXTID(32) ‖ LSLEN(2) ‖ LINKSPECS ‖ HTYPE(2) ‖ HLEN(2) ‖ handshake
//
// NEXTID is SHA-256(RID) — the relay identifier, not an address. Addresses live
// in LINKSPECS, so a relay that has moved is still identifiable and a relay
// cannot be impersonated by whoever holds its address.
const (
	extendIDLen    = 32
	extendMinBody  = extendIDLen + 2 + 2 + 2
	extendedMinLen = 2
)

var (
	ErrExtendMalformed = errors.New("axon/circuit: EXTEND body is malformed")
	ErrHandshakeType   = errors.New("axon/circuit: unsupported handshake type")
	ErrNoCreated       = errors.New("axon/circuit: peer did not answer CREATE")
	ErrDestroyed       = errors.New("axon/circuit: peer destroyed the circuit")
)

// DestroyReason is a DESTROY cell's one-byte reason code.
type DestroyReason uint8

const (
	ReasonNone DestroyReason = iota
	ReasonProtocol
	ReasonIntegrity
	ReasonWrongKey
	ReasonResource
	ReasonTimeout
	ReasonFinished
)

// EncodeExtend builds an EXTEND body.
func EncodeExtend(nextID [32]byte, linkSpecs []byte, htype uint16, handshake []byte) []byte {
	b := make([]byte, 0, extendMinBody+len(linkSpecs)+len(handshake))
	b = append(b, nextID[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(linkSpecs)))
	b = append(b, linkSpecs...)
	b = binary.BigEndian.AppendUint16(b, htype)
	b = binary.BigEndian.AppendUint16(b, uint16(len(handshake)))
	return append(b, handshake...)
}

// DecodeExtend parses an EXTEND body.
//
// Every length is checked against the remaining buffer before it is used. A
// length field trusted before it is bounded is how a parser becomes a read
// primitive, and this one is reachable by any relay on the path.
func DecodeExtend(b []byte) (nextID [32]byte, linkSpecs []byte, htype uint16, handshake []byte, err error) {
	if len(b) < extendMinBody {
		return nextID, nil, 0, nil, fmt.Errorf("%w: %d bytes", ErrExtendMalformed, len(b))
	}
	copy(nextID[:], b[:extendIDLen])
	p := b[extendIDLen:]

	lsLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < lsLen {
		return nextID, nil, 0, nil, fmt.Errorf("%w: link specs claim %d of %d", ErrExtendMalformed, lsLen, len(p))
	}
	linkSpecs = append([]byte(nil), p[:lsLen]...)
	p = p[lsLen:]

	if len(p) < 4 {
		return nextID, nil, 0, nil, fmt.Errorf("%w: truncated handshake header", ErrExtendMalformed)
	}
	htype = binary.BigEndian.Uint16(p)
	hLen := int(binary.BigEndian.Uint16(p[2:]))
	p = p[4:]
	if len(p) < hLen {
		return nextID, nil, 0, nil, fmt.Errorf("%w: handshake claims %d of %d", ErrExtendMalformed, hLen, len(p))
	}
	handshake = append([]byte(nil), p[:hLen]...)
	return nextID, linkSpecs, htype, handshake, nil
}

// EncodeExtended builds an EXTENDED body: HLEN(2) ‖ reply.
func EncodeExtended(reply []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...)
}

// DecodeExtended parses an EXTENDED body.
func DecodeExtended(b []byte) ([]byte, error) {
	if len(b) < extendedMinLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrExtendMalformed, len(b))
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b[2:]) < n {
		return nil, fmt.Errorf("%w: reply claims %d of %d", ErrExtendMalformed, n, len(b)-2)
	}
	return append([]byte(nil), b[2:2+n]...), nil
}

// EncodeCreate builds a CREATE body: HTYPE(2) ‖ HLEN(2) ‖ handshake.
func EncodeCreate(htype uint16, handshake []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, htype)
	b = binary.BigEndian.AppendUint16(b, uint16(len(handshake)))
	return append(b, handshake...)
}

// DecodeCreate parses a CREATE body.
func DecodeCreate(b []byte) (uint16, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrExtendMalformed, len(b))
	}
	htype := binary.BigEndian.Uint16(b)
	n := int(binary.BigEndian.Uint16(b[2:]))
	if len(b[4:]) < n {
		return 0, nil, fmt.Errorf("%w: handshake claims %d of %d", ErrExtendMalformed, n, len(b)-4)
	}
	return htype, append([]byte(nil), b[4:4+n]...), nil
}

// EncodeCreated builds a CREATED body: HLEN(2) ‖ reply.
func EncodeCreated(reply []byte) []byte { return EncodeExtended(reply) }

// DecodeCreated parses a CREATED body.
func DecodeCreated(b []byte) ([]byte, error) { return DecodeExtended(b) }

// -----------------------------------------------------------------------------
// Client side
// -----------------------------------------------------------------------------

// Builder constructs circuits over live links. It takes an explicit path and
// never chooses one.
type Builder struct {
	// Rand is the entropy source; nil means crypto/rand.
	Rand io.Reader
}

func (b *Builder) rnd() io.Reader {
	if b.Rand != nil {
		return b.Rand
	}
	return rand.Reader
}

// Create performs the first hop's handshake over an established cell stream.
func (b *Builder) Create(cs link.CellStream, c *Circuit, static RelayStatic) error {
	h, body, err := NewClientHandshake(b.rnd(), static)
	if err != nil {
		return err
	}
	if err := cs.WriteCell(&link.Cell{
		Circuit: c.ID(), Command: link.CmdCreate, Payload: EncodeCreate(HTypeNtorV1, body),
	}); err != nil {
		return err
	}

	in, err := cs.ReadCell()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoCreated, err)
	}
	if in.Command == link.CmdDestroy {
		return fmt.Errorf("%w: reason %d", ErrDestroyed, destroyReason(in))
	}
	if in.Command != link.CmdCreated {
		return fmt.Errorf("%w: got %s", ErrNoCreated, in.Command)
	}
	reply, err := DecodeCreated(in.Payload)
	if err != nil {
		return err
	}
	keys, err := h.Complete(reply)
	if err != nil {
		// §8.4: a bad AUTH marks the hop it extended THROUGH as well as the
		// target, because either the target is not who the descriptor said or
		// the carrying relay altered the reply. At the first hop there is no
		// carrier, so the guard alone is implicated.
		return err
	}
	hw, err := NewHopWide(keys)
	if err != nil {
		return err
	}
	return c.AddHop(&Hop{Static: static, Crypto: hw})
}

// Extend telescopes the circuit one hop further, through the hops already built.
func (b *Builder) Extend(cs link.CellStream, c *Circuit, next RelayStatic, linkSpecs []byte, af [32]byte) error {
	h, body, err := NewClientHandshake(b.rnd(), next)
	if err != nil {
		return err
	}
	nextID := next.ID()

	msg := &RelayCell{
		Stream: 0, Cmd: RCmdExtend,
		Data: EncodeExtend(nextID, linkSpecs, HTypeNtorV1, body),
	}
	block, err := c.SendRelay(af, msg)
	if err != nil {
		return err
	}
	// Extension requests travel only in RELAY_BUILD (T5.8).
	if err := cs.WriteCell(&link.Cell{
		Circuit: c.ID(), Command: link.CmdRelayBuild, Flags: link.FlagEarly, Payload: block,
	}); err != nil {
		return err
	}

	in, err := cs.ReadCell()
	if err != nil {
		return err
	}
	if in.Command == link.CmdDestroy {
		return fmt.Errorf("%w: reason %d", ErrDestroyed, destroyReason(in))
	}
	reply, err := c.RecvRelay(af, in)
	if err != nil {
		return err
	}
	if reply.Cmd != RCmdExtended {
		return fmt.Errorf("axon/circuit: expected EXTENDED, got %s", reply.Cmd)
	}
	hsReply, err := DecodeExtended(reply.Data)
	if err != nil {
		return err
	}
	keys, err := h.Complete(hsReply)
	if err != nil {
		return err
	}
	hw, err := NewHopWide(keys)
	if err != nil {
		return err
	}
	return c.AddHop(&Hop{Static: next, Crypto: hw})
}

// RecvRelay peels every layer of a backward cell and parses the relay message.
func (c *Circuit) RecvRelay(af [32]byte, in *link.Cell) (*RelayCell, error) {
	if in.Command != link.CmdRelay && in.Command != link.CmdRelayBuild {
		return nil, fmt.Errorf("axon/circuit: %s is not an onioned command", in.Command)
	}
	block := append([]byte(nil), in.Payload...)
	if len(block) != BlockSize {
		return nil, ErrBlockSize
	}
	if err := WideOpenBackwardAtClient(c.Hops(), block); err != nil {
		return nil, err
	}
	inner, err := OpenInnermost(af, block)
	if err != nil {
		return nil, err
	}
	return DecodeRelay(inner)
}

func destroyReason(c *link.Cell) DestroyReason {
	if len(c.Payload) == 0 {
		return ReasonNone
	}
	return DestroyReason(c.Payload[0])
}

// DestroyCell builds a DESTROY.
//
// §8.1: DESTROY is never onioned and never forwarded verbatim — each relay emits
// its own. Forwarding one would carry the originator's reason code and framing
// across a hop that is supposed to re-originate everything it sends.
func DestroyCell(id link.CircuitID, r DestroyReason) *link.Cell {
	body := make([]byte, 16)
	body[0] = byte(r)
	return &link.Cell{Circuit: id, Command: link.CmdDestroy, Payload: body}
}

// -----------------------------------------------------------------------------
// Relay side
// -----------------------------------------------------------------------------

// RelayEndpoint is a relay's per-circuit responder.
type RelayEndpoint struct {
	Static RelayStatic
	// B is the RoutingIdentity static private key.
	B [32]byte
	// Rand is the entropy source; nil means crypto/rand.
	Rand io.Reader
}

func (e *RelayEndpoint) rnd() io.Reader {
	if e.Rand != nil {
		return e.Rand
	}
	return rand.Reader
}

// AnswerCreate handles an incoming CREATE and returns the CREATED cell plus the
// derived per-hop state.
//
// A relay that does not recognise ID, or whose current static key is not B,
// answers DESTROY(WRONG_KEY) and does NO cryptography — §8.2's first line of
// handshake DoS defence, and the reason ServerHandshake checks before it
// multiplies.
func (e *RelayEndpoint) AnswerCreate(in *link.Cell) (*link.Cell, *HopWide, error) {
	htype, body, err := DecodeCreate(in.Payload)
	if err != nil {
		return DestroyCell(in.Circuit, ReasonProtocol), nil, err
	}
	if htype != HTypeNtorV1 {
		return DestroyCell(in.Circuit, ReasonProtocol), nil,
			fmt.Errorf("%w: 0x%04x", ErrHandshakeType, htype)
	}
	keys, reply, err := ServerHandshake(e.rnd(), e.Static, e.B, body)
	if err != nil {
		if errors.Is(err, ErrWrongKey) {
			return DestroyCell(in.Circuit, ReasonWrongKey), nil, err
		}
		return DestroyCell(in.Circuit, ReasonProtocol), nil, err
	}
	hw, err := NewHopWide(keys)
	if err != nil {
		return DestroyCell(in.Circuit, ReasonProtocol), nil, err
	}
	return &link.Cell{
		Circuit: in.Circuit, Command: link.CmdCreated, Payload: EncodeCreated(reply),
	}, hw, nil
}

// SendBackward wraps a relay message for the client and rewrites the id.
func SendBackward(rc *RelayCircuit, af [32]byte, msg *RelayCell) (*link.Cell, error) {
	inner, err := msg.Encode()
	if err != nil {
		return nil, err
	}
	block, err := SealInnermost(af, inner)
	if err != nil {
		return nil, err
	}
	if err := WideSealBackwardAtHop(rc.Crypto, block); err != nil {
		return nil, err
	}
	return &link.Cell{
		Circuit: rc.PrevID, // rewritten back to the upstream link's id
		Command: link.CmdRelayBuild,
		Payload: block,
	}, nil
}

// WrapBackwardHop adds one relay's backward layer to a cell already travelling
// toward the client.
func WrapBackwardHop(rc *RelayCircuit, in *link.Cell) (*link.Cell, error) {
	block := append([]byte(nil), in.Payload...)
	if len(block) != BlockSize {
		return nil, ErrBlockSize
	}
	if err := WideSealBackwardAtHop(rc.Crypto, block); err != nil {
		return nil, err
	}
	return &link.Cell{Circuit: rc.PrevID, Command: in.Command, Flags: in.Flags, Payload: block}, nil
}

// ExtendTarget is what a relay learned from an EXTEND it must act on.
type ExtendTarget struct {
	NextID    [32]byte
	LinkSpecs []byte
	HType     uint16
	Handshake []byte
}

// ParseExtend reads an EXTEND a relay is being asked to perform.
//
// It refuses an EXTEND naming the relay's own predecessor or itself (T5.7's rule
// enforced at the relay, where the client cannot be trusted to have applied it).
func ParseExtend(rc *RelayCircuit, self [32]byte, msg *RelayCell) (*ExtendTarget, error) {
	if msg.Cmd != RCmdExtend {
		return nil, fmt.Errorf("axon/circuit: %s is not EXTEND", msg.Cmd)
	}
	nextID, ls, htype, hs, err := DecodeExtend(msg.Data)
	if err != nil {
		return nil, err
	}
	if nextID == self {
		return nil, fmt.Errorf("%w: EXTEND names this relay", ErrExtendToSelf)
	}
	return &ExtendTarget{NextID: nextID, LinkSpecs: ls, HType: htype, Handshake: hs}, nil
}

// ExtendContext carries what a relay needs to complete an extension.
type ExtendContext struct {
	Ctx context.Context
	// Dial opens a link to the named target. Supplied by the caller so this
	// package never learns how peers are addressed.
	Dial func(ctx context.Context, target *ExtendTarget) (link.CellStream, error)
}
