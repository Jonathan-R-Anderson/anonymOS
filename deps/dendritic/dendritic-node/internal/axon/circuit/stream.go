package circuit

import (
	"errors"
	"fmt"
	"sync"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Stream multiplexing over a circuit (§8.6).
//
// THE ISOLATION RULE, which is the whole reason this file is not just a map:
//
//	streams share a circuit  <=>  equal identity_scope
//	                          AND equal isolation_tag
//	                          AND equal destination
//	                          AND equal traffic_class
//
// The linkability reason, stated exactly. The terminal hop — and the rendezvous
// point of a joined circuit — sees every stream on that circuit. If streams to
// D1 and D2 share a circuit, whoever is or observes that terminal learns a
// single user contacts both. The adversary does not learn WHO the user is; it
// learns that the D1 visitor and the D2 visitor are the same person.
//
// The counter-argument, which is also real: per-destination isolation multiplies
// circuit count, and circuit count is a fingerprint — 40 live circuits is
// distinguishable from 4, and each extra circuit is another draw against the
// hostile fraction. The design accepts this because the linkage above is a
// CERTAIN leak to a SPECIFIC adversary, while circuit-count fingerprinting is a
// statistical leak to an adversary who must already be watching the guard — and
// the guard is pinned and bonded.

// StreamState is a stream's lifecycle.
type StreamState uint8

const (
	SNew        StreamState = iota // allocated, no BEGIN sent
	SConnecting                    // BEGIN sent, awaiting CONNECTED
	SOpen                          // CONNECTED received
	SClosed                        // END sent or received
)

var streamStateNames = map[StreamState]string{
	SNew: "S_NEW", SConnecting: "S_CONNECTING", SOpen: "S_OPEN", SClosed: "S_CLOSED",
}

func (s StreamState) String() string {
	if n, ok := streamStateNames[s]; ok {
		return n
	}
	return "S_?"
}

// Isolation is the four-part key that decides which streams may share a circuit.
//
// It is a comparable struct rather than four arguments so that "equal isolation"
// is a single == and cannot be got subtly wrong by comparing three of four
// fields — which is exactly the bug that would silently merge two users' traffic
// onto one circuit.
type Isolation struct {
	// IdentityScope separates circuits belonging to different identities. §8.5's
	// guard rule, one level down.
	IdentityScope string
	// Tag is the caller's isolation tag, defaulting to the destination.
	Tag string
	// Destination is where the stream goes.
	Destination string
	// Class is the traffic class. INTERACTIVE and BULK never share a circuit.
	Class TrafficClass
}

// Valid reports whether an isolation context is usable.
func (i Isolation) Valid() bool {
	return i.Class.Valid() && i.Destination != ""
}

var (
	ErrStreamCap         = errors.New("axon/circuit: circuit is at its stream cap")
	ErrStreamExists      = errors.New("axon/circuit: stream id already in use")
	ErrStreamUnknown     = errors.New("axon/circuit: no such stream")
	ErrIsolationMismatch = errors.New("axon/circuit: stream isolation does not match the circuit's binding")
	ErrCircuitBound      = errors.New("axon/circuit: circuit is already bound to a different destination")
	ErrCircuitDraining   = errors.New("axon/circuit: circuit is past rotation and accepts no new streams")
	ErrStreamState       = errors.New("axon/circuit: operation not permitted in this stream state")
	ErrNoIsolation       = errors.New("axon/circuit: isolation context is incomplete")
)

// Stream is one end-to-end stream over a circuit.
type Stream struct {
	ID    StreamID
	Iso   Isolation
	state StreamState
	mu    sync.Mutex
}

// State returns the stream's state.
func (s *Stream) State() StreamState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// setState moves the stream, refusing transitions the machine does not have.
func (s *Stream) setState(to StreamState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if to == SClosed {
		s.state = SClosed
		return nil
	}
	ok := (s.state == SNew && to == SConnecting) || (s.state == SConnecting && to == SOpen)
	if !ok {
		return fmt.Errorf("%w: %s -> %s", ErrStreamState, s.state, to)
	}
	s.state = to
	return nil
}

// StreamTable multiplexes streams over one circuit and enforces §8.6's rules.
type StreamTable struct {
	mu sync.Mutex

	streams map[StreamID]*Stream
	// bound is the isolation context this circuit committed to on its first
	// stream. ONCE BOUND, ALWAYS BOUND: reusing a drained circuit for a second
	// destination re-creates exactly the linkage isolation exists to prevent,
	// one destination at a time.
	bound    Isolation
	hasBound bool
	// draining is set once the circuit passes C_ROTATE. A long stream must not
	// keep a circuit alive past rotation and defeat the 10-minute lifetime.
	draining bool
}

// NewStreamTable builds an empty table.
func NewStreamTable() *StreamTable {
	return &StreamTable{streams: map[StreamID]*Stream{}}
}

// Binding returns the isolation context this circuit is committed to.
func (t *StreamTable) Binding() (Isolation, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bound, t.hasBound
}

// Len is the number of live streams.
func (t *StreamTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.streams)
}

// Drain marks the circuit past rotation.
func (t *StreamTable) Drain() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.draining = true
}

// MayCarry reports whether a stream with this isolation may join the circuit,
// and why not when it may not.
//
// It is exported because path selection (P12) needs to ask the question before
// committing to a circuit, and asking it by attempting an Open and rolling back
// would leak a half-created stream into the table.
func (t *StreamTable) MayCarry(iso Isolation) error {
	if !iso.Valid() {
		return ErrNoIsolation
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mayCarryLocked(iso)
}

func (t *StreamTable) mayCarryLocked(iso Isolation) error {
	if t.draining {
		return ErrCircuitDraining
	}
	if len(t.streams) >= params.MaxStreamsPerCircuit {
		return fmt.Errorf("%w: %d streams", ErrStreamCap, len(t.streams))
	}
	if !t.hasBound {
		return nil
	}
	if t.bound == iso {
		return nil
	}
	// Report the SPECIFIC mismatch: an operator debugging a circuit that
	// refuses a stream needs to know which of the four fields differed, and a
	// bare "isolation mismatch" sends them reading source.
	switch {
	case t.bound.Class != iso.Class:
		return fmt.Errorf("%w: circuit carries %s, stream is %s",
			ErrIsolationMismatch, t.bound.Class, iso.Class)
	case t.bound.IdentityScope != iso.IdentityScope:
		return fmt.Errorf("%w: circuit is scoped to %q, stream to %q",
			ErrIsolationMismatch, t.bound.IdentityScope, iso.IdentityScope)
	case t.bound.Destination != iso.Destination:
		return fmt.Errorf("%w: circuit is bound to %q, stream targets %q",
			ErrCircuitBound, t.bound.Destination, iso.Destination)
	default:
		return fmt.Errorf("%w: isolation tags differ (%q vs %q)",
			ErrIsolationMismatch, t.bound.Tag, iso.Tag)
	}
}

// Open registers a new stream, binding the circuit if it is the first.
func (t *StreamTable) Open(id StreamID, iso Isolation) (*Stream, error) {
	if !iso.Valid() {
		return nil, ErrNoIsolation
	}
	if id == 0 {
		return nil, fmt.Errorf("%w: stream 0 is circuit-scoped", ErrStreamExists)
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := t.mayCarryLocked(iso); err != nil {
		return nil, err
	}
	if _, exists := t.streams[id]; exists {
		return nil, ErrStreamExists
	}

	s := &Stream{ID: id, Iso: iso, state: SNew}
	t.streams[id] = s
	if !t.hasBound {
		t.bound, t.hasBound = iso, true
	}
	return s, nil
}

// Get returns a stream by id.
func (t *StreamTable) Get(id StreamID) (*Stream, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.streams[id]
	return s, ok
}

// Close removes a stream. The circuit's binding SURVIVES: once bound, always
// bound, so a drained circuit cannot be recycled for a second destination.
func (t *StreamTable) Close(id StreamID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.streams[id]
	if !ok {
		return ErrStreamUnknown
	}
	_ = s.setState(SClosed)
	delete(t.streams, id)
	return nil
}

// -----------------------------------------------------------------------------
// Message handling
// -----------------------------------------------------------------------------

// BeginBody builds a BEGIN body: DSTTYPE(1) ‖ PORT(2) ‖ DSTLEN(2) ‖ DST ‖ FLAGS(1).
//
// DSTTYPE semantics belong to L5/L7; §8 owns only the framing.
func BeginBody(dstType uint8, port uint16, dst []byte, flags uint8) []byte {
	b := make([]byte, 0, 6+len(dst))
	b = append(b, dstType, byte(port>>8), byte(port))
	b = append(b, byte(len(dst)>>8), byte(len(dst)))
	b = append(b, dst...)
	return append(b, flags)
}

// ParseBeginBody parses a BEGIN body, bounding every length before using it.
func ParseBeginBody(b []byte) (dstType uint8, port uint16, dst []byte, flags uint8, err error) {
	if len(b) < 6 {
		return 0, 0, nil, 0, fmt.Errorf("%w: %d bytes", ErrRelayBadLen, len(b))
	}
	dstType = b[0]
	port = uint16(b[1])<<8 | uint16(b[2])
	n := int(b[3])<<8 | int(b[4])
	if len(b) < 5+n+1 {
		return 0, 0, nil, 0, fmt.Errorf("%w: destination claims %d of %d",
			ErrRelayBadLen, n, len(b)-6)
	}
	dst = append([]byte(nil), b[5:5+n]...)
	flags = b[5+n]
	return dstType, port, dst, flags, nil
}

// HandleInbound applies an inbound relay message to the stream table and reports
// whether the cell was IMPOSSIBLE — structurally valid but arriving in a state
// where it cannot exist.
//
// T5.9 / PAR-28: the caller feeds an impossible result to NoteImpossibleCell.
// Every one of these is a droppable event, and a droppable event nobody counts
// is a signalling channel.
func (t *StreamTable) HandleInbound(msg *RelayCell) (impossible bool, err error) {
	if msg.Cmd.CircuitScoped() {
		return false, nil
	}
	if msg.Cmd == RCmdSendme && msg.Stream == 0 {
		return false, nil // circuit-level SENDME
	}

	s, ok := t.Get(msg.Stream)
	if !ok {
		// A DATA cell for a stream that never opened, a SENDME for a closed
		// stream, an END for a stream already gone: each is valid on the wire
		// and impossible in this state.
		return true, fmt.Errorf("%w: %s for stream %d", ErrStreamUnknown, msg.Cmd, msg.Stream)
	}

	switch msg.Cmd {
	case RCmdConnected:
		if err := s.setState(SOpen); err != nil {
			return true, err
		}
	case RCmdData:
		if s.State() != SOpen {
			return true, fmt.Errorf("%w: DATA on a %s stream", ErrStreamState, s.State())
		}
	case RCmdEnd:
		_ = t.Close(msg.Stream)
	}
	return false, nil
}

// Begin marks a stream as having sent its BEGIN.
func (t *StreamTable) Begin(id StreamID) error {
	s, ok := t.Get(id)
	if !ok {
		return ErrStreamUnknown
	}
	return s.setState(SConnecting)
}
