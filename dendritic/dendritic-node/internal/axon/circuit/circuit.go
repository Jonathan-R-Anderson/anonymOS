package circuit

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Circuit lifecycle and the relay-side circuit table (§8.4, §8.6).
//
// The path is an EXPLICIT ARGUMENT throughout this file. Path selection is P12's
// and P5's phase definition says it "must not leak into P5" -- so nothing here
// chooses a relay, weights one, or knows what a good path looks like.

// State is §8.4's circuit state machine.
type State uint8

const (
	CNew       State = iota // allocated, no link
	CLink                   // link to the guard establishing
	CCreating               // CREATE sent
	CExtending              // EXTEND to hop k sent
	COpen                   // all hops up, no stream
	CActive                 // >= 1 stream
	CRotate                 // past 70 % of lifetime, draining
	CClosing                // DESTROY sent both ways
	CDead                   // freed; circuit id quarantined
)

var stateNames = map[State]string{
	CNew: "C_NEW", CLink: "C_LINK", CCreating: "C_CREATING", CExtending: "C_EXT",
	COpen: "C_OPEN", CActive: "C_ACTIVE", CRotate: "C_ROTATE", CClosing: "C_CLOSING",
	CDead: "C_DEAD",
}

func (s State) String() string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return "C_?"
}

// TrafficClass is R2's mandatory declaration.
//
// THERE IS NO DEFAULT AND THERE MUST NOT BE ONE. P5's phase definition is
// explicit: "the API must force the caller to declare the class (R2); a default
// class is a design error, not a convenience." INTERACTIVE is vulnerable to
// end-to-end correlation and BULK deliberately coarsens timing; a caller who did
// not choose has not understood which of those they are getting.
type TrafficClass uint8

const (
	// ClassUnset is the zero value and is never valid. Its existence is the
	// mechanism that makes the declaration mandatory.
	ClassUnset TrafficClass = iota
	ClassInteractive
	ClassBulk
)

func (c TrafficClass) String() string {
	switch c {
	case ClassInteractive:
		return "INTERACTIVE"
	case ClassBulk:
		return "BULK"
	default:
		return "UNSET"
	}
}

// Valid reports whether a class was actually chosen.
func (c TrafficClass) Valid() bool { return c == ClassInteractive || c == ClassBulk }

var (
	ErrNoTrafficClass = errors.New("axon/circuit: traffic class must be declared (R2); there is no default")
	ErrPathLength     = errors.New("axon/circuit: path length outside the permitted range")
	ErrExtendToSelf   = errors.New("axon/circuit: EXTEND targets a hop already on the circuit")
	ErrWrongState     = errors.New("axon/circuit: operation not permitted in this state")
	ErrCircuitUnknown = errors.New("axon/circuit: no such circuit")
	ErrCircuitExists  = errors.New("axon/circuit: circuit id already in use")
	ErrDropThreshold  = errors.New("axon/circuit: impossible-cell threshold exceeded")
	ErrRelayCapacity  = errors.New("axon/circuit: relay is at its circuit capacity")
)

// Hop is one relay on a client's circuit.
type Hop struct {
	Static RelayStatic
	Crypto *HopWide
}

// Circuit is the client's view: the whole path, and a key set per hop.
type Circuit struct {
	mu sync.Mutex

	id      link.CircuitID
	class   TrafficClass
	state   State
	hops    []*Hop
	created time.Time

	// buildBudget is the remaining RELAY_BUILD allowance (T5.8).
	buildBudget int
	// drops counts structurally valid cells that arrived in impossible states
	// (T5.9).
	drops int

	nextStream StreamID
}

// NewCircuit allocates a client circuit. The class is mandatory.
func NewCircuit(id link.CircuitID, class TrafficClass, now time.Time) (*Circuit, error) {
	if !class.Valid() {
		return nil, ErrNoTrafficClass
	}
	return &Circuit{
		id: id, class: class, state: CNew, created: now,
		buildBudget: params.RelayBuildBudget,
		// The initiator uses odd stream ids so the two ends of a
		// rendezvous-joined circuit cannot collide.
		nextStream: 1,
	}, nil
}

func (c *Circuit) ID() link.CircuitID  { return c.id }
func (c *Circuit) Class() TrafficClass { return c.class }

func (c *Circuit) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Circuit) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hops)
}

// BuildBudget is the remaining RELAY_BUILD allowance.
func (c *Circuit) BuildBudget() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buildBudget
}

// SetState moves the circuit, refusing transitions the machine does not have.
func (c *Circuit) SetState(s State) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !legalTransition(c.state, s) {
		return fmt.Errorf("%w: %s -> %s", ErrWrongState, c.state, s)
	}
	c.state = s
	return nil
}

// legalTransition encodes §8.4's table. Transitions absent from it are refused
// rather than tolerated, so a state machine bug surfaces as an error rather than
// as a circuit in an impossible state.
func legalTransition(from, to State) bool {
	if to == CClosing || to == CDead {
		// Teardown is reachable from anywhere; that is the point of teardown.
		return true
	}
	switch from {
	case CNew:
		return to == CLink
	case CLink:
		return to == CCreating
	case CCreating:
		return to == CExtending || to == COpen
	case CExtending:
		return to == CExtending || to == COpen
	case COpen:
		return to == CActive || to == CRotate
	case CActive:
		return to == CRotate
	case CRotate:
		return false
	default:
		return false
	}
}

// AddHop appends a completed handshake to the path.
//
// It refuses a relay already on the circuit, which is T5.7's rule stated where
// it can be enforced: a circuit that visits a relay twice gives that relay two
// positions and, for the previous hop specifically, collapses the path.
func (c *Circuit) AddHop(h *Hop) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hops) >= params.MaxHops {
		return fmt.Errorf("%w: already %d hops", ErrPathLength, len(c.hops))
	}
	id := h.Static.ID()
	for _, existing := range c.hops {
		if existing.Static.ID() == id {
			return fmt.Errorf("%w: %x is already hop %d", ErrExtendToSelf, id[:4], len(c.hops))
		}
	}
	c.hops = append(c.hops, h)
	return nil
}

// SpendBuildBudget consumes one RELAY_BUILD allowance.
func (c *Circuit) SpendBuildBudget() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buildBudget <= 0 {
		return ErrRelayBudget
	}
	c.buildBudget--
	return nil
}

// NoteImpossibleCell records a structurally valid cell that arrived in a state
// where it cannot exist, and reports whether the circuit must be torn down.
//
// T5.9 / PAR-28: §8.9 argues injection is detected and localised, which holds
// for cells that must be DECRYPTED and says nothing about cells that are valid
// and merely unexpected. Those are droppable, and a droppable event nobody
// counts is a signalling channel.
func (c *Circuit) NoteImpossibleCell() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drops++
	if c.drops >= params.DropCellThreshold {
		return fmt.Errorf("%w: %d impossible cells", ErrDropThreshold, c.drops)
	}
	return nil
}

// Drops is the impossible-cell count.
func (c *Circuit) Drops() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.drops
}

// NextStreamID allocates the next initiator stream id, preserving odd parity.
func (c *Circuit) NextStreamID() StreamID {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextStream
	c.nextStream += 2
	return id
}

// Hops returns the path's crypto states, outermost first.
func (c *Circuit) Hops() []*HopWide {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*HopWide, len(c.hops))
	for i, h := range c.hops {
		out[i] = h.Crypto
	}
	return out
}

// SendRelay wraps a relay message for the whole path.
func (c *Circuit) SendRelay(af [32]byte, r *RelayCell) ([]byte, error) {
	if r.Cmd.ExtensionCommand() {
		if err := c.SpendBuildBudget(); err != nil {
			return nil, err
		}
	}
	inner, err := r.Encode()
	if err != nil {
		return nil, err
	}
	block, err := SealInnermost(af, inner)
	if err != nil {
		return nil, err
	}
	if err := WideSealForward(c.Hops(), block); err != nil {
		return nil, err
	}
	return block, nil
}

// -----------------------------------------------------------------------------
// Relay side
// -----------------------------------------------------------------------------

// RelayCircuit is a relay's view: two link-local ids, one key set, no knowledge
// of the path beyond its two neighbours.
//
// T5.2's property lives in this struct's shape: there is nowhere to put a third
// identity, because a relay is never told one.
type RelayCircuit struct {
	mu sync.Mutex

	// PrevID is the circuit id on the link toward the client.
	PrevID link.CircuitID
	// PrevPeer identifies the upstream neighbour.
	PrevPeer string
	// NextID is the circuit id on the link toward the terminal. It is
	// INDEPENDENT of PrevID -- see AllocateID.
	NextID link.CircuitID
	// NextPeer identifies the downstream neighbour, empty at the terminal.
	NextPeer string

	Crypto *HopWide

	buildBudget int
	drops       int
	created     time.Time
	closed      bool
}

// BuildBudget is the remaining RELAY_BUILD allowance at this hop.
func (rc *RelayCircuit) BuildBudget() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.buildBudget
}

// SpendBuildBudget decrements the allowance at this hop.
//
// The budget is decremented at EVERY hop, not only at the client, because a
// client that ignores its own budget is exactly the client the budget exists to
// bound.
func (rc *RelayCircuit) SpendBuildBudget() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.buildBudget <= 0 {
		return ErrRelayBudget
	}
	rc.buildBudget--
	return nil
}

// NoteImpossibleCell is the relay-side counterpart of the client's counter.
func (rc *RelayCircuit) NoteImpossibleCell() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.drops++
	if rc.drops >= params.DropCellThreshold {
		return fmt.Errorf("%w: %d impossible cells", ErrDropThreshold, rc.drops)
	}
	return nil
}

// Drops is the impossible-cell count.
func (rc *RelayCircuit) Drops() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.drops
}

// AllocateID draws a fresh, unrelated circuit id.
//
// T5.3's property: the id on link G→M must differ from the id on client→G, and
// a correlator holding both must not be able to join them without the relay's
// table. So the new id is drawn from the system CSPRNG and is a function of
// NOTHING the correlator can see -- not the incoming id, not a counter, not the
// time. Any derivation, however obscure, would be a derivation the correlator
// can also compute.
func AllocateID() (link.CircuitID, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("axon/circuit: circuit id: %w", err)
		}
		id := link.CircuitID(binary.BigEndian.Uint64(b[:]))
		// Zero is reserved for link-level cells (§8.1).
		if id != 0 {
			return id, nil
		}
	}
}

// CircuitTable is a relay's circuit table, keyed per link.
type CircuitTable struct {
	mu sync.Mutex
	// byPrev maps (upstream peer, incoming id) to the circuit.
	byPrev map[linkKey]*RelayCircuit
	// byNext maps (downstream peer, outgoing id) to the same circuit, for
	// cells travelling toward the client.
	byNext map[linkKey]*RelayCircuit
	// quarantine holds recently-freed ids until they may be reused.
	quarantine map[linkKey]time.Time

	maxCircuits int
	now         func() time.Time

	// highWater is the largest the tables have been since the last compaction.
	//
	// A GO MAP NEVER RELEASES ITS BUCKET ARRAY. Deleting every entry leaves the
	// backing store at its high-water mark for the life of the map, so a relay
	// that once carried 100k circuits holds that much table forever even while
	// idle. It is bounded rather than monotone, which is why it took an exit
	// criterion to notice -- E5.3 measured 160 % of baseline after 1000
	// build/teardown cycles with every entry deleted.
	highWater int
}

type linkKey struct {
	peer string
	id   link.CircuitID
}

// NewCircuitTable builds an empty table.
func NewCircuitTable(now func() time.Time) *CircuitTable {
	if now == nil {
		now = time.Now
	}
	return &CircuitTable{
		byPrev:      map[linkKey]*RelayCircuit{},
		byNext:      map[linkKey]*RelayCircuit{},
		quarantine:  map[linkKey]time.Time{},
		maxCircuits: params.MaxCircuitsPerRelay,
		now:         now,
	}
}

// Len is the number of live circuits.
func (t *CircuitTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byPrev)
}

// Admit installs a circuit, allocating an independent outgoing id.
func (t *CircuitTable) Admit(prevPeer string, prevID link.CircuitID, crypto *HopWide) (*RelayCircuit, error) {
	if prevID == 0 {
		return nil, fmt.Errorf("%w: circuit id 0 is reserved for link cells", ErrCircuitExists)
	}
	nextID, err := AllocateID()
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.byPrev) >= t.maxCircuits {
		return nil, ErrRelayCapacity
	}
	k := linkKey{prevPeer, prevID}
	if _, exists := t.byPrev[k]; exists {
		return nil, ErrCircuitExists
	}
	if until, quarantined := t.quarantine[k]; quarantined && t.now().Before(until) {
		return nil, fmt.Errorf("%w: id is quarantined until %s", ErrCircuitExists, until)
	}

	rc := &RelayCircuit{
		PrevID: prevID, PrevPeer: prevPeer, NextID: nextID,
		Crypto: crypto, buildBudget: params.RelayBuildBudget, created: t.now(),
	}
	t.byPrev[k] = rc
	return rc, nil
}

// Link binds the downstream neighbour once the circuit is extended.
func (t *CircuitTable) Link(rc *RelayCircuit, nextPeer string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rc.NextPeer = nextPeer
	t.byNext[linkKey{nextPeer, rc.NextID}] = rc
}

// LookupForward finds a circuit by its incoming id.
func (t *CircuitTable) LookupForward(prevPeer string, id link.CircuitID) (*RelayCircuit, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rc, ok := t.byPrev[linkKey{prevPeer, id}]
	return rc, ok
}

// LookupBackward finds a circuit by its outgoing id.
func (t *CircuitTable) LookupBackward(nextPeer string, id link.CircuitID) (*RelayCircuit, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rc, ok := t.byNext[linkKey{nextPeer, id}]
	return rc, ok
}

// Teardown frees a circuit and quarantines both of its ids.
//
// T5.5: teardown propagates BOTH ways and frees state at every hop. The
// destroys are the caller's to emit, and §8.1 requires each relay to emit its
// OWN rather than forward one verbatim -- a forwarded DESTROY would carry the
// originator's reason code and framing across a hop that is supposed to
// re-originate everything.
func (t *CircuitTable) Teardown(rc *RelayCircuit) (notifyPrev, notifyNext string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rc.mu.Lock()
	already := rc.closed
	rc.closed = true
	rc.mu.Unlock()
	if already {
		return "", ""
	}

	until := t.now().Add(params.CircuitIDQuarantine)
	pk := linkKey{rc.PrevPeer, rc.PrevID}
	delete(t.byPrev, pk)
	t.quarantine[pk] = until

	if rc.NextPeer != "" {
		nk := linkKey{rc.NextPeer, rc.NextID}
		delete(t.byNext, nk)
		t.quarantine[nk] = until
	}
	return rc.PrevPeer, rc.NextPeer
}

// PruneQuarantine drops expired quarantine entries, compacts the tables when
// they have emptied out, and returns how many entries it dropped.
func (t *CircuitTable) PruneQuarantine() int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, until := range t.quarantine {
		if now.After(until) {
			delete(t.quarantine, k)
			n++
		}
	}
	t.compactLocked()
	return n
}

// compactThreshold is how far occupancy must fall below the high-water mark
// before the tables are rebuilt. A quarter is a compromise: rebuilding on every
// prune would make teardown O(table) instead of O(1), and never rebuilding
// leaves a relay holding its busiest hour's memory for the rest of its life.
const compactThreshold = 4

// compactLocked rebuilds the maps when they are mostly empty.
//
// Rebuilding is the only way to release a Go map's buckets. The cost is one
// allocation and a copy of the live entries, paid on a prune rather than on the
// teardown path, so a burst of teardowns does not pay for it.
func (t *CircuitTable) compactLocked() {
	live := len(t.byPrev) + len(t.byNext) + len(t.quarantine)
	if live > t.highWater {
		t.highWater = live
	}
	if t.highWater < 64 || live > t.highWater/compactThreshold {
		return
	}
	byPrev := make(map[linkKey]*RelayCircuit, len(t.byPrev))
	for k, v := range t.byPrev {
		byPrev[k] = v
	}
	byNext := make(map[linkKey]*RelayCircuit, len(t.byNext))
	for k, v := range t.byNext {
		byNext[k] = v
	}
	quar := make(map[linkKey]time.Time, len(t.quarantine))
	for k, v := range t.quarantine {
		quar[k] = v
	}
	t.byPrev, t.byNext, t.quarantine = byPrev, byNext, quar
	t.highWater = live
}

// -----------------------------------------------------------------------------
// Forwarding
// -----------------------------------------------------------------------------

// ForwardResult is what a relay decided to do with a cell.
type ForwardResult struct {
	// Terminal is true when this hop is the end of the circuit and the cell's
	// relay message is for it.
	Terminal bool
	// Out is the cell to send onward, with its id already rewritten.
	Out *link.Cell
	// Relay is the parsed message, set only when Terminal.
	Relay *RelayCell
}

// ProcessForward peels one layer and decides what happens next.
//
// The command class is checked BEFORE the extension rule, because a peer that
// puts an EXTEND in a plain RELAY is signalling and must be refused on that
// basis rather than on the budget.
func ProcessForward(rc *RelayCircuit, in *link.Cell, af [32]byte, terminal bool) (*ForwardResult, error) {
	if in.Command != link.CmdRelay && in.Command != link.CmdRelayBuild {
		return nil, fmt.Errorf("axon/circuit: %s is not an onioned command", in.Command)
	}
	block := append([]byte(nil), in.Payload...)
	if len(block) != BlockSize {
		return nil, ErrBlockSize
	}
	if err := WideOpenForwardAtHop(rc.Crypto, block); err != nil {
		return nil, err
	}

	if !terminal {
		out := &link.Cell{
			Circuit: rc.NextID, // T5.3: rewritten, and unrelated to PrevID
			Command: in.Command,
			Flags:   in.Flags,
			Payload: block,
		}
		if in.Command == link.CmdRelayBuild {
			if err := rc.SpendBuildBudget(); err != nil {
				return nil, err
			}
		}
		return &ForwardResult{Out: out}, nil
	}

	inner, err := OpenInnermost(af, block)
	if err != nil {
		return nil, err
	}
	msg, err := DecodeRelay(inner)
	if err != nil {
		return nil, err
	}
	// §8.1: EXTEND/EXTENDED inside a plain RELAY MUST be rejected.
	if msg.Cmd.ExtensionCommand() && in.Command != link.CmdRelayBuild {
		return nil, fmt.Errorf("%w: %s arrived in %s", ErrRelayNotBuild, msg.Cmd, in.Command)
	}
	if in.Command == link.CmdRelayBuild {
		if err := rc.SpendBuildBudget(); err != nil {
			return nil, err
		}
	}
	return &ForwardResult{Terminal: true, Relay: msg}, nil
}
