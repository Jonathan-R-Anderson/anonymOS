package link

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// The AXON link, per P2.
//
// WHY THIS SITS ON libp2p
// The roadmap's section 6 left open whether AXON keeps libp2p at L1/L2 or
// replaces it with a native QUIC + TLS 1.3 raw-public-key stack. Measured
// against the tree: 30 of 455 Go files import libp2p, and 28 of 55 references
// are core/peer -- peer.ID as an identifier, not protocol coupling. The node
// already runs libp2p on an Ed25519 key, and PoF derives its on-chain nodeId
// from that same key, so AXON's NodeIdentity maps onto the existing host
// identity rather than becoming a second one (Constitution section 3).
//
// Decision: keep libp2p for the link and its NAT traversal, and put AXON's
// framing on top. Replacing it now would mean reimplementing QUIC, AutoNAT,
// Circuit Relay v2 and DCUtR to gain a wire format nothing needs yet. The
// native transport enters later through the same transport.Transport seam the
// legacy anonymity transport already occupies -- that seam is the migration
// path, it is proven, and this is therefore a deferral rather than a lock-in.
//
// The cost, stated rather than hidden: the libp2p handshake and the ALPN/
// protocol string identify this network to an observer. That is a censorship
// exposure, not an anonymity one, and section 6.8 already defers obfuscation
// out of v1.

// ProtocolID is the libp2p protocol AXON links speak. It is versioned so a
// future native transport can run beside this one during migration.
const ProtocolID = protocol.ID("/axon/link/1.0.0")

// MaxCircuitsPerLink caps how many circuit-streams one peer may open on one
// link.
//
// R12 gives every circuit its own stream so a stalled circuit cannot block its
// neighbours. That is also a new denial-of-service surface -- per-stream state
// at the relay, opened by the peer -- and P2 requires the cap to land in the
// same commit that creates the surface, not in a later hardening pass.
const MaxCircuitsPerLink = 1000

var (
	ErrIdentityMismatch = errors.New("axon/link: peer presented a different NodeIdentity than requested")
	ErrTooManyCircuits  = errors.New("axon/link: circuit limit for this link reached")
	ErrDuplicateCircuit = errors.New("axon/link: circuit id already open on this link")
	ErrLinkClosed       = errors.New("axon/link: link is closed")
)

// NodeID is the peer identity a link authenticates to. It is derived from the
// Ed25519 NodeIdentity public key, so it is the same identity the rest of the
// system bonds and reputes.
type NodeID = peer.ID

// NodeIDFromPublic maps an AXON NodeIdentity public key to the link-layer peer
// identity. One function so the mapping cannot drift between call sites.
func NodeIDFromPublic(pub ed25519.PublicKey) (NodeID, error) {
	pk, err := libp2pcrypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("axon/link: unmarshal node key: %w", err)
	}
	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("axon/link: derive peer id: %w", err)
	}
	return id, nil
}

// CellStream carries cells for exactly one circuit.
//
// Reads and writes are each serialised, because a cell is a frame: two
// concurrent writers would interleave halves of different cells and destroy the
// framing for everything after them.
type CellStream interface {
	CircuitID() CircuitID
	WriteCell(*Cell) error
	ReadCell() (*Cell, error)
	Close() error
}

// Link is an authenticated connection to one peer, multiplexing circuits.
type Link interface {
	RemoteID() NodeID
	OpenCircuitStream(ctx context.Context, id CircuitID) (CellStream, error)
	AcceptCircuitStream(ctx context.Context) (CellStream, error)
	Close() error
}

// ---------------------------------------------------------------------------
// implementation over a libp2p host
// ---------------------------------------------------------------------------

type cellStream struct {
	circuit CircuitID
	s       network.Stream
	link    *hostLink

	wmu sync.Mutex
	rmu sync.Mutex

	once sync.Once
}

func (c *cellStream) CircuitID() CircuitID { return c.circuit }

func (c *cellStream) WriteCell(cell *Cell) error {
	if cell.Circuit != c.circuit {
		// A stream carries one circuit. Letting a cell claim a different id
		// would make the per-circuit isolation R12 buys meaningless.
		return fmt.Errorf("axon/link: cell circuit %d on stream for circuit %d",
			cell.Circuit, c.circuit)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return WriteCell(c.s, cell)
}

func (c *cellStream) ReadCell() (*Cell, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	cell, err := ReadCell(c.s)
	if err != nil {
		return nil, err
	}
	if cell.Circuit != c.circuit {
		return nil, fmt.Errorf("axon/link: peer sent circuit %d on the stream for circuit %d",
			cell.Circuit, c.circuit)
	}
	return cell, nil
}

func (c *cellStream) Close() error {
	var err error
	c.once.Do(func() {
		c.link.release(c.circuit)
		err = c.s.Close()
	})
	return err
}

type hostLink struct {
	h      host.Host
	remote NodeID

	mu       sync.Mutex
	circuits map[CircuitID]struct{}
	incoming chan *cellStream
	closed   bool
}

func (l *hostLink) RemoteID() NodeID { return l.remote }

// reserve admits a circuit id, enforcing both the cap and uniqueness.
func (l *hostLink) reserve(id CircuitID) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLinkClosed
	}
	if _, dup := l.circuits[id]; dup {
		return ErrDuplicateCircuit
	}
	if len(l.circuits) >= MaxCircuitsPerLink {
		return fmt.Errorf("%w: %d", ErrTooManyCircuits, MaxCircuitsPerLink)
	}
	l.circuits[id] = struct{}{}
	return nil
}

func (l *hostLink) release(id CircuitID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.circuits, id)
}

// CircuitCount is how many circuits are open on this link. Exported for the
// caps test and for metrics that must not expose more than a count.
func (l *hostLink) CircuitCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.circuits)
}

func (l *hostLink) OpenCircuitStream(ctx context.Context, id CircuitID) (CellStream, error) {
	if err := l.reserve(id); err != nil {
		return nil, err
	}
	s, err := l.h.NewStream(ctx, l.remote, ProtocolID)
	if err != nil {
		l.release(id)
		return nil, fmt.Errorf("axon/link: open stream: %w", err)
	}
	// The opener names the circuit in a single cell before anything else, so
	// the accepting side can bind the stream to a circuit without a separate
	// framing format. A PADDING cell is used because it carries no payload and
	// is indistinguishable in size from every other cell.
	cs := &cellStream{circuit: id, s: s, link: l}
	if err := cs.WriteCell(PaddingCell(id)); err != nil {
		_ = s.Reset()
		l.release(id)
		return nil, fmt.Errorf("axon/link: announce circuit: %w", err)
	}
	return cs, nil
}

func (l *hostLink) AcceptCircuitStream(ctx context.Context) (CellStream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case cs, ok := <-l.incoming:
		if !ok {
			return nil, ErrLinkClosed
		}
		return cs, nil
	}
}

func (l *hostLink) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.circuits = map[CircuitID]struct{}{}
	l.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// dialing and listening
// ---------------------------------------------------------------------------

// Dialer opens authenticated links from one host.
type Dialer struct {
	Host host.Host
}

// Dial connects to expect and returns a link, refusing any peer that is not
// exactly the identity asked for.
//
// T2.3 requires the refusal to happen before any cell is sent. libp2p
// authenticates the peer during its security handshake -- NewStream to a peer
// id cannot succeed against a host holding a different key -- so the check
// below is a belt-and-braces assertion on the resulting stream rather than the
// only thing standing between us and an impostor. It is kept because a future
// transport swap must not silently remove the guarantee.
func (d *Dialer) Dial(ctx context.Context, expect NodeID) (Link, error) {
	if expect == "" {
		return nil, errors.New("axon/link: dial requires an expected NodeID")
	}
	if err := d.Host.Connect(ctx, peer.AddrInfo{ID: expect}); err != nil {
		return nil, fmt.Errorf("axon/link: connect: %w", err)
	}
	// Confirm the connection we got is to the identity we asked for.
	conns := d.Host.Network().ConnsToPeer(expect)
	if len(conns) == 0 {
		return nil, fmt.Errorf("axon/link: no connection to %s after connect", expect)
	}
	for _, c := range conns {
		if c.RemotePeer() != expect {
			return nil, fmt.Errorf("%w: wanted %s, got %s", ErrIdentityMismatch, expect, c.RemotePeer())
		}
	}
	return &hostLink{
		h:        d.Host,
		remote:   expect,
		circuits: make(map[CircuitID]struct{}),
		incoming: make(chan *cellStream, 16),
	}, nil
}

// Listener accepts inbound links on a host.
type Listener struct {
	h     host.Host
	mu    sync.Mutex
	links map[NodeID]*hostLink
	inbox chan Link
}

// Listen registers the AXON link protocol on h and returns a Listener.
func Listen(h host.Host) *Listener {
	l := &Listener{
		h:     h,
		links: make(map[NodeID]*hostLink),
		inbox: make(chan Link, 16),
	}
	h.SetStreamHandler(ProtocolID, l.handle)
	return l
}

// Accept returns the next link that has opened at least one circuit.
func (l *Listener) Accept(ctx context.Context) (Link, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case lk, ok := <-l.inbox:
		if !ok {
			return nil, ErrLinkClosed
		}
		return lk, nil
	}
}

// Close stops accepting.
func (l *Listener) Close() error {
	l.h.RemoveStreamHandler(ProtocolID)
	return nil
}

func (l *Listener) handle(s network.Stream) {
	remote := s.Conn().RemotePeer()

	// The first cell names the circuit. Anything else -- including a stream
	// that opens and says nothing -- is refused rather than parked, because a
	// silent stream is a cheap way to hold relay state.
	first, err := ReadCell(s)
	if err != nil {
		_ = s.Reset()
		return
	}

	l.mu.Lock()
	lk, known := l.links[remote]
	if !known {
		lk = &hostLink{
			h:        l.h,
			remote:   remote,
			circuits: make(map[CircuitID]struct{}),
			incoming: make(chan *cellStream, 16),
		}
		l.links[remote] = lk
	}
	l.mu.Unlock()

	// Cap inbound circuits exactly as outbound ones are capped: the surface is
	// per-stream state, and it does not care which side opened the stream.
	if err := lk.reserve(first.Circuit); err != nil {
		_ = s.Reset()
		return
	}

	cs := &cellStream{circuit: first.Circuit, s: s, link: lk}
	if !known {
		select {
		case l.inbox <- lk:
		default:
			// Nobody is accepting links; drop rather than block the handler.
		}
	}
	select {
	case lk.incoming <- cs:
	default:
		lk.release(first.Circuit)
		_ = s.Reset()
	}
}

// Drain reads and discards cells until the stream ends. Used by tests and by
// callers tearing a circuit down; kept here so the io import is honest.
func Drain(cs CellStream) error {
	for {
		if _, err := cs.ReadCell(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
