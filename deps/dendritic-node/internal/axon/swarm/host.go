package swarm

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// Finding peers and connecting to them.
//
// A PeerAddr is opaque here: in the OS it is a node's AXON service address, and
// a Dialer opens a session stream to it. A Tracker answers "who has this file":
// the origin server's coordinator does (it already knows every live node from its
// heartbeats), and DHT location records (§7's ClassLocation) can later stand in
// for it so the swarm keeps working while the origin is down.

// PeerAddr is where a peer can be reached.
type PeerAddr string

// Tracker introduces peers in one file's swarm to each other.
type Tracker interface {
	// Announce says this node is in the swarm for root (and whether it is done).
	Announce(ctx context.Context, root [32]byte, self PeerAddr, complete bool) error
	// Peers returns up to max other members, chosen at random.
	Peers(ctx context.Context, root [32]byte, max int) ([]PeerAddr, error)
}

// Dialer opens a connection to a peer: a session stream whose OPEN metadata is
// StreamMeta(root), so the peer's Host can route it.
type Dialer interface {
	Dial(ctx context.Context, addr PeerAddr, meta []byte) (net.Conn, error)
}

// StreamMeta names a swarm on a stream's OPEN: "axon-swarm/1 <root hex>".
func StreamMeta(root [32]byte) []byte {
	return []byte("axon-swarm/1 " + hex.EncodeToString(root[:]))
}

// ParseStreamMeta is StreamMeta's inverse.
func ParseStreamMeta(b []byte) ([32]byte, bool) {
	var root [32]byte
	rest, ok := strings.CutPrefix(string(b), "axon-swarm/1 ")
	if !ok {
		return root, false
	}
	h, err := hex.DecodeString(rest)
	if err != nil || len(h) != 32 {
		return root, false
	}
	copy(root[:], h)
	return root, true
}

// Host is every swarm one node takes part in, and the accept side of them all.
type Host struct {
	mu     sync.Mutex
	swarms map[[32]byte]*Swarm
}

func NewHost() *Host { return &Host{swarms: map[[32]byte]*Swarm{}} }

// Add registers a swarm so incoming streams for its file reach it.
func (h *Host) Add(s *Swarm) {
	h.mu.Lock()
	h.swarms[s.meta.Root] = s
	h.mu.Unlock()
}

// Swarm returns the swarm for a file, or nil.
func (h *Host) Swarm(root [32]byte) *Swarm {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.swarms[root]
}

// Remove unregisters and closes a swarm.
func (h *Host) Remove(root [32]byte) {
	h.mu.Lock()
	s := h.swarms[root]
	delete(h.swarms, root)
	h.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

var ErrNoSwarm = errors.New("axon/swarm: no swarm for that file on this node")

// Accept serves an incoming stream (meta is its OPEN metadata) until it ends.
func (h *Host) Accept(conn net.Conn, meta []byte) error {
	root, ok := ParseStreamMeta(meta)
	if !ok {
		conn.Close()
		return ErrWire
	}
	h.mu.Lock()
	s := h.swarms[root]
	h.mu.Unlock()
	if s == nil {
		conn.Close()
		return ErrNoSwarm
	}
	return s.Serve(conn)
}

// RunConfig says how a node finds peers for one swarm.
type RunConfig struct {
	Self     PeerAddr
	Tracker  Tracker
	Dialer   Dialer
	MaxPeers int           // connections this node opens (default 8)
	Interval time.Duration // how often it re-announces and tops up (default 30 s)
}

// Run announces the node and keeps it connected to up to MaxPeers peers until
// ctx ends. Inbound connections come through Host.Accept and are not counted
// against MaxPeers: a popular node serving many is the point.
func (s *Swarm) Run(ctx context.Context, rc RunConfig) {
	if rc.MaxPeers <= 0 {
		rc.MaxPeers = 8
	}
	if rc.Interval <= 0 {
		rc.Interval = 30 * time.Second
	}
	var mu sync.Mutex
	dialed := map[PeerAddr]bool{}
	for {
		_ = rc.Tracker.Announce(ctx, s.meta.Root, rc.Self, s.isComplete())
		mu.Lock()
		need := rc.MaxPeers - len(dialed)
		mu.Unlock()
		if need > 0 && !s.isComplete() {
			addrs, _ := rc.Tracker.Peers(ctx, s.meta.Root, rc.MaxPeers*2)
			for _, a := range addrs {
				mu.Lock()
				skip := a == rc.Self || dialed[a] || len(dialed) >= rc.MaxPeers
				if !skip {
					dialed[a] = true
				}
				mu.Unlock()
				if skip {
					continue
				}
				go func(a PeerAddr) {
					defer func() { mu.Lock(); delete(dialed, a); mu.Unlock() }()
					conn, err := rc.Dialer.Dial(ctx, a, StreamMeta(s.meta.Root))
					if err != nil {
						return
					}
					stop := context.AfterFunc(ctx, func() { conn.Close() })
					defer stop()
					_ = s.Serve(conn)
				}(a)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-time.After(rc.Interval):
		}
	}
}

func (s *Swarm) isComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.complete()
}
