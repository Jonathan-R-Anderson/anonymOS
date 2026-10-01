// Package runtime is AXON running: the process that wires the library packages
// (link, circuit, rendez, session, dht records, identity) into a node that
// relays cells for others, builds circuits of its own, publishes hidden
// services and connects to them. It is what replaces I2P: Dial and Listen give
// anonymous byte streams between AXON addresses, the role SAM played.
//
// One Runtime per node. A relay (Config.Relay) accepts links and forwards
// circuits; every node, relay or not, can be a client and host services.
//
// What it is built from, and what this version deliberately keeps simple:
//
//   - Links are libp2p connections (TCP and QUIC) authenticated to the peer's
//     NodeIdentity; one stream per circuit (internal/axon/link).
//   - The relay set is a DIRECTORY of self-signed RelayDescriptors (dht record
//     format and validator) that relays exchange among themselves and clients
//     fetch from their guard. It is Tor's model, not §7's DHT: with the relay
//     set known, a hidden-service descriptor's holders are simply the relays
//     nearest its replica keys, and nothing has to be looked up. The DHT can
//     replace the directory without changing anything above it.
//   - Hidden services follow §9.5: blinded descriptors at replica keys, intro
//     points, a client-chosen rendezvous point, the ntor-shaped rendezvous
//     handshake, and a session (internal/axon/session) on the joined circuit.
//   - Control traffic to a relay as such (directory, descriptor store/fetch) is
//     a session with the circuit's terminal hop, keyed from that hop's
//     handshake, so it is anonymous like everything else.
package runtime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
	"github.com/syndichan/maniwani/storage-client/internal/axon/identity"
	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/session"
)

// Config describes one node.
type Config struct {
	// DataDir holds node.key (the master seed), the pinned guard and service
	// keys. Required.
	DataDir string
	// Listen are libp2p multiaddrs for links, e.g. "/ip4/0.0.0.0/tcp/4001" and
	// "/ip4/0.0.0.0/udp/4001/quic-v1". Empty: outbound only (a pure client).
	Listen []string
	// Relay offers relaying. It needs Listen and a reachable address, and it
	// publishes this node's RelayDescriptor (R3: relaying is gated on being
	// reachable -- a relay nobody can reach is a hole in every path through it).
	Relay bool
	// Announce are the "ip:port" addresses the RelayDescriptor publishes. The
	// relay listens for TCP and QUIC on the same port. Empty: derived from Listen.
	Announce []string
	// Seeds are relays to fetch the directory from at start:
	// "/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo...". A relay with no seeds is a seed.
	Seeds []string
	// Hops is circuit length. Zero means params.DefaultHops.
	Hops int
	// Session configures the sessions this node opens and accepts.
	Session session.Config
	// AllowSameNetwork lets a path use relays in one network prefix -- for a
	// test network on one machine, never for a real one.
	AllowSameNetwork bool
	Logger           *log.Logger
}

// Runtime is one running node.
type Runtime struct {
	cfg     Config
	seed    identity.NodeSeed
	node    identity.NodeIdentity
	routing identity.RoutingIdentity
	prevRtg identity.RoutingIdentity // the previous epoch's, still answered
	host    host.Host
	dialer  *link.Dialer
	links   *link.Listener
	dir     *Directory
	relay   *relay
	log     *log.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	outLinks map[link.NodeID]link.Link
	guard    *RelayInfo
	services []*Service
	dials    map[string]*remote
}

var (
	ErrNoDataDir   = errors.New("axon/runtime: Config.DataDir is required")
	ErrRelayListen = errors.New("axon/runtime: a relay needs Listen addresses")
	ErrTooFewRelay = errors.New("axon/runtime: the directory has too few relays for a circuit")
	ErrClosed      = errors.New("axon/runtime: runtime closed")
)

// Start brings a node up: identity, link host, directory, and -- for a relay --
// the relay service and its published descriptor.
func Start(ctx context.Context, cfg Config) (*Runtime, error) {
	if cfg.DataDir == "" {
		return nil, ErrNoDataDir
	}
	if cfg.Relay && len(cfg.Listen) == 0 {
		return nil, ErrRelayListen
	}
	if cfg.Hops == 0 {
		cfg.Hops = params.DefaultHops
	}
	if cfg.Session.OrphanRetention == 0 {
		cfg.Session = session.DefaultConfig()
	}
	lg := cfg.Logger
	if lg == nil {
		lg = log.New(os.Stderr, "axon: ", log.LstdFlags)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	seed, err := identity.LoadOrCreateSeed(filepath.Join(cfg.DataDir, "node.key"))
	if err != nil {
		return nil, err
	}
	node := identity.DeriveNodeIdentity(seed)
	epoch := identity.PeriodNumber(time.Now())
	sk, err := libp2pcrypto.UnmarshalEd25519PrivateKey(node.PrivateKey())
	if err != nil {
		return nil, err
	}
	opts := []libp2p.Option{libp2p.Identity(sk), libp2p.DisableRelay()}
	if len(cfg.Listen) > 0 {
		opts = append(opts, libp2p.ListenAddrStrings(cfg.Listen...))
	} else {
		opts = append(opts, libp2p.NoListenAddrs)
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("axon/runtime: link host: %w", err)
	}
	rctx, cancel := context.WithCancel(ctx)
	rt := &Runtime{
		cfg: cfg, seed: seed, node: node,
		routing: identity.DeriveRoutingIdentity(seed, epoch),
		prevRtg: identity.DeriveRoutingIdentity(seed, epoch-1),
		host:    h, dialer: &link.Dialer{Host: h}, log: lg,
		ctx: rctx, cancel: cancel,
		outLinks: map[link.NodeID]link.Link{},
		dials:    map[string]*remote{},
	}
	rt.dir = newDirectory(rt)
	if cfg.Relay {
		rt.links = link.Listen(h)
		rt.relay = newRelay(rt)
		go rt.relay.acceptLinks()
		if err := rt.dir.publishSelf(); err != nil {
			rt.Close()
			return nil, err
		}
	}
	rt.dir.serve()
	if err := rt.dir.bootstrap(rctx); err != nil && !cfg.Relay {
		rt.Close()
		return nil, err
	}
	go rt.dir.maintain()
	return rt, nil
}

// Close stops the node.
func (rt *Runtime) Close() error {
	rt.cancel()
	rt.mu.Lock()
	svcs := rt.services
	rems := rt.dials
	rt.dials = map[string]*remote{}
	rt.mu.Unlock()
	for _, s := range svcs {
		s.Close()
	}
	for _, r := range rems {
		r.close()
	}
	return rt.host.Close()
}

// NodeID is this node's link identity.
func (rt *Runtime) NodeID() link.NodeID { return rt.host.ID() }

// Addrs are the multiaddrs this node's links listen on, with its peer id.
func (rt *Runtime) Addrs() []string {
	var out []string
	for _, a := range rt.host.Addrs() {
		out = append(out, a.String()+"/p2p/"+rt.host.ID().String())
	}
	return out
}

// Directory is the relay set this node currently knows.
func (rt *Runtime) Directory() *Directory { return rt.dir }

// static is this relay's current ntor key material.
func (rt *Runtime) static(r identity.RoutingIdentity) circuit.RelayStatic {
	var s circuit.RelayStatic
	copy(s.RID[:], r.EdPublic)
	s.B = r.XPublic
	s.Epoch = r.Epoch
	return s
}

// linkTo returns a link to a relay, dialling it if need be.
func (rt *Runtime) linkTo(ctx context.Context, ri *RelayInfo) (link.Link, error) {
	rt.mu.Lock()
	if lk, ok := rt.outLinks[ri.Peer]; ok {
		rt.mu.Unlock()
		return lk, nil
	}
	rt.mu.Unlock()
	rt.host.Peerstore().AddAddrs(ri.Peer, ri.Multiaddrs(), time.Hour)
	dctx, cancel := context.WithTimeout(ctx, params.LinkTimeout)
	defer cancel()
	lk, err := rt.dialer.Dial(dctx, ri.Peer)
	if err != nil {
		return nil, err
	}
	rt.mu.Lock()
	if prev, ok := rt.outLinks[ri.Peer]; ok {
		rt.mu.Unlock()
		lk.Close()
		return prev, nil
	}
	rt.outLinks[ri.Peer] = lk
	rt.mu.Unlock()
	return lk, nil
}

// dropLink forgets a link that failed, so the next use redials.
func (rt *Runtime) dropLink(id link.NodeID) {
	rt.mu.Lock()
	if lk, ok := rt.outLinks[id]; ok {
		delete(rt.outLinks, id)
		lk.Close()
	}
	rt.mu.Unlock()
}

// parsePeerAddr splits "/ip4/.../p2p/<id>".
func parsePeerAddr(s string) (peer.AddrInfo, error) {
	m, err := ma.NewMultiaddr(s)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	ai, err := peer.AddrInfoFromP2pAddr(m)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	return *ai, nil
}

// nodePubOf is the Ed25519 key a link NodeID was derived from.
func nodePubOf(id link.NodeID) (ed25519.PublicKey, error) {
	pk, err := id.ExtractPublicKey()
	if err != nil {
		return nil, err
	}
	raw, err := pk.Raw()
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("axon/runtime: %s is not an Ed25519 identity", id)
	}
	return ed25519.PublicKey(raw), nil
}
