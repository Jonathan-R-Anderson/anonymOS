// Package transport carries libp2p over AXON: the job internal/i2p did with a
// SAM session, done by this network's own overlay instead.
//
// A node's libp2p address is one of its AXON hidden services, written as the
// multiaddr /axon/<56 base32>. Dialing it builds a rendezvous to that service
// through the overlay (internal/axon/runtime) and runs the ordinary libp2p
// upgrade -- Noise, then a muxer -- over the resulting stream, so everything
// above (the DHT, the shard protocol, compute, DCS RPC) is unchanged.
//
// Neither end learns the other's IP. An inbound stream does not even say which
// AXON address it came from: a hidden service never learns its client's
// address, which is the point. libp2p still knows who it is talking to,
// because the Noise handshake authenticates the peer ID, and it learns the
// peer's own /axon address from identify like any other listen address.
package transport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

// P_AXON is the multiaddr code for an AXON service address. It is in the
// multicodec private-use range (0x300000-0x3fffff): nothing outside this
// network needs to parse it, and a code from the public table would claim a
// registration this protocol does not have.
const P_AXON = 0x3a0e01

// StreamMeta tags a stream that carries libp2p, so a service can also take
// other kinds of stream (a DCS container's ports) without confusing the two.
const StreamMeta = "/libp2p"

// registered is a variable rather than an init func so that package-level
// values built from /axon multiaddrs (anonymous, below) can depend on it: Go
// initialises variables in dependency order, and every init func after them.
var registered = func() bool {
	if err := ma.AddProtocol(ma.Protocol{
		Name:       "axon",
		Code:       P_AXON,
		VCode:      ma.CodeToVarint(P_AXON),
		Size:       ma.LengthPrefixedVarSize,
		Transcoder: ma.NewTranscoderFromFunctions(axonStringToBytes, axonBytesToString, axonValidate),
	}); err != nil {
		panic(fmt.Sprintf("axon/transport: register multiaddr protocol: %v", err))
	}
	return true
}()

// The value is the 56-character address itself, stored as text: it already
// carries its own checksum and version byte, so a binary form would only add a
// second encoding to keep in step.
func axonStringToBytes(s string) ([]byte, error) {
	bare, err := bareAddress(s)
	if err != nil {
		return nil, err
	}
	return []byte(bare), nil
}

func axonBytesToString(b []byte) (string, error) {
	if err := axonValidate(b); err != nil {
		return "", err
	}
	return string(b), nil
}

func axonValidate(b []byte) error {
	_, err := bareAddress(string(b))
	return err
}

// bareAddress validates an AXON address in either form and returns the bare
// 56-character, lowercase spelling used in multiaddrs.
func bareAddress(s string) (string, error) {
	pub, err := identity.ParseAddress(s)
	if err != nil {
		return "", err
	}
	return identity.Address(pub), nil
}

// Multiaddr is /axon/<addr> for an AXON service address in either form.
func Multiaddr(addr string) (ma.Multiaddr, error) {
	bare, err := bareAddress(addr)
	if err != nil {
		return nil, errors.New("invalid AXON address")
	}
	return ma.NewMultiaddr("/axon/" + bare)
}

// Address is the dialable "<addr>.key.axon" form of an /axon multiaddr.
func Address(m ma.Multiaddr) (string, error) {
	value, err := m.ValueForProtocol(P_AXON)
	if err != nil {
		return "", err
	}
	pub, err := identity.ParseAddress(value)
	if err != nil {
		return "", err
	}
	return identity.FullAddress(pub), nil
}

// IsAxonAddr reports whether m is /axon/<addr>, optionally followed by /p2p/<id>.
func IsAxonAddr(m ma.Multiaddr) bool {
	if m == nil {
		return false
	}
	protocols := m.Protocols()
	switch len(protocols) {
	case 1:
		return protocols[0].Code == P_AXON
	case 2:
		return protocols[0].Code == P_AXON && protocols[1].Code == ma.P_P2P
	}
	return false
}

// anonymous is the remote address reported for inbound connections. It is a
// well-formed address (the all-zero key) that nothing can listen on, so it
// satisfies libp2p's need for a remote multiaddr without inventing one.
var anonymous = func() ma.Multiaddr {
	_ = registered
	m, err := Multiaddr(identity.FullAddress(make(ed25519.PublicKey, ed25519.PublicKeySize)))
	if err != nil {
		panic(err)
	}
	return m
}()

// Dialer opens a stream to an AXON service. *runtime.Runtime satisfies it.
type Dialer interface {
	Dial(ctx context.Context, addr string, meta []byte) (net.Conn, error)
}

// Service is this node's own hidden service. *runtime.Service satisfies it.
type Service interface {
	Addr() string
	Accept() (net.Conn, error)
	Close() error
}

// Transport upgrades AXON streams into authenticated, multiplexed libp2p
// connections. It handles no IP, DNS, QUIC, WebSocket, relay or I2P address.
type Transport struct {
	upgrader transport.Upgrader
	rcmgr    network.ResourceManager
	dialer   Dialer
	service  Service
	local    ma.Multiaddr
}

func New(upgrader transport.Upgrader, rcmgr network.ResourceManager, dialer Dialer, service Service) (*Transport, error) {
	if dialer == nil || service == nil {
		return nil, errors.New("axon/transport: a dialer and a service are required")
	}
	if rcmgr == nil {
		rcmgr = &network.NullResourceManager{}
	}
	local, err := Multiaddr(service.Addr())
	if err != nil {
		return nil, err
	}
	return &Transport{upgrader: upgrader, rcmgr: rcmgr, dialer: dialer, service: service, local: local}, nil
}

func (t *Transport) Dial(ctx context.Context, remote ma.Multiaddr, id peer.ID) (transport.CapableConn, error) {
	if !t.CanDial(remote) {
		return nil, errors.New("refusing non-AXON peer address")
	}
	addr, err := Address(remote)
	if err != nil {
		return nil, err
	}
	scope, err := t.rcmgr.OpenConnection(network.DirOutbound, false, remote)
	if err != nil {
		return nil, err
	}
	if err := scope.SetPeer(id); err != nil {
		scope.Done()
		return nil, err
	}
	raw, err := t.dialer.Dial(ctx, addr, []byte(StreamMeta))
	if err != nil {
		scope.Done()
		return nil, err
	}
	conn := &multiaddrConn{Conn: raw, local: t.local, remote: withoutPeer(remote)}
	upgraded, err := t.upgrader.Upgrade(ctx, t, conn, network.DirOutbound, id, scope)
	if err != nil {
		raw.Close()
		scope.Done()
		return nil, err
	}
	return upgraded, nil
}

func (t *Transport) CanDial(remote ma.Multiaddr) bool {
	return IsAxonAddr(remote) && !remote.Equal(anonymous)
}

func (t *Transport) Listen(local ma.Multiaddr) (transport.Listener, error) {
	if !IsAxonAddr(local) || !withoutPeer(local).Equal(t.local) {
		return nil, errors.New("AXON transport may listen only on its own service address")
	}
	listener := &multiaddrListener{service: t.service, local: t.local, closed: make(chan struct{})}
	return t.upgrader.UpgradeListener(t, listener), nil
}

func (t *Transport) Protocols() []int { return []int{P_AXON} }
func (t *Transport) Proxy() bool      { return true }

// Close does nothing: the runtime and service belong to whoever started them.
func (t *Transport) Close() error { return nil }

func withoutPeer(value ma.Multiaddr) ma.Multiaddr {
	if component, err := value.ValueForProtocol(ma.P_P2P); err == nil && component != "" {
		peerPart, _ := ma.NewMultiaddr("/p2p/" + component)
		return value.Decapsulate(peerPart)
	}
	return value
}

type multiaddrConn struct {
	net.Conn
	local, remote ma.Multiaddr
}

func (c *multiaddrConn) LocalMultiaddr() ma.Multiaddr  { return c.local }
func (c *multiaddrConn) RemoteMultiaddr() ma.Multiaddr { return c.remote }

var _ manet.Conn = (*multiaddrConn)(nil)

type metaStream interface{ Meta() []byte }

type multiaddrListener struct {
	service Service
	local   ma.Multiaddr
	once    sync.Once
	closed  chan struct{}
}

func (l *multiaddrListener) Accept() (manet.Conn, error) {
	for {
		raw, err := l.service.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return nil, net.ErrClosed
			default:
			}
			return nil, err
		}
		// Only libp2p streams belong here. Anything else reaching this
		// service was opened for some other purpose and is refused rather
		// than fed to a Noise handshake that would fail on it anyway.
		if s, ok := raw.(metaStream); ok && string(s.Meta()) != StreamMeta {
			raw.Close()
			continue
		}
		return &multiaddrConn{Conn: raw, local: l.local, remote: anonymous}, nil
	}
}

func (l *multiaddrListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.service.Close()
	})
	return err
}

func (l *multiaddrListener) Addr() net.Addr          { return serviceAddr(l.service.Addr()) }
func (l *multiaddrListener) Multiaddr() ma.Multiaddr { return l.local }

var _ manet.Listener = (*multiaddrListener)(nil)

type serviceAddr string

func (serviceAddr) Network() string  { return "axon" }
func (a serviceAddr) String() string { return strings.ToLower(string(a)) }
