package i2p

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// Transport upgrades I2P SAM streams into authenticated, multiplexed libp2p
// connections. It intentionally handles no IP, DNS, QUIC, WebSocket, or relay
// multiaddresses.
type Transport struct {
	upgrader transport.Upgrader
	rcmgr    network.ResourceManager
	session  *Session
	local    ma.Multiaddr
}

func NewTransport(upgrader transport.Upgrader, rcmgr network.ResourceManager, session *Session) (*Transport, error) {
	if session == nil {
		return nil, errors.New("I2P session is required")
	}
	if rcmgr == nil {
		rcmgr = &network.NullResourceManager{}
	}
	local, err := Multiaddr(session.Base32())
	if err != nil {
		return nil, err
	}
	return &Transport{upgrader: upgrader, rcmgr: rcmgr, session: session, local: local}, nil
}

func Multiaddr(base32Host string) (ma.Multiaddr, error) {
	base32Host = normalizeBase32Host(base32Host)
	if !validBase32Host(base32Host) {
		return nil, errors.New("invalid I2P base32 destination")
	}
	return ma.NewMultiaddr("/garlic32/" + base32Host)
}

func IsI2PAddr(value ma.Multiaddr) bool {
	if value == nil {
		return false
	}
	protocols := value.Protocols()
	if len(protocols) == 1 {
		return protocols[0].Code == ma.P_GARLIC32
	}
	if len(protocols) == 2 {
		return protocols[0].Code == ma.P_GARLIC32 && protocols[1].Code == ma.P_P2P
	}
	return false
}

func (t *Transport) Dial(ctx context.Context, remote ma.Multiaddr, id peer.ID) (transport.CapableConn, error) {
	if !t.CanDial(remote) {
		return nil, errors.New("refusing non-I2P peer address")
	}
	scope, err := t.rcmgr.OpenConnection(network.DirOutbound, false, remote)
	if err != nil {
		return nil, err
	}
	if err := scope.SetPeer(id); err != nil {
		scope.Done()
		return nil, err
	}
	base32Host, err := remote.ValueForProtocol(ma.P_GARLIC32)
	if err != nil {
		scope.Done()
		return nil, err
	}
	raw, err := t.session.Dial(ctx, base32Host)
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
	return IsI2PAddr(remote) && hasOnlyGarlicAndOptionalPeer(remote)
}

func (t *Transport) Listen(local ma.Multiaddr) (transport.Listener, error) {
	if !IsI2PAddr(local) || withoutPeer(local).String() != t.local.String() {
		return nil, errors.New("I2P transport may listen only on its persistent destination")
	}
	listener := &multiaddrListener{
		session: t.session, local: t.local, closed: make(chan struct{}),
	}
	return t.upgrader.UpgradeListener(t, listener), nil
}

func (t *Transport) Protocols() []int { return []int{ma.P_GARLIC32} }
func (t *Transport) Proxy() bool      { return true }
func (t *Transport) Close() error     { return t.session.Close() }

func hasOnlyGarlicAndOptionalPeer(value ma.Multiaddr) bool {
	for index, protocol := range value.Protocols() {
		if index == 0 && protocol.Code == ma.P_GARLIC32 {
			continue
		}
		if index == 1 && protocol.Code == ma.P_P2P {
			continue
		}
		return false
	}
	return true
}

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

type multiaddrListener struct {
	session *Session
	local   ma.Multiaddr
	once    sync.Once
	closed  chan struct{}
}

// acceptRetryDelay bounds how fast a failing accept is retried. Short enough
// that a real inbound connection is not delayed noticeably, long enough that a
// persistently broken session does not spin the CPU.
const acceptRetryDelay = 2 * time.Second

func (l *multiaddrListener) Accept() (manet.Conn, error) {
	for {
		select {
		case <-l.closed:
			return nil, net.ErrClosed
		default:
		}
		raw, err := l.session.Accept()
		if err != nil {
			// A waiting STREAM ACCEPT is a long-lived idle socket, and I2P
			// routers close those: the SAM connection returns EOF after a few
			// minutes with no inbound connection. That is ROUTINE, not fatal.
			//
			// Returning it to libp2p was fatal, though -- the swarm treats a
			// non-temporary accept error as terminal and logs "swarm listener
			// unintentionally closed", after which the node can never receive
			// an inbound connection again. In practice every node went deaf
			// about six minutes after starting, so peers could dial it exactly
			// never and shards could not be placed anywhere.
			//
			// Re-issue the accept instead. Only a genuine Close() ends the loop.
			select {
			case <-l.closed:
				return nil, net.ErrClosed
			default:
			}
			time.Sleep(acceptRetryDelay)
			continue
		}
		remoteHost := strings.TrimSuffix(raw.RemoteAddr().String(), ".b32.i2p")
		remote, err := Multiaddr(remoteHost)
		if err != nil {
			// One malformed peer address must not kill the listener either.
			raw.Close()
			continue
		}
		return &multiaddrConn{Conn: raw, local: l.local, remote: remote}, nil
	}
}

func (l *multiaddrListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.session.Close()
	})
	return err
}

func (l *multiaddrListener) Addr() net.Addr          { return addr(l.session.Base32() + ".b32.i2p") }
func (l *multiaddrListener) Multiaddr() ma.Multiaddr { return l.local }

var _ manet.Listener = (*multiaddrListener)(nil)
