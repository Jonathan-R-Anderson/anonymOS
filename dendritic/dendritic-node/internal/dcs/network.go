package dcs

import (
	"context"
	"net"
	"sync"
)

// This file ties the container's I2P destination (a SAM session) to the
// container's network namespace (the ContainerProxy). It is the seam between
// "the container has an address" and "the address reaches the container".

// SessionAccepter is the subset of internal/i2p.Session the proxy needs: accept
// inbound streams on the container's destination -- WITH the port the caller
// dialed -- and close. *i2p.Session satisfies it via AcceptStreamPort. Kept as
// an interface so this package does not hard-depend on the SAM client.
type SessionAccepter interface {
	// AcceptStreamPort returns an inbound stream and the TO_PORT the remote peer
	// dialed on this destination (0 when the router does not report one).
	AcceptStreamPort() (net.Conn, int, error)
	Close() error
}

// sessionListener adapts a SAM session to I2PListener.
//
// MULTI-PORT: yes, one I2P destination carries many ports. A destination is not
// "one port"; SAM v3.2+ multiplexes up to 65536 ports over it via TO_PORT, and
// internal/i2p.AcceptStreamPort surfaces the port each inbound stream targeted.
// So a port scan of the container's single destination arrives here as separate
// accepts, each carrying the probed port, and the proxy dials that exact port
// inside the container's netns. A router that negotiated a pre-3.2 version
// reports port 0, and those streams fall through to the proxy's DefaultPort --
// the graceful degradation, not the design.
type sessionListener struct {
	session SessionAccepter
}

// NewSessionListener wraps a SAM session as an I2PListener.
func NewSessionListener(session SessionAccepter) I2PListener {
	return &sessionListener{session: session}
}

func (l *sessionListener) Accept() (InboundStream, error) {
	conn, toPort, err := l.session.AcceptStreamPort()
	if err != nil {
		return InboundStream{}, err
	}
	return InboundStream{Conn: conn, TargetPort: toPort}, nil
}

func (l *sessionListener) Close() error { return l.session.Close() }

// ContainerNetwork is the per-container network attachment the agent owns for
// the life of a container. Attach starts the inbound proxy; Detach stops it and
// leaves the container with no network path.
type ContainerNetwork struct {
	mu     sync.Mutex
	proxy  *ContainerProxy
	cancel context.CancelFunc
}

// AttachInbound bridges a container's destination to its loopback ports.
//
//	listener    — accepts on the container's I2P destination (NewSessionListener)
//	dialer      — enters the container's netns (NewNamespaceDialer, Linux)
//	primaryPort — where a portless inbound stream is routed (the container's
//	              main service); 0 means "refuse portless streams"
//
// It returns immediately; the accept loop runs until Detach or the container
// stops. Errors from the loop are terminal only for the loop, never for the
// agent -- a container losing its inbound path is a liveness problem for that
// one container, logged, not a crash.
func (n *ContainerNetwork) AttachInbound(containerID string, listener I2PListener, dialer NamespaceDialer, primaryPort int, logf func(string, ...any)) {
	n.mu.Lock()
	defer n.mu.Unlock()

	proxy := NewContainerProxy(containerID, listener, dialer, logf)
	proxy.DefaultPort = primaryPort
	ctx, cancel := context.WithCancel(context.Background())
	n.proxy = proxy
	n.cancel = cancel

	go func() {
		if err := proxy.Serve(ctx); err != nil && logf != nil {
			logf("dcs: container %s inbound proxy stopped: %v", containerID, err)
		}
	}()
}

// Detach tears the network down. After this the container is reachable by
// nothing, which is the correct end state for a stopped or destroyed container
// -- especially a lab one.
func (n *ContainerNetwork) Detach() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cancel != nil {
		n.cancel()
		n.cancel = nil
	}
	if n.proxy != nil {
		_ = n.proxy.Close()
		n.proxy = nil
	}
}
