package dcs

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// This file makes a container reachable AT its own I2P destination.
//
// THE PROBLEM
//
// A DCS container runs with Docker networking set to "none" (see runtime.go):
// it has its own network namespace containing only loopback, no veth, no
// bridge, no route to the host or the internet. That is deliberate -- a
// vulnerable box must not be able to reach anything. But it also means the
// container is, by default, reachable by nothing.
//
// THE BRIDGE
//
// Each container has its own I2P destination (address.go). The agent runs an
// inbound proxy that:
//
//   1. Accept()s a stream on the container's I2P destination.
//   2. Reads which TCP port the caller aimed at (SAMv3 per-stream port; for a
//      port scan, each probed port arrives as a separate accept).
//   3. Joins the CONTAINER'S network namespace and dials 127.0.0.1:<port>
//      there -- which is the container's own loopback, where its services bind.
//   4. Splices bytes between the I2P stream and the container socket.
//
// So a researcher who was handed the destination can scan or connect to the
// vulnerable box's ports over I2P, and nothing else can -- the destination is
// unpublished (lab containers), and the container has no other network path.
//
// Steps 1-3 are Linux- and root-specific and live in netns_linux.go behind the
// NamespaceDialer interface. Step 4, the byte pump, is OS-independent and lives
// here so it is unit-testable without a container.

// InboundStream is one accepted I2P connection to a container's destination.
// *i2p stream connections satisfy net.Conn; TargetPort is the port the caller
// aimed at, or 0 when the SAM session does not report one (then DefaultPort is
// used).
type InboundStream struct {
	Conn       net.Conn
	TargetPort int
}

// I2PListener accepts inbound streams on a container's destination. The i2p
// Session satisfies a thin adapter over this; the interface keeps the proxy
// testable with an in-memory listener.
type I2PListener interface {
	Accept() (InboundStream, error)
	Close() error
}

// NamespaceDialer dials a TCP port inside a container's network namespace. The
// real implementation (netns_linux.go) joins /proc/<pid>/ns/net; a test
// implementation dials an in-process listener.
type NamespaceDialer interface {
	// DialContainerPort connects to 127.0.0.1:port INSIDE the container's netns.
	DialContainerPort(ctx context.Context, port int) (net.Conn, error)
	Close() error
}

// ContainerProxy bridges a container's I2P destination to its loopback ports.
type ContainerProxy struct {
	ContainerID string
	DefaultPort int // used when an inbound stream reports no target port

	listener I2PListener
	dialer   NamespaceDialer
	logf     func(string, ...any)

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	dialTO time.Duration
	idleTO time.Duration
}

func NewContainerProxy(containerID string, listener I2PListener, dialer NamespaceDialer, logf func(string, ...any)) *ContainerProxy {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ContainerProxy{
		ContainerID: containerID,
		DefaultPort: 0,
		listener:    listener,
		dialer:      dialer,
		logf:        logf,
		conns:       map[net.Conn]struct{}{},
		dialTO:      10 * time.Second,
		idleTO:      5 * time.Minute,
	}
}

var ErrProxyClosed = errors.New("dcs: container proxy closed")

// Serve accepts inbound I2P streams until ctx is cancelled or the listener
// closes. Each accepted stream is handled concurrently.
func (p *ContainerProxy) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		p.Close()
	}()
	for {
		inbound, err := p.listener.Accept()
		if err != nil {
			if p.isClosed() {
				return nil
			}
			return err
		}
		go p.handle(ctx, inbound)
	}
}

func (p *ContainerProxy) handle(ctx context.Context, inbound InboundStream) {
	port := inbound.TargetPort
	if port == 0 {
		port = p.DefaultPort
	}
	// A port of 0 with no default means "the caller did not say and we have no
	// single service to assume" -- refuse rather than dial something arbitrary.
	if port <= 0 || port > 65535 {
		_ = inbound.Conn.Close()
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.dialTO)
	defer cancel()
	target, err := p.dialer.DialContainerPort(dialCtx, port)
	if err != nil {
		// A closed port is a normal outcome of a port scan; do not log it as an
		// error, just refuse the connection so the scanner sees it as closed.
		_ = inbound.Conn.Close()
		return
	}

	p.track(inbound.Conn)
	p.track(target)
	defer p.untrack(inbound.Conn)
	defer p.untrack(target)

	splice(inbound.Conn, target, p.idleTO)
}

// splice pumps bytes both directions until either side closes, resetting the
// idle deadline on activity. It is the OS-independent heart of the proxy and is
// what the tests exercise directly.
func splice(a, b net.Conn, idle time.Duration) {
	var once sync.Once
	stop := func() { _ = a.Close(); _ = b.Close() }
	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			if idle > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idle))
			}
			n, err := src.Read(buf)
			if n > 0 {
				if idle > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idle))
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					once.Do(stop)
					return
				}
			}
			if err != nil {
				once.Do(stop)
				return
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	wg.Wait()
}

func (p *ContainerProxy) track(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return
	}
	p.conns[c] = struct{}{}
}

func (p *ContainerProxy) untrack(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, c)
}

func (p *ContainerProxy) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// Close tears down the proxy: the listener, the netns dialer, and every live
// spliced connection. After this the container has no network path at all,
// which is exactly the state a destroyed lab container should be left in.
func (p *ContainerProxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.conns = map[net.Conn]struct{}{}
	p.mu.Unlock()

	_ = p.listener.Close()
	if p.dialer != nil {
		_ = p.dialer.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}
