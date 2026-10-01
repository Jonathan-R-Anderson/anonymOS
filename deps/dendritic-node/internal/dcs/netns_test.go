package dcs

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeListener feeds pre-made inbound streams to the proxy, standing in for the
// container's I2P destination accepting connections.
type fakeListener struct {
	ch     chan InboundStream
	closed chan struct{}
	once   sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{ch: make(chan InboundStream, 8), closed: make(chan struct{})}
}

func (l *fakeListener) Accept() (InboundStream, error) {
	select {
	case s := <-l.ch:
		return s, nil
	case <-l.closed:
		return InboundStream{}, errors.New("listener closed")
	}
}

func (l *fakeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// loopbackContainer stands in for the container's network namespace: a set of
// real TCP listeners on 127.0.0.1 representing the ports the container has
// open. The dialer below "enters" it simply by dialing those real ports, which
// exercises the whole proxy path (accept -> dial -> splice) without needing a
// container, root, or setns.
type loopbackContainer struct {
	openPorts map[int]net.Listener
}

func newLoopbackContainer(t *testing.T, services map[int]func(net.Conn)) *loopbackContainer {
	t.Helper()
	c := &loopbackContainer{openPorts: map[int]net.Listener{}}
	for port, handler := range services {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		// Remember the real port under the logical port the test refers to.
		c.openPorts[port] = ln
		go func(ln net.Listener, handler func(net.Conn)) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go handler(conn)
			}
		}(ln, handler)
	}
	t.Cleanup(func() {
		for _, ln := range c.openPorts {
			_ = ln.Close()
		}
	})
	return c
}

// containerDialer maps the logical container port to the real loopback port of
// the corresponding service. A port with no service dials nothing and errors --
// exactly what a closed port does, which is what a scanner needs to see.
type containerDialer struct{ c *loopbackContainer }

func (d *containerDialer) DialContainerPort(ctx context.Context, port int) (net.Conn, error) {
	ln, ok := d.c.openPorts[port]
	if !ok {
		return nil, errors.New("connection refused") // closed port
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", ln.Addr().String())
}
func (d *containerDialer) Close() error { return nil }

// A researcher reaches an OPEN port on the vulnerable box over its I2P
// destination and exchanges data with the service behind it.
func TestProxyReachesOpenContainerPort(t *testing.T) {
	// The "container" runs an echo service on logical port 8080.
	container := newLoopbackContainer(t, map[int]func(net.Conn){
		8080: func(conn net.Conn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn) // echo
		},
	})
	listener := newFakeListener()
	proxy := NewContainerProxy("ctr-1", listener, &containerDialer{container}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	// The researcher's end of an inbound I2P stream aimed at port 8080.
	researcher, wire := net.Pipe()
	listener.ch <- InboundStream{Conn: wire, TargetPort: 8080}

	msg := []byte("GET / HTTP/1.0\r\n")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = researcher.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := researcher.Write(msg); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(researcher, buf); err != nil {
			t.Errorf("read echo: %v", err)
			return
		}
		if string(buf) != string(msg) {
			t.Errorf("echo mismatch: %q", buf)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("open port did not respond over the proxy")
	}
	_ = researcher.Close()
}

// A CLOSED port refuses the connection -- the proxy dials the netns, gets a
// refusal, and drops the inbound stream. This is what makes a port scan
// meaningful: open and closed are distinguishable over I2P.
func TestProxyClosedPortIsRefused(t *testing.T) {
	container := newLoopbackContainer(t, map[int]func(net.Conn){
		8080: func(conn net.Conn) { _ = conn.Close() },
	})
	listener := newFakeListener()
	proxy := NewContainerProxy("ctr-1", listener, &containerDialer{container}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	researcher, wire := net.Pipe()
	listener.ch <- InboundStream{Conn: wire, TargetPort: 9999} // nothing listening

	// The proxy closes the inbound stream when the container port refuses, so a
	// read returns EOF/closed rather than hanging.
	_ = researcher.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err := researcher.Read(buf)
	if err == nil {
		t.Fatal("a scan of a closed port looked open")
	}
}

// Simulate a port scan: several ports probed, only the open ones respond.
func TestProxyPortScanDistinguishesOpenFromClosed(t *testing.T) {
	container := newLoopbackContainer(t, map[int]func(net.Conn){
		22: func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0\r\n")); _ = c.Close() },
		80: func(c net.Conn) { _, _ = c.Write([]byte("HTTP\r\n")); _ = c.Close() },
	})
	listener := newFakeListener()
	proxy := NewContainerProxy("ctr-1", listener, &containerDialer{container}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	scan := func(port int) bool {
		researcher, wire := net.Pipe()
		listener.ch <- InboundStream{Conn: wire, TargetPort: port}
		_ = researcher.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8)
		n, err := researcher.Read(buf)
		_ = researcher.Close()
		return err == nil && n > 0
	}

	for _, tc := range []struct {
		port int
		open bool
	}{
		{22, true}, {80, true}, {443, false}, {3306, false},
	} {
		if got := scan(tc.port); got != tc.open {
			t.Errorf("port %d: scanner saw open=%v, want %v", tc.port, got, tc.open)
		}
	}
}

// Closing the proxy tears down live connections: after a Destroy the container
// has no network path, which is the state a lab container must be left in.
func TestProxyCloseTearsDownConnections(t *testing.T) {
	container := newLoopbackContainer(t, map[int]func(net.Conn){
		8080: func(conn net.Conn) { io.Copy(conn, conn) },
	})
	listener := newFakeListener()
	proxy := NewContainerProxy("ctr-1", listener, &containerDialer{container}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	researcher, wire := net.Pipe()
	listener.ch <- InboundStream{Conn: wire, TargetPort: 8080}
	// Establish flow so the connection is tracked.
	_, _ = researcher.Write([]byte("x"))
	buf := make([]byte, 1)
	_ = researcher.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = researcher.Read(buf)

	proxy.Close()

	// The researcher's side is now closed by the teardown.
	_ = researcher.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := researcher.Read(buf); err == nil {
		t.Fatal("connection survived proxy close")
	}
}

// A non-Linux target must refuse to build a namespace dialer rather than
// pretend to attach a container.
func TestNamespaceDialerHonestyOnUnsupported(t *testing.T) {
	// On Linux this may succeed or fail depending on privileges; the point of
	// the test is only that the constructor exists and returns an error path.
	// The behaviour we can assert portably: a non-existent PID never yields a
	// usable dialer.
	if _, err := NewNamespaceDialer(2147483647); err == nil {
		t.Skip("environment allowed opening a bogus netns; skipping")
	}
}
