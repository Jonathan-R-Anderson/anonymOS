package session

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Listener is a net.Listener over the streams that any of its sessions'
// clients open: what a service hands to http.Serve. A session is added with
// Serve once its rendezvous completes; streams from every session arrive on
// one Accept, as connections from many clients arrive on one TCP listener.
type Listener struct {
	ch   chan *Stream
	done chan struct{}
	once sync.Once
}

var ErrListenerClosed = errors.New("axon/session: listener closed")

func NewListener() *Listener {
	return &Listener{ch: make(chan *Stream), done: make(chan struct{})}
}

// Serve feeds the session's incoming streams to Accept until the session or
// the listener closes. It returns at once; the work is on its own goroutine.
func (l *Listener) Serve(s *Session) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-l.done:
		case <-s.Done():
		}
		cancel()
	}()
	go func() {
		defer cancel()
		for {
			st, err := s.AcceptStream(ctx)
			if err != nil {
				return
			}
			select {
			case l.ch <- st:
			case <-l.done:
				st.Reset(ResetCancel)
				return
			}
		}
	}()
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case st := <-l.ch:
		return st, nil
	case <-l.done:
		return nil, ErrListenerClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *Listener) Addr() net.Addr { return Addr{} }

// DialContext opens a stream whose OPEN metadata is addr: the shape
// http.Transport.DialContext wants, so an HTTP client reaches a service over
// this session with nothing else changed.
func (s *Session) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.OpenStream([]byte(addr))
}

var _ net.Listener = (*Listener)(nil)
