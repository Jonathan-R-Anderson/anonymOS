package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/swarm"
)

// Front is the origin's door on the dendritic network. Every client reaches it
// over an AXON session, and on that one session opens streams of two kinds:
// HTTP (coordinator, releases, crash intake, tracker) and swarm transfers. Front
// routes each stream by its OPEN metadata -- swarm.StreamMeta names a file -- so
// one session carries both and nothing is ever reached any other way.
type Front struct {
	host  *swarm.Host
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
	srv   *http.Server
}

// NewFront serves handler on network streams (each request context marked by
// MarkNetwork, so operator-only routes refuse it) and swarm streams on host.
func NewFront(handler http.Handler, host *swarm.Host) *Front {
	f := &Front{host: host, conns: make(chan net.Conn), done: make(chan struct{})}
	f.srv = &http.Server{Handler: handler, ConnContext: MarkNetwork}
	go f.srv.Serve(frontListener{f})
	return f
}

// ServeSession routes one client session's streams until it closes. The AXON
// service calls it for every session a client rendezvous with the origin opens.
func (f *Front) ServeSession(s *session.Session) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-f.done:
		case <-s.Done():
		}
		cancel()
	}()
	for {
		st, err := s.AcceptStream(ctx)
		if err != nil {
			return
		}
		if _, ok := swarm.ParseStreamMeta(st.Meta()); ok {
			go f.host.Accept(st, st.Meta())
			continue
		}
		select {
		case f.conns <- st:
		case <-f.done:
			st.Reset(session.ResetCancel)
			return
		}
	}
}

func (f *Front) Close() {
	f.once.Do(func() { close(f.done) })
	f.srv.Close()
}

type frontListener struct{ f *Front }

var errFrontClosed = errors.New("hos-origin: front closed")

func (l frontListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.f.conns:
		return c, nil
	case <-l.f.done:
		return nil, errFrontClosed
	}
}
func (l frontListener) Close() error   { l.f.once.Do(func() { close(l.f.done) }); return nil }
func (l frontListener) Addr() net.Addr { return session.Addr{} }
