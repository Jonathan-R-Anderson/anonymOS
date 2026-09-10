package channel

// SCPP/1 transport — roadmap P5-3.
//
// THIS LAYER IS DELIBERATELY STUPID
// ---------------------------------
// It carries a serialised frame from one node to another and hands what comes
// back to the coordinator. It does not decide:
//
//	whether a channel exists          — the chain does, via Coordinator.Adopt
//	whether a payment is valid        — Channel.Accept does
//	whether a state should be adopted — PeerSession.HandleResponse does
//	whether a deposit is real         — the chain does
//	whether a lock is claimable       — the state machine and the clock do
//
// Every one of those already has an owner. A transport that starts answering
// them is a second payment implementation wearing a networking costume.
//
// A WRITE THAT SUCCEEDED IS NOT A PAYMENT THAT HAPPENED
// -----------------------------------------------------
// The single most dangerous thing this file could do is treat a successful
// send as a completed payment. It never does, and the shape of the code is
// what stops it: Exchange returns the peer's REPLY or an error, and a payment
// is complete only when a fully signed state has been committed. There is no
// path here that reports success on its own authority.
//
// So a connection dying mid-payment is an ordinary protocol event, not a
// verdict:
//
//	STATE_PROPOSE sent → connection dies → NO conclusion about the payment
//	                                     → resync → the signed state decides
//
// That is Coordinator.Recover's job, and it is why Exchange does not retry: a
// retry is a policy decision about a money-bearing operation, and policy lives
// above this file. Retrying is in fact safe — proposals are deterministic and
// intents are idempotent — but "safe" is a property the caller should be
// choosing knowingly, not one this layer quietly assumes.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	ErrTransportClosed = errors.New("transport: closed")
	ErrNoReply         = errors.New("transport: peer sent no reply")
)

// DefaultExchangeTimeout bounds one request/response. A payment path that can
// block forever is a payment path that stops under load.
const DefaultExchangeTimeout = 30 * time.Second

// Dialer opens a connection to one peer. Whatever it is underneath — TCP, a
// unix socket, an I2P stream — is not this file's business.
type Dialer func(ctx context.Context) (net.Conn, error)

// StreamPeer is a Peer over a stream-oriented connection.
//
// One connection per exchange, closed afterwards. That is more expensive than
// pooling and much easier to be sure about: there is no half-consumed frame to
// inherit, no reply arriving on a connection whose request timed out, and no
// interleaving of two payments on one wire. Pooling is worth adding when a hub
// is forwarding at a rate that makes it matter, and is worth adding
// deliberately rather than now.
type StreamPeer struct {
	Dial    Dialer
	Timeout time.Duration
}

// NewStreamPeer builds a peer that dials addr over TCP.
func NewStreamPeer(addr string) *StreamPeer {
	return &StreamPeer{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		Timeout: DefaultExchangeTimeout,
	}
}

// ErrPeerUnreachable means the connection was never established.
//
// The ONLY safe negative in this file. Every other transport failure leaves
// open the possibility that the peer received and acted on the message; a dial
// that never connected wrote no bytes, so the peer provably did not.
var ErrPeerUnreachable = errors.New("transport: the peer could not be reached")

// Exchange sends one message and returns the reply.
//
// An error here says only that the exchange did not complete. It says nothing
// about whether the peer acted on the message — it may have signed and
// persisted a state before the connection dropped. The caller resolves that by
// asking (Coordinator.Recover), never by assuming. The single exception is
// ErrPeerUnreachable, which is raised before anything is written.
func (p *StreamPeer) Exchange(ctx context.Context, out Envelope) (Envelope, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultExchangeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := p.Dial(ctx)
	if err != nil {
		// TAGGED, because this failure is different in kind from the ones
		// below. Nothing has been written yet, so the peer cannot have acted:
		// this is the one transport failure that is NOT ambiguous, and a caller
		// that treats every failure as "may have happened" gives up a fact it
		// actually has. Everything after the first WriteFrame stays ambiguous.
		return Envelope{}, fmt.Errorf("transport: dial: %w: %w", ErrPeerUnreachable, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// Closing the write side after sending would be tidier, but not every
	// net.Conn supports it (net.Pipe does not), and the frame header already
	// tells the reader exactly how much to expect.
	if err := WriteFrame(conn, out); err != nil {
		return Envelope{}, fmt.Errorf("transport: write: %w", err)
	}
	reply, err := ReadFrame(conn)
	if err != nil {
		return Envelope{}, fmt.Errorf("transport: read: %w", err)
	}
	return reply, nil
}

// ---- server ----------------------------------------------------------------

// Handler is what a served connection dispatches to. *Coordinator satisfies it.
//
// An interface rather than a *Coordinator so this file cannot grow a shortcut
// into the store: dispatching is all it can do.
type Handler interface {
	Handle(ctx context.Context, env Envelope) (*Envelope, error)
}

// Server accepts connections and hands their frames to a Handler.
type Server struct {
	Handler Handler
	// Timeout bounds one connection's lifetime. A peer that opens a connection
	// and says nothing must not hold a goroutine indefinitely.
	Timeout time.Duration
	// OnError, if set, is told about per-connection failures. Nothing here
	// logs on its own — a library that writes to stderr on a hostile peer's
	// schedule is a library that can be made to fill a disk.
	OnError func(error)

	mu       sync.Mutex
	listener net.Listener
	closed   bool
	wg       sync.WaitGroup
}

// Serve accepts until the listener is closed.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrTransportClosed
	}
	s.listener = ln
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				break
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			if err := s.ServeConn(ctx, conn); err != nil && s.OnError != nil {
				s.OnError(err)
			}
		}()
	}
	s.wg.Wait()
	return nil
}

// Close stops accepting and waits for connections in flight.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.listener
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	s.wg.Wait()
	return err
}

// ServeConn reads frames from one connection until it ends.
//
// The whole of it: read a frame, hand it to the coordinator, write back
// whatever the coordinator produced. No inspection of the message, no decision
// about what it means.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultExchangeTimeout
	}

	for {
		_ = conn.SetDeadline(time.Now().Add(timeout))

		env, err := ReadFrame(conn)
		if err != nil {
			// A closed connection is how an exchange ends, not a failure.
			if isDisconnect(err) {
				return nil
			}
			// A frame this node could not parse gets an ERROR back where that
			// is still possible, so the peer learns rather than guesses.
			_ = writeError(conn, err)
			return err
		}

		reply, herr := s.Handler.Handle(ctx, env)
		if herr != nil {
			// NOTE: a rejection is not an error. STATE_REJECT comes back as a
			// reply with a nil error, because a refusal is a protocol outcome.
			// Reaching here means the message could not be processed at all.
			_ = writeError(conn, herr)
			return herr
		}
		if reply == nil {
			// Messages that need no answer — an accept the payer applied, a
			// resync response, an announcement. The connection stays open for
			// whatever comes next.
			continue
		}
		if err := WriteFrame(conn, *reply); err != nil {
			return fmt.Errorf("transport: write reply: %w", err)
		}
	}
}

func writeError(conn net.Conn, cause error) error {
	env, err := newEnvelope(MsgError, [32]byte{}, ErrorBody{Detail: cause.Error()})
	if err != nil {
		return err
	}
	// Best effort: the connection that produced the error may already be gone.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return WriteFrame(conn, env)
}

func isDisconnect(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// io.EOF and ErrUnexpectedEOF arrive from ReadFrame's io.ReadFull when the
	// peer closed between or during a frame.
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
