package session

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"time"
)

// Stream is one ordered, reliable byte stream inside a session. It is a
// net.Conn, so anything that speaks over a connection -- HTTP, the DHT's RPCs,
// the storage protocol -- runs over AXON unchanged.
//
// Ordering is the session's, not the stream's: frames are delivered in session
// sequence order, so a stream's bytes arrive in order without a per-stream
// reorder buffer. §9.8 draws the reorder buffer per stream; holding one per
// session is equivalent for ordering and cheaper, and it is the session cursor
// that has to survive the carrier anyway.
//
// Flow control is per stream: the receiver grants a window of StreamWindow
// bytes and extends it as its reader consumes, so one stream whose reader has
// stalled cannot take the whole session's memory. The session's send buffer
// bounds the total across streams.
type Stream struct {
	s    *Session
	id   uint32
	meta []byte

	recvBuf    []byte
	recvOff    uint64 // bytes received in total
	readOff    uint64 // bytes consumed by Read
	recvLimit  uint64 // the window granted to the peer
	recvFin    bool
	peerReset  bool
	resetCode  uint16
	readClosed bool

	sendOff    uint64 // bytes queued
	sendLimit  uint64 // the window the peer granted
	sendFin    bool
	localReset bool

	rdl, wdl time.Time
	rdlTimer *time.Timer
	wdlTimer *time.Timer
}

// Reset codes.
const (
	ResetCancel      uint16 = 0
	ResetFlowControl uint16 = 1 // the peer wrote past its window
)

func (s *Session) newStreamLocked(id uint32, meta []byte) *Stream {
	w := uint64(s.cfg.StreamWindow)
	st := &Stream{s: s, id: id, meta: meta, recvLimit: w, sendLimit: w}
	s.streams[id] = st
	return st
}

// ID is the stream's id within its session (odd: opened by the client).
func (st *Stream) ID() uint32 { return st.id }

// Meta is what the opener sent with the OPEN.
func (st *Stream) Meta() []byte { return st.meta }

// Session is the session carrying the stream.
func (st *Stream) Session() *Session { return st.s }

func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(st.recvBuf) == 0 {
		switch {
		case st.peerReset: // only once what arrived before the RESET is read
			return 0, ErrStreamReset
		case st.readClosed || st.localReset:
			return 0, ErrStreamClosed
		case st.recvFin:
			return 0, io.EOF
		case s.state == Closed:
			return 0, s.closeErr
		case !st.rdl.IsZero() && !time.Now().Before(st.rdl):
			return 0, os.ErrDeadlineExceeded
		}
		s.cond.Wait()
	}
	n := copy(p, st.recvBuf)
	st.recvBuf = st.recvBuf[n:]
	if len(st.recvBuf) == 0 {
		st.recvBuf = nil
	}
	st.readOff += uint64(n)
	// Re-grant once half the window has been consumed: one WINDOW per half
	// window, not one per read.
	w := uint64(s.cfg.StreamWindow)
	if s.state != Closed && !st.recvFin && st.recvLimit-st.readOff <= w/2 {
		st.recvLimit = st.readOff + w
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, st.recvLimit)
		s.queueLocked(ftWindow, st.id, b)
	}
	return n, nil
}

func (st *Stream) Write(p []byte) (int, error) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for {
			switch {
			case s.state == Closed:
				return written, s.closeErr
			case st.peerReset:
				return written, ErrStreamReset
			case st.localReset || st.sendFin:
				return written, ErrStreamClosed
			case !st.wdl.IsZero() && !time.Now().Before(st.wdl):
				return written, os.ErrDeadlineExceeded
			}
			if st.sendOff < st.sendLimit && s.unackedBytes < s.cfg.SendBuffer {
				break
			}
			s.cond.Wait()
		}
		n := len(p)
		if n > MaxData {
			n = MaxData
		}
		if room := st.sendLimit - st.sendOff; uint64(n) > room {
			n = int(room)
		}
		chunk := append([]byte(nil), p[:n]...)
		s.queueLocked(ftData, st.id, chunk)
		st.sendOff += uint64(n)
		p = p[n:]
		written += n
	}
	return written, nil
}

// CloseWrite sends FIN: the peer's Read returns io.EOF once it has every byte.
func (st *Stream) CloseWrite() error {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Closed {
		return s.closeErr
	}
	if st.sendFin || st.localReset || st.peerReset {
		return nil
	}
	st.sendFin = true
	s.queueLocked(ftFin, st.id, nil)
	s.maybeForgetLocked(st)
	return nil
}

// Close finishes writing (FIN) and stops reading, as closing a TCP socket
// does. Unread data is discarded. If the peer keeps writing, its frames meet a
// forgotten stream and are answered with RESET, so its writer fails rather
// than blocking on a window nobody will extend. Close never discards what the
// peer has yet to read: the FIN queues behind every byte already written.
func (st *Stream) Close() error {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Closed {
		return nil
	}
	if st.localReset || st.peerReset {
		delete(s.streams, st.id)
		return nil
	}
	if !st.sendFin {
		st.sendFin = true
		s.queueLocked(ftFin, st.id, nil)
	}
	st.readClosed = true
	st.recvBuf = nil
	s.maybeForgetLocked(st)
	s.cond.Broadcast()
	return nil
}

// Reset aborts the stream in both directions.
func (st *Stream) Reset(code uint16) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != Closed && !st.localReset && !st.peerReset {
		s.resetLocked(st, code)
	}
}

func (s *Session) resetLocked(st *Stream, code uint16) {
	st.localReset = true
	st.recvBuf = nil
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, code)
	s.queueLocked(ftReset, st.id, b)
	delete(s.streams, st.id)
	s.cond.Broadcast()
}

// maybeForgetLocked drops a stream both of whose directions are finished, so a
// long session does not accumulate dead stream state.
func (s *Session) maybeForgetLocked(st *Stream) {
	if st.sendFin && (st.recvFin || st.readClosed) && len(st.recvBuf) == 0 {
		delete(s.streams, st.id)
	}
}

// ---------------------------------------------------------------- net.Conn

// Addr names a stream. It holds the session id and stream id and nothing
// else: there is no address at either end to put in it, which is the point.
type Addr struct {
	Session ID
	Stream  uint32
}

func (Addr) Network() string { return "axon" }
func (a Addr) String() string {
	return hex.EncodeToString(a.Session[:]) + "/" + itoa(a.Stream)
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func (st *Stream) LocalAddr() net.Addr  { return Addr{Session: st.s.id, Stream: st.id} }
func (st *Stream) RemoteAddr() net.Addr { return Addr{Session: st.s.id, Stream: st.id} }

func (st *Stream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.setDeadline(&st.rdl, &st.rdlTimer, t)
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.setDeadline(&st.wdl, &st.wdlTimer, t)
	return nil
}

func (st *Stream) setDeadline(dl *time.Time, tm **time.Timer, t time.Time) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	*dl = t
	if *tm != nil {
		(*tm).Stop()
		*tm = nil
	}
	if t.IsZero() {
		return
	}
	wakeAll := func() {
		s.mu.Lock()
		s.cond.Broadcast()
		s.mu.Unlock()
	}
	if d := time.Until(t); d > 0 {
		*tm = time.AfterFunc(d, wakeAll)
	}
	s.cond.Broadcast()
}

var _ net.Conn = (*Stream)(nil)
