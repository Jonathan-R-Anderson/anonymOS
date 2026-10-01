// Package session is AXON's session layer (§9.8, P23, OUTSTANDING 5.2): a
// reliable, ordered, multiplexed byte stream between a client and a service
// that survives the death of the circuits carrying it.
//
// R9: addresses name destinations, circuits are disposable carriers, and
// STREAMS BIND TO SESSIONS, NOT CIRCUITS. A tunnel expires every ten minutes by
// design (§9.2); without this package every transfer longer than that restarts
// from zero, and the restart is a distinctive pattern on a fixed schedule.
//
// WHAT 5.2 FOUND, AND WHAT THIS PACKAGE IS BECAUSE OF IT. P23 describes "a
// ratcheting session that survives circuit death". T7.2 and E7.1 demand more:
// no byte loss AND no duplication across a forced carrier death. A ratchet
// cannot deliver that -- on migration a sender either re-sends what may already
// have arrived (duplication) or skips it (loss). The requirement is
// ACKNOWLEDGED DELIVERY STATE THAT OUTLIVES THE CIRCUIT: each end knows what
// the PEER has acknowledged, not merely what it sent. So a session holds
//
//   - a send buffer of every reliable frame the peer has not acknowledged,
//     replayed in order onto each new carrier (no loss);
//   - a cumulative receive cursor and a reorder buffer, so a frame that
//     arrives twice -- once on the dying carrier, once on its replacement --
//     is delivered once (no duplication);
//
// and the ratchet is what it was always for: post-compromise security at each
// new rendezvous (case B), not reliability.
//
// The session AEAD is a second, independent layer over the circuit's. Because
// keys and sequence numbers are independent of the carrier, replacing the
// carrier is a routing change, not a cryptographic one -- and a hostile
// rendezvous point that splices its own circuit in can inject nothing: every
// cell it forges fails authentication (CARRIER_HOSTILE).
//
// This package does not build circuits, pick rendezvous points or run the
// resume handshakes on the wire. A Carrier is anything that delivers a
// PacketSize packet to the peer; the owner (the tunnel pool and the rendezvous
// client) attaches carriers and reports their deaths, and the session does the
// rest. That seam is what lets T7.2 be tested against real circuit crypto here
// and against a real network later without changing this code.
package session

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Role is which end of the session this is.
type Role uint8

const (
	// Client chose the session id and builds every carrier. Its streams are odd.
	Client Role = 1
	// Service accepts carriers the client builds. Its streams are even.
	Service Role = 2
)

func (r Role) String() string {
	switch r {
	case Client:
		return "client"
	case Service:
		return "service"
	}
	return "role?"
}

// State is §9.8's session state.
type State uint8

const (
	Attached State = iota + 1 // a carrier is attached
	Orphaned                  // the carrier died; state retained, waiting for another
	Closed                    // keys wiped; nothing further
)

func (s State) String() string {
	switch s {
	case Attached:
		return "ATTACHED"
	case Orphaned:
		return "ORPHANED"
	case Closed:
		return "CLOSED"
	}
	return "STATE?"
}

// Carrier delivers session packets to the peer: today a SESSION relay cell on
// a circuit joined at a rendezvous point. Send is called from one goroutine at
// a time. An error means the carrier is dead; the session then orphans itself
// exactly as if the owner had called CarrierLost.
type Carrier interface {
	Send(packet []byte) error
}

// Close reasons carried in SESSION_CLOSE.
const (
	CloseNormal    uint8 = 0
	CloseGoingAway uint8 = 1 // §9.9 graceful shutdown: no new streams; retry_after says when
	CloseLifetime  uint8 = 2
	CloseIdle      uint8 = 3
)

var (
	ErrClosed         = errors.New("axon/session: session is closed")
	ErrSessionLost    = errors.New("axon/session: no carrier within the orphan retention window")
	ErrLifetime       = errors.New("axon/session: hard session lifetime reached")
	ErrIdle           = errors.New("axon/session: idle timeout")
	ErrPeerClosed     = errors.New("axon/session: peer closed the session")
	ErrCarrierHostile = errors.New("axon/session: carrier delivered cells failing session authentication (CARRIER_HOSTILE)")
	ErrCarrierSilent  = errors.New("axon/session: carrier went silent with frames outstanding")
	ErrCarrierDead    = errors.New("axon/session: carrier reported dead")
	ErrDegraded       = errors.New("axon/session: tunnel pool is DEGRADED; no new streams (§9.2)")
	ErrGoingAway      = errors.New("axon/session: peer is going away; no new streams")
	ErrStreamIDs      = errors.New("axon/session: stream ids exhausted for this session")
	ErrResumeCounter  = errors.New("axon/session: resume counter does not exceed the last accepted")
	ErrResumeProof    = errors.New("axon/session: resume proof does not verify")
	ErrWrongRole      = errors.New("axon/session: operation belongs to the other role")
	ErrStreamReset    = errors.New("axon/session: stream reset by peer")
	ErrStreamClosed   = errors.New("axon/session: stream closed")
)

// Config holds the timers and limits. DefaultConfig takes every value from
// params; tests shorten them.
type Config struct {
	OrphanRetention time.Duration
	IdleTimeout     time.Duration
	HardLifetime    time.Duration
	RekeyPackets    uint64
	RekeyInterval   time.Duration
	MinRTO, MaxRTO  time.Duration
	ProbeTimeout    time.Duration
	StreamWindow    int
	SendBuffer      int
	HostileLimit    int
	// AckDelay is how long a receiver may hold an acknowledgement hoping to
	// piggyback it on data.
	AckDelay time.Duration
	// MaxInFlight is how many packets may be sent and unacknowledged at once.
	MaxInFlight int

	// OnOrphan runs on its own goroutine when the carrier dies. A client's
	// owner builds a replacement (case A, else case B) and calls Attach. A
	// service has nothing to build -- only a client can reach a rendezvous
	// point -- and may leave it nil.
	OnOrphan func(s *Session, why error)
	// OnClose runs on its own goroutine once, when the session closes.
	OnClose func(s *Session, why error)
}

// DefaultConfig is the specified configuration.
func DefaultConfig() Config {
	return Config{
		OrphanRetention: params.SessionOrphanRetention,
		IdleTimeout:     params.SessionIdleTimeout,
		HardLifetime:    params.SessionHardLifetime,
		RekeyPackets:    params.SessionRekeyPackets,
		RekeyInterval:   params.SessionRekeyInterval,
		MinRTO:          params.SessionMinRTO,
		MaxRTO:          params.SessionMaxRTO,
		ProbeTimeout:    params.SessionProbeTimeout,
		StreamWindow:    params.SessionStreamWindow,
		SendBuffer:      params.SessionSendBuffer,
		HostileLimit:    params.SessionHostileLimit,
		AckDelay:        20 * time.Millisecond,
		MaxInFlight:     256,
	}
}

// MigrationBound is T7.2's bound for this configuration given how long the
// owner is allowed to take to supply a replacement carrier. With the default
// configuration and params.TunnelBuildTimeout it is params.SessionMigrationBound.
func (c Config) MigrationBound(replace time.Duration) time.Duration {
	return c.ProbeTimeout + replace + c.MaxRTO
}

// Stats are counters for diagnostics and the tests' assertions.
type Stats struct {
	PacketsSent, PacketsReceived uint64
	FramesSent                   uint64 // reliable frames, first transmissions
	Retransmits                  uint64 // reliable frames sent again (RTO or migration)
	Duplicates                   uint64 // reliable frames received again and dropped
	Hostile                      uint64 // packets refused as forged or replayed
	Replays                      uint64 // of those, packet numbers seen before
	Migrations                   uint64 // carriers attached after the first
	Rekeys                       uint64 // symmetric rekeys, both directions
	Ratchets                     uint64 // case-B root ratchets
}

// dirKey is one direction's live key.
type dirKey struct {
	gen     uint16
	epoch   uint16
	key     [32]byte
	aead    cipher.AEAD
	started time.Time
	count   uint64 // packets under this key
}

func newDirKey(gen uint16, k [32]byte, now time.Time) dirKey {
	return dirKey{gen: gen, key: k, aead: newAEAD(k), started: now}
}

func (d *dirKey) wipe() { wipe(d.key[:]); d.aead = nil }

// outFrame is a reliable frame awaiting acknowledgement.
type outFrame struct {
	f      frame // ack is filled in at seal time
	sent   bool
	sentAt time.Time
	retx   int
	size   int
}

// Session is one end of a session.
type Session struct {
	role Role
	id   ID
	cfg  Config

	mu   sync.Mutex
	cond *sync.Cond // every blocking wait in the package waits on this
	kick chan struct{}
	done chan struct{}

	state      State
	closeErr   error
	closeOnce  bool
	created    time.Time
	activity   time.Time // last reliable frame either way
	orphanedAt time.Time
	attachedAt time.Time
	lastRecv   time.Time

	// keys: committed state, and (service only) a case-B ratchet accepted but
	// not yet confirmed by the client.
	keys       keyState
	gen        uint16
	pending    *keyState
	pendingGen uint16
	tx         dirKey
	rx, rxPrev dirKey
	prx        dirKey // receive key for the pending generation

	pn     uint64
	replay replayWindow

	carrier        Carrier
	carrierHostile int

	// reliability
	nextSeq      uint64
	unacked      []*outFrame
	unackedBytes int
	peerAck      uint64
	recvNext     uint64
	reorder      map[uint64]*frame
	ackOwed      bool
	ackOwedAt    time.Time
	ackNow       bool
	pingOwed     bool
	srtt, rttvar time.Duration
	rto          time.Duration

	final [][]byte // sealed packets to flush before the run loop exits

	// streams
	streams    map[uint32]*Stream
	nextStream uint32
	acceptQ    []*Stream
	degraded   bool
	goingAway  bool
	retryAfter time.Duration

	// resumption
	rpCounter  uint32 // client: case-A commitment counter
	svcCounter uint32 // client: last case-B counter sent; service: last accepted

	stats Stats
}

func newSession(role Role, id ID, keySeed [32]byte, cfg Config) *Session {
	now := time.Now()
	s := &Session{
		role: role, id: id, cfg: cfg,
		kick: make(chan struct{}, 1), done: make(chan struct{}),
		state: Orphaned, created: now, activity: now, orphanedAt: now, lastRecv: now,
		keys:    deriveKeys(rootFromSeed(keySeed, id)),
		nextSeq: 1, recvNext: 1, reorder: map[uint64]*frame{},
		rto:     cfg.MinRTO,
		streams: map[uint32]*Stream{},
	}
	s.cond = sync.NewCond(&s.mu)
	if role == Client {
		s.nextStream = 1
	} else {
		s.nextStream = 2
	}
	s.installKeysLocked(now)
	go s.run()
	return s
}

// NewClient starts the client end of a session from the rendezvous KEY_SEED.
// The session id is fresh randomness and is never reused (§9.8). The session
// starts ORPHANED; Attach the spliced rendezvous circuit to begin.
func NewClient(keySeed [32]byte, cfg Config) (*Session, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return newSession(Client, id, keySeed, cfg), nil
}

// NewService starts the service end for a session id the client chose.
func NewService(keySeed [32]byte, id ID, cfg Config) *Session {
	return newSession(Service, id, keySeed, cfg)
}

func (s *Session) ID() ID     { return s.id }
func (s *Session) Role() Role { return s.role }

func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Err is why the session closed, or nil.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Done is closed when the session is closed.
func (s *Session) Done() <-chan struct{} { return s.done }

// installKeysLocked (re)starts both directions under the committed root.
func (s *Session) installKeysLocked(now time.Time) {
	s.tx.wipe()
	s.rx.wipe()
	s.rxPrev.wipe()
	if s.role == Client {
		s.tx = newDirKey(s.gen, s.keys.kf, now)
		s.rx = newDirKey(s.gen, s.keys.kb, now)
	} else {
		s.tx = newDirKey(s.gen, s.keys.kb, now)
		s.rx = newDirKey(s.gen, s.keys.kf, now)
	}
	s.rxPrev = dirKey{}
}

func (s *Session) wake() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// ---------------------------------------------------------------- carriers

// Attach makes c the session's carrier. Every frame the peer has not
// acknowledged is sent again on it, in order, at once -- which is the whole of
// migration -- and a PING asks the peer to acknowledge promptly so the
// survivors of the old carrier are identified in one round trip.
//
// Attaching while a carrier is live replaces it (tunnel rotation). The old
// carrier's late packets are still accepted: they are authenticated, and the
// receive cursor makes them harmless.
func (s *Session) Attach(c Carrier) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Closed {
		return ErrClosed
	}
	s.attachLocked(c, time.Now())
	return nil
}

func (s *Session) attachLocked(c Carrier, now time.Time) {
	if !s.attachedAt.IsZero() {
		s.stats.Migrations++
	}
	s.carrier = c
	s.carrierHostile = 0
	s.state = Attached
	s.attachedAt = now
	s.orphanedAt = time.Time{}
	for _, of := range s.unacked {
		if of.sent {
			of.sent = false
		}
	}
	s.pingOwed = true
	s.cond.Broadcast()
	s.wake()
}

// CarrierLost reports that c died: a DESTROY, a TRUNCATED, a link failure, a
// pool expiry. If c is still the session's carrier the session is ORPHANED.
func (s *Session) CarrierLost(c Carrier, why error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.carrier != c || s.state != Attached {
		return
	}
	if why == nil {
		why = ErrCarrierDead
	}
	s.orphanLocked(why)
}

func (s *Session) orphanLocked(why error) {
	if s.state != Attached {
		return
	}
	s.state = Orphaned
	s.carrier = nil
	s.orphanedAt = time.Now()
	for _, of := range s.unacked {
		of.sent = false
	}
	if f := s.cfg.OnOrphan; f != nil {
		go f(s, why)
	}
	s.cond.Broadcast()
	s.wake()
}

// SetDegraded is the pool's DEGRADED signal (§9.2): while set, no new streams
// open, rather than every new stream landing on the one surviving tunnel.
func (s *Session) SetDegraded(d bool) {
	s.mu.Lock()
	s.degraded = d
	s.mu.Unlock()
}

// ---------------------------------------------------------------- inbound

// Receive processes one packet that arrived on carrier c.
//
// A packet that fails authentication is counted against c; HostileLimit of
// them and c is abandoned as CARRIER_HOSTILE. Nothing a forger sends changes
// any state: the replay window is marked, the key epoch advanced and a pending
// ratchet confirmed only AFTER the AEAD accepts the packet.
func (s *Session) Receive(c Carrier, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Closed {
		return ErrClosed
	}
	h, err := parseHeader(p)
	if err != nil {
		s.hostileLocked(c)
		return err
	}
	if err := s.replay.check(h.pn); err != nil {
		// Circuits do not duplicate cells, so a packet number seen before was
		// re-sent by someone on the path: as hostile as a forgery, and cheaper
		// to refuse (no AEAD is spent on it).
		s.stats.Replays++
		s.hostileLocked(c)
		return err
	}
	f, commit, err := s.openLocked(h, p)
	if err != nil {
		if errors.Is(err, ErrAuth) {
			s.hostileLocked(c)
		}
		return err
	}
	commit()
	s.replay.mark(h.pn)
	now := time.Now()
	if s.state == Orphaned && c != nil {
		// A carrier that delivers an AUTHENTICATED packet is alive. This is how
		// a service learns a case-A resume happened: the RP held its circuit,
		// the service's own probe timer orphaned it meanwhile, and the first
		// sign the client is back is its packet arriving on that same circuit.
		s.attachLocked(c, now)
	}
	s.lastRecv = now
	s.stats.PacketsReceived++
	s.ackLocked(f.ack, now)

	if f.seq == 0 {
		if f.typ == ftPing {
			// The peer attached a new carrier (Attach sends this). Whatever we
			// sent while it was between carriers may be gone without our own
			// carrier ever dying -- in case A the RP held our circuit and
			// dropped the cells bound for the dead client side -- so send every
			// unacknowledged frame again now rather than one per RTO. The
			// receive cursor makes the copies that did arrive harmless.
			for _, of := range s.unacked {
				of.sent = false
			}
			s.ackOwed, s.ackNow = true, true
		}
		s.wake()
		return nil
	}
	s.activity = now
	switch {
	case f.seq < s.recvNext:
		// It already arrived -- on the old carrier, or before a retransmit
		// timer fired. Dropping it here is the "no duplication" half of T7.2.
		s.stats.Duplicates++
		s.ackOwed, s.ackNow = true, true
	case f.seq == s.recvNext:
		s.deliverLocked(f)
		s.recvNext++
		for {
			nf, ok := s.reorder[s.recvNext]
			if !ok {
				break
			}
			delete(s.reorder, s.recvNext)
			s.deliverLocked(nf)
			s.recvNext++
		}
		if !s.ackOwed {
			s.ackOwed, s.ackOwedAt = true, now
		}
	default:
		// A gap: hold it, and say so at once so the sender retransmits.
		if f.seq-s.recvNext <= uint64(4*s.cfg.MaxInFlight) {
			if _, dup := s.reorder[f.seq]; dup {
				s.stats.Duplicates++
			} else {
				s.reorder[f.seq] = f
			}
		}
		s.ackOwed, s.ackNow = true, true
	}
	s.wake()
	return nil
}

func (s *Session) hostileLocked(c Carrier) {
	s.stats.Hostile++
	if c != nil && c == s.carrier && s.state == Attached {
		s.carrierHostile++
		if s.carrierHostile >= s.cfg.HostileLimit {
			s.orphanLocked(ErrCarrierHostile)
		}
	}
}

// openLocked picks the key a header names and opens the packet. The returned
// commit applies any key-state change the packet implies; the caller runs it
// only once the packet has authenticated.
func (s *Session) openLocked(h header, p []byte) (*frame, func(), error) {
	noop := func() {}
	switch {
	case h.gen == s.gen:
		return s.openDirLocked(&s.rx, &s.rxPrev, h, p)
	case s.pending != nil && h.gen == s.pendingGen:
		// The client has ratcheted: this packet confirms the pending root.
		f, commit, err := s.openDirLocked(&s.prx, nil, h, p)
		if err != nil {
			return nil, noop, err
		}
		return f, func() { commit(); s.commitPendingLocked() }, nil
	}
	return nil, noop, ErrAuth
}

func (s *Session) openDirLocked(cur, prev *dirKey, h header, p []byte) (*frame, func(), error) {
	noop := func() {}
	switch {
	case h.epoch == cur.epoch:
		f, err := open(cur.aead, h, p)
		return f, noop, err
	case prev != nil && prev.aead != nil && h.epoch == prev.epoch && h.epoch+1 == cur.epoch:
		f, err := open(prev.aead, h, p)
		return f, noop, err
	case h.epoch > cur.epoch && h.epoch-cur.epoch <= 8:
		// The peer rekeyed. Derive forward, but keep the result only if the
		// packet authenticates: an injector must not be able to walk our
		// receive key forward and strand the honest peer's packets.
		k := cur.key
		for e := cur.epoch + 1; ; e++ {
			k = rekey(k, e)
			if e == h.epoch {
				break
			}
		}
		next := dirKey{gen: cur.gen, epoch: h.epoch, key: k, aead: newAEAD(k), started: time.Now()}
		f, err := open(next.aead, h, p)
		if err != nil {
			next.wipe()
			return nil, noop, err
		}
		return f, func() {
			if prev != nil {
				prev.wipe()
				*prev = *cur
			} else {
				cur.wipe()
			}
			*cur = next
			s.stats.Rekeys++
		}, nil
	}
	return nil, noop, ErrStaleKey
}

// ackLocked applies the peer's cumulative acknowledgement.
func (s *Session) ackLocked(ack uint64, now time.Time) {
	if ack <= s.peerAck || ack >= s.nextSeq {
		return // old news, or acknowledges what was never sent: ignore
	}
	s.peerAck = ack
	var sample time.Duration
	n := 0
	for n < len(s.unacked) && s.unacked[n].f.seq <= ack {
		of := s.unacked[n]
		if of.sent && of.retx == 0 {
			sample = now.Sub(of.sentAt) // Karn: only never-retransmitted frames time the path
		}
		s.unackedBytes -= of.size
		s.unacked[n] = nil
		n++
	}
	s.unacked = s.unacked[n:]
	if sample > 0 {
		if s.srtt == 0 {
			s.srtt, s.rttvar = sample, sample/2
		} else {
			d := s.srtt - sample
			if d < 0 {
				d = -d
			}
			s.rttvar = (3*s.rttvar + d) / 4
			s.srtt = (7*s.srtt + sample) / 8
		}
	}
	s.rto = s.srtt + 4*s.rttvar
	if s.rto < s.cfg.MinRTO {
		s.rto = s.cfg.MinRTO
	}
	if s.rto > s.cfg.MaxRTO {
		s.rto = s.cfg.MaxRTO
	}
	s.cond.Broadcast() // send-buffer space
}

// deliverLocked applies one in-order reliable frame.
func (s *Session) deliverLocked(f *frame) {
	switch f.typ {
	case ftOpen:
		if (f.stream%2 == 1) != (s.role == Service) || f.stream == 0 {
			return // the peer used one of OUR ids: refuse, never guess
		}
		if _, exists := s.streams[f.stream]; exists {
			return
		}
		st := s.newStreamLocked(f.stream, f.data)
		s.acceptQ = append(s.acceptQ, st)
	case ftData:
		st := s.streams[f.stream]
		if st == nil {
			s.refuseLocked(f.stream)
			return
		}
		if st.recvOff+uint64(len(f.data)) > st.recvLimit {
			// The peer ignored the window it was granted. That is a broken
			// peer, and the stream -- not the session -- pays for it.
			s.resetLocked(st, ResetFlowControl)
			return
		}
		st.recvOff += uint64(len(f.data))
		if st.readClosed {
			// Nobody will read it: account for it and keep the window open so
			// the peer's writer finishes instead of stalling.
			st.readOff = st.recvOff
			if w := uint64(s.cfg.StreamWindow); st.recvLimit-st.readOff <= w/2 {
				st.recvLimit = st.readOff + w
				b := make([]byte, 8)
				binary.LittleEndian.PutUint64(b, st.recvLimit)
				s.queueLocked(ftWindow, st.id, b)
			}
			break
		}
		st.recvBuf = append(st.recvBuf, f.data...)
	case ftFin:
		if st := s.streams[f.stream]; st != nil {
			st.recvFin = true
			s.maybeForgetLocked(st)
		}
	case ftReset:
		if st := s.streams[f.stream]; st != nil {
			st.peerReset = true
			if len(f.data) >= 2 {
				st.resetCode = binary.LittleEndian.Uint16(f.data)
			}
			delete(s.streams, st.id)
		}
	case ftWindow:
		if st := s.streams[f.stream]; st != nil && len(f.data) == 8 {
			if lim := binary.LittleEndian.Uint64(f.data); lim > st.sendLimit {
				st.sendLimit = lim
			}
		}
	case ftClose:
		reason := uint8(CloseNormal)
		if len(f.data) >= 1 {
			reason = f.data[0]
		}
		if reason == CloseGoingAway {
			s.goingAway = true
			if len(f.data) >= 5 {
				s.retryAfter = time.Duration(binary.LittleEndian.Uint32(f.data[1:5])) * time.Second
			}
		} else {
			s.closeLocked(ErrPeerClosed, false)
		}
	}
	s.cond.Broadcast()
}

// refuseLocked answers data for a stream this end has forgotten (closed both
// ways, or reset) with a RESET, once per frame the peer sends -- bounded by
// the window it was granted -- so its writer stops instead of stalling.
func (s *Session) refuseLocked(id uint32) {
	ours := (id%2 == 1) == (s.role == Client)
	if id == 0 || (ours && id >= s.nextStream) {
		return // never opened: nothing to refuse, and nothing to tell
	}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, ResetCancel)
	s.queueLocked(ftReset, id, b)
}

// ---------------------------------------------------------------- outbound

// queueLocked appends a reliable frame to the send buffer.
func (s *Session) queueLocked(typ frameType, stream uint32, data []byte) {
	of := &outFrame{
		f:    frame{seq: s.nextSeq, typ: typ, stream: stream, data: data},
		size: len(data) + frameHeaderSize,
	}
	s.nextSeq++
	s.unacked = append(s.unacked, of)
	s.unackedBytes += of.size
	s.activity = time.Now()
	s.wake()
}

// sealLocked seals one frame with the current ack under the current tx key,
// rekeying first if this key has done its share.
func (s *Session) sealLocked(f frame, now time.Time) ([]byte, error) {
	if s.tx.count >= s.cfg.RekeyPackets || now.Sub(s.tx.started) >= s.cfg.RekeyInterval {
		k := rekey(s.tx.key, s.tx.epoch+1)
		next := newDirKey(s.tx.gen, k, now)
		next.epoch = s.tx.epoch + 1
		s.tx.wipe()
		s.tx = next
		s.stats.Rekeys++
	}
	f.ack = s.recvNext - 1
	s.pn++
	s.tx.count++
	s.stats.PacketsSent++
	return seal(s.tx.aead, header{gen: s.tx.gen, epoch: s.tx.epoch, pn: s.pn}, &f)
}

// collectLocked decides what to transmit now.
func (s *Session) collectLocked(now time.Time) (out [][]byte, c Carrier) {
	if s.state != Attached || s.carrier == nil {
		return nil, nil
	}
	c = s.carrier
	// On a timeout, resend only the OLDEST outstanding frame, as TCP does. A
	// live carrier is ordered and does not lose cells -- loss is the carrier
	// dying, and Attach already resends everything onto the next one -- so a
	// timer firing on a live carrier almost always means the path is slow, not
	// lossy. Resending every outstanding frame then queues a second copy of the
	// whole window behind the first, the path gets slower still, and the timer
	// fires again: a retransmission storm. One probe per RTO cannot do that,
	// and the cumulative ack it draws acknowledges everything behind it.
	inflight := 0
	for i, of := range s.unacked {
		if !of.sent {
			continue
		}
		if i == 0 && now.Sub(of.sentAt) >= s.rto {
			of.sent = false
			s.rto *= 2
			if s.rto > s.cfg.MaxRTO {
				s.rto = s.cfg.MaxRTO
			}
			continue
		}
		inflight++
	}
	for _, of := range s.unacked {
		if of.sent {
			continue
		}
		if inflight >= s.cfg.MaxInFlight {
			break
		}
		p, err := s.sealLocked(of.f, now)
		if err != nil {
			continue
		}
		if of.retx == 0 && of.sentAt.IsZero() {
			s.stats.FramesSent++
		} else {
			s.stats.Retransmits++
		}
		if !of.sentAt.IsZero() {
			of.retx++
		}
		of.sent, of.sentAt = true, now
		inflight++
		out = append(out, p)
	}
	if s.pingOwed {
		if p, err := s.sealLocked(frame{typ: ftPing}, now); err == nil {
			out = append(out, p)
		}
		s.pingOwed = false
	}
	if len(out) > 0 {
		s.ackOwed, s.ackNow = false, false // every packet carries the ack
	} else if s.ackOwed && (s.ackNow || now.Sub(s.ackOwedAt) >= s.cfg.AckDelay) {
		if p, err := s.sealLocked(frame{typ: ftAck}, now); err == nil {
			out = append(out, p)
		}
		s.ackOwed, s.ackNow = false, false
	}
	return out, c
}

// checkTimersLocked runs §9.8's timers.
func (s *Session) checkTimersLocked(now time.Time) {
	if s.state == Closed {
		return
	}
	switch {
	case now.Sub(s.created) >= s.cfg.HardLifetime:
		s.closeLocked(ErrLifetime, true)
		return
	case now.Sub(s.activity) >= s.cfg.IdleTimeout:
		s.closeLocked(ErrIdle, true)
		return
	case s.state == Orphaned && now.Sub(s.orphanedAt) >= s.cfg.OrphanRetention:
		s.closeLocked(ErrSessionLost, false)
		return
	}
	if s.state == Attached {
		outstanding := false
		for _, of := range s.unacked {
			if of.sent {
				outstanding = true
				break
			}
		}
		heard := s.lastRecv
		if s.attachedAt.After(heard) {
			heard = s.attachedAt
		}
		if outstanding && now.Sub(heard) >= s.cfg.ProbeTimeout {
			s.orphanLocked(ErrCarrierSilent)
		}
	}
}

func (s *Session) nextDeadlineLocked(now time.Time) time.Duration {
	next := s.cfg.ProbeTimeout
	consider := func(d time.Duration) {
		if d < next {
			next = d
		}
	}
	consider(s.cfg.HardLifetime - now.Sub(s.created))
	consider(s.cfg.IdleTimeout - now.Sub(s.activity))
	if s.state == Orphaned {
		consider(s.cfg.OrphanRetention - now.Sub(s.orphanedAt))
	}
	if s.state == Attached {
		for _, of := range s.unacked {
			if of.sent {
				consider(s.rto - now.Sub(of.sentAt))
				break
			}
		}
		if s.ackOwed {
			consider(s.cfg.AckDelay - now.Sub(s.ackOwedAt))
		}
	}
	if next < time.Millisecond {
		next = time.Millisecond
	}
	return next
}

// run is the session's single sending goroutine. Packets are sealed under the
// lock and sent outside it, so a carrier that delivers synchronously into the
// peer's Receive cannot deadlock two sessions against each other.
func (s *Session) run() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		s.mu.Lock()
		now := time.Now()
		s.checkTimersLocked(now)
		out, c := s.collectLocked(now)
		if s.state == Closed {
			out, c = s.final, s.carrier
			s.final = nil
			s.carrier = nil
		}
		next := s.nextDeadlineLocked(now)
		closed := s.state == Closed
		s.mu.Unlock()

		for _, p := range out {
			if c == nil {
				break
			}
			if err := c.Send(p); err != nil {
				s.CarrierLost(c, fmt.Errorf("%w: %v", ErrCarrierDead, err))
				break
			}
		}
		if closed {
			return
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(next)
		select {
		case <-s.kick:
		case <-t.C:
		case <-s.done:
		}
	}
}

// ---------------------------------------------------------------- closing

// Close ends the session, telling the peer (SESSION_CLOSE{NORMAL}) when a
// carrier is attached.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Closed {
		return nil
	}
	s.closeLocked(ErrClosed, true)
	return nil
}

// GoAway is §9.9's graceful shutdown notice: SESSION_CLOSE{GOING_AWAY,
// retry_after}. Existing streams continue; neither end opens new ones. The
// caller closes the session when its drain window ends.
func (s *Session) GoAway(retryAfter time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Closed {
		return
	}
	s.goingAway = true
	b := make([]byte, 5)
	b[0] = CloseGoingAway
	binary.LittleEndian.PutUint32(b[1:], uint32(retryAfter/time.Second))
	s.queueLocked(ftClose, 0, b)
}

// RetryAfter is what the peer's GOING_AWAY asked for, if it sent one.
func (s *Session) RetryAfter() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retryAfter, s.goingAway
}

func (s *Session) closeLocked(why error, tell bool) {
	if s.state == Closed {
		return
	}
	if tell && s.state == Attached && s.carrier != nil {
		reason := CloseNormal
		switch why {
		case ErrLifetime:
			reason = CloseLifetime
		case ErrIdle:
			reason = CloseIdle
		}
		b := []byte{reason, 0, 0, 0, 0}
		f := frame{seq: s.nextSeq, typ: ftClose, data: b}
		s.nextSeq++
		if p, err := s.sealLocked(f, time.Now()); err == nil {
			s.final = append(s.final, p)
		}
	}
	s.state = Closed
	s.closeErr = why
	// Zeroise (§9.9): every session key, the pending ratchet, the buffers.
	s.keys.wipe()
	if s.pending != nil {
		s.pending.wipe()
		s.pending = nil
	}
	s.tx.wipe()
	s.rx.wipe()
	s.rxPrev.wipe()
	s.prx.wipe()
	s.unacked, s.unackedBytes, s.reorder = nil, 0, nil
	for _, st := range s.streams {
		st.recvBuf = nil
	}
	if f := s.cfg.OnClose; f != nil && !s.closeOnce {
		go f(s, why)
	}
	s.closeOnce = true
	close(s.done)
	s.cond.Broadcast()
}

// ---------------------------------------------------------------- resumption

// RPResumeID is rp_resume_id, the case-A preimage.
func (s *Session) RPResumeID() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys.rpid
}

// NextResumeCommit is the client's RESUME_REGISTER body: a fresh counter and
// its commitment. Send it on every newly spliced circuit, and again after
// every successful case-A resume -- the RP burns a commitment when it is used.
func (s *Session) NextResumeCommit() (counter uint32, commit [32]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.role != Client {
		return 0, commit, ErrWrongRole
	}
	if s.state == Closed {
		return 0, commit, ErrClosed
	}
	s.rpCounter++
	return s.rpCounter, ResumeCommit(s.keys.rpid, s.rpCounter), nil
}

// ResumeRendezvous is the client's RESUME_RENDEZVOUS body for case A: the
// counter of the commitment registered last, and the preimage that opens it.
func (s *Session) ResumeRendezvous() (counter uint32, preimage [32]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.role != Client {
		return 0, preimage, ErrWrongRole
	}
	if s.state == Closed {
		return 0, preimage, ErrClosed
	}
	return s.rpCounter, s.keys.rpid, nil
}

// ResumeIntro is the client's case-B session_resume, carried in INTRODUCE1
// (rendez.IntroPlaintext's ResumePresent/SessionID/SessionCtr/SessionProof):
// a strictly increasing counter and a proof binding it to the NEW rendezvous
// cookie and the NEW RP's routing id.
func (s *Session) ResumeIntro(cookie [20]byte, rpRoutingID [32]byte) (id ID, counter uint32, proof [32]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.role != Client {
		return id, 0, proof, ErrWrongRole
	}
	if s.state == Closed {
		return id, 0, proof, ErrClosed
	}
	s.svcCounter++
	return s.id, s.svcCounter, resumeProof(s.keys.resume, s.id, s.svcCounter, cookie, rpRoutingID), nil
}

// AcceptResume is the service's check of a case-B session_resume. On success
// the service runs the rendezvous handshake and calls Ratchet with the new
// KEY_SEED; the existing stream state is reattached rather than recreated.
//
// The proof is checked against the committed root and, when one exists,
// against a ratchet the client may already hold but has not yet confirmed --
// a client that received RENDEZVOUS2 and then lost the carrier before its
// first packet arrived is one generation ahead, and refusing it would lose the
// session to an ordinary failure.
func (s *Session) AcceptResume(counter uint32, proof [32]byte, cookie [20]byte, rpRoutingID [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.role != Service {
		return ErrWrongRole
	}
	if s.state == Closed {
		return ErrClosed
	}
	if counter <= s.svcCounter {
		return ErrResumeCounter
	}
	want := resumeProof(s.keys.resume, s.id, counter, cookie, rpRoutingID)
	if !hmacEqual(want, proof) {
		if s.pending == nil {
			return ErrResumeProof
		}
		want = resumeProof(s.pending.resume, s.id, counter, cookie, rpRoutingID)
		if !hmacEqual(want, proof) {
			return ErrResumeProof
		}
		s.commitPendingLocked()
	}
	s.svcCounter = counter
	return nil
}

// Ratchet mixes a new rendezvous KEY_SEED into the session root (case B):
//
//	session_root ← HKDF(salt = session_root, ikm = KEY_SEED', "axon:sess:ratchet:v1")
//
// re-deriving K_f, K_b and resume_secret WITHOUT resetting any sequence
// number. The client commits at once -- it has verified AUTH, so the service
// holds the same seed. The service holds the result as PENDING until a packet
// under it authenticates (or a later resume proves the client has it), and
// sends under it from now on: the only carrier it will have is the new one,
// and only a client that completed this rendezvous is on the other end of it.
func (s *Session) Ratchet(newSeed [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Closed {
		return ErrClosed
	}
	now := time.Now()
	ks := deriveKeys(ratchetRoot(s.keys.root, newSeed))
	s.stats.Ratchets++
	if s.role == Client {
		s.keys.wipe()
		s.keys = ks
		s.gen++
		s.installKeysLocked(now)
		s.rpCounter = 0 // a new root has a new rp_resume_id; its commitments start over
		return nil
	}
	if s.pending != nil {
		s.pending.wipe()
	}
	s.pending = &ks
	s.pendingGen = s.gen + 1
	s.prx.wipe()
	s.prx = newDirKey(s.pendingGen, ks.kf, now)
	s.tx.wipe()
	s.tx = newDirKey(s.pendingGen, ks.kb, now)
	return nil
}

// commitPendingLocked makes the service's pending ratchet the committed root.
func (s *Session) commitPendingLocked() {
	if s.pending == nil {
		return
	}
	s.keys.wipe()
	s.keys = *s.pending
	s.pending = nil
	s.gen = s.pendingGen
	s.rx.wipe()
	s.rxPrev.wipe()
	s.rx, s.prx, s.rxPrev = s.prx, dirKey{}, dirKey{}
}

// ---------------------------------------------------------------- streams

// OpenStream opens a stream; meta (at most MaxData bytes) travels with the
// OPEN and is what the peer's AcceptStream sees -- a service name, a port, an
// RPC verb: the session does not interpret it.
func (s *Session) OpenStream(meta []byte) (*Stream, error) {
	if len(meta) > MaxData {
		return nil, fmt.Errorf("%w: open metadata is %d bytes", ErrFrame, len(meta))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.state == Closed:
		return nil, s.closeErr
	case s.degraded:
		return nil, ErrDegraded
	case s.goingAway:
		return nil, ErrGoingAway
	case s.nextStream > 1<<31:
		return nil, ErrStreamIDs
	}
	id := s.nextStream
	s.nextStream += 2
	st := s.newStreamLocked(id, append([]byte(nil), meta...))
	s.queueLocked(ftOpen, id, st.meta)
	return st, nil
}

// AcceptStream waits for the peer to open a stream.
func (s *Session) AcceptStream(ctx context.Context) (*Stream, error) {
	stop := context.AfterFunc(ctx, func() {
		s.mu.Lock()
		s.cond.Broadcast()
		s.mu.Unlock()
	})
	defer stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.acceptQ) == 0 {
		if s.state == Closed {
			return nil, s.closeErr
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.cond.Wait()
	}
	st := s.acceptQ[0]
	s.acceptQ = s.acceptQ[1:]
	return st, nil
}

func hmacEqual(a, b [32]byte) bool {
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
