package swarm

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"time"
)

// Storage is where a file's bytes live: *os.File satisfies it, as does Mem.
type Storage interface {
	io.ReaderAt
	io.WriterAt
}

// Mem is an in-memory Storage.
type Mem struct{ B []byte }

func (m *Mem) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(m.B)) {
		return 0, io.EOF
	}
	n := copy(p, m.B[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *Mem) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(m.B)) {
		return 0, io.ErrShortWrite
	}
	return copy(m.B[off:], p), nil
}

// Config describes one node's part in one file's swarm.
type Config struct {
	Meta    Meta
	Storage Storage
	// Tree is set by a node that already has the whole file (the origin, or a
	// node restarting with a finished download); proofs then come from it.
	Tree *Tree
	// SuperSeed is the origin's mode: advertise pieces a few at a time, least
	// distributed first, so its scarce upload goes into pieces the swarm does not
	// yet have rather than into copies of what peers could get from each other.
	SuperSeed bool
	// UploadSlots is how many peers are served at once, plus one optimistic.
	UploadSlots int
	// Pipeline is how many requests are outstanding to one peer.
	Pipeline int
	// RechokeInterval is how often upload slots are re-assigned.
	RechokeInterval time.Duration
	// RequestTimeout re-issues a request a peer has sat on.
	RequestTimeout time.Duration
}

func (c *Config) defaults() {
	if c.UploadSlots <= 0 {
		c.UploadSlots = 4
	}
	if c.Pipeline <= 0 {
		c.Pipeline = 4
	}
	if c.RechokeInterval <= 0 {
		c.RechokeInterval = 10 * time.Second
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 60 * time.Second
	}
}

// Stats are a node's counters for one file.
type Stats struct {
	Have, Pieces          int
	Downloaded, Uploaded  int64
	BadPieces, BannedPeer int
	Peers                 int
}

var (
	ErrWrongFile = errors.New("axon/swarm: peer is in a different swarm")
	ErrClosed    = errors.New("axon/swarm: swarm closed")
)

// Swarm is one node's state for one file.
type Swarm struct {
	cfg  Config
	meta Meta
	rng  *rand.Rand

	mu       sync.Mutex
	have     bitfield
	nHave    int
	proofs   [][][32]byte // per piece, as received (when there is no Tree)
	avail    []int        // how many connected peers have each piece
	reqs     []int        // how many peers each piece is requested from
	served   []int        // super-seed: how many times each piece has gone out
	peers    map[*peer]struct{}
	done     chan struct{}
	closed   bool
	stats    Stats
	optimist *peer
	rounds   int
	stop     chan struct{}
}

// New starts a node's swarm for a file. A node with the whole file passes its
// Tree; one starting from nothing passes zeroed Storage of Meta.Size bytes.
func New(cfg Config) (*Swarm, error) {
	cfg.defaults()
	if cfg.Tree != nil {
		cfg.Meta = cfg.Tree.Meta()
	}
	if err := cfg.Meta.Validate(); err != nil {
		return nil, err
	}
	n := cfg.Meta.Pieces()
	s := &Swarm{
		cfg: cfg, meta: cfg.Meta,
		rng:    rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
		have:   newBitfield(n),
		proofs: make([][][32]byte, n),
		avail:  make([]int, n),
		reqs:   make([]int, n),
		served: make([]int, n),
		peers:  map[*peer]struct{}{},
		done:   make(chan struct{}),
		stop:   make(chan struct{}),
	}
	s.stats.Pieces = n
	if cfg.Tree != nil {
		for i := 0; i < n; i++ {
			s.have.set(i)
		}
		s.nHave = n
		s.stats.Have = n
		close(s.done)
	}
	go s.rechokeLoop()
	return s, nil
}

func (s *Swarm) Meta() Meta            { return s.meta }
func (s *Swarm) Done() <-chan struct{} { return s.done }
func (s *Swarm) complete() bool        { return s.nHave == s.meta.Pieces() }
func (s *Swarm) superSeeding() bool    { return s.cfg.SuperSeed && s.complete() }
func (s *Swarm) pieceOff(i int) int64  { return int64(i) * int64(s.meta.PieceSize) }

func (s *Swarm) proofFor(i int) [][32]byte {
	if s.cfg.Tree != nil {
		return s.cfg.Tree.Proof(i)
	}
	return s.proofs[i]
}

// Stats returns the node's counters.
func (s *Swarm) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Peers = len(s.peers)
	return st
}

// Close drops every peer.
func (s *Swarm) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stop)
	ps := make([]*peer, 0, len(s.peers))
	for p := range s.peers {
		ps = append(ps, p)
	}
	s.mu.Unlock()
	for _, p := range ps {
		p.conn.Close()
	}
}

// ---------------------------------------------------------------- one peer

type peer struct {
	s    *Swarm
	conn net.Conn

	// guarded by s.mu
	bits           bitfield
	nHas           int
	helloSeen      bool
	peerChoking    bool // they choke us
	peerInterested bool
	amChoking      bool
	amInterested   bool
	inflight       map[int]time.Time // our requests to them
	rejected       map[int]bool      // pieces they declined to serve
	revealed       map[int]bool      // super-seed: pieces advertised to them
	queued         int               // pieces queued to them, not yet written
	bytesIn        int64             // this rechoke interval
	bytesOut       int64
	rateIn         float64
	rateOut        float64
	dead           bool

	// the writer's queue, guarded by qmu
	qmu   sync.Mutex
	qcond *sync.Cond
	q     []outFrame
	qdone bool
}

type outFrame struct {
	b     []byte
	piece int // >= 0 for a PIECE frame (CANCEL can withdraw it), else -1
}

// send queues a frame; it never blocks, so it may be called under s.mu.
func (p *peer) send(m *message) {
	piece := -1
	if m.typ == msgPiece {
		piece = m.index
	}
	p.qmu.Lock()
	if !p.qdone {
		p.q = append(p.q, outFrame{b: encode(m), piece: piece})
		p.qcond.Signal()
	}
	p.qmu.Unlock()
}

// withdraw removes a queued, unsent PIECE (CANCEL or CHOKE). True if found.
func (p *peer) withdraw(piece int) bool {
	p.qmu.Lock()
	defer p.qmu.Unlock()
	for k, f := range p.q {
		if f.piece == piece || (piece < 0 && f.piece >= 0) {
			p.q = append(p.q[:k], p.q[k+1:]...)
			return true
		}
	}
	return false
}

func (p *peer) writer() {
	for {
		p.qmu.Lock()
		for len(p.q) == 0 && !p.qdone {
			p.qcond.Wait()
		}
		if p.qdone {
			p.qmu.Unlock()
			return
		}
		f := p.q[0]
		p.q = p.q[1:]
		p.qmu.Unlock()
		if _, err := p.conn.Write(f.b); err != nil {
			p.conn.Close()
			return
		}
		if f.piece >= 0 {
			// Counted when written, not when queued: a piece withdrawn by CANCEL
			// or CHOKE never left.
			n := int64(len(f.b))
			p.s.mu.Lock()
			p.queued--
			p.bytesOut += n
			p.s.stats.Uploaded += n
			p.s.mu.Unlock()
		}
	}
}

// Serve runs the peer protocol on one connection -- dialled or accepted, the
// protocol is symmetric -- until it ends.
func (s *Swarm) Serve(conn net.Conn) error {
	p := &peer{s: s, conn: conn, peerChoking: true, amChoking: true,
		inflight: map[int]time.Time{}, rejected: map[int]bool{}, revealed: map[int]bool{},
		bits: newBitfield(s.meta.Pieces())}
	p.qcond = sync.NewCond(&p.qmu)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return ErrClosed
	}
	s.peers[p] = struct{}{}
	hello := &message{typ: msgHello, root: s.meta.Root, bits: newBitfield(s.meta.Pieces())}
	if !s.superSeeding() {
		copy(hello.bits, s.have)
	}
	p.send(hello)
	s.mu.Unlock()
	go p.writer()

	err := s.readLoop(p)

	s.mu.Lock()
	s.dropPeerLocked(p)
	s.mu.Unlock()
	p.qmu.Lock()
	p.qdone = true
	p.qcond.Signal()
	p.qmu.Unlock()
	conn.Close()
	return err
}

func (s *Swarm) readLoop(p *peer) error {
	limit := maxFrame(s.meta)
	for {
		m, err := readMessage(p.conn, limit)
		if err != nil {
			return err
		}
		if m.typ == msgPiece {
			// Verify outside the lock: it is the expensive step, and it needs
			// nothing but the immutable Meta.
			if verr := Verify(s.meta, m.index, m.data, m.proof); verr != nil {
				s.mu.Lock()
				s.stats.BadPieces++
				s.stats.BannedPeer++
				s.mu.Unlock()
				return fmt.Errorf("piece %d: %w (peer banned)", m.index, verr)
			}
		}
		s.mu.Lock()
		err = s.handleLocked(p, m)
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (s *Swarm) dropPeerLocked(p *peer) {
	if p.dead {
		return
	}
	p.dead = true
	delete(s.peers, p)
	for i := 0; i < s.meta.Pieces(); i++ {
		if p.bits.has(i) {
			s.avail[i]--
		}
	}
	for i := range p.inflight {
		s.reqs[i]--
	}
	p.inflight = nil
	if s.optimist == p {
		s.optimist = nil
	}
	// What it was going to deliver is now unrequested: let the others take it.
	for q := range s.peers {
		s.fillLocked(q)
	}
}

func (s *Swarm) handleLocked(p *peer, m *message) error {
	n := s.meta.Pieces()
	if !p.helloSeen && m.typ != msgHello {
		return fmt.Errorf("%w: %d before HELLO", ErrWire, m.typ)
	}
	switch m.typ {
	case msgHello:
		if p.helloSeen {
			return fmt.Errorf("%w: second HELLO", ErrWire)
		}
		if m.root != s.meta.Root {
			return ErrWrongFile
		}
		if len(m.bits) != (n+7)/8 {
			return fmt.Errorf("%w: bitfield of %d bytes", ErrWire, len(m.bits))
		}
		p.helloSeen = true
		for i := 0; i < n; i++ {
			if bitfield(m.bits).has(i) {
				p.bits.set(i)
				p.nHas++
				s.avail[i]++
			}
		}
		if s.complete() && p.nHas == n {
			return io.EOF // two complete nodes have nothing to say
		}
		s.interestLocked(p)
		s.revealLocked(p)
	case msgHave:
		if m.index < 0 || m.index >= n {
			return ErrWire
		}
		if !p.bits.has(m.index) {
			p.bits.set(m.index)
			p.nHas++
			s.avail[m.index]++
		}
		delete(p.rejected, m.index) // (re)advertised: it is willing to be asked
		if s.complete() && p.nHas == n {
			return io.EOF
		}
		s.interestLocked(p)
		s.revealLocked(p) // it got a revealed piece elsewhere: reveal the next
		s.fillLocked(p)
	case msgInterested:
		p.peerInterested = true
		s.unchokeIfFreeLocked(p)
	case msgNotInterested:
		p.peerInterested = false
	case msgChoke:
		p.peerChoking = true
		for i := range p.inflight {
			s.reqs[i]--
			delete(p.inflight, i)
		}
		for q := range s.peers {
			s.fillLocked(q)
		}
	case msgUnchoke:
		// A REJECT usually meant "choked right now", not "never": forget them all,
		// or a piece whose other holders have left is never asked for again.
		p.peerChoking = false
		clear(p.rejected)
		s.fillLocked(p)
	case msgRequest:
		i := m.index
		if i < 0 || i >= n {
			return ErrWire
		}
		if p.amChoking || !s.have.has(i) || p.queued >= 2*s.cfg.Pipeline ||
			(s.superSeeding() && !p.revealed[i]) {
			p.send(&message{typ: msgReject, index: i})
			return nil
		}
		buf := make([]byte, s.meta.PieceLen(i))
		if _, err := s.cfg.Storage.ReadAt(buf, s.pieceOff(i)); err != nil && err != io.EOF {
			return err
		}
		p.queued++
		s.served[i]++
		p.send(&message{typ: msgPiece, index: i, proof: s.proofFor(i), data: buf})
	case msgPiece:
		return s.pieceLocked(p, m)
	case msgReject:
		if _, ok := p.inflight[m.index]; ok {
			delete(p.inflight, m.index)
			s.reqs[m.index]--
			p.rejected[m.index] = true
		}
		s.fillLocked(p)
	case msgCancel:
		if p.withdraw(m.index) {
			p.queued--
		}
	}
	return nil
}

// pieceLocked stores a verified piece.
func (s *Swarm) pieceLocked(p *peer, m *message) error {
	i := m.index
	p.bytesIn += int64(len(m.data))
	if _, ok := p.inflight[i]; ok {
		delete(p.inflight, i)
		s.reqs[i]--
	}
	if s.have.has(i) {
		s.fillLocked(p) // a duplicate from endgame: harmless, already verified
		return nil
	}
	if _, err := s.cfg.Storage.WriteAt(m.data, s.pieceOff(i)); err != nil {
		return err
	}
	s.have.set(i)
	s.nHave++
	s.stats.Have = s.nHave
	s.stats.Downloaded += int64(len(m.data))
	if s.cfg.Tree == nil {
		s.proofs[i] = m.proof
	}
	// Tell everyone at once: a piece shared the moment it is verified is what
	// makes a downloading node a source, and the swarm faster than the origin.
	for q := range s.peers {
		if _, ok := q.inflight[i]; ok && q != p {
			delete(q.inflight, i)
			s.reqs[i]--
			q.send(&message{typ: msgCancel, index: i})
		}
		q.send(&message{typ: msgHave, index: i})
	}
	if s.complete() {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
	for q := range s.peers {
		s.interestLocked(q)
		s.fillLocked(q)
	}
	return nil
}

// interestLocked tells a peer whether it has anything we lack.
func (s *Swarm) interestLocked(p *peer) {
	want := false
	if !s.complete() {
		for i := 0; i < s.meta.Pieces(); i++ {
			if p.bits.has(i) && !s.have.has(i) {
				want = true
				break
			}
		}
	}
	if want != p.amInterested {
		p.amInterested = want
		if want {
			p.send(&message{typ: msgInterested})
		} else {
			p.send(&message{typ: msgNotInterested})
		}
	}
}

// fillLocked keeps a peer's request pipeline full.
func (s *Swarm) fillLocked(p *peer) {
	if p.dead || p.peerChoking || s.complete() || p.inflight == nil {
		return
	}
	for len(p.inflight) < s.cfg.Pipeline {
		i := s.pickLocked(p)
		if i < 0 {
			return
		}
		p.inflight[i] = time.Now()
		s.reqs[i]++
		p.send(&message{typ: msgRequest, index: i})
	}
}

// pickLocked chooses the next piece to ask p for.
//
// RAREST FIRST, once a node has a few pieces: the piece fewest peers hold is the
// one most likely to become unavailable, and the one a node can most usefully
// pass on. The first few are chosen at random instead, so a new node gets
// something to share as soon as possible rather than queueing for the rarest.
// When nothing unrequested is left (endgame), the last pieces are asked of a
// second peer too, so one slow peer cannot hold a finished download hostage.
func (s *Swarm) pickLocked(p *peer) int {
	best, bestAvail, ties := -1, 1<<30, 0
	random := s.nHave < 4
	for i := 0; i < s.meta.Pieces(); i++ {
		if !p.bits.has(i) || s.have.has(i) || s.reqs[i] > 0 || p.rejected[i] {
			continue
		}
		a := s.avail[i]
		if random {
			a = 0
		}
		switch {
		case a < bestAvail:
			best, bestAvail, ties = i, a, 1
		case a == bestAvail:
			ties++
			if s.rng.IntN(ties) == 0 {
				best = i
			}
		}
	}
	if best >= 0 {
		return best
	}
	// Endgame: everything left is already asked of someone.
	for i := 0; i < s.meta.Pieces(); i++ {
		if !p.bits.has(i) || s.have.has(i) || p.rejected[i] || s.reqs[i] >= 2 {
			continue
		}
		if _, mine := p.inflight[i]; mine {
			continue
		}
		return i
	}
	return -1
}

// revealLocked is super-seeding: keep Pipeline pieces advertised to the peer,
// choosing the least distributed -- the fewest copies sent plus the fewest
// peers known to hold it -- that the peer does not already have.
func (s *Swarm) revealLocked(p *peer) {
	if !s.superSeeding() || !p.helloSeen {
		return
	}
	outstanding := 0
	for i := range p.revealed {
		if !p.bits.has(i) {
			outstanding++
		}
	}
	for outstanding < s.cfg.Pipeline {
		best, bestScore, ties := -1, 1<<30, 0
		for i := 0; i < s.meta.Pieces(); i++ {
			if p.bits.has(i) || p.revealed[i] {
				continue
			}
			sc := s.served[i] + s.avail[i]
			switch {
			case sc < bestScore:
				best, bestScore, ties = i, sc, 1
			case sc == bestScore:
				ties++
				if s.rng.IntN(ties) == 0 {
					best = i
				}
			}
		}
		if best < 0 {
			return
		}
		p.revealed[best] = true
		p.send(&message{typ: msgHave, index: best})
		outstanding++
	}
}

// ---------------------------------------------------------------- choking

func (s *Swarm) unchokedLocked() int {
	n := 0
	for q := range s.peers {
		if !q.amChoking {
			n++
		}
	}
	return n
}

// unchokeIfFreeLocked serves a newly interested peer at once when a slot is
// free, rather than making it wait for the next rechoke.
func (s *Swarm) unchokeIfFreeLocked(p *peer) {
	if p.amChoking && s.unchokedLocked() < s.cfg.UploadSlots+1 {
		p.amChoking = false
		p.send(&message{typ: msgUnchoke})
	}
}

func (s *Swarm) rechokeLoop() {
	t := time.NewTicker(s.cfg.RechokeInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			s.rechokeLocked()
			s.mu.Unlock()
		}
	}
}

// rechokeLocked re-assigns upload slots.
//
// TIT FOR TAT while downloading: the peers that gave us the most this interval
// are served; while complete, the peers that take our upload fastest are, so it
// goes where it moves. One extra slot rotates at random (the optimistic unchoke):
// it is how a new peer with nothing to trade gets its first pieces, and how a
// better partner than the current ones is found. Requests a peer has sat on
// past RequestTimeout are taken back and asked of someone else.
func (s *Swarm) rechokeLocked() {
	secs := s.cfg.RechokeInterval.Seconds()
	now := time.Now()
	var cands []*peer
	for q := range s.peers {
		q.rateIn = float64(q.bytesIn) / secs
		q.rateOut = float64(q.bytesOut) / secs
		q.bytesIn, q.bytesOut = 0, 0
		for i, at := range q.inflight {
			if now.Sub(at) > s.cfg.RequestTimeout {
				delete(q.inflight, i)
				s.reqs[i]--
			}
		}
		if q.peerInterested {
			cands = append(cands, q)
		}
	}
	complete := s.complete()
	sort.Slice(cands, func(a, b int) bool {
		if complete {
			return cands[a].rateOut > cands[b].rateOut
		}
		return cands[a].rateIn > cands[b].rateIn
	})
	keep := map[*peer]bool{}
	for k := 0; k < len(cands) && k < s.cfg.UploadSlots; k++ {
		keep[cands[k]] = true
	}
	s.rounds++
	if s.optimist == nil || s.rounds%3 == 0 || !s.optimist.peerInterested {
		var rest []*peer
		for _, q := range cands {
			if !keep[q] {
				rest = append(rest, q)
			}
		}
		s.optimist = nil
		if len(rest) > 0 {
			s.optimist = rest[s.rng.IntN(len(rest))]
		}
	}
	if s.optimist != nil {
		keep[s.optimist] = true
	}
	for q := range s.peers {
		switch {
		case keep[q] && q.amChoking:
			q.amChoking = false
			q.send(&message{typ: msgUnchoke})
		case !keep[q] && !q.amChoking:
			q.amChoking = true
			for q.withdraw(-1) {
				q.queued--
			}
			q.send(&message{typ: msgChoke})
		}
	}
	for q := range s.peers {
		s.fillLocked(q)
	}
}
