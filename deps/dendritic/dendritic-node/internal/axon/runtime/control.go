package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
	"github.com/syndichan/maniwani/storage-client/internal/axon/dht"
	"github.com/syndichan/maniwani/storage-client/internal/axon/dhtcircuit"
	"github.com/syndichan/maniwani/storage-client/internal/axon/rendez"
	"github.com/syndichan/maniwani/storage-client/internal/axon/session"
)

// Control sessions: a client and the relay its circuit ends at, talking to each
// other as such -- not across a splice. Keyed from the terminal hop's handshake
// (dhtcircuit.TerminalSeed), so both ends derive the same session from secrets
// only they hold, and run like any other session over SESSION cells.
//
// What travels on them is the relays' service to clients: hidden-service
// descriptors stored at and fetched from the relays nearest their keys
// ("axon-hsdir/1"). A client reaches a descriptor's holders through a circuit,
// so a holder learns that some client wanted some blinded key, and not who.

const hsdirMeta = "axon-hsdir/1"

// controlID is the control session's id: derived, since neither end chooses it.
func controlID(seed [32]byte) session.ID {
	h := sha256.Sum256(append([]byte("axon:sess:terminal-id:v1"), seed[:]...))
	var id session.ID
	copy(id[:], h[:])
	return id
}

func controlConfig() session.Config {
	c := session.DefaultConfig()
	c.IdleTimeout = 2 * time.Minute
	return c
}

// control opens (once) this circuit's control session to its terminal hop.
func (cc *clientCircuit) control() *session.Session {
	cc.mu.Lock()
	if cc.onSession != nil {
		cc.mu.Unlock()
		return nil
	}
	cc.mu.Unlock()
	seed := dhtcircuit.TerminalSeed(cc.termKeys())
	s := session.NewClientWithID(seed, controlID(seed), controlConfig())
	cc.attach(s)
	return s
}

// relay side: SESSION cells on an un-spliced circuit are this control session.
type relayCarrier struct{ c *relayCirc }

func (k relayCarrier) Send(p []byte) error {
	return k.c.sendBackward(rendez.RelayCell(circuit.RCmdSession, p))
}

func (c *relayCirc) controlReceive(data []byte) error {
	c.mu.Lock()
	s := c.ctl
	if s == nil {
		seed := dhtcircuit.TerminalSeed(c.keys)
		s = session.NewService(seed, controlID(seed), controlConfig())
		s.Attach(relayCarrier{c})
		c.ctl = s
		go c.r.serveControl(s)
	}
	c.mu.Unlock()
	return s.Receive(relayCarrier{c}, data)
}

func (r *relay) serveControl(s *session.Session) {
	for {
		st, err := s.AcceptStream(r.rt.ctx)
		if err != nil {
			return
		}
		switch string(st.Meta()) {
		case hsdirMeta:
			go r.hsdir.serve(st)
		default:
			st.Reset(session.ResetCancel)
		}
	}
}

// ---------------------------------------------------------------- hsdir

// hsdirStore holds hidden-service descriptors. Each is validated against the
// key it is stored under (dht Validator: canonical encoding, the key derives
// from the record, expiry, the blinded key's signature) and replaced only by a
// higher revision.
type hsdirStore struct {
	v  *dht.Validator
	mu sync.Mutex
	m  map[dht.Key]storedDesc
}

type storedDesc struct {
	wire    []byte
	rev     uint64
	expires time.Time
}

const hsdirMaxEntries = 100000

func newHSDirStore() *hsdirStore {
	return &hsdirStore{v: &dht.Validator{Now: time.Now}, m: map[dht.Key]storedDesc{}}
}

func (h *hsdirStore) put(key dht.Key, wire []byte) error {
	rec, err := h.v.Validate(dht.ClassDesc, key, wire)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.m[key]; ok && old.rev >= rec.Seq() {
		return nil
	}
	if _, ok := h.m[key]; !ok && len(h.m) >= hsdirMaxEntries {
		return errors.New("axon/runtime: descriptor store full")
	}
	h.m[key] = storedDesc{wire: append([]byte(nil), wire...), rev: rec.Seq(), expires: rec.Expiry()}
	return nil
}

func (h *hsdirStore) get(key dht.Key) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	d, ok := h.m[key]
	if !ok || time.Now().After(d.expires) {
		return nil
	}
	return d.wire
}

func (h *hsdirStore) prune() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for k, d := range h.m {
		if now.After(d.expires) {
			delete(h.m, k)
		}
	}
}

// The protocol, one request per stream:
//
//	'S' key(32) len u32 wire   -> 'K' | 'E'
//	'F' key(32)                -> len u32 wire   (len 0: none)
func (h *hsdirStore) serve(st *session.Stream) {
	defer st.Close()
	st.SetDeadline(time.Now().Add(30 * time.Second))
	var hdr [33]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		return
	}
	var key dht.Key
	copy(key[:], hdr[1:])
	switch hdr[0] {
	case 'S':
		wire, err := readLV(st, dht.MaxServiceDescriptor)
		if err != nil {
			return
		}
		if h.put(key, wire) != nil {
			st.Write([]byte{'E'})
			return
		}
		st.Write([]byte{'K'})
	case 'F':
		writeLV(st, h.get(key))
	}
}

func readLV(r io.Reader, max int) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint32(n[:])
	if int(l) > max {
		return nil, errors.New("axon/runtime: value too large")
	}
	b := make([]byte, l)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeLV(w io.Writer, b []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// hsdirStoreAt stores a descriptor at the relay a circuit ends at.
func hsdirStoreAt(ctx context.Context, ctl *session.Session, key dht.Key, wire []byte) error {
	st, err := ctl.OpenStream([]byte(hsdirMeta))
	if err != nil {
		return err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		st.SetDeadline(dl)
	}
	req := append([]byte{'S'}, key[:]...)
	if _, err := st.Write(req); err != nil {
		return err
	}
	if err := writeLV(st, wire); err != nil {
		return err
	}
	st.CloseWrite()
	var ok [1]byte
	if _, err := io.ReadFull(st, ok[:]); err != nil {
		return err
	}
	if ok[0] != 'K' {
		return errors.New("axon/runtime: descriptor refused by its holder")
	}
	return nil
}

// hsdirFetchAt fetches a descriptor from the relay a circuit ends at.
func hsdirFetchAt(ctx context.Context, ctl *session.Session, key dht.Key) ([]byte, error) {
	st, err := ctl.OpenStream([]byte(hsdirMeta))
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		st.SetDeadline(dl)
	}
	if _, err := st.Write(append([]byte{'F'}, key[:]...)); err != nil {
		return nil, err
	}
	st.CloseWrite()
	return readLV(st, dht.MaxServiceDescriptor)
}
