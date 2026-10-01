// Package dhtcircuit carries DHT lookups over AXON circuits (item 2.10b), which
// is what finally meets R4(b): the node that stores a record learns that a relay
// asked for it, never which client did.
//
// Each of a lookup's d disjoint paths gets its own circuit (dht.CircuitRPC
// enforces that, and that no two share a terminal relay). Over each circuit the
// client holds a session (internal/axon/session) with the circuit's last hop,
// and sends that relay one request per FIND_VALUE on a fresh stream. The relay
// runs the query as itself and returns the answer. A session rather than bare
// cells because an answer -- twenty contacts and a record of up to 16 KiB --
// does not fit in one, and because a lookup should not fail when the circuit
// under it is rotated mid-query.
//
// The dht package does not import this one: §7 finds records and does not
// build paths, and the dht.Dispatcher interface is the seam between the two.
package dhtcircuit

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
	"github.com/syndichan/maniwani/storage-client/internal/axon/dht"
	"github.com/syndichan/maniwani/storage-client/internal/axon/session"
)

// StreamMeta is the OPEN metadata of a lookup stream: the protocol and its
// version, and nothing about the query.
const StreamMeta = "axon-lookup/1"

// QueryTimeout bounds one FIND_VALUE end to end. Lookup's own concurrency and
// retry logic decide what a timeout means; this only stops a stream hanging.
const QueryTimeout = 20 * time.Second

var ErrNotLookup = errors.New("axon/dhtcircuit: stream is not a lookup")

// TerminalSeed derives the session KEY_SEED a client shares with its circuit's
// last hop from that hop's handshake keys -- the only secret the two have in
// common. Domain-separated, so the session keys are independent of the onion
// layer's.
func TerminalSeed(ks circuit.KeySet) [32]byte {
	ikm := append(append([]byte(nil), ks.Kf[:]...), ks.Kb[:]...)
	r := hkdf.New(sha256.New, ikm, nil, []byte("axon:sess:terminal:v1"))
	var out [32]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		panic(err)
	}
	return out
}

// Circuit is a dht.Circuit over a session with the circuit's terminal relay.
type Circuit struct {
	id       dht.CircuitID
	terminal dht.NodeID
	s        *session.Session
}

// NewCircuit wraps a client session whose peer is the relay `terminal`.
func NewCircuit(id dht.CircuitID, terminal dht.NodeID, s *session.Session) *Circuit {
	return &Circuit{id: id, terminal: terminal, s: s}
}

func (c *Circuit) ID() dht.CircuitID    { return c.id }
func (c *Circuit) Terminal() dht.NodeID { return c.terminal }

// Query sends one FIND_VALUE through the terminal relay.
func (c *Circuit) Query(ctx context.Context, to dht.Contact, key dht.Key) (dht.Response, error) {
	req, err := dht.EncodeLookupRequest(to, key)
	if err != nil {
		return dht.Response{}, err
	}
	st, err := c.s.OpenStream([]byte(StreamMeta))
	if err != nil {
		return dht.Response{}, err
	}
	defer st.Close()
	dl := time.Now().Add(QueryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	st.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { st.SetDeadline(time.Now()) })
	defer stop()
	if _, err := st.Write(req); err != nil {
		return dht.Response{}, err
	}
	if err := st.CloseWrite(); err != nil {
		return dht.Response{}, err
	}
	b, err := io.ReadAll(io.LimitReader(st, dht.MaxLookupMessage+1))
	if err != nil {
		if ctx.Err() != nil {
			return dht.Response{}, ctx.Err()
		}
		return dht.Response{}, err
	}
	if len(b) > dht.MaxLookupMessage {
		return dht.Response{}, fmt.Errorf("%w: answer exceeds %d bytes", dht.ErrLookupWire, dht.MaxLookupMessage)
	}
	return dht.DecodeLookupResponse(b)
}

// Serve answers lookup streams on a relay's session with a client: every
// stream whose metadata is StreamMeta carries one request, which `query` -- the
// relay's own, direct FIND_VALUE -- answers. It returns when the session or ctx
// ends.
//
// The relay is not an open proxy: the request can name only a DHT contact, the
// query is only FIND_VALUE, and `query` is the relay's ordinary DHT client with
// its ordinary port and limits. What it does make the relay is the visible
// asker, which is the point; a relay that would rather not be one declines to
// carry the capability rather than filtering queries it cannot judge.
func Serve(ctx context.Context, s *session.Session, query dht.RPC) {
	for {
		st, err := s.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveOne(ctx, st, query)
	}
}

func serveOne(ctx context.Context, st *session.Stream, query dht.RPC) {
	defer st.Close()
	if string(st.Meta()) != StreamMeta {
		st.Reset(session.ResetCancel)
		return
	}
	st.SetDeadline(time.Now().Add(QueryTimeout))
	b, err := io.ReadAll(io.LimitReader(st, 513))
	if err != nil {
		return
	}
	to, key, err := dht.DecodeLookupRequest(b)
	if err != nil {
		st.Reset(session.ResetCancel)
		return
	}
	qctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	resp, err := query(qctx, 0, to, key)
	if err != nil {
		st.Reset(session.ResetCancel)
		return
	}
	if len(resp.Closer) > dht.BucketSize {
		resp.Closer = resp.Closer[:dht.BucketSize]
	}
	out, err := dht.EncodeLookupResponse(resp)
	if err != nil {
		st.Reset(session.ResetCancel)
		return
	}
	st.Write(out)
}
