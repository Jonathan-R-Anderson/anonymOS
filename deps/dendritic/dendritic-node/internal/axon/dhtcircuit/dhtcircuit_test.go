package dhtcircuit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/dht"
	"github.com/syndichan/maniwani/storage-client/internal/axon/session"
)

// pipe is a minimal in-memory carrier pair: what a circuit to a relay is, for
// the purpose of this test. internal/axon/session and internal/axon/rendez test
// the session over real circuit crypto; this test is about who sees what.
type pipeEnd struct {
	to    *session.Session
	other *pipeEnd
	q     chan []byte
}

func (e *pipeEnd) Send(p []byte) error {
	e.q <- append([]byte(nil), p...)
	return nil
}

func pipe(t *testing.T, cli, relay *session.Session) {
	a := &pipeEnd{to: relay, q: make(chan []byte, 4096)}
	b := &pipeEnd{to: cli, q: make(chan []byte, 4096)}
	a.other, b.other = b, a
	for _, e := range []*pipeEnd{a, b} {
		go func(e *pipeEnd) {
			for p := range e.q {
				e.to.Receive(e.other, p)
			}
		}(e)
	}
	relay.Attach(b)
	cli.Attach(a)
}

// network is a synthetic DHT. It records WHO asked each storing node -- the
// observable R4(b) is about.
type network struct {
	nodes   []dht.Contact
	holders map[[32]byte]bool
	wire    []byte
	mu      sync.Mutex
	askers  map[string]int // asker identity -> queries
}

func mkNet(t *testing.T, n int) *network {
	var srv dht.SRV
	rand.Read(srv[:])
	w := &network{holders: map[[32]byte]bool{}, wire: []byte("descriptor-of-origin.anonymous.axon"), askers: map[string]int{}}
	for i := 0; i < n; i++ {
		var pub [32]byte
		binary.BigEndian.PutUint64(pub[:8], uint64(i+1))
		addr := netip.AddrFrom4([4]byte{byte(10 + i%200), byte(i / 200), byte(i), 1})
		prefix, _ := dht.PrefixFor(addr)
		id, err := dht.DeriveKadID(pub, srv, prefix)
		if err != nil {
			t.Fatal(err)
		}
		w.nodes = append(w.nodes, dht.Contact{NodeIDPub: pub, KadID: id, Addr: addr, Prefix: prefix,
			ASN: uint32(1000 + i), Verified: true})
	}
	return w
}

func (w *network) closest(key dht.Key, n int) []dht.Contact {
	out := append([]dht.Contact(nil), w.nodes...)
	sort.Slice(out, func(i, j int) bool {
		a, b := dht.Distance(out[i].KadID, key), dht.Distance(out[j].KadID, key)
		return new(big.Int).SetBytes(a[:]).Cmp(new(big.Int).SetBytes(b[:])) < 0
	})
	return out[:n]
}

// rpcAs is the network's FIND_VALUE as issued by `asker`.
func (w *network) rpcAs(asker string) dht.RPC {
	return func(_ context.Context, _ int, to dht.Contact, key dht.Key) (dht.Response, error) {
		w.mu.Lock()
		w.askers[asker]++
		w.mu.Unlock()
		r := dht.Response{Closer: w.closest(key, dht.BucketSize)}
		if w.holders[to.NodeIDPub] {
			r.Wire = w.wire
		}
		return r, nil
	}
}

type dispatcher struct {
	circuits []*Circuit
}

func (d *dispatcher) ForPath(_ context.Context, path int) (dht.Circuit, error) {
	if path >= len(d.circuits) {
		return nil, errors.New("no circuit")
	}
	return d.circuits[path], nil
}

// TestR4bLookupOverCircuits is item 2.10b: a lookup whose d paths each run over
// their own session to their own relay finds the record, records NO unsafe
// mode, and the storing nodes were asked only by the relays -- never by the
// client.
func TestR4bLookupOverCircuits(t *testing.T) {
	w := mkNet(t, 200)
	key := dht.MustDeriveKey(dht.ClassDesc, []byte("origin.anonymous.axon"))
	for _, h := range w.closest(key, dht.Replicas) {
		w.holders[h.NodeIDPub] = true
	}
	cfg := session.DefaultConfig()
	d := &dispatcher{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < dht.DisjointPaths; i++ {
		var seed [32]byte
		rand.Read(seed[:])
		cli, _ := session.NewClient(seed, cfg)
		relay := session.NewService(seed, cli.ID(), cfg)
		defer cli.Close()
		defer relay.Close()
		pipe(t, cli, relay)
		name := string(rune('A' + i))
		go Serve(ctx, relay, w.rpcAs("relay-"+name))
		var term dht.NodeID
		term[0] = byte(i + 1)
		d.circuits = append(d.circuits, NewCircuit(dht.CircuitID(i+1), term, cli))
	}

	self := dht.MustDeriveKey(dht.ClassRelay, []byte("client"))
	tbl := dht.NewTable(self)
	for _, c := range w.nodes[:60] {
		tbl.Admit(c)
	}
	res, err := dht.Lookup(ctx, tbl, key, dht.CircuitRPC(d), dht.CircuitConfig(dht.LookupConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Wires) == 0 || string(res.Wires[0]) != string(w.wire) {
		t.Fatalf("lookup over circuits found %d records", len(res.Wires))
	}
	if len(res.UnsafeModes) != 0 {
		t.Fatalf("unsafe modes %v: R4(b) should be met", res.UnsafeModes)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.askers) != dht.DisjointPaths {
		t.Fatalf("askers %v: want exactly the %d relays", w.askers, dht.DisjointPaths)
	}
	for who := range w.askers {
		if who[:6] != "relay-" {
			t.Fatalf("a storing node was asked by %q", who)
		}
	}
	t.Logf("R4(b): record found over %d circuits; the network saw only %v", dht.DisjointPaths, w.askers)
}

func TestLookupWireBoundsAndUnverified(t *testing.T) {
	w := mkNet(t, 30)
	r := dht.Response{Closer: w.nodes[:dht.BucketSize], Wire: []byte("x")}
	b, err := dht.EncodeLookupResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := dht.DecodeLookupResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Closer {
		if c.Verified {
			t.Fatal("a contact learned from a reply came back Verified (§7.3 rule (c))")
		}
	}
	if got.Closer[3].Addr != w.nodes[3].Addr || got.Closer[3].KadID != w.nodes[3].KadID {
		t.Fatal("contact did not round-trip")
	}
	if _, err := dht.EncodeLookupResponse(dht.Response{Closer: w.nodes[:dht.BucketSize+1]}); err == nil {
		t.Fatal("an over-long closer list was encoded")
	}
	if _, err := dht.DecodeLookupResponse(append(b, make([]byte, dht.MaxLookupMessage)...)); err == nil {
		t.Fatal("an oversized response was decoded")
	}
	req, _ := dht.EncodeLookupRequest(w.nodes[0], dht.Key{1})
	if to, key, err := dht.DecodeLookupRequest(req); err != nil || to.NodeIDPub != w.nodes[0].NodeIDPub || key != (dht.Key{1}) {
		t.Fatalf("request round trip: %v", err)
	}
}

// TestQueryRespectsContext: a relay that never answers cannot hang a lookup.
func TestQueryRespectsContext(t *testing.T) {
	var seed [32]byte
	rand.Read(seed[:])
	cfg := session.DefaultConfig()
	cli, _ := session.NewClient(seed, cfg)
	relay := session.NewService(seed, cli.ID(), cfg)
	defer cli.Close()
	defer relay.Close()
	pipe(t, cli, relay)
	go func() { // a relay that accepts and then says nothing
		for {
			if _, err := relay.AcceptStream(context.Background()); err != nil {
				return
			}
		}
	}()
	c := NewCircuit(1, dht.NodeID{1}, cli)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Query(ctx, mkNet(t, 1).nodes[0], dht.Key{}); err == nil {
		t.Fatal("a silent relay produced an answer")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("query ignored its context for %v", time.Since(start))
	}
}
