package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/swarm"
)

// An in-memory carrier pair: what a rendezvous circuit is, for this test. The
// session package tests sessions over real circuit crypto; this test is about
// the origin's composition.
type pend struct {
	to    *session.Session
	other *pend
	q     chan []byte
}

func (e *pend) Send(p []byte) error { e.q <- append([]byte(nil), p...); return nil }

func sessionPair(t *testing.T) (cli, svc *session.Session) {
	var seed [32]byte
	rand.Read(seed[:])
	cfg := session.DefaultConfig()
	cli, err := session.NewClient(seed, cfg)
	if err != nil {
		t.Fatal(err)
	}
	svc = session.NewService(seed, cli.ID(), cfg)
	a := &pend{to: svc, q: make(chan []byte, 8192)}
	b := &pend{to: cli, q: make(chan []byte, 8192)}
	a.other, b.other = b, a
	for _, e := range []*pend{a, b} {
		go func(e *pend) {
			for p := range e.q {
				e.to.Receive(e.other, p)
			}
		}(e)
	}
	svc.Attach(b)
	cli.Attach(a)
	t.Cleanup(func() { cli.Close(); svc.Close() })
	return cli, svc
}

// node is one computer: a swarm host that accepts streams on every session a
// peer opens to it.
type node struct {
	addr swarm.PeerAddr
	host *swarm.Host
	sw   *swarm.Swarm
	mem  *swarm.Mem
}

type world struct {
	t      *testing.T
	mu     sync.Mutex
	nodes  map[swarm.PeerAddr]*node
	origin *Front
}

// dialer opens a stream to a peer: on the node's session to the origin for the
// origin, and on a fresh session to any other node.
type dialer struct {
	w        *world
	toOrigin *session.Session
}

const originAddr = "origin.key.axon"

func (d dialer) Dial(_ context.Context, addr swarm.PeerAddr, meta []byte) (net.Conn, error) {
	if addr == originAddr {
		return d.toOrigin.OpenStream(meta)
	}
	d.w.mu.Lock()
	n := d.w.nodes[addr]
	d.w.mu.Unlock()
	if n == nil {
		return nil, fmt.Errorf("no node %s", addr)
	}
	cli, svc := sessionPair(d.w.t)
	go func() {
		for {
			st, err := svc.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go n.host.Accept(st, st.Meta())
		}
	}()
	return cli.OpenStream(meta)
}

// TestOriginSeedsARealArtifactToTheSwarmOverSessions is the whole release path
// short of the AXON runtime: an artifact dropped in the origin's state directory
// is seeded under its Merkle root; every computer learns its locator and its
// peers from the origin's tracker -- HTTP over an AXON session -- and fetches
// pieces from the origin and from each other over session streams.
func TestOriginSeedsARealArtifactToTheSwarmOverSessions(t *testing.T) {
	const size, nodes = 3<<20 + 12345, 6
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	file := make([]byte, size)
	rand.Read(file)
	os.MkdirAll(store.Path("artifacts"), 0o755)
	if err := os.WriteFile(store.Path("artifacts/anonymos-0.2.1.hosupd"), file, 0o644); err != nil {
		t.Fatal(err)
	}
	tracker := NewTracker(originAddr)
	seeder := NewSeeder(tracker)
	if err := seeder.Load(store.Path("artifacts")); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	tracker.Register(mux, seeder)
	front := NewFront(mux, seeder.Host)
	defer front.Close()
	w := &world{t: t, nodes: map[swarm.PeerAddr]*node{}, origin: front}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var all []*node
	var meta swarm.Meta
	for i := 0; i < nodes; i++ {
		cli, svc := sessionPair(t)
		go front.ServeSession(svc)
		hc := &http.Client{Transport: &http.Transport{DialContext: cli.DialContext}, Timeout: 20 * time.Second}

		// What the computer learns first: the locator, from the origin.
		if i == 0 {
			resp, err := hc.Get("http://" + originAddr + "/api/v1/swarm")
			if err != nil {
				t.Fatal(err)
			}
			var list struct {
				Seeding map[string]string `json:"seeding"`
			}
			json.NewDecoder(resp.Body).Decode(&list)
			resp.Body.Close()
			if meta, err = swarm.ParseLocator(list.Seeding["anonymos-0.2.1.hosupd"]); err != nil {
				t.Fatalf("origin did not list the artifact's locator: %v (%v)", err, list.Seeding)
			}
		}
		mem := &swarm.Mem{B: make([]byte, meta.Size)}
		sw, err := swarm.New(swarm.Config{Meta: meta, Storage: mem, RechokeInterval: 300 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer sw.Close()
		n := &node{addr: swarm.PeerAddr(fmt.Sprintf("node%d.key.axon", i)), host: swarm.NewHost(), sw: sw, mem: mem}
		n.host.Add(sw)
		w.mu.Lock()
		w.nodes[n.addr] = n
		w.mu.Unlock()
		all = append(all, n)
		go sw.Run(ctx, swarm.RunConfig{Self: n.addr, Tracker: swarm.HTTPTracker{Client: hc, Base: "http://" + originAddr},
			Dialer: dialer{w, cli}, MaxPeers: 4, Interval: 200 * time.Millisecond})
	}
	want := sha256.Sum256(file)
	for i, n := range all {
		select {
		case <-n.sw.Done():
		case <-time.After(60 * time.Second):
			t.Fatalf("node %d stuck at %d/%d pieces", i, n.sw.Stats().Have, n.sw.Stats().Pieces)
		}
		if sha256.Sum256(n.mem.B) != want {
			t.Fatalf("node %d assembled a different file", i)
		}
	}
	originStats := seeder.Host.Swarm(meta.Root).Stats()
	var fromPeers int64
	for _, n := range all {
		fromPeers += n.sw.Stats().Uploaded
	}
	t.Logf("%d computers got %.1f MiB over AXON sessions: origin uploaded %.2f copies, the computers %.2f between them",
		nodes, float64(size)/(1<<20), float64(originStats.Uploaded)/size, float64(fromPeers)/size)
	if fromPeers == 0 {
		t.Fatal("no computer served another: this was a download, not a swarm")
	}
}

// The tracker refuses junk and hands out the origin first for what it seeds.
func TestTrackerValidatesAndPutsTheOriginFirst(t *testing.T) {
	tr := NewTracker(originAddr)
	var root [32]byte
	root[0] = 7
	tr.seeds[root] = true
	for i := 0; i < 10; i++ {
		if err := tr.announce(root, swarm.PeerAddr(fmt.Sprintf("n%d.key.axon", i)), false); err != nil {
			t.Fatal(err)
		}
	}
	ps := tr.peers(root, 5, "n3.key.axon")
	if len(ps) != 5 || ps[0] != originAddr {
		t.Fatalf("peers = %v; want 5 with the origin first", ps)
	}
	for _, p := range ps {
		if p == "n3.key.axon" {
			t.Fatal("the asker was handed itself")
		}
	}
	mux := http.NewServeMux()
	tr.Register(mux, NewSeeder(tr))
	for _, bad := range []string{`{"addr":"UPPER"}`, `{"addr":""}`, `not json`, `{"addr":"` + string(make([]byte, 200)) + `"}`} {
		req := httptest.NewRequest("POST", "/api/v1/swarm/"+fmt.Sprintf("%064x", 7)+"/announce", strings.NewReader(bad))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == 200 {
			t.Errorf("announce %q accepted", bad)
		}
	}
	tr.nowFunc = func() time.Time { return time.Now().Add(4 * announceInterval) }
	if ps := tr.peers(root, 50, ""); len(ps) != 1 {
		t.Fatalf("expired members still listed: %v", ps)
	}
}
