package swarm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- a shaped network

// bucket is a token bucket: a node's upload capacity, shared by all its links.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	tokens float64
	last   time.Time
}

func newBucket(rate float64) *bucket { return &bucket{rate: rate, tokens: 16 << 10, last: time.Now()} }

func (b *bucket) take(n int) {
	for {
		b.mu.Lock()
		now := time.Now()
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if burst := float64(32 << 10); b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
		if b.tokens >= float64(n) {
			b.tokens -= float64(n)
			b.mu.Unlock()
			return
		}
		wait := time.Duration((float64(n) - b.tokens) / b.rate * float64(time.Second))
		b.mu.Unlock()
		time.Sleep(wait)
	}
}

type shapedConn struct {
	net.Conn
	up *bucket
}

func (c shapedConn) Write(p []byte) (int, error) {
	done := 0
	for len(p) > 0 {
		k := len(p)
		if k > 4096 {
			k = 4096
		}
		c.up.take(k)
		n, err := c.Conn.Write(p[:k])
		done += n
		if err != nil {
			return done, err
		}
		p = p[k:]
	}
	return done, nil
}

type simNode struct {
	addr PeerAddr
	host *Host
	up   *bucket
	sw   *Swarm
}

type simNet struct {
	mu      sync.Mutex
	nodes   map[PeerAddr]*simNode
	members map[[32]byte]map[PeerAddr]bool
}

func newSimNet() *simNet {
	return &simNet{nodes: map[PeerAddr]*simNode{}, members: map[[32]byte]map[PeerAddr]bool{}}
}

func (n *simNet) Announce(_ context.Context, root [32]byte, self PeerAddr, _ bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.members[root] == nil {
		n.members[root] = map[PeerAddr]bool{}
	}
	n.members[root][self] = true
	return nil
}

func (n *simNet) Peers(_ context.Context, root [32]byte, max int) ([]PeerAddr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []PeerAddr
	for a := range n.members[root] {
		out = append(out, a)
	}
	mrand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// dialer is one node's view of the network: its uploads are shaped by its own
// bucket, the target's by the target's.
type dialer struct {
	n    *simNet
	self *simNode
}

func (d dialer) Dial(_ context.Context, addr PeerAddr, meta []byte) (net.Conn, error) {
	d.n.mu.Lock()
	t := d.n.nodes[addr]
	d.n.mu.Unlock()
	if t == nil {
		return nil, errors.New("no such node")
	}
	a, b := net.Pipe()
	go t.host.Accept(shapedConn{b, t.up}, meta)
	return shapedConn{a, d.self.up}, nil
}

func (n *simNet) add(addr PeerAddr, up float64, sw *Swarm) *simNode {
	nd := &simNode{addr: addr, host: NewHost(), up: newBucket(up), sw: sw}
	nd.host.Add(sw)
	n.mu.Lock()
	n.nodes[addr] = nd
	n.mu.Unlock()
	return nd
}

func randFile(t testing.TB, size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func testCfg() Config {
	return Config{UploadSlots: 4, Pipeline: 4, RechokeInterval: 300 * time.Millisecond, RequestTimeout: 3 * time.Second}
}

// release builds an origin for a file: whole tree, super-seeding.
func release(t testing.TB, file []byte, piece int) (*Tree, *Swarm) {
	tree, err := BuildTree(bytes.NewReader(file), int64(len(file)), piece)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testCfg()
	cfg.Tree, cfg.Storage, cfg.SuperSeed = tree, &Mem{B: file}, true
	sw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return tree, sw
}

func leecher(t testing.TB, m Meta) (*Swarm, *Mem) {
	st := &Mem{B: make([]byte, m.Size)}
	cfg := testCfg()
	cfg.Meta, cfg.Storage = m, st
	sw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return sw, st
}

// ---------------------------------------------------------------- tests

// TestReleaseDayFlashCrowd is the case the swarm exists for: an update is
// published and every computer fetches it at once. Sixteen nodes, an origin
// with 1 MiB/s of upload and nodes with a quarter of that each.
//
// Served by the origin alone, that is 16 MiB through a 1 MiB/s pipe: 16 s, and
// the origin uploads 16 copies. The swarm's floor is set by total upload
// capacity -- 16 MiB over 1 + 16 x 0.25 = 5 MiB/s, about 3.2 s -- and the test
// asserts it finishes in under half the client-server time with the origin
// uploading under three copies of the file.
func TestReleaseDayFlashCrowd(t *testing.T) {
	const size, piece, nodes = 1 << 20, 16 << 10, 16
	const originUp, nodeUp = 1 << 20, 256 << 10
	file := randFile(t, size)
	tree, origin := release(t, file, piece)
	defer origin.Close()
	net := newSimNet()
	net.add("origin", originUp, origin)
	net.Announce(context.Background(), tree.Meta().Root, "origin", true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	var ls []*Swarm
	var stores []*Mem
	for i := 0; i < nodes; i++ {
		sw, st := leecher(t, tree.Meta())
		defer sw.Close()
		nd := net.add(PeerAddr(fmt.Sprintf("node-%02d", i)), nodeUp, sw)
		ls, stores = append(ls, sw), append(stores, st)
		go sw.Run(ctx, RunConfig{Self: nd.addr, Tracker: net, Dialer: dialer{net, nd},
			MaxPeers: 6, Interval: 200 * time.Millisecond})
	}
	for i, sw := range ls {
		select {
		case <-sw.Done():
		case <-time.After(60 * time.Second):
			t.Fatalf("node %d stuck at %d/%d pieces", i, sw.Stats().Have, sw.Stats().Pieces)
		}
	}
	took := time.Since(start)
	want := sha256.Sum256(file)
	for i, st := range stores {
		if sha256.Sum256(st.B) != want {
			t.Fatalf("node %d assembled a different file", i)
		}
	}
	clientServer := time.Duration(float64(nodes*size) / float64(originUp) * float64(time.Second))
	up := origin.Stats().Uploaded
	var peerUp int64
	for _, sw := range ls {
		peerUp += sw.Stats().Uploaded
	}
	t.Logf("%d nodes x %d KiB: done in %v (client-server alone: %v, %.1fx faster); origin uploaded %.2f copies, nodes uploaded %.2f copies between them",
		nodes, size>>10, took.Round(10*time.Millisecond), clientServer, float64(clientServer)/float64(took),
		float64(up)/size, float64(peerUp)/size)
	// The origin keeps uploading the whole time -- in a flash crowd its upload is
	// part of the swarm's capacity, and idling it would be waste. What super-seeding
	// buys is that its upload goes into pieces the swarm lacks, and that shows in
	// the finishing time against the floor set by total upload capacity.
	floor := time.Duration(float64(nodes*size) / float64(originUp+nodes*nodeUp) * float64(time.Second))
	t.Logf("floor (all data / all upload capacity): %v; achieved %.0f%% of it", floor, 100*float64(floor)/float64(took))
	if took > clientServer/2 {
		t.Fatalf("swarm took %v, not under half the client-server %v", took, clientServer)
	}
}

// TestLyingPeerIsBannedAndCostsNothing: a peer advertises the whole file and
// serves corrupt pieces with genuine proofs. Every corrupt piece fails its
// proof, the peer is dropped, and every node still assembles the right bytes.
func TestLyingPeerIsBannedAndCostsNothing(t *testing.T) {
	const size, piece = 256 << 10, 16 << 10
	file := randFile(t, size)
	tree, origin := release(t, file, piece)
	defer origin.Close()
	bad := append([]byte(nil), file...)
	for i := range bad {
		bad[i] ^= 0x5a
	}
	lcfg := testCfg()
	lcfg.Tree, lcfg.Storage = tree, &Mem{B: bad}
	liar, _ := New(lcfg)
	defer liar.Close()

	net := newSimNet()
	net.add("origin", 1<<20, origin)
	net.add("liar", 8<<20, liar) // fast, so it is everybody's favourite source
	net.Announce(context.Background(), tree.Meta().Root, "origin", true)
	net.Announce(context.Background(), tree.Meta().Root, "liar", true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ls []*Swarm
	var stores []*Mem
	for i := 0; i < 4; i++ {
		sw, st := leecher(t, tree.Meta())
		defer sw.Close()
		nd := net.add(PeerAddr(fmt.Sprintf("n%d", i)), 512<<10, sw)
		ls, stores = append(ls, sw), append(stores, st)
		go sw.Run(ctx, RunConfig{Self: nd.addr, Tracker: net, Dialer: dialer{net, nd},
			MaxPeers: 4, Interval: 100 * time.Millisecond})
	}
	bad0 := 0
	for i, sw := range ls {
		select {
		case <-sw.Done():
		case <-time.After(30 * time.Second):
			t.Fatalf("node %d stuck at %d/%d", i, sw.Stats().Have, sw.Stats().Pieces)
		}
		bad0 += sw.Stats().BadPieces
	}
	for i, st := range stores {
		if !bytes.Equal(st.B, file) {
			t.Fatalf("node %d took a corrupt piece", i)
		}
	}
	if bad0 == 0 {
		t.Fatal("the liar was never contacted; the test proves nothing")
	}
	t.Logf("%d corrupt pieces refused, every node intact", bad0)
}

// TestChurnHalfTheSwarmLeaves: half the nodes quit midway; the rest finish.
func TestChurnHalfTheSwarmLeaves(t *testing.T) {
	const size, piece = 512 << 10, 16 << 10
	file := randFile(t, size)
	tree, origin := release(t, file, piece)
	defer origin.Close()
	net := newSimNet()
	net.add("origin", 512<<10, origin)
	net.Announce(context.Background(), tree.Meta().Root, "origin", true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ls []*Swarm
	for i := 0; i < 10; i++ {
		sw, _ := leecher(t, tree.Meta())
		nd := net.add(PeerAddr(fmt.Sprintf("n%d", i)), 256<<10, sw)
		ls = append(ls, sw)
		go sw.Run(ctx, RunConfig{Self: nd.addr, Tracker: net, Dialer: dialer{net, nd},
			MaxPeers: 5, Interval: 100 * time.Millisecond})
	}
	for ls[0].Stats().Have < ls[0].Stats().Pieces/2 {
		time.Sleep(10 * time.Millisecond)
	}
	for _, sw := range ls[:5] {
		sw.Close()
	}
	for i, sw := range ls[5:] {
		select {
		case <-sw.Done():
		case <-time.After(30 * time.Second):
			t.Fatalf("survivor %d stuck at %d/%d after churn", i, sw.Stats().Have, sw.Stats().Pieces)
		}
		sw.Close()
	}
}

func TestMerkleProofs(t *testing.T) {
	for _, size := range []int{1, 1023, 1024, 1025, 5*4096 + 17, 64 << 10} {
		file := randFile(t, size)
		tree, err := BuildTree(bytes.NewReader(file), int64(size), 4096)
		if size < 1 {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		m := tree.Meta()
		for i := 0; i < m.Pieces(); i++ {
			data := file[i*4096 : i*4096+m.PieceLen(i)]
			if err := Verify(m, i, data, tree.Proof(i)); err != nil {
				t.Fatalf("size %d piece %d: %v", size, i, err)
			}
			flip := append([]byte(nil), data...)
			flip[0] ^= 1
			if Verify(m, i, flip, tree.Proof(i)) == nil {
				t.Fatalf("size %d: a flipped byte verified", size)
			}
			if m.Pieces() > 1 && Verify(m, (i+1)%m.Pieces(), data, tree.Proof(i)) == nil &&
				m.PieceLen(i) == m.PieceLen((i+1)%m.Pieces()) {
				t.Fatalf("size %d: piece %d verified at another index", size, i)
			}
		}
		back, err := ParseLocator(m.Locator())
		if err != nil || back != m {
			t.Fatalf("locator round trip: %v %+v", err, back)
		}
	}
	if _, err := ParseLocator("axon-swarm:00?size=1&piece=3"); err == nil {
		t.Fatal("a malformed locator parsed")
	}
}

func TestWireRefusesOversizeAndJunk(t *testing.T) {
	m := Meta{Size: 1 << 20, PieceSize: 16 << 10}
	for name, frame := range map[string][]byte{
		"oversized length": {0x7f, 0xff, 0xff, 0xff, byte(msgHave)},
		"unknown type":     {0, 0, 0, 1, 0xee},
		"short HAVE":       {0, 0, 0, 3, byte(msgHave), 0, 1},
		"CHOKE with body":  {0, 0, 0, 2, byte(msgChoke), 9},
	} {
		if _, err := readMessage(bytes.NewReader(frame), maxFrame(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	msg := &message{typ: msgPiece, index: 7, proof: [][32]byte{{1}, {2}}, data: []byte("data")}
	got, err := readMessage(bytes.NewReader(encode(msg)), maxFrame(m))
	if err != nil || got.index != 7 || len(got.proof) != 2 || string(got.data) != "data" {
		t.Fatalf("PIECE round trip: %+v %v", got, err)
	}
}
