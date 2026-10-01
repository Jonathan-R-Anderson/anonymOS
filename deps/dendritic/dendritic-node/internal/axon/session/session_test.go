package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func randBytes(t testing.TB, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func accept(t testing.TB, s *Session) *Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := s.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return st
}

// progressReader counts bytes as they are read, so a test can see a stream
// stall and resume.
type progressReader struct {
	r io.Reader
	n *atomic.Int64
}

func (p progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n.Add(int64(n))
	return n, err
}

// transfer runs one stream carrying `size` bytes each way at once, and returns
// what each side received plus the progress counters.
type xfer struct {
	up, down         []byte // sent client→service, service→client
	gotUp, gotDown   []byte
	errUp, errDown   error
	nUp, nDown       atomic.Int64
	done             chan struct{}
	wErrCli, wErrSvc error
	cs, ss           *Stream
}

// arrived is how many bytes have reached a stream's receive side -- not how
// many the application has read, which could be satisfied from a buffer and
// hide a stall.
func arrived(st *Stream) int64 {
	st.s.mu.Lock()
	defer st.s.mu.Unlock()
	return int64(st.recvOff)
}

func startTransfer(t *testing.T, pr *pairT, size int) *xfer {
	x := &xfer{up: randBytes(t, size), down: randBytes(t, size), done: make(chan struct{})}
	cs, err := pr.cli.OpenStream([]byte("e71"))
	if err != nil {
		t.Fatal(err)
	}
	ss := accept(t, pr.svc)
	if string(ss.Meta()) != "e71" {
		t.Fatalf("open metadata %q", ss.Meta())
	}
	x.cs, x.ss = cs, ss
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); _, x.wErrCli = cs.Write(x.up); cs.CloseWrite() }()
	go func() { defer wg.Done(); _, x.wErrSvc = ss.Write(x.down); ss.CloseWrite() }()
	go func() {
		defer wg.Done()
		x.gotUp, x.errUp = io.ReadAll(progressReader{ss, &x.nUp})
	}()
	go func() {
		defer wg.Done()
		x.gotDown, x.errDown = io.ReadAll(progressReader{cs, &x.nDown})
	}()
	go func() { wg.Wait(); close(x.done) }()
	return x
}

func (x *xfer) check(t *testing.T) {
	t.Helper()
	for _, e := range []error{x.wErrCli, x.wErrSvc, x.errUp, x.errDown} {
		if e != nil {
			t.Fatalf("application-visible error: %v", e)
		}
	}
	if len(x.gotUp) != len(x.up) || sha256.Sum256(x.gotUp) != sha256.Sum256(x.up) {
		t.Fatalf("client→service: got %d bytes (want %d) or wrong content -- loss or duplication",
			len(x.gotUp), len(x.up))
	}
	if len(x.gotDown) != len(x.down) || sha256.Sum256(x.gotDown) != sha256.Sum256(x.down) {
		t.Fatalf("service→client: got %d bytes (want %d) or wrong content -- loss or duplication",
			len(x.gotDown), len(x.down))
	}
}

// waitProgress returns how long until n() exceeds base.
func waitProgress(n func() int64, base int64, limit time.Duration) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < limit {
		if n() > base {
			return time.Since(start), true
		}
		time.Sleep(time.Millisecond)
	}
	return time.Since(start), false
}

func migrateUnderLoad(t *testing.T, explicit bool) {
	cfg := testConfig()
	const replace = 100 * time.Millisecond
	pr := newPair(t, cfg, replace)
	const size = 6 << 20
	x := startTransfer(t, pr, size)
	bound := cfg.MigrationBound(replace)

	for i, target := range []int64{size / 4, size / 2, size * 3 / 4} {
		for x.nUp.Load() < target || x.nDown.Load() < target {
			select {
			case <-x.done:
				t.Fatalf("transfer finished before kill %d", i+1)
			case <-time.After(time.Millisecond):
			}
		}
		p := pr.path()
		p.mu.Lock() // freeze delivery so "arrived" is exact at the moment of death
		up, down := arrived(x.ss), arrived(x.cs)
		p.mu.Unlock()
		p.kill(explicit)
		dUp, ok1 := waitProgress(func() int64 { return arrived(x.ss) }, up, 2*bound)
		dDown, ok2 := waitProgress(func() int64 { return arrived(x.cs) }, down, 2*bound)
		if !ok1 || !ok2 {
			t.Fatalf("kill %d: stream did not resume within 2x the bound (%v)", i+1, bound)
		}
		stall := dUp
		if dDown > stall {
			stall = dDown
		}
		if stall > bound {
			t.Fatalf("kill %d: stream stalled %v, beyond the stated bound %v", i+1, stall, bound)
		}
		t.Logf("kill %d (explicit=%v) at %d/%d bytes: resumed in %v (bound %v)", i+1, explicit, up, size, stall, bound)
	}
	select {
	case <-x.done:
	case <-time.After(60 * time.Second):
		t.Fatal("transfer did not finish")
	}
	x.check(t)
	cs, ss := pr.cli.Stats(), pr.svc.Stats()
	if cs.Migrations < 3 || ss.Migrations < 3 {
		t.Fatalf("migrations: client %d service %d, want >= 3", cs.Migrations, ss.Migrations)
	}
	t.Logf("client: %+v", cs)
	t.Logf("service: %+v", ss)
}

// TestT72ExplicitCarrierDeath is T7.2 and E7.1's shape, compressed: a transfer
// in both directions survives three forced carrier deaths -- in-flight cells
// lost each time -- with zero application-visible error, zero lost and zero
// duplicated bytes, and each stall within the stated bound.
func TestT72ExplicitCarrierDeath(t *testing.T) { migrateUnderLoad(t, true) }

// TestT72SilentCarrierDeath is the slow case: the carrier blackholes and
// nobody says so. The probe timeout must find it inside the same bound.
func TestT72SilentCarrierDeath(t *testing.T) { migrateUnderLoad(t, false) }

// TestDuplicatesAreDroppedNotDelivered forces the duplication case directly:
// every packet is delivered twice. The receiver must count them and deliver
// each byte once.
func TestDuplicatesAreDroppedNotDelivered(t *testing.T) {
	pr := newPair(t, testConfig(), 50*time.Millisecond)
	p := pr.path()
	p.mu.Lock()
	p.tamper = func(dir int, pk []byte) []byte {
		to := p.svc.to
		via := p.cli
		if dir == 0 {
			to, via = p.cli.to, p.svc
		}
		_ = to.Receive(via, append([]byte(nil), pk...)) // the copy goes first
		return pk
	}
	p.mu.Unlock()
	x := startTransfer(t, pr, 512<<10)
	<-x.done
	x.check(t)
	if pr.svc.Stats().Replays == 0 && pr.svc.Stats().Duplicates == 0 {
		t.Fatal("every packet arrived twice and nothing was counted")
	}
}

// TestHostileRPCannotInject is §9.8's defence: the RP splices whatever it
// likes, and every cell it forges fails authentication.
func TestHostileRPCannotInject(t *testing.T) {
	cfg := testConfig()
	cfg.HostileLimit = 1000 // keep the carrier: this test counts, the next one abandons
	pr := newPair(t, cfg, 50*time.Millisecond)
	cs, err := pr.cli.OpenStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	ss := accept(t, pr.svc)

	// Capture one genuine client→service packet.
	var captured []byte
	var mu sync.Mutex
	p := pr.path()
	p.mu.Lock()
	p.tamper = func(dir int, pk []byte) []byte {
		mu.Lock()
		if dir == 0 && captured == nil {
			captured = append([]byte(nil), pk...)
		}
		mu.Unlock()
		return pk
	}
	p.mu.Unlock()
	if _, err := cs.Write([]byte("genuine")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(ss, buf); err != nil || string(buf) != "genuine" {
		t.Fatalf("genuine data: %q %v", buf, err)
	}
	mu.Lock()
	genuine := captured
	mu.Unlock()

	other, _ := NewClient(seed(t), cfg) // a session the RP controls
	defer other.Close()
	before := pr.svc.Stats()

	forgeries := map[string][]byte{}
	flip := append([]byte(nil), genuine...)
	flip[len(flip)-20] ^= 1
	forgeries["bit-flipped genuine packet"] = flip
	hdr := append([]byte(nil), genuine...)
	hdr[5] ^= 0x80 // the packet number: AAD, so the tag fails
	forgeries["altered header"] = hdr
	forgeries["random bytes, valid version"] = append([]byte{1}, randBytes(t, PacketSize-1)...)
	other.mu.Lock()
	alien, _ := other.sealLocked(frame{seq: 1, typ: ftData, stream: cs.ID(), data: []byte("INJECTED")}, time.Now())
	other.mu.Unlock()
	forgeries["sealed under another session's keys"] = alien
	forgeries["truncated"] = genuine[:100]

	for name, f := range forgeries {
		if err := pr.svc.Receive(p.svc, f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := pr.svc.Receive(p.svc, genuine); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed genuine packet: %v, want ErrReplay", err)
	}
	after := pr.svc.Stats()
	if got := after.Hostile - before.Hostile; got != uint64(len(forgeries))+1 {
		t.Errorf("hostile count rose by %d, want %d (every forgery and the replay)", got, len(forgeries)+1)
	}
	ss.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := ss.Read(make([]byte, 64)); n != 0 || !errors.Is(err, errDeadline) {
		t.Fatalf("a forged or replayed cell reached the application: n=%d err=%v", n, err)
	}
}

var errDeadline = os.ErrDeadlineExceeded

// TestHostileCarrierIsAbandoned: past HostileLimit forged cells the carrier is
// dropped as CARRIER_HOSTILE and the session migrates off it.
func TestHostileCarrierIsAbandoned(t *testing.T) {
	cfg := testConfig()
	cfg.HostileLimit = 4
	var why atomic.Value
	k := seed(t)
	svcCfg := cfg
	svcCfg.OnOrphan = func(_ *Session, err error) { why.Store(err) }
	cli, _ := NewClient(k, cfg)
	svc := NewService(k, cli.ID(), svcCfg)
	defer cli.Close()
	defer svc.Close()
	p := connect(t, cli, svc)
	defer p.kill(false)
	for i := 0; i < cfg.HostileLimit; i++ {
		_ = svc.Receive(p.svc, append([]byte{1}, randBytes(t, PacketSize-1)...))
	}
	deadline := time.Now().Add(2 * time.Second)
	for svc.State() != Orphaned && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if svc.State() != Orphaned {
		t.Fatalf("state %s after %d forged cells, want ORPHANED", svc.State(), cfg.HostileLimit)
	}
	for why.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err, _ := why.Load().(error); !errors.Is(err, ErrCarrierHostile) {
		t.Fatalf("orphaned because %v, want CARRIER_HOSTILE", err)
	}
}

// TestRekeyCrossesEpochs: with a tiny rekey threshold, a transfer crosses many
// key epochs in both directions without losing a byte.
func TestRekeyCrossesEpochs(t *testing.T) {
	cfg := testConfig()
	cfg.RekeyPackets = 64
	pr := newPair(t, cfg, 50*time.Millisecond)
	x := startTransfer(t, pr, 1<<20)
	<-x.done
	x.check(t)
	if r := pr.cli.Stats().Rekeys + pr.svc.Stats().Rekeys; r < 20 {
		t.Fatalf("only %d rekeys across ~2300 packets at 64 per key", r)
	}
	pr.cli.mu.Lock()
	ep := pr.cli.tx.epoch
	pr.cli.mu.Unlock()
	if ep < 8 {
		t.Fatalf("client tx epoch %d", ep)
	}
}

// TestFlowControlBoundsAStalledReader: a reader that stops reading holds the
// writer to one window, not the whole send buffer.
func TestFlowControlBoundsAStalledReader(t *testing.T) {
	cfg := testConfig()
	cfg.StreamWindow = 64 << 10
	pr := newPair(t, cfg, 50*time.Millisecond)
	cs, _ := pr.cli.OpenStream(nil)
	ss := accept(t, pr.svc)
	var wrote atomic.Int64
	go func() {
		chunk := make([]byte, 4096)
		for {
			if _, err := cs.Write(chunk); err != nil {
				return
			}
			wrote.Add(int64(len(chunk)))
		}
	}()
	time.Sleep(300 * time.Millisecond)
	if w := wrote.Load(); w > int64(cfg.StreamWindow)+4096 {
		t.Fatalf("writer got %d bytes ahead of a reader that never read (window %d)", w, cfg.StreamWindow)
	}
	// Reading opens the window again.
	buf := make([]byte, 32<<10)
	total := 0
	for total < 4*cfg.StreamWindow {
		n, err := ss.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if wrote.Load() < int64(3*cfg.StreamWindow) {
		t.Fatalf("writer did not resume after the reader drained: %d", wrote.Load())
	}
}

// TestManyStreamsInterleave: fifty concurrent echo streams on one session.
func TestManyStreamsInterleave(t *testing.T) {
	pr := newPair(t, testConfig(), 50*time.Millisecond)
	go func() {
		for {
			st, err := pr.svc.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() { io.Copy(st, st); st.CloseWrite() }()
		}
	}()
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := pr.cli.OpenStream([]byte{byte(i)})
			if err != nil {
				errs <- err
				return
			}
			msg := bytes.Repeat([]byte{byte(i)}, 5000+i*37)
			go func() { st.Write(msg); st.CloseWrite() }()
			got, err := io.ReadAll(st)
			if err != nil || !bytes.Equal(got, msg) {
				errs <- errors.New("echo mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// TestOrphanRetentionCloses: no carrier inside the retention window and the
// session is CLOSED; blocked callers get ErrSessionLost.
func TestOrphanRetentionCloses(t *testing.T) {
	cfg := testConfig()
	cfg.OrphanRetention = 300 * time.Millisecond
	k := seed(t)
	cli, _ := NewClient(k, cfg) // no OnOrphan: nobody rebuilds
	svc := NewService(k, cli.ID(), cfg)
	p := connect(t, cli, svc)
	st, _ := cli.OpenStream(nil)
	ss := accept(t, svc)
	_ = ss
	errc := make(chan error, 1)
	go func() { _, err := st.Read(make([]byte, 1)); errc <- err }()
	p.kill(true)
	select {
	case err := <-errc:
		if !errors.Is(err, ErrSessionLost) {
			t.Fatalf("blocked read returned %v, want ErrSessionLost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked read never returned")
	}
	if cli.State() != Closed {
		t.Fatalf("state %s", cli.State())
	}
	// Zeroised (§9.9).
	cli.mu.Lock()
	z := cli.keys.root == [32]byte{} && cli.keys.resume == [32]byte{} && cli.tx.key == [32]byte{}
	cli.mu.Unlock()
	if !z {
		t.Fatal("keys survived CLOSED")
	}
}

// TestHardLifetimeAndIdle: the two caps close the session and tell the peer.
func TestHardLifetimeAndIdle(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Config)
		want error
	}{
		{"lifetime", func(c *Config) { c.HardLifetime = 300 * time.Millisecond }, ErrLifetime},
		{"idle", func(c *Config) { c.IdleTimeout = 300 * time.Millisecond }, ErrIdle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.set(&cfg)
			k := seed(t)
			cli, _ := NewClient(k, cfg)
			svcCfg := testConfig()
			svc := NewService(k, cli.ID(), svcCfg)
			defer svc.Close()
			p := connect(t, cli, svc)
			defer p.kill(false)
			select {
			case <-cli.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("session outlived its cap")
			}
			if !errors.Is(cli.Err(), tc.want) {
				t.Fatalf("closed with %v, want %v", cli.Err(), tc.want)
			}
			select {
			case <-svc.Done():
				if !errors.Is(svc.Err(), ErrPeerClosed) {
					t.Fatalf("peer closed with %v", svc.Err())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the peer was not told")
			}
		})
	}
}

// TestGoAwayStopsNewStreamsOnly is §9.9: existing streams finish, no new ones
// open, and retry_after reaches the peer.
func TestGoAwayStopsNewStreamsOnly(t *testing.T) {
	pr := newPair(t, testConfig(), 50*time.Millisecond)
	cs, _ := pr.cli.OpenStream(nil)
	ss := accept(t, pr.svc)
	pr.svc.GoAway(90 * time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if ra, ok := pr.cli.RetryAfter(); ok {
			if ra != 90*time.Second {
				t.Fatalf("retry_after %v", ra)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("GOING_AWAY never arrived")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := pr.cli.OpenStream(nil); !errors.Is(err, ErrGoingAway) {
		t.Fatalf("new stream after GOING_AWAY: %v", err)
	}
	go func() { cs.Write([]byte("still here")); cs.CloseWrite() }()
	got, err := io.ReadAll(ss)
	if err != nil || string(got) != "still here" {
		t.Fatalf("existing stream after GOING_AWAY: %q %v", got, err)
	}
}

// TestDegradedRefusesNewStreams is §9.2's DEGRADED signal.
func TestDegradedRefusesNewStreams(t *testing.T) {
	pr := newPair(t, testConfig(), 50*time.Millisecond)
	pr.cli.SetDegraded(true)
	if _, err := pr.cli.OpenStream(nil); !errors.Is(err, ErrDegraded) {
		t.Fatalf("open while DEGRADED: %v", err)
	}
	pr.cli.SetDegraded(false)
	if _, err := pr.cli.OpenStream(nil); err != nil {
		t.Fatal(err)
	}
}

// TestStreamCloseIsLikeTCP: a server that writes its answer and closes loses
// none of it, and a client that keeps writing to a closed stream is told.
func TestStreamCloseIsLikeTCP(t *testing.T) {
	pr := newPair(t, testConfig(), 50*time.Millisecond)
	cs, _ := pr.cli.OpenStream(nil)
	ss := accept(t, pr.svc)
	answer := randBytes(t, 100<<10)
	if _, err := ss.Write(answer); err != nil {
		t.Fatal(err)
	}
	ss.Close() // without reading the request, and before the client has read
	got, err := io.ReadAll(cs)
	if err != nil || !bytes.Equal(got, answer) {
		t.Fatalf("answer after Close: %d bytes, %v", len(got), err)
	}
	var werr error
	for i := 0; i < 200 && werr == nil; i++ {
		_, werr = cs.Write(make([]byte, 4096))
		time.Sleep(2 * time.Millisecond)
	}
	if !errors.Is(werr, ErrStreamReset) {
		t.Fatalf("writing to a closed stream: %v, want ErrStreamReset", werr)
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	for _, pn := range []uint64{1, 2, 3, 10, 5, 1100, 1099, 2000} {
		if err := w.check(pn); err != nil {
			t.Fatalf("fresh pn %d refused", pn)
		}
		w.mark(pn)
		if w.check(pn) == nil {
			t.Fatalf("pn %d accepted twice", pn)
		}
	}
	if w.check(5) == nil || w.check(975) == nil {
		t.Fatal("a number outside the window was accepted")
	}
	if w.check(1500) != nil {
		t.Fatal("an unseen number inside the window was refused")
	}
	if w.check(0) == nil {
		t.Fatal("pn 0 accepted")
	}
}

func TestPacketsAreAlwaysFull(t *testing.T) {
	pr := newPair(t, testConfig(), 50*time.Millisecond)
	p := pr.path()
	var sizes sync.Map
	p.mu.Lock()
	p.tamper = func(dir int, pk []byte) []byte { sizes.Store(len(pk), true); return pk }
	p.mu.Unlock()
	cs, _ := pr.cli.OpenStream(nil)
	ss := accept(t, pr.svc)
	for _, n := range []int{1, 7, 100, MaxData, MaxData + 1, 5000} {
		cs.Write(randBytes(t, n))
		io.ReadFull(ss, make([]byte, n))
	}
	n := 0
	sizes.Range(func(k, _ any) bool {
		n++
		if k.(int) != PacketSize {
			t.Errorf("a %d-byte packet crossed the RP; every packet must be %d", k, PacketSize)
		}
		return true
	})
	if n == 0 {
		t.Fatal("nothing observed")
	}
}
