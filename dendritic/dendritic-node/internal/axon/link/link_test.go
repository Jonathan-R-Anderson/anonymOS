package link

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// P2's link tests. These need two live endpoints, so they stand up real libp2p
// hosts on loopback rather than mocking the transport -- a mocked multiplexer
// would prove nothing about R12, which is a property of the real one.

func newHost(t *testing.T) (host.Host, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sk, err := libp2pcrypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	h, err := libp2p.New(
		libp2p.Identity(sk),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, pub
}

func connect(t *testing.T, from, to host.Host) {
	t.Helper()
	from.Peerstore().AddAddrs(to.ID(), to.Addrs(), time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := from.Connect(ctx, peer.AddrInfo{ID: to.ID(), Addrs: to.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

// TestNodeIDDerivationMatchesHostIdentity: the AXON NodeIdentity public key and
// the libp2p peer id must name the same node, or the link authenticates
// something other than the identity the rest of the system bonds.
func TestNodeIDDerivationMatchesHostIdentity(t *testing.T) {
	h, pub := newHost(t)
	got, err := NodeIDFromPublic(pub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got != h.ID() {
		t.Fatalf("NodeIDFromPublic = %s, host id = %s", got, h.ID())
	}
}

// TestDialRefusesWrongIdentity is T2.3. A link presenting an identity other
// than the one requested must be refused before any cell is sent.
func TestDialRefusesWrongIdentity(t *testing.T) {
	client, _ := newHost(t)
	server, _ := newHost(t)
	impostor, impostorPub := newHost(t)

	// Point the client at the impostor's ADDRESS while asking for the server's
	// identity: the classic substitution. libp2p's security handshake must
	// refuse it, and we assert the refusal rather than assuming it.
	client.Peerstore().AddAddrs(server.ID(), impostor.Addrs(), time.Hour)

	d := &Dialer{Host: client}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	if _, err := d.Dial(ctx, server.ID()); err == nil {
		t.Fatal("dial succeeded against a host holding a different key")
	}

	// Sanity: the impostor's own identity is reachable at that address, so the
	// failure above was about identity and not about the address being dead.
	impID, err := NodeIDFromPublic(impostorPub)
	if err != nil {
		t.Fatal(err)
	}
	client.Peerstore().AddAddrs(impID, impostor.Addrs(), time.Hour)
	if _, err := d.Dial(ctx, impID); err != nil {
		t.Fatalf("dial to the impostor's real identity failed: %v", err)
	}
}

// TestDialRequiresExpectedIdentity: dialing without naming who you expect is a
// programming error, not a convenience.
func TestDialRequiresExpectedIdentity(t *testing.T) {
	h, _ := newHost(t)
	d := &Dialer{Host: h}
	if _, err := d.Dial(context.Background(), ""); err == nil {
		t.Fatal("dial accepted an empty expected identity")
	}
}

// TestCircuitStreamRoundTrip: cells cross a real link intact.
func TestCircuitStreamRoundTrip(t *testing.T) {
	client, _ := newHost(t)
	server, _ := newHost(t)
	connect(t, client, server)

	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	d := &Dialer{Host: client}
	lk, err := d.Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer lk.Close()

	cs, err := lk.OpenCircuitStream(ctx, 7)
	if err != nil {
		t.Fatalf("open circuit: %v", err)
	}

	srvLink, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("accept link: %v", err)
	}
	srvStream, err := srvLink.AcceptCircuitStream(ctx)
	if err != nil {
		t.Fatalf("accept circuit: %v", err)
	}
	if srvStream.CircuitID() != 7 {
		t.Fatalf("server bound circuit %d, want 7", srvStream.CircuitID())
	}

	want := []byte("cells cross intact")
	// CmdRelay is onioned: LENGTH is zero on the wire and the receiver gets the
	// whole 944-byte region, because only the hop holding the key knows where
	// the real message ends. The prefix is what must survive.
	if err := cs.WriteCell(&Cell{Circuit: 7, Command: CmdRelay, Payload: want}); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := srvStream.ReadCell()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Payload) != MaxPayload {
		t.Fatalf("onioned payload = %d bytes, want the full %d region", len(got.Payload), MaxPayload)
	}
	if string(got.Payload[:len(want)]) != string(want) {
		t.Fatalf("payload = %q, want prefix %q", got.Payload[:len(want)], want)
	}
	if got.Circuit != 7 {
		t.Fatalf("circuit = %d, want 7", got.Circuit)
	}
}

// TestStreamRejectsForeignCircuitID: a stream carries exactly one circuit.
// Allowing a cell to claim another id would make R12's isolation meaningless.
func TestStreamRejectsForeignCircuitID(t *testing.T) {
	client, _ := newHost(t)
	server, _ := newHost(t)
	connect(t, client, server)
	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lk, err := (&Dialer{Host: client}).Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer lk.Close()
	cs, err := lk.OpenCircuitStream(ctx, 1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := cs.WriteCell(&Cell{Circuit: 2, Command: CmdRelay}); err == nil {
		t.Fatal("a cell for circuit 2 was accepted on the stream for circuit 1")
	}
}

// TestDuplicateCircuitRefused: circuit ids are unique per link.
func TestDuplicateCircuitRefused(t *testing.T) {
	client, _ := newHost(t)
	server, _ := newHost(t)
	connect(t, client, server)
	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lk, err := (&Dialer{Host: client}).Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer lk.Close()

	if _, err := lk.OpenCircuitStream(ctx, 5); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := lk.OpenCircuitStream(ctx, 5); !errors.Is(err, ErrDuplicateCircuit) {
		t.Fatalf("duplicate circuit accepted: %v", err)
	}
}

// TestCircuitCapIsEnforced is E2.3: a relay under MaxCircuitsPerLink streams
// from one peer refuses the next one rather than growing without bound.
func TestCircuitCapIsEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("opens MaxCircuitsPerLink streams")
	}
	client, _ := newHost(t)
	server, _ := newHost(t)
	connect(t, client, server)
	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	lk, err := (&Dialer{Host: client}).Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer lk.Close()

	hl := lk.(*hostLink)
	// Reserve up to the cap without opening real streams: the cap is the
	// bookkeeping invariant, and this keeps the test from being a load test.
	for i := 0; i < MaxCircuitsPerLink; i++ {
		if err := hl.reserve(CircuitID(i)); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	if got := hl.CircuitCount(); got != MaxCircuitsPerLink {
		t.Fatalf("circuit count = %d, want %d", got, MaxCircuitsPerLink)
	}
	if err := hl.reserve(CircuitID(MaxCircuitsPerLink)); !errors.Is(err, ErrTooManyCircuits) {
		t.Fatalf("the %dth circuit was accepted: %v", MaxCircuitsPerLink+1, err)
	}
	// Closing one must free exactly one slot, or the cap leaks over time.
	hl.release(0)
	if err := hl.reserve(CircuitID(MaxCircuitsPerLink)); err != nil {
		t.Fatalf("slot was not freed on release: %v", err)
	}
}

// TestHeadOfLineIsolation is T2.2 / E2.2, the property R12 exists for: a
// circuit whose peer has stopped reading must not block its neighbours.
//
// The experiment has to isolate head-of-line blocking from ordinary bandwidth
// competition, and an earlier version of this test did not -- it kept circuit A
// writing at full rate, so circuit B slowed by ~5x simply because A was using
// the link. That measured contention, not blocking, and it was flaky at any
// threshold because the two are different phenomena.
//
// The correct condition: drive A until its flow-control window is FULL, so its
// writer is parked in a single blocked write and consumes no further bandwidth.
// A is then stalled and idle. If circuits share an ordered stream, B is stuck
// behind A's undelivered bytes and throughput collapses. If R12 holds -- one
// stream per circuit -- B is unaffected, because A's backlog is in A's stream.
func TestHeadOfLineIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput comparison")
	}
	client, _ := newHost(t)
	server, _ := newHost(t)
	connect(t, client, server)
	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	lk, err := (&Dialer{Host: client}).Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer lk.Close()

	srvLinkC := make(chan Link, 1)
	go func() {
		if l, err := ln.Accept(ctx); err == nil {
			srvLinkC <- l
		}
	}()

	// Circuit B: the one the server drains.
	bClient, err := lk.OpenCircuitStream(ctx, 2)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	sl := <-srvLinkC
	bServer, err := sl.AcceptCircuitStream(ctx)
	if err != nil {
		t.Fatalf("accept B: %v", err)
	}

	baseline := pump(t, bClient, bServer, 300)

	// Circuit A: accepted but never read by the server.
	aClient, err := lk.OpenCircuitStream(ctx, 1)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	if _, err := sl.AcceptCircuitStream(ctx); err != nil {
		t.Fatalf("accept A: %v", err)
	}

	// Fill A's window, then STOP. blocked closes when a write parks, which is
	// the moment A becomes stalled-and-idle -- the condition under test.
	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		payload := make([]byte, MaxPayload)
		for i := 0; i < 100_000; i++ {
			if err := aClient.WriteCell(&Cell{Circuit: 1, Command: CmdRelay, Payload: payload}); err != nil {
				return
			}
		}
	}()

	// Give the writer time to saturate A's window and park.
	time.Sleep(750 * time.Millisecond)

	stalled := pump(t, bClient, bServer, 300)

	_ = aClient.Close() // unblock the parked writer
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled-circuit writer did not unblock when its stream was closed")
	}

	ratio := float64(stalled) / float64(baseline)
	t.Logf("B throughput: baseline %v, with A stalled %v (%.2fx)", baseline, stalled, ratio)

	// The assertion is LIVENESS, not a throughput ratio, and that is deliberate.
	//
	// Head-of-line blocking and bandwidth contention are different outcomes: if
	// circuits shared an ordered stream, B would not be slower behind a stalled
	// A -- it would be stopped, indefinitely, because A's undelivered bytes sit
	// in front of B's. Any finite completion time falsifies that.
	//
	// A ratio assertion was tried first and was flaky at every threshold, for a
	// reason worth recording: on loopback the BASELINE is the unstable term
	// (measured 2.2ms-13.3ms across runs, against a stalled figure of 6-15ms),
	// because 300 cells is short enough to be dominated by congestion-window
	// ramp and scheduler noise. Tuning the threshold would have hidden that
	// rather than measured anything.
	//
	// E2.2's "within 10%" is a production-network criterion. It needs a
	// controlled link with stable RTT and a warmed window, not a loopback pair
	// in a unit test, so E2.2 is NOT discharged here -- only the qualitative
	// property that R12 exists to provide.
	if stalled > 5*time.Second {
		t.Fatalf("circuit B took %v behind a stalled circuit A — B is blocked, not merely slowed; R12 is not holding", stalled)
	}
}

// pump sends n cells on `from` and reads them on `to`, returning elapsed time.
func pump(t *testing.T, from, to CellStream, n int) time.Duration {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			if _, err := to.ReadCell(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	start := time.Now()
	for i := 0; i < n; i++ {
		if err := from.WriteCell(&Cell{
			Circuit: from.CircuitID(), Command: CmdRelay,
			Payload: make([]byte, MaxPayload),
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("read: %v", err)
	}
	return time.Since(start)
}

// TestManyCellsAcrossALink is the framing half of E2.1 at link scale: a long
// run of cells crosses a real link with zero framing errors.
func TestManyCellsAcrossALink(t *testing.T) {
	client, _ := newHost(t)
	server, _ := newHost(t)
	connect(t, client, server)
	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	lk, err := (&Dialer{Host: client}).Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer lk.Close()

	cs, err := lk.OpenCircuitStream(ctx, 3)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srvLink, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("accept link: %v", err)
	}
	srv, err := srvLink.AcceptCircuitStream(ctx)
	if err != nil {
		t.Fatalf("accept circuit: %v", err)
	}

	const n = 5000
	errc := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			c, err := srv.ReadCell()
			if err != nil {
				errc <- err
				return
			}
			if len(c.Payload) != MaxPayload || c.Payload[0] != byte(i) {
				errc <- errors.New("cell content diverged")
				return
			}
		}
		errc <- nil
	}()
	for i := 0; i < n; i++ {
		if err := cs.WriteCell(&Cell{Circuit: 3, Command: CmdRelay, Payload: []byte{byte(i)}}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("across %d cells: %v", n, err)
	}
}
