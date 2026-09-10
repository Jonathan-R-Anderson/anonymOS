package link

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/quic-go/quic-go"
)

var soak = flag.Bool("soak", false, "run the E2.1 10^6-cell soak")

// P2's transport-parity criteria. T2.4 says QUIC and TCP must produce
// byte-identical cell sequences for one input; T2.5 says 0-RTT is off.
//
// The point of T2.4 is not that the two transports are interchangeable -- they
// are not, and R12's isolation is a QUIC property -- but that the FRAMING above
// them is transport-independent. A cell that encoded differently depending on
// how it travelled would make every capture-based test transport-specific and
// would mean the fallback path is a second protocol wearing the same name.

// newHostOn builds a host listening on the given multiaddr template.
func newHostOn(t *testing.T, listen string) host.Host {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sk, err := libp2pcrypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	h, err := libp2p.New(
		libp2p.Identity(sk),
		libp2p.ListenAddrStrings(listen),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatalf("host on %s: %v", listen, err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// exchange sends the given cells across a link built on one transport and
// returns the exact bytes the receiver saw, in order.
func exchange(t *testing.T, listenAddr string, cells []*Cell) []byte {
	t.Helper()

	server := newHostOn(t, listenAddr)
	client := newHostOn(t, listenAddr)

	// Confirm the link really used the transport under test rather than
	// silently falling back to another one the host also supports.
	assertTransport(t, server, listenAddr)

	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), time.Hour)
	if err := client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatalf("%s: connect: %v", listenAddr, err)
	}

	lk, err := (&Dialer{Host: client}).Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("%s: dial: %v", listenAddr, err)
	}
	defer lk.Close()

	const circuit = 11
	cs, err := lk.OpenCircuitStream(ctx, circuit)
	if err != nil {
		t.Fatalf("%s: open: %v", listenAddr, err)
	}

	srvLink, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("%s: accept link: %v", listenAddr, err)
	}
	srv, err := srvLink.AcceptCircuitStream(ctx)
	if err != nil {
		t.Fatalf("%s: accept circuit: %v", listenAddr, err)
	}

	got := make(chan []byte, 1)
	go func() {
		var seen bytes.Buffer
		for range cells {
			c, err := srv.ReadCell()
			if err != nil {
				got <- nil
				return
			}
			// Re-encode what arrived. Comparing re-encoded cells rather than
			// raw socket bytes is deliberate: the socket carries the
			// transport's own framing, which differs by construction. What
			// must match is the CELL sequence.
			buf := make([]byte, 1024)
			if err := c.Encode(buf); err != nil {
				got <- nil
				return
			}
			seen.Write(buf)
		}
		got <- seen.Bytes()
	}()

	for i, c := range cells {
		if err := cs.WriteCell(c); err != nil {
			t.Fatalf("%s: write %d: %v", listenAddr, i, err)
		}
	}

	select {
	case b := <-got:
		if b == nil {
			t.Fatalf("%s: receiver failed", listenAddr)
		}
		return b
	case <-ctx.Done():
		t.Fatalf("%s: timed out", listenAddr)
		return nil
	}
}

// assertTransport fails if the host is not actually listening on the transport
// the test believes it is testing.
func assertTransport(t *testing.T, h host.Host, listenAddr string) {
	t.Helper()
	want := "tcp"
	if strings.Contains(listenAddr, "quic") {
		want = "quic"
	}
	for _, a := range h.Addrs() {
		if strings.Contains(a.String(), want) {
			return
		}
	}
	t.Fatalf("host is not listening on %s; addrs=%v", want, h.Addrs())
}

// TestCellSequenceIdenticalOverQUICAndTCP is T2.4.
func TestCellSequenceIdenticalOverQUICAndTCP(t *testing.T) {
	// A deliberately varied input: empty, tiny, maximal, flagged, several
	// commands. If framing depended on the transport, one of these would be
	// where it showed.
	cells := []*Cell{
		{Circuit: 11, Command: CmdRelay, Payload: nil},
		{Circuit: 11, Command: CmdRelay, Payload: []byte{0x00}},
		{Circuit: 11, Command: CmdRelay, Payload: []byte("a longer payload with bytes \x00\xff\x7f")},
		{Circuit: 11, Command: CmdCreate, Flags: FlagEarly, Payload: bytes.Repeat([]byte{0xa5}, MaxPayload)},
		{Circuit: 11, Command: CmdPadding},
		{Circuit: 11, Command: CmdDestroy, Payload: []byte("bye")},
	}

	overTCP := exchange(t, "/ip4/127.0.0.1/tcp/0", cells)
	overQUIC := exchange(t, "/ip4/127.0.0.1/udp/0/quic-v1", cells)

	if len(overTCP) != len(cells)*1024 {
		t.Fatalf("TCP produced %d bytes, want %d", len(overTCP), len(cells)*1024)
	}
	if !bytes.Equal(overTCP, overQUIC) {
		// Report the first divergence rather than dumping 6 KB.
		for i := range overTCP {
			if i >= len(overQUIC) || overTCP[i] != overQUIC[i] {
				t.Fatalf("cell sequences diverge at byte %d (cell %d, offset %d): tcp=0x%02x quic=0x%02x",
					i, i/1024, i%1024, overTCP[i], overQUIC[i])
			}
		}
		t.Fatal("cell sequences differ in length")
	}
}

// TestZeroRTTIsOff is T2.5, the configuration half.
//
// quic-go accepts 0-RTT only when Allow0RTT is set on the server config, and it
// is false unless something sets it. This asserts the default we depend on
// rather than trusting it: 0-RTT data is replayable by definition, and a
// replayed CREATE cell is a circuit an attacker did not pay to build.
func TestZeroRTTIsOff(t *testing.T) {
	var cfg quic.Config
	if cfg.Allow0RTT {
		t.Fatal("quic.Config zero value enables 0-RTT")
	}

	// And nothing in this package turns it on.
	if got := grepPackageFor("Allow0RTT"); got != 0 {
		t.Fatalf("axon/link references Allow0RTT %d times; 0-RTT must stay off (T2.5)", got)
	}
}

// TestBothTransportsCarryManyCells guards the fallback path against being a
// second-class citizen: a framing bug that only appears under load on one
// transport is exactly what T2.4's single-shot comparison would miss.
func TestBothTransportsCarryManyCells(t *testing.T) {
	if testing.Short() {
		t.Skip("bulk transfer")
	}
	const n = 2000
	cells := make([]*Cell, n)
	for i := range cells {
		cells[i] = &Cell{
			Circuit: 11, Command: CmdRelay,
			Payload: []byte{byte(i), byte(i >> 8)},
		}
	}
	tcp := exchange(t, "/ip4/127.0.0.1/tcp/0", cells)
	quicBytes := exchange(t, "/ip4/127.0.0.1/udp/0/quic-v1", cells)
	if !bytes.Equal(tcp, quicBytes) {
		t.Fatalf("%d-cell sequences diverge between transports", n)
	}
	if len(tcp) != n*1024 {
		t.Fatalf("expected %d bytes, got %d", n*1024, len(tcp))
	}
}

// grepPackageFor counts occurrences of s in this package's non-test sources.
// A source-level assertion because the property is "we never set this", which
// no runtime check can establish.
// grepPackageFor counts CODE references to an identifier in this package.
//
// COMMENTS ARE STRIPPED FIRST, and that is not a loosening. The audit exists to
// catch code that SETS a field; a comment explaining why the field is
// deliberately left alone is the documentation the audit wants to encourage, and
// counting it made the audit fail on correct code. An audit that fails on
// correct code gets deleted, which is strictly worse than one that reads only
// code. Anything that actually assigns or reads the field still shows up.
func grepPackageFor(s string) int {
	entries, err := os.ReadDir(".")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			count += strings.Count(line, s)
		}
	}
	return count
}

// TestSoakOneMillionCells is E2.1: 10^6 cells over each transport with zero
// framing errors. Gated behind -soak because it is a minutes-long run, not
// something every `go test` should pay for.
//
// It compares a rolling digest rather than accumulating a gigabyte in memory:
// the criterion is "identical byte sequences", and a hash establishes that
// without the test itself becoming the memory hog.
func TestSoakOneMillionCells(t *testing.T) {
	if !*soak {
		t.Skip("use -soak to run E2.1 (10^6 cells per transport)")
	}
	const n = 1_000_000
	tcpSum := soakOne(t, "/ip4/127.0.0.1/tcp/0", n)
	quicSum := soakOne(t, "/ip4/127.0.0.1/udp/0/quic-v1", n)
	if tcpSum != quicSum {
		t.Fatalf("E2.1: digests diverge after %d cells\n  tcp  %x\n  quic %x", n, tcpSum, quicSum)
	}
	t.Logf("E2.1: %d cells over each transport, identical digest %x", n, tcpSum)
}

func soakOne(t *testing.T, listenAddr string, n int) [32]byte {
	t.Helper()
	server := newHostOn(t, listenAddr)
	client := newHostOn(t, listenAddr)
	ln := Listen(server)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), time.Hour)
	if err := client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	lk, err := (&Dialer{Host: client}).Dial(ctx, server.ID())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer lk.Close()
	cs, err := lk.OpenCircuitStream(ctx, 21)
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

	done := make(chan [32]byte, 1)
	errc := make(chan error, 1)
	go func() {
		h := sha256.New()
		buf := make([]byte, 1024)
		for i := 0; i < n; i++ {
			c, err := srv.ReadCell()
			if err != nil {
				errc <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if err := c.Encode(buf); err != nil {
				errc <- fmt.Errorf("re-encode %d: %w", i, err)
				return
			}
			h.Write(buf)
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		done <- sum
	}()

	payload := make([]byte, 64)
	for i := 0; i < n; i++ {
		payload[0], payload[1], payload[2] = byte(i), byte(i>>8), byte(i>>16)
		if err := cs.WriteCell(&Cell{Circuit: 21, Command: CmdRelay, Payload: payload}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		select {
		case err := <-errc:
			t.Fatalf("%s: %v", listenAddr, err)
		default:
		}
	}
	select {
	case sum := <-done:
		return sum
	case err := <-errc:
		t.Fatalf("%s: %v", listenAddr, err)
	case <-ctx.Done():
		t.Fatalf("%s: soak timed out", listenAddr)
	}
	return [32]byte{}
}
