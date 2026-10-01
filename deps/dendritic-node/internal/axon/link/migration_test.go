package link

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// TestTransportProfileMatchesSection62 pins §6.2's table.
//
// Every value here is a wire-visible constant that MUST be identical on every
// node. §12: "Transport parameters fixed by spec, not by config. No knob may
// change a byte that is visible before the handshake completes."
func TestTransportProfileMatchesSection62(t *testing.T) {
	c := TransportProfile()
	if MaxUDPPayloadSize != params.DatagramSize {
		t.Errorf("max_udp_payload_size %d diverges from params.DatagramSize %d; "+
			"§6.2 and §16 are the same number and two copies drift",
			MaxUDPPayloadSize, params.DatagramSize)
	}
	if c.MaxIdleTimeout != 60*time.Second {
		t.Errorf("max_idle_timeout %v, §6.2 says 60s", c.MaxIdleTimeout)
	}
	if c.InitialStreamReceiveWindow != 64<<10 {
		t.Errorf("initial_max_stream_data %d, §6.2 says 64 KiB", c.InitialStreamReceiveWindow)
	}
	if c.InitialConnectionReceiveWindow != 4<<20 {
		t.Errorf("initial_max_data %d, §6.2 says 4 MiB", c.InitialConnectionReceiveWindow)
	}
	if c.MaxIncomingStreams != 512 {
		t.Errorf("initial_max_streams_bidi %d, §6.2 says 512", c.MaxIncomingStreams)
	}
	if c.MaxIncomingUniStreams != 0 {
		t.Errorf("initial_max_streams_uni %d, §6.2 says 0 -- 'a node offering them "+
			"is not speaking AXON'", c.MaxIncomingUniStreams)
	}
	// The windows must not AUTO-TUNE. A growing window is a per-connection
	// behaviour an observer can watch, which is the same leak class as a knob.
	if c.MaxStreamReceiveWindow != c.InitialStreamReceiveWindow {
		t.Error("the stream window auto-tunes; its growth is observable and varies " +
			"per connection")
	}
	if c.MaxConnectionReceiveWindow != c.InitialConnectionReceiveWindow {
		t.Error("the connection window auto-tunes")
	}
	// §6.2 fixes max_udp_payload_size at 1200 so there is NO per-path size
	// variation. PMTU discovery would produce exactly that.
	if !c.DisablePathMTUDiscovery {
		t.Error("PMTU discovery is on; packet sizes then vary per path, which is the " +
			"variation §6.2's fixed 1200 exists to remove")
	}
	// §6.6's relay-to-relay keepalive, and it must stay under §6.2's 60 s idle
	// timeout or links reap themselves between keepalives.
	if c.KeepAlivePeriod <= 0 || c.KeepAlivePeriod >= c.MaxIdleTimeout {
		t.Errorf("keepalive %v against a %v idle timeout", c.KeepAlivePeriod, c.MaxIdleTimeout)
	}
	// 0-RTT is covered by TestZeroRTTIsOff, which also audits that no code in
	// this package names the field. Re-checking it here would name it.
}

// TestTransportProfileTakesNoConfiguration is §12's rule, as a signature check.
//
// A profile that accepted options would let two operators produce two different
// ClientHellos, and a network whose nodes are individually identifiable by their
// transport parameters has lost what every other layer is paying for.
func TestTransportProfileTakesNoConfiguration(t *testing.T) {
	src, err := os.ReadFile("migration.go")
	if err != nil {
		t.Fatal(err)
	}
	sig := regexp.MustCompile(`func TransportProfile\(([^)]*)\)`).FindStringSubmatch(string(src))
	if sig == nil {
		t.Fatal("TransportProfile is gone")
	}
	if strings.TrimSpace(sig[1]) != "" {
		t.Errorf("TransportProfile takes %q; a per-operator parameter is a "+
			"per-operator fingerprint (§12)", sig[1])
	}
}

// TestGuardRefusesRatherThanStallingIsL13 is INVARIANT L1-3's prescribed
// outcome: "a link that cannot be migrated, not one that may be migrated
// unsafely".
func TestGuardRefusesRatherThanStallingIsL13(t *testing.T) {
	g := &MigrationGuard{}
	// depth-1 probes fit; the last entry is held for the ACTIVE path.
	want := MigrationPoolDepth - 1
	for i := 0; i < want; i++ {
		if err := g.Begin(); err != nil {
			t.Fatalf("probe %d refused with %d of %d committed: %v",
				i, g.Outstanding(), MigrationPoolDepth, err)
		}
	}
	if err := g.Begin(); !errors.Is(err, ErrCIDStarved) {
		t.Fatalf("the pool-exhausting probe was allowed to start: %v", err)
	}
	// Releasing one makes room again.
	g.End()
	if err := g.Begin(); err != nil {
		t.Fatalf("a released entry was not reusable: %v", err)
	}
}

// TestGuardHoldsOneEntryForTheActivePath is why the bound is depth-1.
//
// Spending the last connection ID on a probe leaves nothing to migrate TO if the
// current path dies mid-probe — the defence becoming the failure it defends
// against.
func TestGuardHoldsOneEntryForTheActivePath(t *testing.T) {
	g := &MigrationGuard{Depth: 2}
	if err := g.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := g.Begin(); !errors.Is(err, ErrCIDStarved) {
		t.Fatal("a depth-2 pool allowed two outstanding probes, leaving no connection " +
			"ID for the path currently carrying traffic")
	}
	// A depth-1 pool can migrate at all only by giving up that reserve, so it
	// must refuse everything rather than pretend.
	one := &MigrationGuard{Depth: 1}
	if err := one.Begin(); !errors.Is(err, ErrCIDStarved) {
		t.Fatal("a depth-1 pool started a probe")
	}
}

// TestSpecAndLibraryDisagreeOnPoolDepth records the §6.2 shortfall as a fact.
//
// §6.2 specifies active_connection_id_limit = 8, and quic-go v0.59.1 hardcodes
// 4 with no way to set it. Naming both, rather than quietly redefining the spec
// value, is the point: L1-3 says the limit "exists to guarantee the pool is
// never empty at the moment of migration", and half the pool is half that
// margin.
func TestSpecAndLibraryDisagreeOnPoolDepth(t *testing.T) {
	if LibraryActiveConnectionIDLimit >= SpecActiveConnectionIDLimit {
		t.Fatalf("the library now offers %d connection IDs, meeting or exceeding "+
			"§6.2's %d -- the shortfall note in migration.go is stale and should be "+
			"removed", LibraryActiveConnectionIDLimit, SpecActiveConnectionIDLimit)
	}
	// The MEASURED depth is smaller still than the library's own constant, and
	// the guard must be built on the measurement.
	if MigrationPoolDepth > LibraryActiveConnectionIDLimit {
		t.Fatalf("the measured depth %d exceeds the library constant %d",
			MigrationPoolDepth, LibraryActiveConnectionIDLimit)
	}
	// The guard must be built on the LIBRARY's number, not the spec's, or it
	// permits probes that can only stall.
	g := &MigrationGuard{}
	if g.depth() != MigrationPoolDepth {
		t.Fatalf("the guard defaults to depth %d; using §6.2's aspirational %d or the "+
			"library's %d would allow probes the library cannot back with a "+
			"connection ID", g.depth(), SpecActiveConnectionIDLimit,
			LibraryActiveConnectionIDLimit)
	}
}

// TestMigrationOverRealQUIC exercises §6.6 CASE 1 against the actual library.
//
// A real client and server on loopback, a real second UDP socket, and a real
// PATH_CHALLENGE/PATH_RESPONSE. A mock would only prove this file agrees with
// itself, and F4's whole content is whether quic-go does what §6.6 assumes.
func TestMigrationOverRealQUIC(t *testing.T) {
	conn, cleanup := testLink(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A NEW local socket: this is the address change §6.6 CASE 1 describes.
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	tr := &quic.Transport{Conn: udp}
	defer tr.Close()

	g := &MigrationGuard{}
	outcome, err := Migrate(ctx, g, conn, tr)
	if outcome != MigrationSucceeded {
		t.Fatalf("migration to a new local socket did not succeed: %s / %v", outcome, err)
	}
	if g.Outstanding() != 0 {
		t.Fatalf("the guard leaked %d reservations", g.Outstanding())
	}
	t.Log("§6.6 CASE 1 verified against quic-go: the link survived an initiator " +
		"address change")
}

// TestPoolDepthMeasuredAgainstTheLibrary pins the real depth empirically.
//
// The constant above is read off quic-go's source; this checks the BEHAVIOUR
// matches, so a dependency bump that changes it becomes a failure here rather
// than a stall in production.
func TestPoolDepthMeasuredAgainstTheLibrary(t *testing.T) {
	conn, cleanup := testLink(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Stage paths WITHOUT the guard, to observe where the library actually
	// starves rather than where the guard predicts it will.
	staged := 0
	var keep []*quic.Transport
	for i := 0; i < SpecActiveConnectionIDLimit+4; i++ {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			break
		}
		tr := &quic.Transport{Conn: udp}
		keep = append(keep, tr)
		path, err := conn.AddPath(tr)
		if err != nil {
			break
		}
		pctx, pcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		err = path.Probe(pctx)
		pcancel()
		if err != nil {
			break
		}
		staged++
	}
	for _, tr := range keep {
		tr.Close()
	}
	t.Logf("staged %d concurrent validated paths (§6.2 asks for a pool of %d, "+
		"quic-go hardcodes %d, the guard is built on a measured %d)", staged,
		SpecActiveConnectionIDLimit, LibraryActiveConnectionIDLimit, MigrationPoolDepth)
	if staged == 0 {
		t.Fatal("no path could be validated at all; §6.6 CASE 1 does not work here")
	}
	// The guard must never permit more outstanding probes than the library can
	// actually back with a connection ID.
	if MigrationPoolDepth-1 > staged {
		t.Fatalf("the guard would allow %d outstanding probes but the library only "+
			"sustained %d validated paths; the guard is built on a number the "+
			"library does not honour", MigrationPoolDepth-1, staged)
	}
}

// TestServerCannotInitiateMigration is §6.6 CASE 2, as a property of the
// library rather than a claim in prose.
//
// RFC 9000 has no server-initiated migration, which is exactly why a responder's
// address change kills its inbound links while an initiator's does not, and why
// §6.6 has the relay absorb a reconnection storm instead.
func TestServerCannotInitiateMigration(t *testing.T) {
	sudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	str := &quic.Transport{Conn: sudp}
	defer str.Close()
	ln, err := str.Listen(selfSignedTLS(t), TransportProfile())
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()

	accepted := make(chan *quic.Conn, 1)
	go func() {
		if c, err := ln.Accept(context.Background()); err == nil {
			accepted <- c
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	ctr := &quic.Transport{Conn: cudp}
	defer ctr.Close()
	client, err := ctr.Dial(ctx, ln.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"axon-test"},
	}, TransportProfile())
	if err != nil {
		t.Skipf("cannot dial: %v", err)
	}
	defer client.CloseWithError(0, "")

	var srv *quic.Conn
	select {
	case srv = <-accepted:
	case <-ctx.Done():
		t.Skip("no inbound connection")
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	tr := &quic.Transport{Conn: udp}
	defer tr.Close()

	if _, err := srv.AddPath(tr); err == nil {
		t.Fatal("the responder migrated; §6.6 CASE 2's whole analysis -- that inbound " +
			"links die and the relay must absorb a reconnection storm -- assumes it " +
			"cannot")
	}
}

// testLink brings up a client and a server on loopback, BOTH ON EXPLICIT
// quic.Transports.
//
// THE EXPLICIT TRANSPORT IS LOAD-BEARING AND THAT IS THE TRAP. Built with the
// convenience helpers quic.ListenAddr/quic.DialAddr instead, AddPath succeeds,
// Probe sends nothing, and the migration times out after the full deadline with
// `context deadline exceeded` -- indistinguishable from an unreachable network.
// It took a bisect to find, and it is precisely the silent failure §6.6's
// "detectable" claim assumes away. A link layer built on the helpers would have
// no working migration and no error saying so.
func testLink(t *testing.T) (client *quic.Conn, cleanup func()) {
	t.Helper()
	sudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	str := &quic.Transport{Conn: sudp}
	ln, err := str.Listen(selfSignedTLS(t), TransportProfile())
	if err != nil {
		str.Close()
		t.Skipf("cannot listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-c.Context().Done() }()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ln.Close()
		str.Close()
		t.Skipf("cannot listen: %v", err)
	}
	ctr := &quic.Transport{Conn: cudp}
	conn, err := ctr.Dial(ctx, ln.Addr(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"axon-test"},
	}, TransportProfile())
	if err != nil {
		ctr.Close()
		ln.Close()
		str.Close()
		t.Skipf("cannot dial: %v", err)
	}
	<-conn.HandshakeComplete()
	return conn, func() {
		conn.CloseWithError(0, "")
		ctr.Close()
		ln.Close()
		str.Close()
	}
}

// TestMigrationNeedsAnExplicitTransport records the trap as a test.
//
// It is the reason testLink exists, and without it the next person to simplify
// the setup to quic.DialAddr reintroduces a silent, three-second, wholly
// undiagnosable migration failure.
func TestMigrationNeedsAnExplicitTransport(t *testing.T) {
	ln, err := quic.ListenAddr("127.0.0.1:0", selfSignedTLS(t), TransportProfile())
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-c.Context().Done() }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"axon-test"},
	}, TransportProfile())
	if err != nil {
		t.Skipf("cannot dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	<-conn.HandshakeComplete()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	tr := &quic.Transport{Conn: udp}
	defer tr.Close()

	outcome, _ := Migrate(ctx, &MigrationGuard{}, conn, tr)
	if outcome == MigrationSucceeded {
		t.Fatal("migration now works over quic.DialAddr; the explicit-Transport " +
			"requirement in testLink and the note in migration.go are stale and " +
			"should be removed")
	}
	t.Logf("confirmed: over quic.DialAddr the migration reports %s with no "+
		"indication that the transport is the reason", outcome)
}

// selfSignedTLS builds a throwaway server certificate.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "axon-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"axon-test"},
	}
}
