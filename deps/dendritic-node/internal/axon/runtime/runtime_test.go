package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
)

// A real AXON network on loopback: relays with libp2p links (TCP), a hidden
// service on a node that relays nothing and accepts nothing, and a client that
// finds the service by its address alone.

func testSession() session.Config {
	c := session.DefaultConfig()
	c.MinRTO = 300 * time.Millisecond
	c.MaxRTO = 2 * time.Second
	c.ProbeTimeout = 4 * time.Second
	return c
}

func quietLog() *log.Logger {
	if os.Getenv("AXON_TEST_LOG") != "" {
		return log.New(os.Stderr, "axon: ", log.Lmicroseconds)
	}
	return log.New(io.Discard, "", 0)
}

func startRelays(t *testing.T, n int) []*Runtime {
	t.Helper()
	ctx := context.Background()
	var relays []*Runtime
	var seeds []string
	for i := 0; i < n; i++ {
		rt, err := Start(ctx, Config{DataDir: t.TempDir(), Listen: []string{"/ip4/127.0.0.1/tcp/0"},
			Relay: true, Seeds: seeds, AllowSameNetwork: true, Session: testSession(), Logger: quietLog()})
		if err != nil {
			t.Fatalf("relay %d: %v", i, err)
		}
		t.Cleanup(func() { rt.Close() })
		if i == 0 {
			seeds = rt.Addrs()[:1]
		}
		relays = append(relays, rt)
	}
	for _, rt := range relays {
		rt.Directory().Refresh(ctx)
	}
	return relays
}

func startClient(t *testing.T, relays []*Runtime) *Runtime {
	t.Helper()
	rt, err := Start(context.Background(), Config{DataDir: t.TempDir(), Seeds: relays[0].Addrs()[:1],
		AllowSameNetwork: true, Session: testSession(), Logger: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close() })
	return rt
}

func TestDirectoryConverges(t *testing.T) {
	relays := startRelays(t, 5)
	for i, rt := range relays {
		if got := len(rt.Directory().Relays()); got != 5 {
			t.Fatalf("relay %d knows %d relays, want 5", i, got)
		}
	}
	c := startClient(t, relays)
	if got := len(c.Directory().Relays()); got != 5 {
		t.Fatalf("client knows %d relays, want 5", got)
	}
}

func TestCircuitThroughRealRelays(t *testing.T) {
	relays := startRelays(t, 4)
	c := startClient(t, relays)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	last := relays[3].Directory().Self()
	cc, err := c.circuitTo(ctx, last, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	if len(cc.hops) != 3 || cc.terminal().Peer != last.Peer {
		t.Fatalf("circuit of %d hops ending at %s", len(cc.hops), cc.terminal().Peer)
	}
	// A control session to the terminal hop, over the three hops.
	ctl := cc.control()
	defer ctl.Close()
	var key [32]byte
	rand.Read(key[:])
	if wire, err := hsdirFetchAt(ctx, ctl, key); err != nil || len(wire) != 0 {
		t.Fatalf("fetch of an absent descriptor: %d bytes, %v", len(wire), err)
	}
}

func echoService(t *testing.T, svc *Service) {
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
}

// TestHiddenServiceEndToEnd: a service published by address, reached by a
// client that knows nothing but the address, over real relays.
func TestHiddenServiceEndToEnd(t *testing.T) {
	relays := startRelays(t, 6)
	server := startClient(t, relays)
	var seed [32]byte
	rand.Read(seed[:])
	svc, err := server.Listen(seed)
	if err != nil {
		t.Fatal(err)
	}
	echoService(t, svc)
	client := startClient(t, relays)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := client.Dial(ctx, svc.Addr(), []byte("echo"))
	if err != nil {
		t.Fatalf("dial %s: %v", svc.Addr(), err)
	}
	t.Logf("connected to %s in %v", svc.Addr(), time.Since(start).Round(time.Millisecond))
	msg := make([]byte, 256<<10)
	rand.Read(msg)
	go func() { conn.Write(msg); conn.(interface{ CloseWrite() error }).CloseWrite() }()
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %d bytes, %v", len(got), err)
	}
	// A second stream reuses the session.
	c2, err := client.Dial(ctx, svc.Addr(), []byte("echo"))
	if err != nil {
		t.Fatal(err)
	}
	c2.Write([]byte("again"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c2, buf); err != nil || string(buf) != "again" {
		t.Fatalf("second stream: %q %v", buf, err)
	}
}

// TestSessionSurvivesTheRendezvousPointDying: the RP is killed mid-transfer;
// the client resumes through a new RP (case B) and not a byte is lost.
func TestSessionSurvivesTheRendezvousPointDying(t *testing.T) {
	relays := startRelays(t, 7)
	server := startClient(t, relays)
	var seed [32]byte
	rand.Read(seed[:])
	svc, err := server.Listen(seed)
	if err != nil {
		t.Fatal(err)
	}
	echoService(t, svc)
	client := startClient(t, relays)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, svc.Addr(), []byte("echo"))
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 2<<20)
	rand.Read(msg)
	var got []byte
	var rerr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); got, rerr = io.ReadAll(conn) }()
	go func() {
		conn.Write(msg[:len(msg)/2])
		// Kill the rendezvous point.
		client.mu.Lock()
		var rp *RelayInfo
		for _, r := range client.dials {
			r.mu.Lock()
			rp = r.rp
			r.mu.Unlock()
		}
		client.mu.Unlock()
		for _, rt := range relays {
			if rp != nil && rt.NodeID() == rp.Peer {
				rt.Close()
				t.Logf("killed the rendezvous point %s", rp.Peer)
			}
		}
		conn.Write(msg[len(msg)/2:])
		conn.(interface{ CloseWrite() error }).CloseWrite()
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("transfer did not finish")
	}
	if rerr != nil || sha256.Sum256(got) != sha256.Sum256(msg) {
		t.Fatalf("after the RP died: %d/%d bytes, %v", len(got), len(msg), rerr)
	}
}
