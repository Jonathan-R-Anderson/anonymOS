package transport

import (
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	coretransport "github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime/runtimetest"
)

func TestMultiaddrRoundTripsAndRejectsGarbage(t *testing.T) {
	var seed [32]byte
	rand.Read(seed[:])
	id, err := identity.ServiceIdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	full := identity.FullAddress(id.Public)
	m, err := Multiaddr(full)
	if err != nil {
		t.Fatal(err)
	}
	if !IsAxonAddr(m) {
		t.Fatalf("%s is not recognised", m)
	}
	parsed, err := ma.NewMultiaddr(m.String())
	if err != nil || !parsed.Equal(m) {
		t.Fatalf("string round trip: %v", err)
	}
	if back, err := Address(m); err != nil || back != full {
		t.Fatalf("address = %q, %v", back, err)
	}
	withPeer, _ := ma.NewMultiaddr(m.String() + "/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA")
	if !IsAxonAddr(withPeer) {
		t.Fatal("/axon/.../p2p/... is an AXON address")
	}
	// A checksum error is a different key, not a typo to be forgiven.
	bad := []byte(m.String())
	bad[len(bad)-3] ^= 1
	for _, s := range []string{string(bad), "/axon/short", "/garlic32/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if parsed, err := ma.NewMultiaddr(s); err == nil && IsAxonAddr(parsed) {
			t.Fatalf("%s accepted", s)
		}
	}
	tcp, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/4001")
	if (&Transport{}).CanDial(tcp) {
		t.Fatal("an IP address must never be dialled by the AXON transport")
	}
}

func axonHost(t *testing.T, rt *runtime.Runtime) host.Host {
	t.Helper()
	var seed [32]byte
	rand.Read(seed[:])
	svc, err := rt.Listen(seed)
	if err != nil {
		t.Fatal(err)
	}
	local, err := Multiaddr(svc.Addr())
	if err != nil {
		t.Fatal(err)
	}
	h, err := libp2p.New(
		libp2p.NoTransports,
		libp2p.Transport(func(u coretransport.Upgrader, rc network.ResourceManager) (coretransport.Transport, error) {
			return New(u, rc, rt, svc)
		}),
		libp2p.ListenAddrs(local),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// Two libp2p hosts that share no transport but AXON find each other by their
// /axon addresses and run an authenticated stream through real relays.
func TestLibp2pOverAxon(t *testing.T) {
	seeds := runtimetest.Network(t, 6)
	server := axonHost(t, runtimetest.Client(t, seeds))
	client := axonHost(t, runtimetest.Client(t, seeds))

	server.SetStreamHandler("/echo/1.0.0", func(s network.Stream) {
		defer s.Close()
		io.Copy(s, s)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatalf("connect over AXON: %v", err)
	}
	s, err := client.NewStream(ctx, server.ID(), "/echo/1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 64<<10)
	rand.Read(msg)
	go func() { s.Write(msg); s.CloseWrite() }()
	got, err := io.ReadAll(s)
	if err != nil || string(got) != string(msg) {
		t.Fatalf("echo: %d bytes, %v", len(got), err)
	}
	if conns := client.Network().ConnsToPeer(server.ID()); len(conns) == 0 || !IsAxonAddr(conns[0].RemoteMultiaddr()) {
		t.Fatalf("connection is not over AXON: %v", conns)
	}
}
