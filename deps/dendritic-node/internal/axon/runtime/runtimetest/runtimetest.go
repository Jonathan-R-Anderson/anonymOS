// Package runtimetest starts a real AXON network on loopback for other
// packages' tests: relays with libp2p links, and nodes that join them as
// clients. It replaces the fake SAM bridges the I2P transport was tested with.
package runtimetest

import (
	"context"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
)

// Session is a session config with timeouts sized for loopback.
func Session() session.Config {
	c := session.DefaultConfig()
	c.MinRTO = 300 * time.Millisecond
	c.MaxRTO = 2 * time.Second
	c.ProbeTimeout = 4 * time.Second
	return c
}

func logger() *log.Logger {
	if os.Getenv("AXON_TEST_LOG") != "" {
		return log.New(os.Stderr, "axon: ", log.Lmicroseconds)
	}
	return log.New(io.Discard, "", 0)
}

// Network starts n relays on loopback and returns the seed address clients
// join through. Six is enough for distinct guard, middle, intro and
// rendezvous hops.
func Network(t testing.TB, n int) []string {
	t.Helper()
	ctx := context.Background()
	var relays []*runtime.Runtime
	var seeds []string
	for i := 0; i < n; i++ {
		rt, err := runtime.Start(ctx, runtime.Config{DataDir: t.TempDir(),
			Listen: []string{"/ip4/127.0.0.1/tcp/0"}, Relay: true, Seeds: seeds,
			AllowSameNetwork: true, Session: Session(), Logger: logger()})
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
	return seeds
}

// Config is what a node joining the network from Network should start with.
func Config(t testing.TB, seeds []string) runtime.Config {
	return runtime.Config{DataDir: t.TempDir(), Seeds: seeds, AllowSameNetwork: true,
		Session: Session(), Logger: logger()}
}

// Client starts a non-relaying node on the network.
func Client(t testing.TB, seeds []string) *runtime.Runtime {
	t.Helper()
	rt, err := runtime.Start(context.Background(), Config(t, seeds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close() })
	return rt
}
