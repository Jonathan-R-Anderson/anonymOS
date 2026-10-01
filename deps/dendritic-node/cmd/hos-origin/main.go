// hos-origin -- the anonymOS origin server (roadmap/ORIGIN_SERVER_ROADMAP.md).
//
// One process on the VPS: the dendritic network's coordinator (signed bootstrap document,
// heartbeats, peer list), the release channel the OS update client polls, crash-report intake,
// and the tracker and first seeder of every release's swarm (swarm.go).  It listens on loopback
// only: computers running anonymOS reach it as an AXON hidden service, never directly.
//
// It holds no release-signing key: releases are signed by the owner's wallet off this machine,
// and clients verify that signature themselves.  Taking this server over lets an attacker stop
// updates, not ship one.
//
//	hos-origin keygen -out coordinator.key     # once: the coordinator's Ed25519 seed
//	hos-origin serve  -data /var/lib/hos-origin -key coordinator.key -listen 127.0.0.1:8470
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/swarm"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "pubkey":
		cmdPubkey(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hos-origin keygen -out FILE | pubkey -key FILE | serve [flags]")
	os.Exit(2)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "coordinator.key", "where to write the hex Ed25519 seed (mode 0600)")
	_ = fs.Parse(args)
	if _, err := os.Stat(*out); err == nil {
		log.Fatalf("%s exists; refusing to overwrite a coordinator key", *out)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		log.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	fmt.Printf("coordinator key written to %s\npublic key (pin this in the OS image): %s\n", *out,
		NewCoordinator(key, nil, nil).PublicKeyB64())
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("coordinator key must be a 32-byte hex seed (hos-origin keygen)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func cmdPubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	keyPath := fs.String("key", "coordinator.key", "coordinator key file")
	_ = fs.Parse(args)
	key, err := loadKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(NewCoordinator(key, nil, nil).PublicKeyB64())
}

type seedList []string

func (s *seedList) String() string     { return strings.Join(*s, ",") }
func (s *seedList) Set(v string) error { *s = append(*s, v); return nil }

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data", "/var/lib/hos-origin", "state directory")
	keyPath := fs.String("key", "/etc/hos-origin/coordinator.key", "coordinator key file")
	listen := fs.String("listen", "127.0.0.1:8470", "address to listen on (loopback only: the AXON service forwards to it)")
	var seeds seedList
	fs.Var(&seeds, "seed", "a bootstrap multiaddr always published (repeatable): the origin's own node")
	swarmAddr := fs.String("swarm-addr", "", "the origin's own AXON address, handed to swarm members as the first seed")
	_ = fs.Parse(args)

	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("listen %s is not loopback: the origin is reached only through the dendritic network", *listen)
	}
	for _, s := range seeds {
		if !reBootstrap.MatchString(s) {
			log.Fatalf("seed %q is not a /garlic32/<b32>/p2p/<peer-id> multiaddr", s)
		}
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	store, err := NewStore(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	coord := NewCoordinator(key, seeds, store)
	releases := NewReleases(store)
	crashes := NewCrashIntake(store)

	tracker := NewTracker(swarm.PeerAddr(*swarmAddr))
	seeder := NewSeeder(tracker)
	if err := seeder.Load(store.Path("artifacts")); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	coord.Register(mux)
	releases.Register(mux)
	crashes.Register(mux)
	tracker.Register(mux, seeder)
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "active_nodes": coord.ActiveCount(),
			"coordinator_public_key": coord.PublicKeyB64(), "time": time.Now().UTC().Format(time.RFC3339)})
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 10 * time.Minute, MaxHeaderBytes: 16 << 10}
	log.Printf("hos-origin: coordinator %s, serving on %s (state %s)", coord.PublicKeyB64(), *listen, *dataDir)
	log.Fatal(srv.ListenAndServe())
}
