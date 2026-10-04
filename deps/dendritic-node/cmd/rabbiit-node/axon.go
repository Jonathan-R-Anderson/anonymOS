package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/proxy"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
	"github.com/rabbiit/maniwani/storage-client/internal/bootstrap"
	"github.com/rabbiit/maniwani/storage-client/internal/config"
	"github.com/rabbiit/maniwani/storage-client/internal/heartbeat"
	"github.com/rabbiit/maniwani/storage-client/internal/p2p"
)

// The overlay: AXON, which carries every peer connection this node makes and
// which replaced the I2P router that used to have to run beside it.
//
// Joining needs relays to enter through. They come from the operator's config
// when it names some, and otherwise from the signed bootstrap document -- the
// same document that names the first peers, so one signature covers both who
// to talk to and the network to reach them through. The last good list is kept
// on disk, so a node restarting while the coordinator is down still joins.

const overlaySeedCache = "bootstrap-seeds.json"

type overlaySeeds struct {
	Relays []string `json:"relays"`
	Origin string   `json:"origin,omitempty"`
}

// startOverlay joins AXON and returns the runtime and the coordinator's AXON
// address (empty when none is known). It retries until it has joined or ctx
// ends: a node that cannot reach a relay yet -- the network is down, the
// machine has just booted -- is waiting, not broken, and exiting would only
// hand the wait to systemd's restart timer.
func startOverlay(ctx context.Context, cfg config.Config, relay bool, logger *log.Logger) (*runtime.Runtime, string, error) {
	dir := filepath.Join(cfg.DataDir, "axon")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	delay := 15 * time.Second
	for {
		seeds := overlaySeedsFor(ctx, cfg, dir, logger)
		rc := runtime.Config{
			DataDir:  dir,
			Listen:   cfg.Axon.Listen,
			Relay:    relay,
			Announce: cfg.Axon.Announce,
			Seeds:    seeds.Relays,
			Logger:   log.New(logger.Writer(), logger.Prefix()+"axon: ", logger.Flags()),
		}
		rt, err := runtime.Start(ctx, rc)
		if err == nil {
			role := "client"
			if relay {
				role = "relay"
			}
			logger.Printf("joined the AXON overlay as a %s through %d seed relay(s); %d relay(s) known",
				role, len(seeds.Relays), len(rt.Directory().Relays()))
			if relay {
				// What a coordinator publishes in its bootstrap document
				// (AXON_RELAYS, or hos-origin -relay) so other nodes can join
				// through this one: the public address, then the peer id.
				for _, addr := range relayPublishAddrs(cfg.Axon.Announce, rt) {
					logger.Printf("AXON relay: other nodes can join through %s", addr)
				}
			}
			return rt, seeds.Origin, nil
		}
		if len(seeds.Relays) == 0 && !relay {
			logger.Printf("AXON: no relays to join through yet (set axon.seeds, or wait for the "+
				"bootstrap document); retrying in %s", delay)
		} else {
			logger.Printf("AXON: could not join (%v); retrying in %s", err, delay)
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(delay):
		}
		if delay < 5*time.Minute {
			delay *= 2
		}
	}
}

// relayPublishAddrs is this relay's address as others should dial it: each
// announced ip:port (TCP and QUIC on the same port, as the runtime listens),
// or the listen addresses when nothing is announced.
func relayPublishAddrs(announce []string, rt *runtime.Runtime) []string {
	if len(announce) == 0 {
		return rt.Addrs()
	}
	id := rt.NodeID().String()
	var out []string
	for _, hostport := range announce {
		host, port, err := net.SplitHostPort(hostport)
		if err != nil {
			continue
		}
		family := "ip4"
		if ip := net.ParseIP(host); ip == nil {
			family = "dns"
		} else if ip.To4() == nil {
			family = "ip6"
		}
		out = append(out,
			fmt.Sprintf("/%s/%s/tcp/%s/p2p/%s", family, host, port, id),
			fmt.Sprintf("/%s/%s/udp/%s/quic-v1/p2p/%s", family, host, port, id))
	}
	return out
}

// overlaySeedsFor is the relay list and origin to join with: the operator's,
// else the signed document's, else the last ones that worked.
func overlaySeedsFor(ctx context.Context, cfg config.Config, dir string, logger *log.Logger) overlaySeeds {
	seeds := overlaySeeds{Relays: cfg.Axon.Seeds, Origin: cfg.Axon.Origin}
	if len(seeds.Relays) > 0 && seeds.Origin != "" {
		return seeds
	}
	_, _, bootstrapURL := p2p.CoordinatorEndpoints()
	fetched, err := fetchOverlaySeeds(ctx, heartbeat.DirectHTTPClient(), bootstrapURL, cfg.Bootstrap.CoordinatorKey)
	if err != nil {
		logger.Printf("AXON: bootstrap document unavailable (%v); using the last relays that worked", err)
		fetched, err = readOverlaySeeds(filepath.Join(dir, overlaySeedCache))
		if err != nil {
			return seeds
		}
	} else if err := writeOverlaySeeds(filepath.Join(dir, overlaySeedCache), fetched); err != nil {
		logger.Printf("AXON: could not cache relays: %v", err)
	}
	if len(seeds.Relays) == 0 {
		seeds.Relays = fetched.Relays
	}
	if seeds.Origin == "" {
		seeds.Origin = fetched.Origin
	}
	return seeds
}

// fetchOverlaySeeds reads the relays and origin from the bootstrap document.
//
// Fetched directly: there is no overlay yet to fetch it through, which is the
// point. The signature is checked against the pinned coordinator key when the
// config has one, and otherwise against the key the document carries -- the
// same trust the peer list from this URL has always had, over the TLS of a
// host this network runs.
func fetchOverlaySeeds(ctx context.Context, client *http.Client, url, pinnedKey string) (overlaySeeds, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return overlaySeeds{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return overlaySeeds{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return overlaySeeds{}, fmt.Errorf("bootstrap document: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return overlaySeeds{}, err
	}
	doc, rawExpires, err := bootstrap.Parse(body)
	if err != nil {
		return overlaySeeds{}, err
	}
	key := pinnedKey
	if key == "" {
		key = doc.CoordinatorPublicKey
	}
	if err := bootstrap.Verify(doc, rawExpires, key); err != nil {
		return overlaySeeds{}, err
	}
	if !doc.ExpiresAt.IsZero() && time.Now().After(doc.ExpiresAt) {
		return overlaySeeds{}, bootstrap.ErrExpired
	}
	if len(doc.Relays) == 0 {
		return overlaySeeds{}, errors.New("bootstrap document names no AXON relays")
	}
	return overlaySeeds{Relays: doc.Relays, Origin: doc.Origin}, nil
}

// startAxonProxy serves the loopback proxy onto the overlay until ctx ends. A
// port already in use is logged, not fatal: the proxy is a convenience for the
// person at this machine, and the node's own work does not depend on it.
func startAxonProxy(ctx context.Context, listen string, rt *runtime.Runtime, logger *log.Logger) {
	server := &http.Server{Addr: listen, Handler: proxy.New(rt.DialContext), ReadHeaderTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	go func() {
		logger.Printf("AXON proxy for .key.axon addresses on http://%s", listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("AXON proxy not started: %v", err)
		}
	}()
}

func readOverlaySeeds(path string) (overlaySeeds, error) {
	var seeds overlaySeeds
	raw, err := os.ReadFile(path)
	if err != nil {
		return seeds, err
	}
	if err := json.Unmarshal(raw, &seeds); err != nil {
		return seeds, err
	}
	if len(seeds.Relays) == 0 {
		return seeds, errors.New("no cached relays")
	}
	return seeds, nil
}

func writeOverlaySeeds(path string, seeds overlaySeeds) error {
	raw, err := json.MarshalIndent(seeds, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
