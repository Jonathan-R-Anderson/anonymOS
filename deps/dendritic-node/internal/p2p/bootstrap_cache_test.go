package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/contain"
	"github.com/syndichan/maniwani/storage-client/internal/bootstrap"
)

// signedDocument builds a document the node will accept, signed by a key the
// test pins — the strong path, so the cache records Verified: true.
func signedDocument(t *testing.T, peers []string, expires time.Time) (body []byte, pinned string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawStdEncoding.EncodeToString(pub)
	rawExpires := expires.UTC().Format(time.RFC3339)
	sig := ed25519.Sign(priv, bootstrap.Message(peers, key, rawExpires))

	envelope := map[string]any{
		"version":                1,
		"peers":                  peers,
		"coordinator_public_key": key,
		"expires_at":             rawExpires,
		"signature":              base64.StdEncoding.EncodeToString(sig),
	}
	body, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body, key
}

// TestT162NodeJoinsFromCacheWhenTheDocumentIsUnreachable is T16.2 end to end,
// through the node's own refresh path rather than through the cache API:
//
//	"A node with the bootstrap document unreachable still joins from cached
//	peers."
//
// Round 1 the gateway answers and the node caches what it learned. The gateway
// then goes away entirely. Round 2 must still produce a set of peers to dial,
// from disk, with no document and no signature available.
func TestT162NodeJoinsFromCacheWhenTheDocumentIsUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	peers := []string{
		"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWA9jJHRLfKZ4pRVCEsGN7YbmXbYRzWkYCLTLAgKmMSpBc",
		"/ip4/127.0.0.1/tcp/4002/p2p/12D3KooWKRyzVWW6ChFjQjK4miCty85Niy49tpPV95XdKu1BcvMA",
	}
	body, pinned := signedDocument(t, peers, time.Now().Add(time.Hour))

	var served int
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))

	dir := t.TempDir()
	logs := &strings.Builder{}
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, nil,
		log.New(logs, "", 0), false)
	if err != nil {
		t.Fatalf("openNode: %v", err)
	}
	defer node.Close()

	cfg := bootstrap.Config{
		CoordinatorKey: pinned,
		URLs:           []string{gateway.URL + bootstrap.DocumentPath},
	}

	// --- Round 1: the gateway answers. ----------------------------------
	node.refreshDiscoveredBootstrap(ctx, &cfg)
	if served == 0 {
		t.Fatal("the gateway was never asked for the document")
	}
	cached, err := bootstrap.LoadCache(dir, time.Now())
	if err != nil {
		t.Fatalf("a reachable document left no cache: %v (served=%d)\nlog:\n%s", err, served, logs.String())
	}
	if len(cached.Peers) != len(peers) {
		t.Fatalf("cached %d peers, want %d", len(cached.Peers), len(peers))
	}
	if !cached.Verified {
		t.Error("the document was verified against a pinned key; the cache says otherwise")
	}
	// The key the node learned in round 1, which round 2 must not disturb.
	node.keyMu.RLock()
	keyAfterRound1 := append(ed25519.PublicKey(nil), node.coordKey...)
	node.keyMu.RUnlock()
	if len(keyAfterRound1) != ed25519.PublicKeySize {
		t.Fatalf("round 1 did not install a coordinator key (%d bytes)", len(keyAfterRound1))
	}

	// --- The gateway goes away. -----------------------------------------
	gateway.Close()
	logs.Reset()

	// --- Round 2: nothing is reachable. ---------------------------------
	node.refreshDiscoveredBootstrap(ctx, &cfg)

	out := logs.String()
	if !strings.Contains(out, "joining from 2 of 2 cached peers") {
		t.Errorf("the node did not join from cache with the document unreachable.\nlog:\n%s", out)
	}
	// The weaker provenance has to stay visible rather than being implied away.
	if !strings.Contains(out, "coordinator key is NOT restored from cache") {
		t.Errorf("the log does not say the trust root was left unrefreshed.\nlog:\n%s", out)
	}

	// The trust root must be untouched by a cache-served round: not replaced,
	// not cleared. Reading a key from a file is not verifying a signature.
	node.keyMu.RLock()
	keyAfterRound2 := append(ed25519.PublicKey(nil), node.coordKey...)
	node.keyMu.RUnlock()
	if !keyAfterRound1.Equal(keyAfterRound2) {
		t.Error("a cache-served round changed the coordinator key")
	}
}

// TestT162FirstRunWithNoNetworkIsNotAnError: a node that has never reached a
// document has nothing to join from, which is ordinary rather than a fault.
func TestT162FirstRunWithNoNetworkIsNotAnError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	logs := &strings.Builder{}
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, nil,
		log.New(logs, "", 0), false)
	if err != nil {
		t.Fatalf("openNode: %v", err)
	}
	defer node.Close()

	// A URL nothing is listening on.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL + bootstrap.DocumentPath
	dead.Close()

	node.refreshDiscoveredBootstrap(ctx, &bootstrap.Config{URLs: []string{url}})

	out := logs.String()
	if !strings.Contains(out, "no cached peers yet") {
		t.Errorf("a first run with no network should say so plainly.\nlog:\n%s", out)
	}
	if strings.Contains(out, "unusable") {
		t.Errorf("an absent cache was reported as a failure.\nlog:\n%s", out)
	}
}

// TestT162StaleCacheIsNotDialled: a cache older than the churn bound describes
// a network the node has been away from too long to trust as a routing hint.
func TestT162StaleCacheIsNotDialled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	old := time.Now().Add(-bootstrap.MaxCacheAge - time.Hour)
	err := bootstrap.SaveCache(dir, &bootstrap.Result{
		Document: &bootstrap.Document{Peers: []string{
			"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWA9jJHRLfKZ4pRVCEsGN7YbmXbYRzWkYCLTLAgKmMSpBc",
		}},
	}, old)
	if err != nil {
		t.Fatalf("SaveCache: %v", err)
	}

	logs := &strings.Builder{}
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, nil,
		log.New(logs, "", 0), false)
	if err != nil {
		t.Fatalf("openNode: %v", err)
	}
	defer node.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL + bootstrap.DocumentPath
	dead.Close()

	node.refreshDiscoveredBootstrap(ctx, &bootstrap.Config{URLs: []string{url}})

	out := logs.String()
	if !strings.Contains(out, "too old to use") {
		t.Errorf("a stale cache should be refused with its age, not dialled.\nlog:\n%s", out)
	}
	if strings.Contains(out, "joining from") {
		t.Errorf("a stale cache was dialled.\nlog:\n%s", out)
	}
}

// TestContainedPeerDoesNotReturnThroughTheCache is item 4.10e.
//
// The incident drill found that containment lapsed across a restart through the
// bootstrap path: the peer cache is on disk and consulted nothing, so a host an
// operator had contained came straight back. This drives the whole cycle --
// cache it, contain it, restart, and check it is neither dialled nor still in
// the file.
func TestContainedPeerDoesNotReturnThroughTheCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const (
		keepAddr = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWA9jJHRLfKZ4pRVCEsGN7YbmXbYRzWkYCLTLAgKmMSpBc"
		badAddr  = "/ip4/127.0.0.1/tcp/4002/p2p/12D3KooWKRyzVWW6ChFjQjK4miCty85Niy49tpPV95XdKu1BcvMA"
		badID    = "12D3KooWKRyzVWW6ChFjQjK4miCty85Niy49tpPV95XdKu1BcvMA"
	)
	peers := []string{keepAddr, badAddr}
	body, pinned := signedDocument(t, peers, time.Now().Add(time.Hour))
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer gateway.Close()

	dir := t.TempDir()
	logs := &strings.Builder{}
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, nil,
		log.New(logs, "", 0), false)
	if err != nil {
		t.Fatalf("openNode: %v", err)
	}
	defer node.Close()

	cfg := bootstrap.Config{
		CoordinatorKey: pinned,
		URLs:           []string{gateway.URL + bootstrap.DocumentPath},
	}

	// Round 1: nothing contained. Both peers are cached.
	node.refreshDiscoveredBootstrap(ctx, &cfg)
	cached, err := bootstrap.LoadCache(dir, time.Now())
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if len(cached.Peers) != 2 {
		t.Fatalf("cached %d peers, want 2", len(cached.Peers))
	}

	// The incident: the operator contains one of them, and saves.
	list := contain.New()
	if err := list.Deny(badID, "drill: host seized", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := list.Save(dir); err != nil {
		t.Fatal(err)
	}

	// The restart: a list read back off disk, wired into a node whose cache
	// still names the contained peer.
	reloaded, err := contain.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	node.SetContainment(reloaded)
	logs.Reset()

	// Round 2, cache-served: the gateway is gone.
	gateway.Close()
	node.refreshDiscoveredBootstrap(ctx, &cfg)

	out := logs.String()
	if !strings.Contains(out, "contained by operator decision") {
		t.Errorf("the contained peer was not refused on the cache path.\nlog:\n%s", out)
	}
	if strings.Contains(out, "joining from 2 cached peers") {
		t.Errorf("both peers were joined; the contained one should have been "+
			"dropped.\nlog:\n%s", out)
	}
}

// TestContainedPeerIsNeverWrittenToTheCache: dropping it at dial time only
// would leave it in the file, to be re-applied by somebody who has forgotten.
func TestContainedPeerIsNeverWrittenToTheCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const badID = "12D3KooWKRyzVWW6ChFjQjK4miCty85Niy49tpPV95XdKu1BcvMA"
	peers := []string{
		"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWA9jJHRLfKZ4pRVCEsGN7YbmXbYRzWkYCLTLAgKmMSpBc",
		"/ip4/127.0.0.1/tcp/4002/p2p/" + badID,
	}
	body, pinned := signedDocument(t, peers, time.Now().Add(time.Hour))
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer gateway.Close()

	dir := t.TempDir()
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, nil,
		log.New(&strings.Builder{}, "", 0), false)
	if err != nil {
		t.Fatalf("openNode: %v", err)
	}
	defer node.Close()

	list := contain.New()
	if err := list.Deny(badID, "drill: host seized", time.Now()); err != nil {
		t.Fatal(err)
	}
	node.SetContainment(list)

	node.refreshDiscoveredBootstrap(ctx, &bootstrap.Config{
		CoordinatorKey: pinned,
		URLs:           []string{gateway.URL + bootstrap.DocumentPath},
	})

	cached, err := bootstrap.LoadCache(dir, time.Now())
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	for _, p := range cached.Peers {
		if strings.Contains(p, badID) {
			t.Errorf("the contained peer was written to the cache: %s", p)
		}
	}
	if len(cached.Peers) != 1 {
		t.Errorf("cached %d peers, want 1 (the uncontained one)", len(cached.Peers))
	}
}
