package bootstrap

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustSave(t *testing.T, dir string, peers []string, now time.Time) {
	t.Helper()
	r := &Result{
		Document: &Document{Peers: peers, CoordinatorPublicKey: "SHOULD-NOT-BE-CACHED"},
		Source:   "https://gw-a.example/.well-known/syndichan/storage-node.json",
		Verified: true,
	}
	if err := SaveCache(dir, r, now); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}
}

// TestT162CachedPeersSurviveAnUnreachableDocument is T16.2 as written: "A node
// with the bootstrap document unreachable still joins from cached peers."
func TestT162CachedPeersSurviveAnUnreachableDocument(t *testing.T) {
	dir := t.TempDir()
	saved := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	want := []string{"/ip4/10.0.0.2/tcp/4001/p2p/QmB", "/ip4/10.0.0.1/tcp/4001/p2p/QmA"}
	mustSave(t, dir, want, saved)

	// The document is unreachable; nothing is fetched. The node reads what it
	// has, a day later.
	c, err := LoadCache(dir, saved.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("LoadCache with the document unreachable: %v", err)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("got %d cached peers, want 2 — nothing to join from", len(c.Peers))
	}
	// Sorted, so two nodes given the same document write identical files.
	if c.Peers[0] >= c.Peers[1] {
		t.Errorf("cached peers are not ordered: %v", c.Peers)
	}
	if !c.Verified {
		t.Error("provenance lost: the document was signature-verified when cached")
	}
	if c.Age(saved.Add(24*time.Hour)) != 24*time.Hour {
		t.Errorf("Age = %v, want 24h", c.Age(saved.Add(24*time.Hour)))
	}
}

// TestCacheNeverHoldsTheCoordinatorKey is the design rule, asserted against the
// bytes on disk rather than against the struct — a future field added to Cache
// would pass a struct check and still write the key to a file.
func TestCacheNeverHoldsTheCoordinatorKey(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	secret := "AAAACOORDINATORKEYAAAA"
	r := &Result{
		Document: &Document{
			Peers:                []string{"/ip4/10.0.0.1/tcp/4001/p2p/QmA"},
			CoordinatorPublicKey: secret,
		},
	}
	if err := SaveCache(dir, r, now); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}
	body, err := os.ReadFile(CachePath(dir))
	if err != nil {
		t.Fatalf("reading cache: %v", err)
	}
	if strings.Contains(string(body), secret) {
		t.Fatalf("the coordinator key reached the cache file:\n%s", body)
	}
	// The whole point: reading a key back from disk is not verifying a
	// signature, so no field may carry one.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("cache is not valid JSON: %v", err)
	}
	for k := range raw {
		if strings.Contains(strings.ToLower(k), "key") {
			t.Errorf("cache field %q looks like a trust root; peers only", k)
		}
	}
}

func TestCacheStaleIsRefusedRatherThanDialled(t *testing.T) {
	dir := t.TempDir()
	saved := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	mustSave(t, dir, []string{"/ip4/10.0.0.1/tcp/4001/p2p/QmA"}, saved)

	// Just inside the bound.
	if _, err := LoadCache(dir, saved.Add(MaxCacheAge-time.Minute)); err != nil {
		t.Errorf("cache inside MaxCacheAge was refused: %v", err)
	}
	// Just outside it.
	c, err := LoadCache(dir, saved.Add(MaxCacheAge+time.Minute))
	if !errors.Is(err, ErrCacheStale) {
		t.Errorf("cache past MaxCacheAge: err = %v, want ErrCacheStale", err)
	}
	// Still returned, so a caller can report how old it was rather than only
	// that it was refused.
	if c == nil || len(c.Peers) == 0 {
		t.Error("a stale cache should still be readable for its age")
	}
	// A clock that moved backwards must not make a cache valid forever.
	if _, err := LoadCache(dir, saved.Add(-time.Hour)); !errors.Is(err, ErrCacheStale) {
		t.Errorf("cache stamped in the future: err = %v, want ErrCacheStale", err)
	}
}

func TestCacheMissIsDistinguishableFromStale(t *testing.T) {
	dir := t.TempDir()
	// A first run has no cache, which is ordinary and must not read as a
	// failure the operator should act on.
	if _, err := LoadCache(dir, time.Now()); !errors.Is(err, ErrNoCache) {
		t.Errorf("empty data dir: err = %v, want ErrNoCache", err)
	}
}

func TestCacheRefusesToOverwriteWithNothing(t *testing.T) {
	dir := t.TempDir()
	saved := time.Now()
	mustSave(t, dir, []string{"/ip4/10.0.0.1/tcp/4001/p2p/QmA"}, saved)

	// A document with no peers must not turn a recoverable outage into an
	// unjoinable node.
	err := SaveCache(dir, &Result{Document: &Document{Peers: []string{"", "  "}}}, saved)
	if err == nil {
		t.Fatal("SaveCache accepted an empty peer set")
	}
	c, err := LoadCache(dir, saved)
	if err != nil || len(c.Peers) != 1 {
		t.Fatalf("the good cache did not survive: %v %+v", err, c)
	}
}

func TestCacheRejectsAnUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	// A node that finds a version it does not know discards the cache rather
	// than guessing at the fields: a misparsed peer list is a silently wrong
	// view of the network.
	body := `{"format":99,"saved_at":"2026-08-19T12:00:00Z","peers":["/ip4/10.0.0.1/tcp/4001/p2p/QmA"]}`
	if err := os.WriteFile(filepath.Join(dir, CacheFileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCache(dir, time.Date(2026, 8, 19, 13, 0, 0, 0, time.UTC)); err == nil {
		t.Error("a cache in an unknown format was accepted")
	}
}

func TestCacheIsCappedAndDeduplicated(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	peers := make([]string, 0, MaxCachedPeers*2)
	for i := 0; i < MaxCachedPeers*2; i++ {
		peers = append(peers, "/ip4/10.0.0.1/tcp/4001/p2p/Qm"+string(rune('a'+i%26))+itoa(i))
	}
	peers = append(peers, peers[0], peers[1]) // repeats
	mustSave(t, dir, peers, now)
	c, err := LoadCache(dir, now)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if len(c.Peers) > MaxCachedPeers {
		t.Errorf("cached %d peers, cap is %d", len(c.Peers), MaxCachedPeers)
	}
	seen := map[string]bool{}
	for _, p := range c.Peers {
		if seen[p] {
			t.Fatalf("duplicate peer survived: %q", p)
		}
		seen[p] = true
	}
}

func TestCacheWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	mustSave(t, dir, []string{"/ip4/10.0.0.1/tcp/4001/p2p/QmA"}, now)
	mustSave(t, dir, []string{"/ip4/10.0.0.2/tcp/4001/p2p/QmB"}, now)

	// No temp files left behind: the node that reads this directory next is
	// the one whose network is already broken enough to need it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != CacheFileName {
			t.Errorf("stray file left in the data directory: %s", e.Name())
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
