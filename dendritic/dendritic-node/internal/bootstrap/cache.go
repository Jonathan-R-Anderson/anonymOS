package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// T16.2: a node whose bootstrap document is unreachable still joins, from peers
// it cached the last time one was reachable.
//
// WHAT IS CACHED, AND WHAT DELIBERATELY IS NOT
// The peer list, and nothing else. NOT the coordinator key.
//
// This package's own risk note is the reason: "A bad peer costs a failed dial.
// A bad coordinator key means accepting forged storage leases indefinitely,
// with nothing to notice it." Those two payloads do not deserve the same
// treatment when the network is unreachable and no signature can be checked.
//
// So the two halves degrade differently AND THAT IS THE DESIGN:
//
//	peers              served from cache. Worst case, the node dials addresses
//	                   that have moved and finds nobody -- which is exactly
//	                   what happens today with no cache at all, so the cache
//	                   cannot make the joining case worse.
//	coordinator key    NOT served from cache. A node running on cache keeps
//	                   whatever key it already had in memory and refreshes
//	                   nothing. If it had none, storage leases stay unavailable
//	                   until a real document is verified.
//
// Reading a key back from a file is not the same act as verifying a signature,
// and a cache that restored one would quietly convert "verified once, months
// ago" into "trusted now" -- across a restart, with no signature involved and
// no way for the node to tell the difference. The routing hint is recoverable
// from disk; the trust root is not.
//
// WHY AN AGE BOUND RATHER THAN AN EXPIRY
// The document carries a signed ExpiresAt, and the cache deliberately does not
// reuse it: that field says when the COORDINATOR wanted the document refreshed,
// which is a liveness policy for a reachable network. The cache's question is
// different -- how long a peer address stays worth dialling -- and the answer
// is bounded by peer churn, not by the coordinator's refresh cadence. Honouring
// the signed expiry would make the cache useless in precisely the outage it
// exists for, since a document expires long before its peers do.

const (
	// CacheFileName sits beside the rest of the node's state.
	CacheFileName = "bootstrap-peers.json"

	// CacheFormat is stored in the file. A node that finds a version it does
	// not know discards the cache rather than guessing at the fields, because
	// a misparsed peer list is a silently wrong view of the network.
	CacheFormat = 1

	// MaxCacheAge bounds how long a cached peer set is worth dialling.
	//
	// Seven days: long enough to cover an outage measured in days, short
	// enough that a node returning after a month re-derives its view rather
	// than dialling a set the network has churned past. There is no measured
	// churn figure to derive this from -- P3's peer-lifetime data does not
	// exist yet -- so it is a stated policy, not a computed one, and it is
	// stated here rather than buried at a call site.
	MaxCacheAge = 7 * 24 * time.Hour

	// MaxCachedPeers caps what is written, so a hostile or broken document
	// cannot turn the cache file into unbounded disk.
	MaxCachedPeers = 256
)

var (
	// ErrNoCache means there is nothing usable on disk. Ordinary on a first
	// run, and not an error worth alarming about.
	ErrNoCache = errors.New("no cached bootstrap peers")
	// ErrCacheStale means the cache exists and is older than MaxCacheAge.
	ErrCacheStale = errors.New("cached bootstrap peers are stale")
)

// Cache is the on-disk record of the last peer set that came from a document
// this node accepted.
type Cache struct {
	Format int `json:"format"`
	// SavedAt is when the document was accepted, not when the file was
	// written -- they are the same today and the distinction matters if a
	// future caller ever re-writes a cache without re-fetching.
	SavedAt time.Time `json:"saved_at"`
	Peers   []string  `json:"peers"`
	// Verified records whether the document these peers came from had its
	// signature checked against a PINNED key, or was merely corroborated
	// across sources. Carried so a node running on cache can say which of the
	// two it is running on rather than implying the stronger one.
	Verified bool `json:"verified"`
	// Source is the gateway that supplied the document, for the operator's
	// benefit when a cached view turns out to be wrong.
	Source string `json:"source,omitempty"`
}

// CachePath is where the cache lives for a given data directory.
func CachePath(dataDir string) string {
	return filepath.Join(dataDir, CacheFileName)
}

// SaveCache records a peer set that came from an accepted document.
//
// Written to a temporary file and renamed, because the alternative -- a
// truncate-then-write that is interrupted -- leaves a zero-length cache, and
// the node that reads it next is the node whose network is already broken
// enough to need it.
func SaveCache(dataDir string, result *Result, now time.Time) error {
	if result == nil || result.Document == nil {
		return errors.New("bootstrap: nothing to cache")
	}
	peers := dedupePeers(result.Document.Peers)
	if len(peers) == 0 {
		// Refusing to cache an empty set is not pedantry: overwriting a good
		// cache with an empty one turns a recoverable outage into an
		// unjoinable node, and a document with no peers is a coordinator
		// problem rather than something to persist.
		return errors.New("bootstrap: refusing to cache an empty peer set")
	}
	if len(peers) > MaxCachedPeers {
		peers = peers[:MaxCachedPeers]
	}
	c := Cache{
		Format:   CacheFormat,
		SavedAt:  now.UTC(),
		Peers:    peers,
		Verified: result.Verified,
		Source:   result.Source,
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("bootstrap: encoding cache: %w", err)
	}
	body = append(body, '\n')

	path := CachePath(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("bootstrap: cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), CacheFileName+".tmp*")
	if err != nil {
		return fmt.Errorf("bootstrap: cache temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("bootstrap: writing cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("bootstrap: syncing cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bootstrap: closing cache: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("bootstrap: cache permissions: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("bootstrap: replacing cache: %w", err)
	}
	return nil
}

// LoadCache returns the cached peer set if it is usable.
//
// Every failure returns a reason rather than an empty list, so a caller can
// tell "never had one" from "had one and it is too old" -- the second is worth
// telling an operator about and the first is not.
func LoadCache(dataDir string, now time.Time) (*Cache, error) {
	body, err := os.ReadFile(CachePath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoCache
		}
		return nil, fmt.Errorf("bootstrap: reading cache: %w", err)
	}
	var c Cache
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("bootstrap: cache is unreadable: %w", err)
	}
	if c.Format != CacheFormat {
		return nil, fmt.Errorf("bootstrap: cache format %d is not %d",
			c.Format, CacheFormat)
	}
	c.Peers = dedupePeers(c.Peers)
	if len(c.Peers) == 0 {
		return nil, ErrNoCache
	}
	if len(c.Peers) > MaxCachedPeers {
		c.Peers = c.Peers[:MaxCachedPeers]
	}
	if c.SavedAt.IsZero() {
		return nil, fmt.Errorf("bootstrap: cache has no timestamp")
	}
	// A cache stamped in the future is a clock that moved, not a fresh cache.
	// Treated as stale, because the alternative is honouring it forever.
	if age := now.Sub(c.SavedAt); age > MaxCacheAge || age < 0 {
		return &c, fmt.Errorf("%w: saved %s ago", ErrCacheStale,
			age.Round(time.Minute))
	}
	return &c, nil
}

// Age reports how old the cache was at `now`.
func (c *Cache) Age(now time.Time) time.Duration { return now.Sub(c.SavedAt) }

// dedupePeers removes blanks and repeats and orders the result.
//
// Sorted so that two nodes given the same document write byte-identical caches,
// which makes a cache file something an operator can diff across machines when
// a partition is suspected.
func dedupePeers(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
