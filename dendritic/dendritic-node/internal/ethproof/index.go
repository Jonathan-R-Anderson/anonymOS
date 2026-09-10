package ethproof

// The small local index — roadmap P12-4.
//
// WHAT IT IS
// ----------
// A map from (channel, block) to the DHT key holding the evidence, plus the
// highest block seen per channel. Kilobytes per channel, and its whole purpose
// is to avoid listing the store on every question.
//
// WHAT IT IS NOT
// --------------
// Authority. Every entry is a POINTER, never a value:
//
//	index   "the evidence for channel X at block N is under key K"
//	store   holds K, sealed
//	Verify  decides whether K's contents are true
//
// So a corrupted, stale or hostile index can send a reader to the wrong object
// or to none. It cannot make a wrong value verify, because the value is never
// in here. That is why the index may be rebuilt from the store at any time and
// why losing it is an inconvenience rather than a loss of evidence.
//
// The temptation this is written to resist is caching the VALUE alongside the
// key. It would save a fetch and it would create a second answer to "what does
// the chain say", which is the thing every layer of this system has refused to
// grow.
//
// CANONICALITY IS NOT ITS JOB EITHER
// ----------------------------------
// The index records which blocks evidence exists for. Whether those blocks are
// Ethereum's is HeaderVerifier's question, and it currently answers no — see
// anchor.go. Lookup therefore takes a verifier and refuses to present evidence
// as authoritative while the anchor is missing, rather than quietly handing
// back something that merely verified internally.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ErrNoEvidence means the index knows of nothing for a channel. A real answer:
// a channel nobody has ever proven anything about is the ordinary case.
var ErrNoEvidence = errors.New("ethproof: no evidence indexed for this channel")

// IndexEntry points at one stored record.
type IndexEntry struct {
	BlockNumber uint64
	BlockHash   string
	Key         string
}

// Index is the local pointer map.
type Index struct {
	mu sync.RWMutex
	// byChannel holds entries per channel, kept sorted by block number.
	byChannel map[string][]IndexEntry
}

// NewIndex builds an empty one.
func NewIndex() *Index {
	return &Index{byChannel: map[string][]IndexEntry{}}
}

// channelKey normalises the two identifiers a channel is named by.
func channelKey(chainID uint64, contract, channelID string) string {
	return fmt.Sprintf("%d/%s/%s", chainID,
		strings.ToLower(strip0x(contract)), strings.ToLower(strip0x(channelID)))
}

// Note records that evidence exists, without fetching it.
//
// Idempotent: re-noting the same key changes nothing, which matters because
// Rebuild re-notes everything and a watchtower may Rebuild at any time.
func (ix *Index) Note(chainID uint64, contract, channelID string, e IndexEntry) {
	ck := channelKey(chainID, contract, channelID)

	ix.mu.Lock()
	defer ix.mu.Unlock()
	entries := ix.byChannel[ck]
	for _, existing := range entries {
		if existing.Key == e.Key {
			return
		}
	}
	entries = append(entries, e)
	// Sorted by block, then by hash so a reorg's two records at one height have
	// a stable order rather than whichever arrived first.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].BlockNumber != entries[j].BlockNumber {
			return entries[i].BlockNumber < entries[j].BlockNumber
		}
		return entries[i].BlockHash < entries[j].BlockHash
	})
	ix.byChannel[ck] = entries
}

// Entries returns what is known for a channel, oldest block first.
func (ix *Index) Entries(chainID uint64, contract, channelID string) []IndexEntry {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	entries := ix.byChannel[channelKey(chainID, contract, channelID)]
	return append([]IndexEntry(nil), entries...)
}

// Highest returns the newest block evidence exists for.
func (ix *Index) Highest(chainID uint64, contract, channelID string) (IndexEntry, bool) {
	entries := ix.Entries(chainID, contract, channelID)
	if len(entries) == 0 {
		return IndexEntry{}, false
	}
	return entries[len(entries)-1], true
}

// Channels lists every channel the index knows of.
func (ix *Index) Channels() []string {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	out := make([]string, 0, len(ix.byChannel))
	for k := range ix.byChannel {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Rebuild reconstructs the index by listing the store.
//
// The index is a cache, so this is always available and always correct — losing
// the local disk costs a listing, not evidence. Keys are PARSED rather than
// fetched: rebuilding does not need to open, decrypt or verify anything, which
// is what makes it cheap enough to do on every start.
func (ix *Index) Rebuild(ctx context.Context, backend EvidenceBackend) (int, error) {
	keys, err := backend.List(ctx, EvidenceKeyPrefix)
	if err != nil {
		return 0, fmt.Errorf("ethproof: rebuilding the index: %w", err)
	}
	noted := 0
	for _, key := range keys {
		chainID, contract, channel, entry, ok := parseKey(key)
		if !ok {
			// A key that does not parse is not evidence this index can point
			// at. Skipped rather than fatal: one stray object must not stop a
			// watchtower from finding the rest.
			continue
		}
		ix.Note(chainID, contract, channel, entry)
		noted++
	}
	return noted, nil
}

// parseKey reverses Evidence.Key.
//
//	eth/<chainid>/<contract>/<channel>/<block>/<blockhash>
func parseKey(key string) (chainID uint64, contract, channel string, entry IndexEntry, ok bool) {
	rest, found := strings.CutPrefix(key, EvidenceKeyPrefix)
	if !found {
		return 0, "", "", IndexEntry{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 5 {
		return 0, "", "", IndexEntry{}, false
	}
	if _, err := fmt.Sscanf(parts[0], "%d", &chainID); err != nil {
		return 0, "", "", IndexEntry{}, false
	}
	var block uint64
	if _, err := fmt.Sscanf(parts[3], "%d", &block); err != nil {
		return 0, "", "", IndexEntry{}, false
	}
	return chainID, parts[1], parts[2],
		IndexEntry{BlockNumber: block, BlockHash: parts[4], Key: key}, true
}

// Lookup returns the newest VERIFIED evidence for a channel.
//
// THE ANCHOR IS CHECKED FIRST, before anything is fetched.
//
// It is the blocking problem: without it no record can be believed however well
// it verifies, so fetching would be work done to reach a conclusion that cannot
// be used. It is also the more useful thing to report — a caller with a broken
// store AND a missing anchor who is told about the store will fix the store and
// still be unable to proceed.
//
// Then, newest first: fetch, re-verify, use. Walking backwards means a corrupt
// record at the head costs one fetch rather than hiding everything behind it.
func (ix *Index) Lookup(ctx context.Context, store *EvidenceStore, v *HeaderVerifier,
	chainID uint64, contract, channelID string) (Evidence, error) {

	if !v.Anchor().Trustworthy() {
		return Evidence{}, fmt.Errorf("%w (anchor is %q; see doc/trust-anchor.md)",
			ErrNoTrustAnchor, v.Anchor().Kind)
	}

	entries := ix.Entries(chainID, contract, channelID)
	if len(entries) == 0 {
		return Evidence{}, ErrNoEvidence
	}

	var firstErr error
	for i := len(entries) - 1; i >= 0; i-- {
		e, err := store.Get(ctx, entries[i].Key)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := v.VerifyHeader(BlockHeader{
			Number: fmt.Sprintf("0x%x", e.BlockNumber),
			Hash:   e.BlockHash, ParentHash: e.ParentHash, StateRoot: e.StateRoot,
		}); err != nil {
			return Evidence{}, err
		}
		return e, nil
	}
	if firstErr != nil {
		return Evidence{}, firstErr
	}
	return Evidence{}, ErrNoEvidence
}
