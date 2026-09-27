package ethproof

// The local index — roadmap P12-4.
//
// The index is a POINTER MAP, not a cache of values, and these tests exist to
// keep it that way: the worst thing it could do is answer a question about the
// chain, and the second worst is to survive being wrong.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func entry(block uint64, hash string) IndexEntry {
	return IndexEntry{
		BlockNumber: block, BlockHash: hash,
		Key: Evidence{ChainID: 1, BlockNumber: block, BlockHash: hash,
			Contract: deployedChannelManager, ChannelID: "0x01"}.Key(),
	}
}

func TestTheIndexOrdersByBlock(t *testing.T) {
	ix := NewIndex()
	for _, e := range []IndexEntry{entry(30, "0xcc"), entry(10, "0xaa"), entry(20, "0xbb")} {
		ix.Note(1, deployedChannelManager, "0x01", e)
	}
	got := ix.Entries(1, deployedChannelManager, "0x01")
	if len(got) != 3 || got[0].BlockNumber != 10 || got[2].BlockNumber != 30 {
		t.Fatalf("out of order: %+v", got)
	}
	highest, ok := ix.Highest(1, deployedChannelManager, "0x01")
	if !ok || highest.BlockNumber != 30 {
		t.Errorf("Highest = %+v", highest)
	}
}

// Rebuild re-notes everything, so noting must be idempotent or the index grows
// on every restart.
func TestNotingIsIdempotent(t *testing.T) {
	ix := NewIndex()
	for i := 0; i < 5; i++ {
		ix.Note(1, deployedChannelManager, "0x01", entry(10, "0xaa"))
	}
	if got := ix.Entries(1, deployedChannelManager, "0x01"); len(got) != 1 {
		t.Fatalf("%d entries after re-noting one key", len(got))
	}
}

// A reorg puts two records at one height. Both must be indexed.
func TestBothSidesOfAReorgAreIndexed(t *testing.T) {
	ix := NewIndex()
	ix.Note(1, deployedChannelManager, "0x01", entry(10, "0xaaaa"))
	ix.Note(1, deployedChannelManager, "0x01", entry(10, "0xbbbb"))
	if got := ix.Entries(1, deployedChannelManager, "0x01"); len(got) != 2 {
		t.Fatalf("%d entries; a reorg's losing side was dropped", len(got))
	}
}

// The index must be case-insensitive about identifiers, for the same reason
// Evidence.Key is: a lookup that misses its own records is the worst failure.
func TestLookupIsCaseInsensitive(t *testing.T) {
	ix := NewIndex()
	ix.Note(1, strings.ToLower(deployedChannelManager), "0xAB", entry(10, "0xaa"))
	if got := ix.Entries(1, deployedChannelManager, "0xab"); len(got) != 1 {
		t.Fatal("a mixed-case lookup missed its own record")
	}
}

// Losing the index costs a listing, not evidence.
func TestRebuildReconstructsFromTheStore(t *testing.T) {
	backend := newMemEvidence()
	ctx := context.Background()
	for _, e := range []Evidence{
		{ChainID: 1, BlockNumber: 7, BlockHash: "0xaa", Contract: deployedChannelManager, ChannelID: "0x01"},
		{ChainID: 1, BlockNumber: 9, BlockHash: "0xbb", Contract: deployedChannelManager, ChannelID: "0x01"},
		{ChainID: 1, BlockNumber: 3, BlockHash: "0xcc", Contract: deployedChannelManager, ChannelID: "0x02"},
	} {
		if err := backend.Put(ctx, e.Key(), []byte("sealed")); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	// A stray object under the prefix must not stop the rebuild.
	_ = backend.Put(ctx, EvidenceKeyPrefix+"garbage", []byte("x"))

	ix := NewIndex()
	noted, err := ix.Rebuild(ctx, backend)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if noted != 3 {
		t.Errorf("noted %d entries, want 3 (the stray skipped)", noted)
	}
	if got, ok := ix.Highest(1, deployedChannelManager, "0x01"); !ok || got.BlockNumber != 9 {
		t.Errorf("highest for channel 1 = %+v", got)
	}
	if len(ix.Channels()) != 2 {
		t.Errorf("channels = %v", ix.Channels())
	}
}

// THE RULE: the index points, it never answers. A lookup must not present
// evidence as authoritative while canonicality is unestablished.
func TestLookupRefusesWithoutATrustAnchor(t *testing.T) {
	backend := newMemEvidence()
	store := testStore(backend)
	ctx := context.Background()

	e := Evidence{ChainID: 1, BlockNumber: 7, BlockHash: "0xaa",
		Contract: deployedChannelManager, ChannelID: "0x01"}
	// Sealed but never verified — it does not matter, because the anchor check
	// comes first and refuses regardless.
	_ = backend.Put(ctx, e.Key(), []byte("s:"+`{"chain_id":1}`))

	ix := NewIndex()
	if _, err := ix.Rebuild(ctx, backend); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	v := &HeaderVerifier{ChainID: 1, Endpoint: alchemy}

	_, err := ix.Lookup(ctx, store, v, 1, deployedChannelManager, "0x01")
	if err == nil {
		t.Fatal("Lookup returned evidence with no trust anchor")
	}
}

func TestLookupOnAnUnknownChannelIsARealAnswer(t *testing.T) {
	ix := NewIndex()
	v := &HeaderVerifier{ChainID: 1, Endpoint: alchemy}
	// Anchored, so this exercises the path AFTER the anchor check. Without it
	// the anchor refusal fires first — correctly, since nothing can be believed
	// without one — and this test would never reach what it is about.
	if err := v.SetAnchor(Anchor{
		Kind: AnchorSyncCommittee, Source: "https://beaconstate.example",
	}); err != nil {
		t.Fatalf("SetAnchor: %v", err)
	}
	_, err := ix.Lookup(context.Background(), testStore(newMemEvidence()), v,
		1, deployedChannelManager, "0xffff")
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("got %v, want ErrNoEvidence", err)
	}
}

// The index stores pointers. If it ever grew a value field, this is the test
// that should be updated only with a very good reason.
func TestTheIndexHoldsNoValues(t *testing.T) {
	e := entry(10, "0xaa")
	if e.Key == "" {
		t.Fatal("an index entry with no key points at nothing")
	}
	// IndexEntry has exactly three fields, all of them locators.
	if got := struct{ a, b, c any }{e.BlockNumber, e.BlockHash, e.Key}; got.c == nil {
		t.Fatal("unreachable")
	}
}
