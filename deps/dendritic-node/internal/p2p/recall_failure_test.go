package p2p

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// A LEDGER READ FAILURE IS NOT "NOBODY HAS IT"
// ============================================
// RecallObjectID used to treat every error from LoadRecall as "there is no
// tombstone" and hand back an empty record with a nil error. A bolt failure or a
// row that would not unmarshal therefore reached the site's purge page as "the
// ledger recorded no confirmed remote holder for this object" -- the page an
// operator uses to answer a takedown, being told a number nobody knew.

// nodeWithCorruptRecallRow builds a node whose recall ledger contains a row that
// will not parse.
//
// The bad row is written with a bare bolt handle because no store API exists to
// write one, which is exactly why the failure was never exercised. That couples
// this test to the bucket NAME; if store.bucketRecall is ever renamed the lookup
// below returns nil and the test says so rather than silently passing.
func nodeWithCorruptRecallRow(t *testing.T, objectID string) (*Node, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()

	// Let the store lay out its schema, then release the file: bolt admits one
	// process at a time.
	storage, err := store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(dir+"/storage/metadata.db", 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		recalls := tx.Bucket([]byte("shard_recall"))
		if recalls == nil {
			return errors.New(`no "shard_recall" bucket: store.bucketRecall was ` +
				`renamed and this test needs the new name`)
		}
		return recalls.Put([]byte(objectID), []byte(`{"shards": [`))
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	storage, err = store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, storage,
		log.New(io.Discard, "", 0), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	return node, ctx
}

func TestALedgerReadFailureIsNotReportedAsNoHolders(t *testing.T) {
	const objectID = "0f0f0f0f0f0f0f0f"
	node, ctx := nodeWithCorruptRecallRow(t, objectID)

	record, err := node.RecallObjectID(ctx, objectID, nil, "admin DHT purge")
	if err == nil {
		t.Fatalf("an unreadable recall ledger was reported as a clean, empty "+
			"record (%#v). The page then prints 'the ledger recorded no confirmed "+
			"remote holder for this object', which is an unknown drawn as a zero.",
			record)
	}
	if record != nil {
		t.Fatalf("a failed ledger read returned a record as well as an error: %#v", record)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed read was classified as absence: %v", err)
	}
	if !errors.Is(err, store.ErrRecallLedgerUnreadable) {
		t.Fatalf("the gateway cannot tell this from any other failure: %v", err)
	}
}

// The other side of the same branch, which must keep working: an object that
// never left this disk has no tombstone, and that is an answer, not a fault.
func TestAnAbsentLedgerEntryStillReportsCleanlyAsAbsent(t *testing.T) {
	h := newRecallHarness(t)

	record, err := h.source.RecallObjectID(h.ctx, stringOf('b', 64), nil, "admin DHT purge")
	if err != nil {
		t.Fatalf("an object with nothing to recall reported an error: %v", err)
	}
	if record == nil {
		t.Fatal("an object with nothing to recall reported no record at all")
	}
	if len(record.Shards) != 0 || record.Outstanding() != 0 {
		t.Fatalf("an object with nothing to recall claimed holders: %#v", record)
	}
}

// A REVOCATION IS SPENT ONCE
// ==========================
// The nonce was signed and never remembered, so the same delete frame worked at
// its recipient until the token expired.
func TestAReplayedRevocationIsRefused(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('a', 64)
	shardID := h.plantShard(t, objectID, bytes.Repeat([]byte("delete me once"), 32))

	token := h.token(objectID, shardID)
	first := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &token,
	})
	if !first.OK || !first.Deleted {
		t.Fatalf("the genuine article was not honoured: %#v", first)
	}

	// The same bytes, again. Whoever holds a copy of the frame -- the recipient
	// most obviously -- must not be able to spend it twice.
	replay := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &token,
	})
	if replay.OK || !replay.Refused {
		t.Fatalf("a replayed revocation was accepted: %#v", replay)
	}
	if !strings.Contains(replay.Error, "already been used") {
		t.Fatalf("a replay was refused for the wrong reason, so the refusal is "+
			"about something else: %q", replay.Error)
	}
}

// And the cache refuses replays without refusing everything: a token minted for
// a different shard, with its own nonce, still deletes.
func TestAFreshRevocationStillWorksAfterOneIsSpent(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('a', 64)
	first := h.plantShard(t, objectID, bytes.Repeat([]byte("the first shard"), 32))
	second := h.plantShard(t, objectID, bytes.Repeat([]byte("the second shard"), 32))

	spent := h.token(objectID, first)
	if answer := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: first, Revocation: &spent,
	}); !answer.OK || !answer.Deleted {
		t.Fatalf("the first delete did not happen: %#v", answer)
	}

	fresh := h.token(objectID, second)
	answer := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: second, Revocation: &fresh,
	})
	if !answer.OK || !answer.Deleted {
		t.Fatalf("a fresh revocation was refused after another was spent: %#v", answer)
	}
	if h.stillHeld(second) {
		t.Fatal("the shard survived a valid, unspent revocation")
	}
}
