package store

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// UNKNOWN IS NOT ZERO
// ===================
// The recall ledger answers three different questions with what used to be one
// error: there is no tombstone, there is one, and I could not tell. The third
// was folded into the first all the way up to the admin page, where it printed
// as "the ledger recorded no confirmed remote holder for this object" -- a
// number, on a takedown page, standing in for a value nobody knew.

// corruptTombstone writes bytes into the recall bucket that are not a record.
// This is the failure that actually happens: a truncated write, a partially
// flushed page, a row from a future schema.
func corruptTombstone(t *testing.T, storage *Store, objectID string) {
	t.Helper()
	err := storage.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRecall).Put([]byte(objectID), []byte(`{"shards": [`))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestALedgerReadFailureIsNotReportedAsAbsence(t *testing.T) {
	storage := openRecallStore(t)
	const objectID = "0123456789abcdef"
	corruptTombstone(t, storage, objectID)

	record, err := storage.LoadRecall(objectID)
	if err == nil {
		t.Fatalf("an unreadable tombstone loaded cleanly as %#v", record)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatal("an unreadable tombstone was reported as an absent one, which is " +
			"how a failed read becomes 'no holders' on the purge page")
	}
	if !errors.Is(err, ErrRecallLedgerUnreadable) {
		t.Fatalf("callers cannot classify this error: %v", err)
	}
	if record != nil {
		t.Fatalf("a failed read returned a record as well as an error: %#v", record)
	}
}

func TestAGenuinelyAbsentTombstoneStillReportsAsAbsent(t *testing.T) {
	storage := openRecallStore(t)

	record, err := storage.LoadRecall("an-object-with-no-tombstone")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an absent tombstone no longer reports as absent: %v", err)
	}
	if errors.Is(err, ErrRecallLedgerUnreadable) {
		t.Fatal("absence was reported as a read failure, which would make every " +
			"purely local object look like a broken ledger")
	}
	if record != nil {
		t.Fatalf("an absent tombstone returned a record: %#v", record)
	}
}

// A row that will not parse used to be skipped silently, so the object it
// belonged to simply stopped appearing in the admin summary -- the same defect
// one layer up.
func TestAnUnreadableRowIsCountedRatherThanSkipped(t *testing.T) {
	storage := openRecallStore(t)
	corruptTombstone(t, storage, "unreadable-object")

	rows, unreadable, err := storage.AllRecalls()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("an unreadable row was returned as a record: %#v", rows)
	}
	if unreadable != 1 {
		t.Fatalf("unreadable rows counted %d, want 1", unreadable)
	}
}

// --------------------------------------------------------------------------
// F7 -- a revocation nonce is spent once
// --------------------------------------------------------------------------

func TestARevocationNonceCanOnlyBeSpentOnce(t *testing.T) {
	storage := openRecallStore(t)
	expires := time.Now().Add(10 * time.Minute)

	fresh, err := storage.ClaimRevocationNonce("nonce-aaaaaaaaaaaaaaaa", expires)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Fatal("a nonce nobody has used was reported as already spent")
	}
	replay, err := storage.ClaimRevocationNonce("nonce-aaaaaaaaaaaaaaaa", expires)
	if err != nil {
		t.Fatal(err)
	}
	if replay {
		t.Fatal("the same revocation nonce was accepted twice, so a delete token " +
			"is still replayable at its recipient for its whole lifetime")
	}
	// And a different token is unaffected: a replay cache that refuses
	// everything would look identical to one that works, from the replay side.
	other, err := storage.ClaimRevocationNonce("nonce-bbbbbbbbbbbbbbbb", expires)
	if err != nil {
		t.Fatal(err)
	}
	if !other {
		t.Fatal("a fresh nonce was refused")
	}
}

// The cache is on disk rather than in memory precisely so a restart does not
// reopen the replay window. A crash loop is a machine that restarts repeatedly
// inside the ten minutes a token lives.
func TestASpentNonceSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	storage, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(10 * time.Minute)
	if fresh, err := storage.ClaimRevocationNonce("nonce-cccccccccccccccc", expires); err != nil || !fresh {
		t.Fatalf("first claim: %v %v", fresh, err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	replay, err := reopened.ClaimRevocationNonce("nonce-cccccccccccccccc", expires)
	if err != nil {
		t.Fatal(err)
	}
	if replay {
		t.Fatal("restarting the node made a spent revocation token usable again")
	}
}

// The cache is fed by a remote party, so it has to be bounded. Expired entries
// go first -- they defend against tokens that are already refused on age.
func TestTheReplayCacheDropsExpiredEntries(t *testing.T) {
	storage := openRecallStore(t)
	// A claim whose token has one millisecond left, and then a claim made after
	// it has elapsed.
	if fresh, err := storage.ClaimRevocationNonce("nonce-dddddddddddddddd",
		time.Now().Add(20*time.Millisecond)); err != nil || !fresh {
		t.Fatalf("first claim: %v %v", fresh, err)
	}
	time.Sleep(40 * time.Millisecond)
	if fresh, err := storage.ClaimRevocationNonce("nonce-eeeeeeeeeeeeeeee",
		time.Now().Add(10*time.Minute)); err != nil || !fresh {
		t.Fatalf("second claim: %v %v", fresh, err)
	}
	var live int
	if err := storage.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRevocationNonces).ForEach(func(_, _ []byte) error {
			live++
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("the replay cache holds %d entries, want 1: expired entries are "+
			"not being reclaimed and a remote party controls the fill rate", live)
	}
}

func TestAnExpiredTokenCannotBeClaimed(t *testing.T) {
	storage := openRecallStore(t)
	if _, err := storage.ClaimRevocationNonce("nonce-ffffffffffffffff",
		time.Now().Add(-time.Second)); err == nil {
		t.Fatal("a token that has already expired was recorded as spent, which " +
			"would fill the cache with entries that defend against nothing")
	}
}

// --------------------------------------------------------------------------
// F8 -- a permanently refusing holder stops being asked every ten minutes
// --------------------------------------------------------------------------

// tombstoneWithOneHolder builds a real tombstone the way a delete does: place an
// object, confirm a holder for every shard, delete it.
func tombstoneWithOneHolder(t *testing.T, storage *Store, key, holder string) string {
	t.Helper()
	if err := storage.CreateBucket("recall"); err != nil {
		t.Fatal(err)
	}
	manifest, err := storage.PutObject("recall", key, "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{4, 2}, 1000)))
	if err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range row.Shards {
		if err := storage.ConfirmShardHolder(manifest.ObjectID, shard.ShardID, holder); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.DeleteObject("recall", key); err != nil {
		t.Fatal(err)
	}
	return manifest.ObjectID
}

// refusePass records one whole background pass in which every holder refused.
func refusePass(t *testing.T, storage *Store, objectID, holder string) {
	t.Helper()
	if err := storage.MarkRecallAttempt(objectID); err != nil {
		t.Fatal(err)
	}
	record, err := storage.LoadRecall(objectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range record.Shards {
		err := storage.RecordRecallOutcome(objectID, shard.ShardID, holder,
			RecallRefused, "a local manifest still references these bytes")
		if err != nil {
			t.Fatal(err)
		}
	}
}

// backdate moves the tombstone's last attempt into the past, which is the only
// way to test a schedule without sleeping through it.
func backdate(t *testing.T, storage *Store, objectID string, ago time.Duration) {
	t.Helper()
	err := storage.updateRecall(objectID, func(record *RecallRecord) error {
		record.LastAttempt = time.Now().UTC().Add(-ago)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

const testHolder = "12D3KooWGRUts8ZckKrhVePMWnwLKrDMbYrgvXvJVwFHhPHu3EXV"

func TestAPermanentlyRefusingHolderStopsBeingRetriedOnTheFastClock(t *testing.T) {
	storage := openRecallStore(t)
	objectID := tombstoneWithOneHolder(t, storage, "refused.bin", testHolder)

	for pass := 0; pass < recallAttemptCeiling; pass++ {
		refusePass(t, storage, objectID, testHolder)
	}
	// Half an hour later: fifteen times the base cooldown, and three passes of
	// the background loop.
	backdate(t, storage, objectID, 30*time.Minute)

	pending, err := storage.PendingRecalls(10, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("a holder that has refused %d times is still being asked every "+
			"pass, minting a fresh coordinator token each time: %#v",
			recallAttemptCeiling, pending)
	}
	// Deferred, not resolved and not forgotten: the ledger still says these
	// shards are out there.
	record, err := storage.LoadRecall(objectID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Resolved() {
		t.Fatal("backing off marked the holders as having answered terminally")
	}
	if !record.Deferred() {
		t.Fatal("the record does not report that it has been deferred, so an " +
			"operator cannot tell the retry clock changed")
	}
}

// The give-up is a SCHEDULE and not a decision. A holder that starts answering
// again -- it finished fetching the bootstrap document, or the manifest that
// referenced the bytes was deleted -- must still be reached.
func TestADeferredHolderIsRetriedAgainAndCanStillResolve(t *testing.T) {
	storage := openRecallStore(t)
	objectID := tombstoneWithOneHolder(t, storage, "recovers.bin", testHolder)
	for pass := 0; pass < recallAttemptCeiling+4; pass++ {
		refusePass(t, storage, objectID, testHolder)
	}

	backdate(t, storage, objectID, recallDeferredInterval+time.Minute)
	pending, err := storage.PendingRecalls(10, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("a deferred tombstone was never retried again: %d candidates. "+
			"The ceiling is a backoff, not an abandonment.", len(pending))
	}

	// And this time the holder honours it.
	record, err := storage.LoadRecall(objectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range record.Shards {
		if err := storage.RecordRecallOutcome(objectID, shard.ShardID, testHolder,
			RecallDeleted, "the holder removed the shard"); err != nil {
			t.Fatal(err)
		}
	}
	after, err := storage.LoadRecall(objectID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Resolved() {
		t.Fatal("a holder that answered after being deferred did not resolve the " +
			"tombstone")
	}
}

// The clock follows the least-asked OUTSTANDING holder, so a stubborn refuser
// does not slow down a holder that has only just been recorded, and a holder
// that answers terminally stops counting at all.
func TestTheBackoffFollowsTheLeastAskedOutstandingHolder(t *testing.T) {
	base := time.Minute
	fresh := RecallRecord{Shards: []RecallShard{{ShardID: "a", Holders: []RecallHolder{
		{PeerID: "p1", State: RecallPending},
	}}}}
	if got := fresh.retryAfter(base); got != base {
		t.Fatalf("a never-asked holder waits %s, want %s", got, base)
	}

	asked := RecallRecord{Shards: []RecallShard{{ShardID: "a", Holders: []RecallHolder{
		{PeerID: "p1", State: RecallRefused, Attempts: 3},
	}}}}
	if got := asked.retryAfter(base); got != 8*base {
		t.Fatalf("three refusals wait %s, want %s", got, 8*base)
	}

	stubborn := RecallRecord{Shards: []RecallShard{{ShardID: "a", Holders: []RecallHolder{
		{PeerID: "p1", State: RecallRefused, Attempts: recallAttemptCeiling},
	}}}}
	if got := stubborn.retryAfter(base); got != recallDeferredInterval {
		t.Fatalf("a holder at the ceiling waits %s, want %s", got, recallDeferredInterval)
	}

	// Same stubborn holder, plus one that was just added by a re-capture.
	joined := RecallRecord{Shards: []RecallShard{{ShardID: "a", Holders: []RecallHolder{
		{PeerID: "p1", State: RecallRefused, Attempts: recallAttemptCeiling},
		{PeerID: "p2", State: RecallPending},
	}}}}
	if got := joined.retryAfter(base); got != base {
		t.Fatalf("a newly recorded holder waits %s behind a deferred one, want %s",
			got, base)
	}
	if joined.Deferred() {
		t.Fatal("a record with a holder nobody has asked yet reports as deferred")
	}

	// A holder that answered terminally stops holding the record back at all.
	done := RecallRecord{Shards: []RecallShard{{ShardID: "a", Holders: []RecallHolder{
		{PeerID: "p1", State: RecallDeleted, Attempts: 1},
		{PeerID: "p2", State: RecallRefused, Attempts: recallAttemptCeiling},
	}}}}
	if got := done.retryAfter(base); got != recallDeferredInterval {
		t.Fatalf("a deleted holder still sets the clock: %s", got)
	}
}
