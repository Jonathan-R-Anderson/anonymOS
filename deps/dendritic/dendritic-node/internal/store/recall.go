package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// SHARD RECALL
// ============
// Placement said WHERE a shard went. Recall is the other half: getting it back
// off the peer it went to, and being able to say afterwards which peers actually
// dropped it.
//
// THE ORDERING BUG THIS FIXES
// ---------------------------
// DeleteObject used to end with forgetPlacement(objectID), which DELETES the
// holder list. The holder list is the only record on Earth of which peers hold
// shards of that object -- the peers themselves keep a row keyed by shard id and
// have no idea who else has a piece, and DHT provider records expire. So the
// delete destroyed the one thing a recall needs, and it did so unconditionally,
// from four separate call sites (DeleteObject, RejectAndRemove, and the two
// "the object is gone but the ledger row survived" ghost paths in repair and
// replicate).
//
// The fix is not to keep the placement row -- the dispersal and repair queues
// both scan bucketPlacement and would immediately start re-placing shards of a
// deleted object. The row MOVES to a tombstone in its own bucket:
//
//	bucketPlacement  ->  bucketRecall  ->  (dropped when every holder is resolved)
//
// Out of bucketPlacement, so the queues cannot see it. In bucketRecall, so the
// recall pass can retry a holder that was unreachable the first time and can
// still name the holders that refused.
//
// A tombstone is only dropped when every holder of every shard has reached a
// terminal answer. "Unreachable" is NOT terminal: a peer that has not fetched
// the coordinator's bootstrap document yet refuses everything, and a peer over
// I2P is routinely unreachable for minutes. Recording either as "gone" would
// make the ledger lie in the one direction that matters.
var bucketRecall = []byte("shard_recall")

// Holder states. Terminal states are the two that establish the shard is not on
// that peer any more; the other two are outcomes the next pass retries.
const (
	// RecallPending: no answer yet from this holder.
	RecallPending = "pending"
	// RecallDeleted: the holder confirmed it removed the bytes. Terminal.
	RecallDeleted = "deleted"
	// RecallAbsent: the holder answered, and did not have the shard. Terminal.
	RecallAbsent = "absent"
	// RecallRefused: the holder answered and said no, with a reason -- most
	// often "another manifest of mine still references these bytes". A refusal
	// is a real, reportable outcome and is deliberately NOT the same thing as
	// silence. Retried, because the reason can stop being true.
	RecallRefused = "refused"
	// RecallUnreachable: no answer. Retried forever; never treated as gone.
	RecallUnreachable = "unreachable"
)

// RecallHolder is one peer's answer about one shard.
type RecallHolder struct {
	PeerID    string    `json:"peer_id"`
	State     string    `json:"state"`
	Detail    string    `json:"detail,omitempty"`
	Attempts  int       `json:"attempts"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// RecallShard is one erasure shard and every peer the ledger recorded for it.
type RecallShard struct {
	ShardID    string         `json:"shard_id"`
	ChunkIndex int            `json:"chunk_index"`
	ShardIndex int            `json:"shard_index"`
	Size       int64          `json:"size"`
	Holders    []RecallHolder `json:"holders"`
}

// RecallRecord is the tombstone for one object.
type RecallRecord struct {
	ObjectID    string        `json:"object_id"`
	Bucket      string        `json:"bucket"`
	Key         string        `json:"key"`
	Shards      []RecallShard `json:"shards"`
	RequestedAt time.Time     `json:"requested_at"`
	Attempts    int           `json:"attempts"`
	LastAttempt time.Time     `json:"last_attempt,omitempty"`
	UpdatedAt   time.Time     `json:"updated_at"`
	// Reason is free text recording why the recall was raised (a delete, an
	// operator rejection, a ghost row) so the report can say which.
	Reason string `json:"reason,omitempty"`
}

// Counts tallies holder answers by state, which is exactly the per-layer report
// the purge page prints: deleted / refused / unreachable are three different
// true outcomes and one boolean cannot hold them.
func (r RecallRecord) Counts() map[string]int {
	counts := map[string]int{}
	for _, shard := range r.Shards {
		for _, holder := range shard.Holders {
			counts[holder.State]++
		}
	}
	return counts
}

// Outstanding is the number of holder answers that are not terminal yet.
func (r RecallRecord) Outstanding() int {
	outstanding := 0
	for _, shard := range r.Shards {
		for _, holder := range shard.Holders {
			if holder.State != RecallDeleted && holder.State != RecallAbsent {
				outstanding++
			}
		}
	}
	return outstanding
}

// Resolved reports whether every holder reached a terminal answer.
func (r RecallRecord) Resolved() bool { return r.Outstanding() == 0 }

// HolderPeers lists the distinct peers this record still has to reach.
func (r RecallRecord) HolderPeers() []string {
	seen := map[string]bool{}
	var out []string
	for _, shard := range r.Shards {
		for _, holder := range shard.Holders {
			if !seen[holder.PeerID] {
				seen[holder.PeerID] = true
				out = append(out, holder.PeerID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CaptureRecall copies an object's holder list out of the placement ledger into
// a recall tombstone, BEFORE anything deletes the placement row.
//
// Returns nil when there is nothing to recall: no ledger row, or a row whose
// shards were never confirmed on any peer. That is not an error -- an object
// that never left this disk has no remote copy to chase.
//
// Idempotent, and non-destructive to answers already collected: capturing twice
// (a delete, then an operator re-running a purge) preserves the per-holder state
// already recorded, so a retry resumes rather than restarts.
func (s *Store) CaptureRecall(objectID, reason string) (*RecallRecord, error) {
	if objectID == "" {
		return nil, errors.New("empty object ID")
	}
	var captured *RecallRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketPlacement).Get([]byte(objectID))
		if value == nil {
			// No ledger row. If a tombstone already exists (a previous delete
			// captured it) hand that back rather than reporting nothing.
			if existing := tx.Bucket(bucketRecall).Get([]byte(objectID)); existing != nil {
				var record RecallRecord
				if err := json.Unmarshal(existing, &record); err == nil {
					captured = &record
				}
			}
			return nil
		}
		var row ObjectPlacement
		if err := json.Unmarshal(value, &row); err != nil {
			return err
		}
		previous := map[string]RecallHolder{}
		if existing := tx.Bucket(bucketRecall).Get([]byte(objectID)); existing != nil {
			var old RecallRecord
			if err := json.Unmarshal(existing, &old); err == nil {
				for _, shard := range old.Shards {
					for _, holder := range shard.Holders {
						previous[shard.ShardID+"\x00"+holder.PeerID] = holder
					}
				}
			}
		}
		record := RecallRecord{
			ObjectID: row.ObjectID, Bucket: row.Bucket, Key: row.Key,
			RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
			Reason: reason,
		}
		for _, shard := range row.Shards {
			entry := RecallShard{
				ShardID: shard.ShardID, ChunkIndex: shard.ChunkIndex,
				ShardIndex: shard.ShardIndex, Size: shard.Size,
			}
			for _, peerID := range shard.Holders {
				if peerID == "" {
					continue
				}
				if carried, ok := previous[shard.ShardID+"\x00"+peerID]; ok {
					entry.Holders = append(entry.Holders, carried)
					continue
				}
				entry.Holders = append(entry.Holders, RecallHolder{
					PeerID: peerID, State: RecallPending,
				})
			}
			if len(entry.Holders) == 0 {
				continue
			}
			record.Shards = append(record.Shards, entry)
		}
		if len(record.Shards) == 0 {
			return nil
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketRecall).Put([]byte(objectID), encoded); err != nil {
			return err
		}
		captured = &record
		return nil
	})
	if err != nil {
		return nil, err
	}
	return captured, nil
}

// RetirePlacement is the ONLY sanctioned way a placement row leaves the ledger:
// capture the holders into a recall tombstone, then forget.
//
// All four former callers of forgetPlacement go through this -- the two delete
// paths and the two "the object is gone but the ledger row survived" ghost paths
// in repair and replicate. The ghost paths matter most: they fire when an object
// was deleted while this node was down, or by a path that predates the ledger,
// and those are precisely the cases where the holder list is the only surviving
// evidence that anything was ever placed.
func (s *Store) RetirePlacement(objectID, reason string) error {
	if objectID == "" {
		return nil
	}
	_, _ = s.CaptureRecall(objectID, reason)
	return s.forgetPlacement(objectID)
}

// ErrRecallLedgerUnreadable means the tombstone could not be READ: bolt failed,
// or the row will not unmarshal. It is a different error from os.ErrNotExist on
// purpose, and every caller has to keep them apart.
//
// "there is no tombstone" and "I could not find out whether there is a
// tombstone" are opposite answers on the page an operator uses for takedowns.
// Collapsing the second into the first prints "the ledger recorded no confirmed
// remote holder for this object" -- i.e. draws an unknown as a zero, in the
// comfortable direction -- which is the same defect as a backfill counter that
// fell on schedule while every node stayed empty.
var ErrRecallLedgerUnreadable = errors.New("the recall ledger could not be read")

// LoadRecall returns one tombstone, os.ErrNotExist when the object genuinely has
// none, or an error wrapping ErrRecallLedgerUnreadable when the answer is not
// known.
func (s *Store) LoadRecall(objectID string) (*RecallRecord, error) {
	var record RecallRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketRecall).Get([]byte(objectID))
		if value == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(value, &record)
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		// %v on the cause, not %w: callers classify on ErrRecallLedgerUnreadable
		// and must not accidentally match a bolt or json sentinel underneath it.
		return nil, fmt.Errorf("%w (%s): %v", ErrRecallLedgerUnreadable, objectID, err)
	}
	return &record, nil
}

// A REFUSAL IS NOT TERMINAL, BUT IT IS NOT FREE EITHER
// ----------------------------------------------------
// RecallRefused is deliberately non-terminal: "another manifest of mine still
// references these bytes" can stop being true, and a holder that refuses because
// it has not fetched the coordinator's bootstrap document yet starts honouring
// tokens the moment it does. So the tombstone survives and the holder is asked
// again.
//
// With a flat cooldown, though, a holder that refuses PERMANENTLY was asked
// every ten minutes forever, and each pass minted a fresh coordinator-signed
// revocation for it -- a destructive token, spent on a peer that has already
// said no a hundred times -- and wrote another line to the log. Verifying
// deletions (a holder that claims deletion and still has the shard is now
// recorded refused, not deleted) only produces MORE of these.
//
// The answer is a backoff with a ceiling, and NOT a terminal state:
//
//   - the delay doubles from the base cooldown per answered pass, so a holder
//     mid-outage costs a handful of retries instead of one every ten minutes;
//   - once the least-asked outstanding holder has answered recallAttemptCeiling
//     times, the tombstone drops to recallDeferredInterval and stays there;
//   - it is never dropped and never marked gone. Deferred is a SCHEDULE, so a
//     holder that starts answering again is still retried -- just hourly-ish
//     rather than every ten minutes;
//   - and it binds the BACKGROUND pass only. An operator re-running a recall
//     from the admin page calls RecallObject directly and is never deferred:
//     the ceiling exists to stop the machine from spending tokens on a peer
//     that keeps saying no, not to stop a human from asking.
//
// The clock is the least-asked OUTSTANDING holder, so one stubborn refuser
// cannot slow down a holder that was only just added by a re-capture, and a
// holder that reaches a terminal answer stops counting against the record.
const (
	recallAttemptCeiling   = 6
	recallDeferredInterval = 6 * time.Hour
)

// leastAskedOutstanding is how many answers the least-asked non-terminal holder
// has given. Zero when a holder has never been reached at all.
func (r RecallRecord) leastAskedOutstanding() int {
	fewest := -1
	for _, shard := range r.Shards {
		for _, holder := range shard.Holders {
			if holder.State == RecallDeleted || holder.State == RecallAbsent {
				continue
			}
			if fewest < 0 || holder.Attempts < fewest {
				fewest = holder.Attempts
			}
		}
	}
	if fewest < 0 {
		return 0
	}
	return fewest
}

// retryAfter is the cooldown this tombstone has earned: base, doubling per
// answered pass, capped at recallDeferredInterval.
func (r RecallRecord) retryAfter(base time.Duration) time.Duration {
	if base <= 0 {
		base = time.Minute
	}
	attempts := r.leastAskedOutstanding()
	if attempts >= recallAttemptCeiling {
		return recallDeferredInterval
	}
	delay := base
	for i := 0; i < attempts; i++ {
		delay *= 2
		if delay >= recallDeferredInterval {
			return recallDeferredInterval
		}
	}
	return delay
}

// Deferred reports whether the background pass has backed off to the long
// interval for this tombstone. Exported so the admin report can say so out loud:
// "still outstanding, and being retried every six hours" is a different fact
// from "still outstanding", and an operator watching for progress deserves the
// difference.
func (r RecallRecord) Deferred() bool {
	return r.Outstanding() > 0 && r.leastAskedOutstanding() >= recallAttemptCeiling
}

// PendingRecalls returns tombstones with outstanding holders, least-recently
// attempted first, skipping anything still inside the cooldown it has earned.
// Same shape as DispersalCandidates so a recall storm is rate-limited the same
// way.
func (s *Store) PendingRecalls(limit int, cooldown time.Duration) ([]RecallRecord, error) {
	if limit <= 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	var rows []RecallRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRecall).ForEach(func(_, value []byte) error {
			var record RecallRecord
			if err := json.Unmarshal(value, &record); err != nil {
				return nil
			}
			if record.Resolved() {
				return nil
			}
			if !record.LastAttempt.IsZero() &&
				record.LastAttempt.Add(record.retryAfter(cooldown)).After(now) {
				return nil
			}
			rows = append(rows, record)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].LastAttempt.Before(rows[j].LastAttempt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// AllRecalls lists every tombstone, resolved or not, for the admin listing, and
// separately COUNTS the rows it could not parse.
//
// The count is returned rather than swallowed for the same reason LoadRecall
// classifies its errors: a row that will not unmarshal used to vanish from this
// listing, so an object whose holders were still being chased simply stopped
// being mentioned and the summary's "recalls outstanding" silently shrank. A row
// that cannot be read is not a row that is not there.
func (s *Store) AllRecalls() ([]RecallRecord, int, error) {
	var rows []RecallRecord
	unreadable := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRecall).ForEach(func(_, value []byte) error {
			var record RecallRecord
			if err := json.Unmarshal(value, &record); err != nil {
				unreadable++
				return nil
			}
			rows = append(rows, record)
			return nil
		})
	})
	return rows, unreadable, err
}

// RecallSummary is the whole-node recall picture.
//
// Counted in ONE place so the two things that report it -- the gateway's
// GET /?placement and the heartbeat the coordinator draws the admin panel from
// -- cannot disagree. Two independent loops over the same ledger is two chances
// to classify "deferred" differently, and an operator comparing the page against
// the gateway would have no way to tell which of them was lying.
type RecallSummary struct {
	Records     int `json:"recalls"`
	Outstanding int `json:"recalls_outstanding"`
	// Tombstones the background pass has backed off on. Separate from
	// Outstanding so "outstanding and being chased" is not read off the same
	// number as "outstanding and now retried every six hours".
	Deferred int `json:"recalls_deferred"`
	// Rows that would not parse. Reported rather than skipped: an unreadable row
	// used to disappear from every count, which makes an unknown look like zero.
	Unreadable  int `json:"recalls_unreadable"`
	HoldersLeft int `json:"recall_holders_left"`
}

// RecallSummary counts the recall ledger.
func (s *Store) RecallSummary() (RecallSummary, error) {
	recalls, unreadable, err := s.AllRecalls()
	if err != nil {
		// Zero counts with an error, never zero counts alone: the caller must
		// not publish this as "nothing outstanding".
		return RecallSummary{}, err
	}
	summary := RecallSummary{Records: len(recalls), Unreadable: unreadable}
	for _, record := range recalls {
		if !record.Resolved() {
			summary.Outstanding++
		}
		if record.Deferred() {
			summary.Deferred++
		}
		summary.HoldersLeft += record.Outstanding()
	}
	return summary, nil
}

func (s *Store) updateRecall(objectID string, mutate func(*RecallRecord) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		recalls := tx.Bucket(bucketRecall)
		value := recalls.Get([]byte(objectID))
		if value == nil {
			return os.ErrNotExist
		}
		var record RecallRecord
		if err := json.Unmarshal(value, &record); err != nil {
			return err
		}
		if err := mutate(&record); err != nil {
			return err
		}
		record.UpdatedAt = time.Now().UTC()
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return recalls.Put([]byte(objectID), encoded)
	})
}

// MarkRecallAttempt stamps the tombstone as just worked on, so the cooldown in
// PendingRecalls survives a restart.
func (s *Store) MarkRecallAttempt(objectID string) error {
	return s.updateRecall(objectID, func(record *RecallRecord) error {
		record.LastAttempt = time.Now().UTC()
		record.Attempts++
		return nil
	})
}

// RecordRecallOutcome writes one peer's answer for one shard.
func (s *Store) RecordRecallOutcome(objectID, shardID, peerID, state, detail string) error {
	switch state {
	case RecallPending, RecallDeleted, RecallAbsent, RecallRefused, RecallUnreachable:
	default:
		return errors.New("unknown recall state " + state)
	}
	if len(detail) > 400 {
		detail = detail[:400]
	}
	return s.updateRecall(objectID, func(record *RecallRecord) error {
		// EVERY matching entry, not the first. Shards are content-addressed, so
		// one object can legitimately contain the same shard id more than once
		// (a chunk of constant bytes produces identical data shards). Stopping
		// at the first match would leave the duplicates pending forever and the
		// tombstone would never resolve.
		for i := range record.Shards {
			if record.Shards[i].ShardID != shardID {
				continue
			}
			for j := range record.Shards[i].Holders {
				if record.Shards[i].Holders[j].PeerID != peerID {
					continue
				}
				record.Shards[i].Holders[j].State = state
				record.Shards[i].Holders[j].Detail = detail
				record.Shards[i].Holders[j].Attempts++
				record.Shards[i].Holders[j].UpdatedAt = time.Now().UTC()
			}
		}
		return nil
	})
}

// DropRecall removes a tombstone. Called only once every holder is terminal, or
// by an operator who has decided to stop chasing.
func (s *Store) DropRecall(objectID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRecall).Delete([]byte(objectID))
	})
}

// ErrShardStillReferenced means the holder keeps the bytes because one of its
// OWN manifests still needs them. Shards are content-addressed, so two objects
// with identical chunk bytes are literally the same shard file: honouring a
// revocation for one would silently corrupt the other.
var ErrShardStillReferenced = errors.New("shard is still referenced by a local manifest")

// ErrShardHeldForAnotherObject means this peer's remote_shards row credits these
// bytes to a DIFFERENT object than the revocation names. The row is keyed by
// shard id alone (one row, one ObjectID, last writer wins), so the peer cannot
// tell whether the other owner is still live -- and a revocation minted by one
// owner must not strip bytes another owner is depending on. Refused, loudly,
// rather than guessed at.
var ErrShardHeldForAnotherObject = errors.New("shard is held on behalf of another object")

// DeleteRemoteShard is the HOLDER side of a recall: drop a shard this node is
// storing on somebody else's behalf.
//
// Returns (true, nil) when bytes were removed, (false, nil) when the shard was
// already gone -- both are terminal, honest answers, and the caller reports them
// differently. Everything else is a refusal with a reason.
//
// Three things happen, in this order, and all three are needed:
//
//  1. The references are checked. A shard a local manifest still points at is
//     REFUSED: removeUnreferenced would decline to unlink the file anyway, and
//     dropping the remote row while keeping the file would leave this node
//     answering `have` with true for a shard it no longer admits holding.
//  2. The shard is added to the local denylist. Without this the delete is
//     undone within minutes -- the owner's replicate pass (every 5 minutes) and
//     the repair pass both re-push shards a peer no longer has, and
//     PutRemoteShard refuses only what is on the denylist.
//  3. The remote row is dropped and the FILE is unlinked through
//     removeUnreferenced, which also gives the capacity counter its bytes back.
//     Deleting the bolt row alone is not deleting the shard: `have` and `get`
//     both read the file off disk and never consult remote_shards.
func (s *Store) DeleteRemoteShard(objectID, shardID string) (bool, error) {
	if !IsContentID(shardID) {
		// Charset, not just length -- see IsContentID. A length-only check
		// here made this an arbitrary-file-unlink primitive.
		return false, errors.New("invalid shard ID")
	}
	var heldFor string
	var hadRow bool
	if err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketRemote).Get([]byte(shardID))
		if value == nil {
			return nil
		}
		hadRow = true
		var row RemoteShard
		if err := json.Unmarshal(value, &row); err != nil {
			return nil
		}
		heldFor = row.ObjectID
		return nil
	}); err != nil {
		return false, err
	}
	if hadRow && objectID != "" && heldFor != "" && heldFor != objectID {
		return false, ErrShardHeldForAnotherObject
	}
	// ONE TRANSACTION for the whole decision: is this shard still referenced,
	// record the scoped refusal, and drop the remote row. Previously these were
	// three separate transactions with the unlink outside all of them, so a
	// concurrent PutRemoteShard could make the shard referenced after the check
	// passed and the recall would delete it anyway. The unlink stays outside --
	// a filesystem operation cannot be rolled back, so it must come after the
	// commit that authorises it, never inside.
	//
	// The scoped refusal is written here rather than by refuseRecalledShard so
	// it shares this transaction; see that function for WHY the moderation
	// denylist is the wrong tool.
	var referenced bool
	if err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		if referenced, err = manifestReferencesShardTx(tx, shardID); err != nil {
			return err
		}
		if referenced {
			return nil
		}
		deadline := time.Now().UTC().Add(recallRefusalTTL).Format(time.RFC3339Nano)
		if err := tx.Bucket(bucketDenied).Put(recallRefusalKey(objectID, shardID), []byte(deadline)); err != nil {
			return err
		}
		return tx.Bucket(bucketRemote).Delete([]byte(shardID))
	}); err != nil {
		return false, err
	}
	if referenced {
		return false, ErrShardStillReferenced
	}
	_, statErr := os.Stat(s.shardPath(shardID))
	existed := statErr == nil
	if err := s.removeUnreferenced([]string{shardID}); err != nil {
		return false, err
	}
	if _, err := os.Stat(s.shardPath(shardID)); err == nil {
		// removeUnreferenced declined. The only reason left is a reference this
		// node's own data created between the check and now.
		return false, ErrShardStillReferenced
	}
	return existed || hadRow, nil
}

// manifestReferencesShard asks only about THIS node's own objects, deliberately
// ignoring bucketRemote: the remote row is what the recall is removing, so
// counting it as a reference would make every recall refuse itself.
// manifestReferencesShardTx is the reference check INSIDE a caller's
// transaction. DeleteRemoteShard needs the check and the delete to see the same
// database state: with separate transactions a concurrent PutRemoteShard for a
// different object lands between them, and the recall then deletes bytes that
// became referenced a microsecond earlier.
func manifestReferencesShardTx(tx *bolt.Tx, shardID string) (bool, error) {
	var referenced bool
	err := tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
		if referenced {
			return nil
		}
		var manifest Manifest
		if err := json.Unmarshal(value, &manifest); err != nil {
			return err
		}
		for _, chunk := range manifest.Chunks {
			for _, shard := range chunk.Shards {
				if shard.ID == shardID {
					referenced = true
					return nil
				}
			}
		}
		return nil
	})
	return referenced, err
}

func (s *Store) manifestReferencesShard(shardID string) (bool, error) {
	var referenced bool
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			if referenced {
				return nil
			}
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			for _, chunk := range manifest.Chunks {
				for _, shard := range chunk.Shards {
					if shard.ID == shardID {
						referenced = true
						return nil
					}
				}
			}
			return nil
		})
	})
	return referenced, err
}

// PlacementView is one row of the admin listing: the ledger row, joined to the
// manifest for the things the ledger does not carry (size, content type, age),
// plus the per-peer rollup nothing stores because the index only goes the other
// way.
type PlacementView struct {
	ObjectID    string `json:"object_id"`
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	ContentType string `json:"content_type,omitempty"`
	// PlainSize is the STORED length, read from the manifest. Summing shard
	// sizes would report padded ciphertext instead, which is a different number
	// and would be wrong in the same way a derived shard count is wrong.
	PlainSize int64     `json:"plain_size"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	// ObjectPresent is false for a tombstoned object: the ledger remembers where
	// its shards went after the manifest is gone.
	ObjectPresent bool `json:"object_present"`

	DataShards   int `json:"data_shards"`
	ParityShards int `json:"parity_shards"`
	Chunks       int `json:"chunks"`
	ShardCount   int `json:"shard_count"`
	// LocalShards counts shards still on this node's own disk.
	LocalShards int `json:"local_shards"`
	// PlacedShards counts shards with at least one confirmed remote holder.
	PlacedShards int `json:"placed_shards"`

	DistinctHolders  int            `json:"distinct_holders"`
	HolderShards     map[string]int `json:"holder_shards,omitempty"`
	WeakestChunk     int            `json:"weakest_chunk"`
	DurableThreshold int            `json:"durable_threshold"`
	UnderReplicated  bool           `json:"under_replicated"`
	FullyDispersed   bool           `json:"fully_dispersed"`

	LastAttempt time.Time `json:"last_attempt,omitempty"`
	Attempts    int       `json:"attempts"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`

	// Shards is populated only for the single-object view; a bucket listing of
	// 11k objects times 9 shards a chunk is not a page.
	Shards []ShardPlacement `json:"shards,omitempty"`
	// Recall is the tombstone, when one is outstanding.
	Recall *RecallRecord `json:"recall,omitempty"`
}

// PlacementListing is one page of the ledger.
type PlacementListing struct {
	Objects []PlacementView `json:"objects"`
	// NextMarker is the object id to pass back to continue. Empty at the end.
	NextMarker string `json:"next_marker,omitempty"`
	Scanned    int    `json:"scanned"`
	Truncated  bool   `json:"truncated"`
}

// maxPlacementScan bounds one listing request. The bucket is full-scanned and
// every row JSON-unmarshalled, so an unbounded filtered listing over a bucket
// with no matches would walk the whole ledger while a caller waited.
const maxPlacementScan = 20000

// ListPlacements pages the placement ledger, optionally filtered to one bucket
// and key prefix, joining each row to its manifest.
//
// Pagination is by opaque marker (the last object id returned) rather than by
// offset, because bolt keys are object ids and an offset into a hash ordering
// means nothing and shifts under writes.
func (s *Store) ListPlacements(bucket, prefix, marker string, limit int, withShards bool) (PlacementListing, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	var listing PlacementListing
	err := s.db.View(func(tx *bolt.Tx) error {
		objects := tx.Bucket(bucketObjects)
		recalls := tx.Bucket(bucketRecall)
		cursor := tx.Bucket(bucketPlacement).Cursor()
		var key, value []byte
		if marker != "" {
			key, value = cursor.Seek([]byte(marker))
			if key != nil && string(key) == marker {
				key, value = cursor.Next()
			}
		} else {
			key, value = cursor.First()
		}
		for ; key != nil; key, value = cursor.Next() {
			listing.Scanned++
			if listing.Scanned > maxPlacementScan {
				listing.Truncated = true
				listing.NextMarker = string(key)
				return nil
			}
			var row ObjectPlacement
			if err := json.Unmarshal(value, &row); err != nil {
				continue
			}
			if bucket != "" && row.Bucket != bucket {
				continue
			}
			if prefix != "" && !strings.HasPrefix(row.Key, prefix) {
				continue
			}
			view := placementView(row, withShards)
			if stored := objects.Get(objectKey(row.Bucket, row.Key)); stored != nil {
				var manifest Manifest
				if err := json.Unmarshal(stored, &manifest); err == nil &&
					manifest.ObjectID == row.ObjectID {
					view.ObjectPresent = true
					view.ContentType = manifest.ContentType
					view.PlainSize = manifest.PlainSize
					view.CreatedAt = manifest.CreatedAt
				}
			}
			if tomb := recalls.Get([]byte(row.ObjectID)); tomb != nil {
				var record RecallRecord
				if err := json.Unmarshal(tomb, &record); err == nil {
					view.Recall = &record
				}
			}
			listing.Objects = append(listing.Objects, view)
			if len(listing.Objects) >= limit {
				next, _ := cursor.Next()
				if next != nil {
					listing.NextMarker = string(key)
					listing.Truncated = true
				}
				return nil
			}
		}
		return nil
	})
	return listing, err
}

// PlacementFor returns the full ledger view of one object, shards included.
func (s *Store) PlacementFor(objectID string) (*PlacementView, error) {
	row, err := s.LoadObjectPlacement(objectID)
	if err != nil {
		return nil, err
	}
	view := placementView(*row, true)
	_ = s.db.View(func(tx *bolt.Tx) error {
		if stored := tx.Bucket(bucketObjects).Get(objectKey(row.Bucket, row.Key)); stored != nil {
			var manifest Manifest
			if err := json.Unmarshal(stored, &manifest); err == nil &&
				manifest.ObjectID == row.ObjectID {
				view.ObjectPresent = true
				view.ContentType = manifest.ContentType
				view.PlainSize = manifest.PlainSize
				view.CreatedAt = manifest.CreatedAt
			}
		}
		if tomb := tx.Bucket(bucketRecall).Get([]byte(objectID)); tomb != nil {
			var record RecallRecord
			if err := json.Unmarshal(tomb, &record); err == nil {
				view.Recall = &record
			}
		}
		return nil
	})
	return &view, nil
}

// ObjectIDForKey resolves bucket/key to the ledger's primary key, preferring the
// live manifest and falling back to a scan of the ledger so a tombstoned object
// is still addressable after its manifest is gone.
func (s *Store) ObjectIDForKey(bucket, key string) (string, error) {
	var objectID string
	err := s.db.View(func(tx *bolt.Tx) error {
		if stored := tx.Bucket(bucketObjects).Get(objectKey(bucket, key)); stored != nil {
			var manifest Manifest
			if err := json.Unmarshal(stored, &manifest); err == nil {
				objectID = manifest.ObjectID
				return nil
			}
		}
		return tx.Bucket(bucketPlacement).ForEach(func(id, value []byte) error {
			if objectID != "" {
				return nil
			}
			var row ObjectPlacement
			if err := json.Unmarshal(value, &row); err != nil {
				return nil
			}
			if row.Bucket == bucket && row.Key == key {
				objectID = row.ObjectID
			}
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	if objectID == "" {
		return "", os.ErrNotExist
	}
	return objectID, nil
}

func placementView(row ObjectPlacement, withShards bool) PlacementView {
	view := PlacementView{
		ObjectID: row.ObjectID, Bucket: row.Bucket, Key: row.Key,
		DataShards: row.DataShards, ParityShards: row.ParityShards,
		Chunks: len(row.ChunkIndexes()), ShardCount: len(row.Shards),
		WeakestChunk:     row.WeakestChunk(),
		DurableThreshold: DurableRemoteHolders(row.DataShards, row.ParityShards),
		UnderReplicated:  row.UnderReplicated(),
		FullyDispersed:   row.FullyDispersed(),
		LastAttempt:      row.LastAttempt, Attempts: row.Attempts,
		UpdatedAt: row.UpdatedAt,
	}
	holders := map[string]int{}
	for _, shard := range row.Shards {
		if shard.Local {
			view.LocalShards++
		}
		if len(shard.Holders) > 0 {
			view.PlacedShards++
		}
		for _, peerID := range shard.Holders {
			holders[peerID]++
		}
	}
	view.DistinctHolders = len(holders)
	if len(holders) > 0 {
		view.HolderShards = holders
	}
	if withShards {
		view.Shards = append([]ShardPlacement(nil), row.Shards...)
	}
	return view
}

// recallRefusalTTL bounds how long a holder refuses a shard it recalled.
//
// Long enough to outlast the owner's replicate cycle, so a recall is not
// immediately undone by the very loop that placed the shard; short enough that
// the holder does not carry a permanent grudge against a content address it may
// legitimately be asked to store again for a different object.
const recallRefusalTTL = 6 * time.Hour

func recallRefusalKey(objectID, shardID string) []byte {
	return []byte("recall\x00" + objectID + "\x00" + shardID)
}

// refuseRecalledShard records that this object's copy of this shard was
// recalled. Scoped to the object and expiring -- see the call site for why the
// moderation denylist is the wrong tool.
func (s *Store) refuseRecalledShard(objectID, shardID string) error {
	if !IsContentID(shardID) {
		return errors.New("invalid shard ID")
	}
	deadline := time.Now().UTC().Add(recallRefusalTTL).Format(time.RFC3339Nano)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDenied).Put(recallRefusalKey(objectID, shardID), []byte(deadline))
	})
}

// REVOCATION REPLAY, AND WHY THE NONCE IS WRITTEN TO DISK
// =======================================================
// A revocation carries a Nonce, it is inside the signed message, and nothing
// remembered it. A delete token was therefore reusable at its recipient for its
// entire lifetime: anything holding a copy of the frame -- the holder itself,
// most obviously -- could present the same bytes again and again until it
// expired. The practical damage was small (the shard is gone and denylisted, so
// a replay deletes nothing), but a destructive capability that can be spent
// twice is a bug in the capability, not in its consequences.
//
// PERSISTED, LIKE refuseRecalledShard, AND FOR A WEAKER VERSION OF THE SAME
// REASON. That function is on disk because an in-memory cooldown resets in a
// crash loop and the owner's replicate pass would push the recalled shard
// straight back -- a permanent loss of the guarantee. Here the exposure is
// bounded by the token's own lifetime instead: validateRevocation refuses
// anything expiring more than an hour out, and the coordinator mints ten
// minutes, so an in-memory cache would only reopen the replay window for a node
// that restarted inside those minutes. That is a narrower hole, but a crash
// loop is exactly a machine that restarts repeatedly inside ten minutes, and the
// cost of closing it is one bolt write on a path that already writes to bolt
// (DeleteRemoteShard) and that runs at most once per placed shard per recall.
// So: persisted.
//
// BOUNDED, BECAUSE A REMOTE PARTY FEEDS IT. Entries can only be created by a
// token this node has already fully validated -- coordinator-signed, naming this
// node as recipient and the authenticated peer as requester -- so the fill rate
// is the coordinator's minting rate and not an attacker's request rate. It is
// still bounded twice: every claim drops entries whose token has expired (they
// are inert, validateRevocation rejects them on age alone), and if that still
// leaves more than maxRevocationNonces, the entries closest to expiry are
// dropped to make room. Evicting the closest to expiry is the least-harmful
// choice available: those are the tokens with the least remaining life in which
// to be replayed.
var bucketRevocationNonces = []byte("revocation_nonces")

// maxRevocationNonces caps the replay cache. A holder sees one token per shard
// it holds of the object being recalled -- tens, for a large object -- and a
// token lives at most an hour, so a few thousand covers a very busy hour with
// room to spare. At roughly 80 bytes an entry the cap is a few hundred kB.
const maxRevocationNonces = 4096

// maxRevocationNonceLength mirrors validateRevocation's own ceiling so a caller
// that forgot to validate cannot use this bucket as unbounded remote storage.
const maxRevocationNonceLength = 128

// ClaimRevocationNonce records a revocation nonce as SPENT and reports whether
// this caller is the first to spend it. A false return is a replay.
//
// Check-and-set inside one transaction on purpose: two streams presenting the
// same captured token at the same moment must not both read "unused" and both
// be honoured.
//
// The caller passes the token's own expiry, so an entry lives exactly as long as
// the token it defends against and not a second longer.
func (s *Store) ClaimRevocationNonce(nonce string, expiresAt time.Time) (bool, error) {
	if nonce == "" {
		return false, errors.New("revocation nonce is empty")
	}
	if len(nonce) > maxRevocationNonceLength {
		return false, errors.New("revocation nonce is too long")
	}
	now := time.Now().UTC()
	if !expiresAt.After(now) {
		return false, errors.New("revocation has already expired")
	}
	fresh := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		spent := tx.Bucket(bucketRevocationNonces)
		if raw := spent.Get([]byte(nonce)); raw != nil {
			deadline, perr := time.Parse(time.RFC3339Nano, string(raw))
			if perr == nil && now.Before(deadline) {
				// Spent, and the token it was spent on is still live. Replay.
				return nil
			}
			// An elapsed or unparseable entry is re-claimable: a token that old
			// cannot be honoured anyway (validateRevocation checks the expiry),
			// so keeping the entry would only consume space.
		}
		if err := pruneRevocationNonces(tx, now); err != nil {
			return err
		}
		fresh = true
		return spent.Put([]byte(nonce),
			[]byte(expiresAt.UTC().Format(time.RFC3339Nano)))
	})
	if err != nil {
		return false, err
	}
	return fresh, nil
}

// pruneRevocationNonces drops expired entries, then -- if the bucket is still at
// its cap -- enough of the entries closest to expiry to fit one more.
//
// Keys are collected and deleted after the walk rather than through the cursor,
// because deleting under an iterating cursor is the kind of subtlety that works
// until the day it skips an entry.
func pruneRevocationNonces(tx *bolt.Tx, now time.Time) error {
	spent := tx.Bucket(bucketRevocationNonces)
	type entry struct {
		key      []byte
		deadline time.Time
	}
	var expired [][]byte
	var live []entry
	if err := spent.ForEach(func(key, value []byte) error {
		deadline, err := time.Parse(time.RFC3339Nano, string(value))
		if err != nil || !now.Before(deadline) {
			expired = append(expired, append([]byte(nil), key...))
			return nil
		}
		live = append(live, entry{key: append([]byte(nil), key...), deadline: deadline})
		return nil
	}); err != nil {
		return err
	}
	for _, key := range expired {
		if err := spent.Delete(key); err != nil {
			return err
		}
	}
	if len(live) < maxRevocationNonces {
		return nil
	}
	sort.SliceStable(live, func(i, j int) bool {
		return live[i].deadline.Before(live[j].deadline)
	})
	for i := 0; i <= len(live)-maxRevocationNonces; i++ {
		if err := spent.Delete(live[i].key); err != nil {
			return err
		}
	}
	return nil
}

// RecallRefused reports whether this object's copy of this shard is still
// within its refusal window. An unparseable or elapsed deadline is NOT a
// refusal: the failure direction has to be "accept the shard", because
// refusing forever is the bug this replaced.
func (s *Store) RecallRefused(objectID, shardID string) bool {
	var refused bool
	s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketDenied).Get(recallRefusalKey(objectID, shardID))
		if raw == nil {
			return nil
		}
		deadline, err := time.Parse(time.RFC3339Nano, string(raw))
		if err != nil {
			return nil
		}
		refused = time.Now().UTC().Before(deadline)
		return nil
	})
	return refused
}
