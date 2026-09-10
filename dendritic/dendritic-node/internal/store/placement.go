package store

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
)

// THE PLACEMENT LEDGER
// ====================
// Where a shard went was never written down anywhere. ShardRef carries id,
// index and size and nothing else, and the manifest cannot be extended to carry
// holders: ObjectID is the sha256 of the manifest with ObjectID blanked
// (canonicalManifest), and s3api returns ObjectID as the S3 ETag — adding a
// field would change every ETag in existence and break multipart completion.
// The DHT manifest record is also capped at 512 KiB, which per-shard holder
// lists would push large objects straight through.
//
// So placement lives in its own bolt buckets, keyed by object id, entirely
// outside the content-addressed identity of the object. Three consequences that
// were previously impossible are now possible:
//
//  1. A durable dispersal queue. The old one was `map[string]struct{}` in RAM,
//     marked on ATTEMPT rather than on success, so a restart replayed 11k
//     objects and a failed push was recorded as done forever.
//  2. An audit. "Is chunk 7 of this object still rebuildable without me?" has an
//     answer instead of a DHT provider search that only says who once claimed a
//     shard before the record expired.
//  3. Repair. Nothing can re-place a shard whose holder vanished if nothing ever
//     recorded that the holder had it.
var (
	bucketPlacement      = []byte("shard_placement")
	bucketPlacementIndex = []byte("shard_placement_index")
)

// ShardPlacement is the ledger row for one erasure shard.
type ShardPlacement struct {
	ShardID    string `json:"shard_id"`
	ChunkIndex int    `json:"chunk_index"`
	ShardIndex int    `json:"shard_index"`
	Size       int64  `json:"size"`
	// Holders are peer IDs that CONFIRMED storing these bytes — the peer replied
	// ok to a store frame after the content address was verified on its side.
	// Never an attempt, never an intention.
	Holders []string `json:"holders,omitempty"`
	// Silences counts CONSECUTIVE audits in which a holder failed to answer
	// while other holders of the same object answered fine. It is keyed by peer
	// id and reset to nothing the moment that peer answers again.
	//
	// It lives in the ledger rather than in memory because that is the only
	// place it means anything: audits of one object are hours apart and a
	// process restart in between must not hand a holder that has been silent for
	// two days a clean slate. Without it there are only two possible policies,
	// and both are wrong -- evict on the first missed probe (a reboot costs a
	// node every shard it holds) or never evict at all (a node that dropped out
	// stays in the ledger forever and its pieces are never rebuilt).
	Silences map[string]int `json:"silences,omitempty"`
	// Local records whether this node still has the bytes on its own disk.
	Local bool `json:"local"`
}

// ObjectPlacement is the ledger row for one object.
type ObjectPlacement struct {
	ObjectID     string           `json:"object_id"`
	Bucket       string           `json:"bucket"`
	Key          string           `json:"key"`
	DataShards   int              `json:"data_shards"`
	ParityShards int              `json:"parity_shards"`
	Shards       []ShardPlacement `json:"shards"`
	// LastAttempt is when dispersal or repair last ran for this object. It is
	// the rate limiter: the pass orders by it and skips anything touched
	// recently, so a netsplit that makes every object look under-replicated
	// cannot spin the same objects in a loop.
	LastAttempt time.Time `json:"last_attempt"`
	Attempts    int       `json:"attempts"`
	// LastRebalance is when the levelling mover last worked on this object.
	//
	// A SEPARATE clock from LastAttempt on purpose. Stamping the shared one
	// would make the lowest-priority mover in the system push the object's next
	// REPAIR audit six hours into the future every time it looked at it, so
	// levelling would starve the loop that keeps objects alive. Absent from
	// older rows, which decode as the zero time and are therefore due
	// immediately -- correct, since they have never been levelled.
	LastRebalance time.Time `json:"last_rebalance,omitempty"`
	Rebalances    int       `json:"rebalances,omitempty"`
	// LastDrain is when the drain mover last examined this object for shards on
	// a peer that is being retired.
	//
	// A THIRD clock, for the same reason LastRebalance is a second one, and it is
	// what makes a drain resumable: a drain runs for hours and the process will
	// be restarted inside it -- that is precisely what the operator is preparing
	// to do -- so the position has to be on disk. In memory it would restart at
	// the top of the bucket on every restart, re-examining the same first few
	// objects forever while the tail was never reached. Absent from older rows,
	// which decode as the zero time and are therefore due immediately.
	LastDrain time.Time `json:"last_drain,omitempty"`
	Drains    int       `json:"drains,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DurableRemoteHolders is how many DISTINCT PEERS must hold shards of a chunk
// before this node calls the object durable.
//
// WHY HOLDERS AND NOT PLACED INDEXES
// ----------------------------------
// The metric this replaced counted distinct remote shard INDEXES, which is
// blind to the only thing dispersal is for. Nine indexes confirmed by ONE peer
// scored nine out of nine: fully placed, durable, retired from the queue -- with
// the entire object on a single machine. Reed-Solomon does not make copies, it
// makes pieces, and a pile of pieces in one building is not redundancy. What
// bounds survival is how many machines have to fail, and that is the number of
// distinct holders.
//
// WHY dataShards+1 WITH 6+3
// -------------------------
// Six indexes is the decode threshold: below it the remote copies are not an
// object, they are noise, so six distinct indexes on six distinct peers is the
// first point at which the chunk exists anywhere but this node's disk. It is
// also, exactly, zero redundancy -- losing any ONE of those six takes it back
// under the decode threshold, and "a node drops out" is the event the whole
// feature was asked for. SEVEN distinct peers is the first arrangement that
// answers the requirement: the chunk is rebuildable without this node AND
// without any one of the peers holding it.
//
// Requiring all nine here would make durability hostage to the least available
// peer, holding an object in the queue forever over one refused shard while
// eight sit safely placed. Seven is where the promise becomes true; the pass
// keeps pushing toward nine afterwards, because nine shards on nine distinct
// peers is what buys the full three-node loss tolerance, and FullyDispersed is
// the flag that says it got there.
//
// With no parity at all there is nothing to spare: dataShards distinct peers is
// the most the layout can offer and the threshold has to say so.
func DurableRemoteHolders(dataShards, parityShards int) int {
	if dataShards < 1 {
		dataShards = 1
	}
	if parityShards < 1 {
		return dataShards
	}
	return dataShards + 1
}

// PlacementSnapshot is the read-only view the dispersal and repair passes work
// from, converted into the pure planner's vocabulary.
func (p ObjectPlacement) PlacementSnapshot(chunkIndex int) []placement.Shard {
	var out []placement.Shard
	for _, shard := range p.Shards {
		if shard.ChunkIndex != chunkIndex {
			continue
		}
		out = append(out, placement.Shard{
			ID: shard.ShardID, Index: shard.ShardIndex,
			Size: shard.Size, Holders: append([]string(nil), shard.Holders...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// ChunkIndexes lists the chunk numbers this object has, in order.
func (p ObjectPlacement) ChunkIndexes() []int {
	seen := make(map[int]bool)
	var out []int
	for _, shard := range p.Shards {
		if !seen[shard.ChunkIndex] {
			seen[shard.ChunkIndex] = true
			out = append(out, shard.ChunkIndex)
		}
	}
	sort.Ints(out)
	return out
}

// WeakestChunk returns the number of DISTINCT REMOTE HOLDERS of the worst
// chunk, which is the object's real durability: an object is only as
// recoverable as its least dispersed chunk, since every chunk is needed to
// reassemble the whole, and a chunk is only as safe as the number of separate
// machines its pieces sit on.
func (p ObjectPlacement) WeakestChunk() int {
	chunks := p.ChunkIndexes()
	if len(chunks) == 0 {
		return 0
	}
	weakest := -1
	for _, chunk := range chunks {
		count := placement.DistinctHolders(p.PlacementSnapshot(chunk))
		if weakest < 0 || count < weakest {
			weakest = count
		}
	}
	return weakest
}

// ChunkIsDurable reports whether one chunk has reached the durability
// threshold: enough distinct holders, arranged so that the chunk still decodes
// without this node AND without any one of those holders.
//
// Both halves are needed. The holder count alone would accept seven peers where
// one of them holds four of the nine pieces; the loss test alone would accept
// arrangements the threshold is meant to describe in plain numbers.
func (p ObjectPlacement) ChunkIsDurable(chunkIndex int) bool {
	shards := p.PlacementSnapshot(chunkIndex)
	if len(shards) == 0 {
		return false
	}
	if placement.DistinctHolders(shards) < DurableRemoteHolders(p.DataShards, p.ParityShards) {
		return false
	}
	return placement.SurvivesHolderLosses(shards, p.DataShards, 1)
}

// ChunkIsSpread reports whether one chunk has reached the FULL dispersal
// target: every shard on some peer, spread so the chunk survives parityShards
// holders dropping out at once. That is the loss tolerance a 6+3 layout is
// supposed to buy, and it is a claim about holders, not about placements.
func (p ObjectPlacement) ChunkIsSpread(chunkIndex int) bool {
	shards := p.PlacementSnapshot(chunkIndex)
	if len(shards) == 0 {
		return false
	}
	for _, shard := range shards {
		if len(shard.Holders) == 0 {
			return false
		}
	}
	return placement.SurvivesHolderLosses(shards, p.DataShards, p.ParityShards)
}

// UnderReplicated reports whether this object still lacks the remote holders
// that would make it recoverable without this node and without any one of them.
func (p ObjectPlacement) UnderReplicated() bool {
	chunks := p.ChunkIndexes()
	if len(chunks) == 0 {
		return true
	}
	for _, chunk := range chunks {
		if !p.ChunkIsDurable(chunk) {
			return true
		}
	}
	return false
}

// FullyDispersed reports whether every chunk has reached the full dispersal
// target. This is what retires an object from the dispersal queue, so it is
// also the guard against retiring a CO-LOCATED object: a chunk whose pieces
// share too few machines never satisfies it, however many placements were
// confirmed.
func (p ObjectPlacement) FullyDispersed() bool {
	chunks := p.ChunkIndexes()
	if len(chunks) == 0 {
		return false
	}
	for _, chunk := range chunks {
		if !p.ChunkIsSpread(chunk) {
			return false
		}
	}
	return true
}

// RecordObjectPlacement writes (or refreshes) the ledger row for a manifest.
// Existing confirmed holders for a shard id are preserved: shards are
// content-addressed, so the same bytes rewritten under a new object are already
// on the same peers and re-pushing them would be wasted transfer.
func (s *Store) RecordObjectPlacement(manifest Manifest) error {
	row := ObjectPlacement{
		ObjectID: manifest.ObjectID, Bucket: manifest.Bucket, Key: manifest.Key,
		DataShards: manifest.DataShards, ParityShards: manifest.ParityShards,
		UpdatedAt: time.Now().UTC(),
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			row.Shards = append(row.Shards, ShardPlacement{
				ShardID: ref.ID, ChunkIndex: chunk.Index, ShardIndex: ref.Index,
				Size: int64(ref.Size), Local: true,
			})
		}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		placements := tx.Bucket(bucketPlacement)
		if existing := placements.Get([]byte(row.ObjectID)); existing != nil {
			var previous ObjectPlacement
			if err := json.Unmarshal(existing, &previous); err == nil {
				known := make(map[string]ShardPlacement, len(previous.Shards))
				for _, shard := range previous.Shards {
					known[shard.ShardID] = shard
				}
				for i := range row.Shards {
					// Silence counts travel with the holders they judge; losing
					// them on a rewrite would give a holder that has been
					// unreachable for days a clean slate.
					row.Shards[i].Holders = known[row.Shards[i].ShardID].Holders
					row.Shards[i].Silences = known[row.Shards[i].ShardID].Silences
				}
				row.LastAttempt, row.Attempts = previous.LastAttempt, previous.Attempts
				// The levelling clock travels with them. A rewrite that reset it
				// would hand the mover a fresh licence to churn the object every
				// time the same bytes were re-PUT under a new key.
				row.LastRebalance, row.Rebalances = previous.LastRebalance, previous.Rebalances
			}
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			return err
		}
		if err := placements.Put([]byte(row.ObjectID), encoded); err != nil {
			return err
		}
		index := tx.Bucket(bucketPlacementIndex)
		for _, shard := range row.Shards {
			if err := index.Put([]byte(shard.ShardID), []byte(row.ObjectID)); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnrolMissingPlacements gives a ledger row to objects stored before the ledger
// existed, up to limit per call, and reports how many it enrolled and how many
// are still waiting.
//
// This is the migration path for the objects already on disk. It runs in ONE
// bolt transaction rather than one per object: a node with 11k objects would
// otherwise pay 11k fsyncs, and doing it a handful at a time (the shape the old
// backfill used) would take days to even notice the backlog exists.
func (s *Store) EnrolMissingPlacements(limit int) (enrolled int, pending int, err error) {
	if limit <= 0 {
		limit = 1
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		placements := tx.Bucket(bucketPlacement)
		index := tx.Bucket(bucketPlacementIndex)
		return tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return nil
			}
			if manifest.ObjectID == "" || placements.Get([]byte(manifest.ObjectID)) != nil {
				return nil
			}
			if enrolled >= limit {
				pending++
				return nil
			}
			row := ObjectPlacement{
				ObjectID: manifest.ObjectID, Bucket: manifest.Bucket, Key: manifest.Key,
				DataShards: manifest.DataShards, ParityShards: manifest.ParityShards,
				UpdatedAt: time.Now().UTC(),
			}
			for _, chunk := range manifest.Chunks {
				for _, ref := range chunk.Shards {
					row.Shards = append(row.Shards, ShardPlacement{
						ShardID: ref.ID, ChunkIndex: chunk.Index, ShardIndex: ref.Index,
						Size: int64(ref.Size), Local: true,
					})
				}
			}
			encoded, marshalErr := json.Marshal(row)
			if marshalErr != nil {
				return nil
			}
			if err := placements.Put([]byte(row.ObjectID), encoded); err != nil {
				return err
			}
			for _, shard := range row.Shards {
				if err := index.Put([]byte(shard.ShardID), []byte(row.ObjectID)); err != nil {
					return err
				}
			}
			enrolled++
			return nil
		})
	})
	return enrolled, pending, err
}

// LoadObjectPlacement returns the ledger row for an object.
func (s *Store) LoadObjectPlacement(objectID string) (*ObjectPlacement, error) {
	var row ObjectPlacement
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketPlacement).Get([]byte(objectID))
		if value == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(value, &row)
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// updatePlacement is the single mutation path, so every change is one
// read-modify-write inside one bolt transaction and concurrent confirmations
// from parallel shard pushes cannot lose one another.
func (s *Store) updatePlacement(objectID string, mutate func(*ObjectPlacement) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		placements := tx.Bucket(bucketPlacement)
		value := placements.Get([]byte(objectID))
		if value == nil {
			return os.ErrNotExist
		}
		var row ObjectPlacement
		if err := json.Unmarshal(value, &row); err != nil {
			return err
		}
		if err := mutate(&row); err != nil {
			return err
		}
		row.UpdatedAt = time.Now().UTC()
		encoded, err := json.Marshal(row)
		if err != nil {
			return err
		}
		return placements.Put([]byte(objectID), encoded)
	})
}

// ConfirmShardHolder records that a peer acknowledged storing a shard. Called
// ONLY after the peer replied ok — the old code recorded success before the
// stream was even opened.
func (s *Store) ConfirmShardHolder(objectID, shardID, peerID string) error {
	if peerID == "" {
		return errors.New("empty holder")
	}
	return s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		for i := range row.Shards {
			if row.Shards[i].ShardID != shardID {
				continue
			}
			for _, existing := range row.Shards[i].Holders {
				if existing == peerID {
					return nil
				}
			}
			row.Shards[i].Holders = append(row.Shards[i].Holders, peerID)
		}
		return nil
	})
}

// DropShardHolder forgets a holder that no longer has the shard — it answered
// "have" with false, or has been unreachable across several consecutive audits.
// This is what turns a node dropping out into a repairable deficit instead of a
// permanent lie in the ledger.
func (s *Store) DropShardHolder(objectID, shardID, peerID string) error {
	return s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		for i := range row.Shards {
			if row.Shards[i].ShardID != shardID {
				continue
			}
			kept := row.Shards[i].Holders[:0]
			for _, existing := range row.Shards[i].Holders {
				if existing != peerID {
					kept = append(kept, existing)
				}
			}
			row.Shards[i].Holders = append([]string(nil), kept...)
			// The silence count judged a holder that is no longer recorded, so
			// it must go with it: a peer that comes back and is placed here
			// again starts from zero rather than one probe from eviction.
			delete(row.Shards[i].Silences, peerID)
			if len(row.Shards[i].Silences) == 0 {
				row.Shards[i].Silences = nil
			}
		}
		return nil
	})
}

// NoteHolderSilence records ONE audit in which a holder did not answer, and
// returns how many consecutive audits it has now missed. The caller decides
// what the count is worth; the ledger only remembers.
func (s *Store) NoteHolderSilence(objectID, shardID, peerID string) (int, error) {
	silences := 0
	err := s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		for i := range row.Shards {
			if row.Shards[i].ShardID != shardID {
				continue
			}
			holds := false
			for _, existing := range row.Shards[i].Holders {
				if existing == peerID {
					holds = true
					break
				}
			}
			if !holds {
				continue
			}
			if row.Shards[i].Silences == nil {
				row.Shards[i].Silences = make(map[string]int, 1)
			}
			row.Shards[i].Silences[peerID]++
			if row.Shards[i].Silences[peerID] > silences {
				silences = row.Shards[i].Silences[peerID]
			}
		}
		return nil
	})
	return silences, err
}

// NoteHolderAnswered clears a holder's silence count. A holder is dropped only
// for CONSECUTIVE silences, so one answer has to wipe the record: a node that
// is unreachable one evening a month must never accumulate its way to eviction.
func (s *Store) NoteHolderAnswered(objectID, shardID, peerID string) error {
	return s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		for i := range row.Shards {
			if row.Shards[i].ShardID != shardID {
				continue
			}
			if _, counted := row.Shards[i].Silences[peerID]; !counted {
				continue
			}
			delete(row.Shards[i].Silences, peerID)
			if len(row.Shards[i].Silences) == 0 {
				row.Shards[i].Silences = nil
			}
		}
		return nil
	})
}

// HolderSilences reports a holder's consecutive-silence count, for the audit
// log and for tests.
func (p ObjectPlacement) HolderSilences(shardID, peerID string) int {
	for _, shard := range p.Shards {
		if shard.ShardID == shardID {
			return shard.Silences[peerID]
		}
	}
	return 0
}

// HoldsSiblingShard reports whether a peer is already recorded as holding a
// DIFFERENT shard of the same chunk.
//
// This is the last gate in front of a push, and it is deliberately a question
// about the ledger rather than about a plan. The planner refuses to put two
// shards of a chunk on one node, but a plan is a snapshot: two placement rounds
// overlapping on the same object (a PUT-time dispersal, the replicate pass and
// the repair pass are three separate goroutines) each computed theirs before
// the other's confirmations landed. Asking again, immediately before the bytes
// go out, is what turns the planner's per-call guarantee into a property of the
// object.
//
// "Different" is by content address, not by index: a chunk of uniform bytes
// produces several indexes with the SAME shard id, and a peer already holding
// those bytes is not made any more co-located by being asked for them again.
func (s *Store) HoldsSiblingShard(objectID, shardID, peerID string) bool {
	row, err := s.LoadObjectPlacement(objectID)
	if err != nil {
		return false
	}
	chunks := make(map[int]bool)
	for _, shard := range row.Shards {
		if shard.ShardID == shardID {
			chunks[shard.ChunkIndex] = true
		}
	}
	for _, shard := range row.Shards {
		if !chunks[shard.ChunkIndex] || shard.ShardID == shardID {
			continue
		}
		for _, holder := range shard.Holders {
			if holder == peerID {
				return true
			}
		}
	}
	return false
}

// SetShardLocal records whether this node still holds the bytes itself.
func (s *Store) SetShardLocal(objectID, shardID string, local bool) error {
	return s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		for i := range row.Shards {
			if row.Shards[i].ShardID == shardID {
				row.Shards[i].Local = local
			}
		}
		return nil
	})
}

// MarkPlacementAttempt stamps the object as just worked on. The rate limit
// lives here rather than in the caller because it has to survive a restart:
// an in-memory cooldown resets on every crash loop, which is exactly when a
// repair storm is least affordable.
func (s *Store) MarkPlacementAttempt(objectID string) error {
	return s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		row.LastAttempt = time.Now().UTC()
		row.Attempts++
		return nil
	})
}

// HoldersForShard returns the peers the ledger believes hold a shard, for the
// read path to try first. Empty (not an error) when the shard is unknown.
func (s *Store) HoldersForShard(shardID string) []string {
	var holders []string
	_ = s.db.View(func(tx *bolt.Tx) error {
		objectID := tx.Bucket(bucketPlacementIndex).Get([]byte(shardID))
		if objectID == nil {
			return nil
		}
		value := tx.Bucket(bucketPlacement).Get(objectID)
		if value == nil {
			return nil
		}
		var row ObjectPlacement
		if err := json.Unmarshal(value, &row); err != nil {
			return nil
		}
		for _, shard := range row.Shards {
			if shard.ShardID == shardID {
				holders = append(holders, shard.Holders...)
			}
		}
		return nil
	})
	return holders
}

// DispersalCandidates returns objects that still need work, least-recently
// attempted first, skipping anything attempted inside cooldown.
//
// under-replicated objects come first: an object with zero remote shards is a
// single disk away from gone, while one sitting at 7 of 9 is only short of its
// full loss tolerance.
func (s *Store) DispersalCandidates(limit int, cooldown time.Duration) ([]ObjectPlacement, error) {
	return s.placementCandidates(limit, cooldown, true)
}

// AuditCandidates returns objects due for a repair audit, INCLUDING ones that
// currently look perfect.
//
// This is not the same set as DispersalCandidates and the difference is the
// whole point of repair. A fully dispersed object has nothing left to place, so
// the dispersal queue is right to skip it -- but "fully dispersed" is a record
// of what peers confirmed in the past, and the event repair exists to catch is
// precisely one of those peers going away. Auditing only the objects that
// already look broken would mean a healthy object silently decays to zero
// holders and nothing ever asks.
func (s *Store) AuditCandidates(limit int, cooldown time.Duration) ([]ObjectPlacement, error) {
	return s.placementCandidates(limit, cooldown, false)
}

func (s *Store) placementCandidates(limit int, cooldown time.Duration, onlyIncomplete bool) ([]ObjectPlacement, error) {
	if limit <= 0 {
		return nil, nil
	}
	cutoff := time.Now().UTC().Add(-cooldown)
	var rows []ObjectPlacement
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPlacement).ForEach(func(_, value []byte) error {
			var row ObjectPlacement
			if err := json.Unmarshal(value, &row); err != nil {
				return nil
			}
			if onlyIncomplete && row.FullyDispersed() {
				return nil
			}
			if !row.LastAttempt.IsZero() && row.LastAttempt.After(cutoff) {
				return nil
			}
			rows = append(rows, row)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i].UnderReplicated(), rows[j].UnderReplicated()
		if left != right {
			return left
		}
		return rows[i].LastAttempt.Before(rows[j].LastAttempt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// PlacementSummary is what the management page and the logs report, so a node
// never states a durability it does not have.
type PlacementSummary struct {
	Objects         int `json:"objects"`
	UnderReplicated int `json:"under_replicated"`
	FullyDispersed  int `json:"fully_dispersed"`
	LocalOnly       int `json:"local_only"`
}

// PlacementStatus summarises the ledger.
func (s *Store) PlacementStatus() (PlacementSummary, error) {
	var summary PlacementSummary
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPlacement).ForEach(func(_, value []byte) error {
			var row ObjectPlacement
			if err := json.Unmarshal(value, &row); err != nil {
				return nil
			}
			summary.Objects++
			switch {
			case row.FullyDispersed():
				summary.FullyDispersed++
			case row.WeakestChunk() == 0:
				summary.LocalOnly++
			}
			if row.UnderReplicated() {
				summary.UnderReplicated++
			}
			return nil
		})
	})
	return summary, err
}

// PutRegeneratedShard stores shard bytes rebuilt by the repair loop.
//
// Separate from PutRemoteShard because a regenerated shard is NOT a shard this
// node is holding on somebody else's behalf: it belongs to an object this node
// owns, it is already referenced by that object's manifest, and giving it a
// remote_shards row would pin it against removeUnreferenced forever. The
// content-address check is the same one every other write path performs, so a
// reconstruction that produced the wrong bytes is refused rather than stored.
func (s *Store) PutRegeneratedShard(shardID string, value []byte) error {
	if s.IsRejected("shard", shardID) {
		return errors.New("shard is rejected by this node")
	}
	return s.writeShard(shardID, value)
}

// ForgetPlacement drops the ledger rows for an object that no longer exists.
func (s *Store) ForgetPlacement(objectID string) error { return s.forgetPlacement(objectID) }

// forgetPlacement removes the ledger rows for a deleted object.
func (s *Store) forgetPlacement(objectID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		placements := tx.Bucket(bucketPlacement)
		value := placements.Get([]byte(objectID))
		if value == nil {
			return nil
		}
		var row ObjectPlacement
		if err := json.Unmarshal(value, &row); err == nil {
			index := tx.Bucket(bucketPlacementIndex)
			for _, shard := range row.Shards {
				// Only drop the index entry if it still points at this object;
				// content-addressed shards are shared between objects.
				if current := index.Get([]byte(shard.ShardID)); current != nil &&
					string(current) == objectID {
					if err := index.Delete([]byte(shard.ShardID)); err != nil {
						return err
					}
				}
			}
		}
		return placements.Delete([]byte(objectID))
	})
}
