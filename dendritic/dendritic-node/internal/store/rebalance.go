package store

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
)

// THE LEDGER SIDE OF LEVELLING
// ============================
// Two things the mover needs that nothing else does: a queue of objects it is
// allowed to level, and a memory of where it has just moved a shard AWAY from.
//
// Both are persisted rather than held in memory, for the reason RepairStored
// already gives: an in-memory cooldown resets on every crash loop, and a crash
// loop is exactly when a storm is least affordable.

// RebalanceCandidates returns objects the levelling mover may work on, least
// recently levelled first, skipping anything levelled inside cooldown.
//
// THIS IS WHERE "NEVER REBALANCE WHILE UNDER-REPLICATED" IS ENFORCED FIRST.
// Getting an object to the durability threshold always beats levelling one that
// is already there, so an under-replicated row never enters the queue at all --
// it belongs to dispersal and repair, which run more often and take priority.
// The mover re-checks the same condition under its per-object lock before it
// moves anything, because this queue is read once per pass and a holder can
// vanish while the pass is still running.
//
// An object with no remote holder is skipped for the same reason from the other
// direction: there is nothing on any peer to move.
func (s *Store) RebalanceCandidates(limit int, cooldown time.Duration) ([]ObjectPlacement, error) {
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
			if row.UnderReplicated() {
				return nil
			}
			if !row.LastRebalance.IsZero() && row.LastRebalance.After(cutoff) {
				return nil
			}
			if !row.HasRemoteHolder() {
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
		return rows[i].LastRebalance.Before(rows[j].LastRebalance)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// HasRemoteHolder reports whether any shard of the object sits on a peer.
func (p ObjectPlacement) HasRemoteHolder() bool {
	for _, shard := range p.Shards {
		if len(shard.Holders) > 0 {
			return true
		}
	}
	return false
}

// MarkRebalanceAttempt stamps the object as just levelled, on its own clock so
// the mover cannot delay a repair audit.
func (s *Store) MarkRebalanceAttempt(objectID string) error {
	return s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		row.LastRebalance = time.Now().UTC()
		row.Rebalances++
		return nil
	})
}

// ChunkHasDurabilityMargin reports whether a chunk has more distinct holders
// than durability requires -- the only chunks levelling may touch.
//
// STRICTLY ABOVE THE THRESHOLD, not at it. A chunk sitting on exactly
// DurableRemoteHolders distinct peers is durable and nothing more. The move
// itself would be safe in the ordinary case, because the destination is counted
// before the source is dropped -- but the WINDOW is not: a crash, a coordinator
// outage or a failed delete between the two leaves an arrangement nobody
// re-checked until the next audit, and tidying is never worth spending the last
// margin an object has. An object that is durable but not yet fully dispersed
// still belongs to dispersal, which runs twelve times as often.
func (p ObjectPlacement) ChunkHasDurabilityMargin(chunkIndex int) bool {
	shards := p.PlacementSnapshot(chunkIndex)
	if len(shards) == 0 {
		return false
	}
	return placement.DistinctHolders(shards) > DurableRemoteHolders(p.DataShards, p.ParityShards)
}

// MovableChunkShards returns the shards of one chunk that levelling is allowed
// to move off `from`. Empty when the chunk has no durability margin to spend.
//
// The margin test is the LEVELLING policy over ChunkShardsHeldBy's enumeration,
// and draining deliberately applies a different one: see ChunkShardsHeldBy.
func (p ObjectPlacement) MovableChunkShards(chunkIndex int, from string) []placement.Shard {
	if !p.ChunkHasDurabilityMargin(chunkIndex) {
		return nil
	}
	return p.ChunkShardsHeldBy(chunkIndex, from)
}

// SurvivesLosingHolder reports whether one chunk would still be durable if a
// peer stopped holding one shard of it -- the question that authorises the
// delete half of a move.
//
// Both halves of ChunkIsDurable are re-asked against the projected arrangement,
// through the same helpers, so this is the existing durability rule applied to
// a hypothetical rather than a second rule that happens to agree today.
func (p ObjectPlacement) SurvivesLosingHolder(chunkIndex int, shardID, peerID string) bool {
	after := placement.WithoutHolder(p.PlacementSnapshot(chunkIndex), shardID, peerID)
	if placement.DistinctHolders(after) < DurableRemoteHolders(p.DataShards, p.ParityShards) {
		return false
	}
	return placement.SurvivesHolderLosses(after, p.DataShards, 1)
}

// ChunkIndexOfShard returns the chunk a shard belongs to, and whether it was
// found. A content-addressed shard can appear in more than one chunk of the
// same object; the first is enough, because the caller asks only about the
// chunk it is currently levelling.
func (p ObjectPlacement) ChunkIndexOfShard(shardID string) (int, bool) {
	for _, shard := range p.Shards {
		if shard.ShardID == shardID {
			return shard.ChunkIndex, true
		}
	}
	return 0, false
}

// HolderOfShard reports whether the ledger records a peer as holding a shard.
func (p ObjectPlacement) HolderOfShard(shardID, peerID string) bool {
	for _, shard := range p.Shards {
		if shard.ShardID != shardID {
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

// movedAwayKey scopes the memory to one object, one shard and one peer, which
// is exactly the scope of the refusal it mirrors on the holder.
func movedAwayKey(objectID, shardID, peerID string) []byte {
	return []byte("moved\x00" + objectID + "\x00" + shardID + "\x00" + peerID)
}

// NoteShardMovedAway remembers that levelling recalled this shard from this
// peer, for as long as that peer will refuse it.
//
// WHY THE MOVER HAS TO REMEMBER ITS OWN RECALLS
// ---------------------------------------------
// DeleteRemoteShard makes the holder refuse this object's copy of this shard
// for recallRefusalTTL (see refuseRecalledShard). That refusal is right and must
// stay: it is the only thing that stops the owner's five-minute replicate loop
// from undoing an operator's delete. But it means the peer levelling just took
// a shard off will answer "recalled recently" if placement offers it the same
// shard again inside the window -- and answeredNo counts that as a refusal, so
// three of them drop an otherwise healthy volunteer out of every candidate set
// for half an hour. The mover would be locking itself, and repair, out of a
// peer because of a refusal it caused.
//
// The alternative -- teaching the holder to skip the refusal when the recall is
// a rebalance -- would mean a new field inside the coordinator-signed revocation
// message (a wire break in both directions, and a change to the one destructive
// verb this project has already had adversarially reviewed), and it would weaken
// the purge case, where the refusal is load-bearing. So the knowledge stays on
// the owner, where it costs nothing and is enforced before a lease is spent:
// placeOne consults it, so dispersal, repair and levelling all decline to send a
// shard to a peer that is going to refuse it.
func (s *Store) NoteShardMovedAway(objectID, shardID, peerID string) error {
	if !IsContentID(shardID) {
		return errors.New("invalid shard ID")
	}
	if objectID == "" || peerID == "" {
		return errors.New("a moved-away record needs an object and a peer")
	}
	deadline := time.Now().UTC().Add(recallRefusalTTL).Format(time.RFC3339Nano)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDenied).Put(movedAwayKey(objectID, shardID, peerID), []byte(deadline))
	})
}

// ShardMovedAwayFrom reports whether levelling took this shard off this peer
// recently enough that the peer is still refusing it.
//
// Fails OPEN, like RecallRefused: an unparseable or elapsed deadline means "go
// ahead and place it". The worst an over-eager placement costs is one refused
// push; refusing forever would quietly shrink the candidate set.
func (s *Store) ShardMovedAwayFrom(objectID, shardID, peerID string) bool {
	var recent bool
	_ = s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketDenied).Get(movedAwayKey(objectID, shardID, peerID))
		if raw == nil {
			return nil
		}
		deadline, err := time.Parse(time.RFC3339Nano, string(raw))
		if err != nil {
			return nil
		}
		recent = time.Now().UTC().Before(deadline)
		return nil
	})
	return recent
}
