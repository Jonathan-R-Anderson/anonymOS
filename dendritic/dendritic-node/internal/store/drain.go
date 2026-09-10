package store

import (
	"encoding/json"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
)

// THE LEDGER SIDE OF DRAINING
// ===========================
// Levelling asks "who is holding more than their share". Draining asks a
// narrower and more urgent question: "which of my objects still have a shard on
// the machine that is being switched off". The answer needs its own queue, its
// own clock and its own report, and each of those differs from levelling's in a
// way that is worth stating rather than inheriting by accident.

// DrainCandidates returns objects with at least one shard recorded on a peer
// that is leaving, least recently drained first, skipping anything attempted
// inside cooldown.
//
// THREE DELIBERATE DIFFERENCES FROM RebalanceCandidates
// -----------------------------------------------------
//  1. UNDER-REPLICATED OBJECTS ARE INCLUDED. Levelling skips them because
//     tidying an object that still owes the network a holder is work taken from
//     the loop trying to make it whole. Draining is the opposite case: the
//     holder is going away whether or not anything is done about it, so an
//     object that is already short is the one the operator most needs told
//     about. It still will not be MOVED -- the per-chunk durability gate in the
//     mover refuses that -- it is queued so it can be REPORTED. An unmovable
//     shard nobody counts is how a drain "finishes" with data on a machine that
//     is about to be unplugged.
//  2. THE CLOCK IS ITS OWN. LastDrain, not LastAttempt and not LastRebalance:
//     stamping either of the others would let a drain push an object's repair
//     audit hours into the future, or let a levelling pass a day ago hide an
//     object from a drain happening now.
//  3. THE COOLDOWN IS SHORT, because somebody is waiting to power a machine off.
//     Levelling's is a day; the drain's is minutes.
//
// The clock is persisted for the reason every other cooldown here is: a drain
// runs for hours, the process WILL be restarted inside it (that is what the
// operator is preparing to do), and an in-memory position would restart at the
// top of the bucket every time -- re-examining the same first N objects forever
// while the tail of the ledger is never reached.
func (s *Store) DrainCandidates(leaving map[string]bool, limit int, cooldown time.Duration) ([]ObjectPlacement, error) {
	if limit <= 0 || len(leaving) == 0 {
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
			if !row.HeldByAny(leaving) {
				return nil
			}
			if !row.LastDrain.IsZero() && row.LastDrain.After(cutoff) {
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
		return rows[i].LastDrain.Before(rows[j].LastDrain)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// HeldByAny reports whether any shard of the object sits on one of these peers.
func (p ObjectPlacement) HeldByAny(peers map[string]bool) bool {
	for _, shard := range p.Shards {
		for _, holder := range shard.Holders {
			if peers[holder] {
				return true
			}
		}
	}
	return false
}

// MarkDrainAttempt stamps the object as just examined by the drain, on its own
// clock so the drain cannot delay a repair audit or hide behind a levelling one.
func (s *Store) MarkDrainAttempt(objectID string) error {
	return s.updatePlacement(objectID, func(row *ObjectPlacement) error {
		row.LastDrain = time.Now().UTC()
		row.Drains++
		return nil
	})
}

// ChunkShardsHeldBy returns the shards of one chunk that a peer holds.
//
// UNCONDITIONAL, unlike MovableChunkShards: this is the enumeration, not the
// policy. Levelling layers "and only if the chunk has margin to spare" on top;
// draining must not, because the source is leaving and the margin goes with it.
// One enumeration with two policies over it, rather than two enumerations that
// have to be kept in step.
func (p ObjectPlacement) ChunkShardsHeldBy(chunkIndex int, from string) []placement.Shard {
	var held []placement.Shard
	for _, shard := range p.PlacementSnapshot(chunkIndex) {
		for _, holder := range shard.Holders {
			if holder == from {
				held = append(held, shard)
				break
			}
		}
	}
	return held
}

// DrainRemaining is how much of this node's ledger still names peers that are
// leaving. It is the operator's "is it safe to switch off yet" number, taken
// from the OWNER's side of the wire.
type DrainRemaining struct {
	Objects int   `json:"objects"`
	Shards  int   `json:"shards"`
	Bytes   int64 `json:"bytes"`
}

// ShardsRecordedOn counts what the ledger still places on the leaving peers.
//
// A full scan per pass, deliberately: the alternative is a running counter, and
// a counter that drifts is worse than no counter here -- it would let a drain
// report "nothing left" while shards sat on a machine somebody then unplugged.
func (s *Store) ShardsRecordedOn(peers map[string]bool) (DrainRemaining, error) {
	var out DrainRemaining
	if len(peers) == 0 {
		return out, nil
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPlacement).ForEach(func(_, value []byte) error {
			var row ObjectPlacement
			if err := json.Unmarshal(value, &row); err != nil {
				return nil
			}
			counted := false
			for _, shard := range row.Shards {
				for _, holder := range shard.Holders {
					if !peers[holder] {
						continue
					}
					out.Shards++
					out.Bytes += shard.Size
					if !counted {
						out.Objects++
						counted = true
					}
				}
			}
			return nil
		})
	})
	return out, err
}

// HeldForOthers is the DRAINING node's own view of the same question: how much
// of its disk is other peers' shards.
//
// Counted from the remote_shards rows rather than from a walk of the shard
// tree, because the shard tree also holds this node's OWN objects and those are
// not what a drain moves -- they are lost with the machine or they were already
// recoverable without it, which is a different sentence in the report.
//
// This is the number that reaches zero. The owner-side count above is what each
// owner still believes; this is what is actually on the disk, and an operator
// standing at the machine should trust the disk.
func (s *Store) HeldForOthers() (DrainRemaining, error) {
	var out DrainRemaining
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRemote).ForEach(func(_, value []byte) error {
			var shard RemoteShard
			if err := json.Unmarshal(value, &shard); err != nil {
				// Counted, not skipped. An unreadable row is a shard this node
				// cannot account for, and rounding it down to zero is exactly how
				// a drain reports "finished" over bytes it still has.
				out.Shards++
				return nil
			}
			out.Shards++
			out.Bytes += shard.Size
			return nil
		})
	})
	return out, err
}
