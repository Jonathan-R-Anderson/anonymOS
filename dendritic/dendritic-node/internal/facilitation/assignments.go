package facilitation

import (
	"encoding/hex"
	"sort"
)

// What this node claims to be storing.
//
// Assignments are self-reported, which sounds like a hole and is not: the claim
// is only ever a liability. Claiming a shard you do not hold earns nothing —
// the challenge derives unpredictable chunks and the proof fails. Omitting one
// you do hold earns nothing either, because unchallenged work is unpaid. The
// incentive therefore points at reporting exactly what you have, and no
// signature over the list is needed to make that true.
//
// What a node must NOT be able to do is choose the shard root, which is why the
// root is recomputed from the bytes on disk rather than taken from a manifest.

// ShardReader is the slice of the store this needs — kept narrow so the
// assignment logic can be tested without one.
type ShardReader interface {
	ListShardIDs() ([]string, error)
	ReadShard(id string) ([]byte, error)
}

// AssignmentChunkSize is the chunking every node commits to. It has to be
// identical network-wide: a different size yields a different root for the same
// bytes, and the proof would be rejected as if the data were wrong.
const AssignmentChunkSize = 4096

// LocalAssignments enumerates the shards this node holds, with the Merkle root
// each will be audited against.
//
// Roots are computed from the stored bytes, so a shard that has rotted produces
// a root that will not match what the network expects — surfacing corruption as
// a failed audit rather than silently proving the wrong data.
func LocalAssignments(nodeID [32]byte, store ShardReader) ([]Assignment, error) {
	ids, err := store.ListShardIDs()
	if err != nil {
		return nil, err
	}
	sort.Strings(ids) // stable order so two runs agree
	out := make([]Assignment, 0, len(ids))
	for _, id := range ids {
		assignmentID, err := ShardIDToAssignment(id)
		if err != nil {
			continue // not a shard id we can address; skip rather than abort
		}
		data, err := store.ReadShard(id)
		if err != nil {
			// Listed but unreadable: do not advertise it. Claiming a shard we
			// cannot read would guarantee a failed audit.
			continue
		}
		chunks, leaves := ChunkShard(data, AssignmentChunkSize)
		out = append(out, Assignment{
			NodeID:       nodeID,
			AssignmentID: assignmentID,
			ShardRoot:    BuildTree(leaves).Root,
			NumChunks:    len(chunks),
			Bytes:        uint64(len(data)),
		})
	}
	return out, nil
}

// ShardIDToAssignment converts the store's 64-hex shard id into the 32-byte
// assignment id used on the wire and in receipts.
func ShardIDToAssignment(shardID string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(shardID)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, errInvalidShardID
	}
	copy(out[:], raw)
	return out, nil
}

// AssignmentToShardID is the inverse, for looking a challenge back up in the
// store.
func AssignmentToShardID(a [32]byte) string { return hex.EncodeToString(a[:]) }

var errInvalidShardID = &shardIDError{}

type shardIDError struct{}

func (e *shardIDError) Error() string { return "facilitation: shard id is not 32 bytes" }

// StoreShardLoader adapts a store to the loader the challenge responder needs.
func StoreShardLoader(store ShardReader) ShardLoader {
	return func(assignmentID [32]byte) ([]byte, int, bool) {
		data, err := store.ReadShard(AssignmentToShardID(assignmentID))
		if err != nil {
			return nil, 0, false
		}
		return data, AssignmentChunkSize, true
	}
}

// MaxAdvertisedAssignments bounds one advertisement.
//
// A node holding thousands of shards used to advertise every one of them, which
// the relay refused outright — so it advertised NOTHING, and a node with the
// most to prove was the one that could prove none of it. The relay's limit is
// the real constraint; this stays under it.
//
// Advertising a subset costs nothing in the long run because the subset
// ROTATES: over enough epochs every shard takes its turn. What it must not do
// is rotate randomly, or a node could re-roll until it advertised only the
// shards it still has.
const MaxAdvertisedAssignments = 1000

// AdvertisableAssignments returns the window of assignments to publish this
// epoch.
//
// The window walks forward one full stride per epoch over a canonically-ordered
// list, so coverage is complete, deterministic, and not something the node
// chooses. A node holding fewer than the cap advertises everything, every time.
func AdvertisableAssignments(all []Assignment, epoch uint64) []Assignment {
	if len(all) <= MaxAdvertisedAssignments {
		return all
	}
	// LocalAssignments already sorts by shard id; sorting here too keeps this
	// correct for any caller and costs nothing on an already-sorted slice.
	ordered := make([]Assignment, len(all))
	copy(ordered, all)
	sort.Slice(ordered, func(i, j int) bool {
		return lessAssignmentID(ordered[i].AssignmentID, ordered[j].AssignmentID)
	})

	start := int((epoch * uint64(MaxAdvertisedAssignments)) % uint64(len(ordered)))
	out := make([]Assignment, 0, MaxAdvertisedAssignments)
	for i := 0; i < MaxAdvertisedAssignments; i++ {
		out = append(out, ordered[(start+i)%len(ordered)])
	}
	return out
}

func lessAssignmentID(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
