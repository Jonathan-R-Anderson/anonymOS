package placement

import "sort"

// LEVELLING THE POOLS
// ===================
// Plan (above) answers "where does this shard go", once, at write time. It
// never revisits the decision, so a node that joined early accumulates while a
// node that joined tonight stays empty, and two peers were already refusing
// shards with "storage capacity exceeded" while six machines sat almost idle.
//
// This half answers the other question: given what every node is HOLDING right
// now, how much should leave each one. It is deliberately pure -- no store, no
// libp2p, no ledger -- because the arithmetic is where a levelling loop goes
// wrong (a target that never converges, a deadband that lets two nodes trade a
// megabyte forever) and that is testable without a network.
//
// It is the Go twin of backend/services/pool_levelling.py, which computes the
// same target for the admin panel's read-only report. The node computes its own
// rather than asking the site: the site's copy is a report, and a mover that
// depended on it would stop levelling whenever the site was unreachable and
// would be moving bytes on the strength of a number it cannot verify.
//
// EQUAL BYTES, NOT EQUAL PERCENTAGE
// ---------------------------------
// The target is the same absolute byte count on every node, not the same
// fraction of each node's capacity. Durability here is counted in DISTINCT
// HOLDERS (see DurableRemoteHolders), so a 20 GB volunteer buys a holder-slot
// exactly as cheaply as a 200 GB one; levelling by percentage would send ten
// times as much to the big node and concentrate the network on the machines
// whose loss hurts most. Filling small pools first is the durability-maximising
// choice, not merely the fair-seeming one.

const (
	// LevelDeadband is how far from the target a node may sit before anything
	// moves. Without it two nodes a megabyte apart trade shards forever, and
	// every trade costs a coordinator lease, two I2P round trips and a delete.
	//
	// Same value as pool_levelling.DEADBAND so the node and the site's report
	// agree about who is fat; an operator comparing the two must not see one
	// call a node balanced and the other call it a source.
	LevelDeadband = 0.10
	// MinLevelMove is the floor under the deadband. Ten percent of a nearly
	// empty pool is a few kilobytes, which would make a young network churn
	// over nothing.
	MinLevelMove int64 = 64 << 20
)

// Pool is one node's storage occupancy, as levelling sees it.
//
// Used must come from MEASURED usage -- the node's own walk of its shard tree,
// or the free/capacity pair a peer publishes from its own measurement. It must
// never be derived by summing the placement ledger: the ledger records intent
// and the disk records fact, they diverge on a failed delete or a manual
// removal, and levelling toward a fiction moves real bytes.
type Pool struct {
	PeerID   string
	Used     int64
	Capacity int64
}

// Headroom is what this pool can still accept.
func (p Pool) Headroom() int64 {
	free := p.Capacity - p.Used
	if free < 0 {
		return 0
	}
	return free
}

// Role is what levelling wants a node to do.
type Role string

const (
	// RoleBalanced: inside the deadband. Does nothing, receives nothing.
	RoleBalanced Role = "balanced"
	// RoleSource: holds more than the target by more than the deadband.
	RoleSource Role = "source"
	// RoleSink: holds less than the target by more than the deadband, and has
	// room.
	RoleSink Role = "sink"
)

// PoolStatus is one node's position relative to the target.
type PoolStatus struct {
	Pool
	// Target is this node's own target: the fleet target, capped at its
	// capacity, so a small volunteer is not permanently "behind".
	Target int64
	// Delta is Used-Target. Positive is surplus, negative is deficit.
	Delta int64
	// Band is the deadband applied to this node, in bytes.
	Band int64
	Role Role
}

// Levelling is one snapshot of the fleet's occupancy and what it implies.
type Levelling struct {
	// Target is the byte count every node with room for it should converge on.
	Target int64
	// Nodes is every pool in the levelling set, largest surplus first.
	Nodes []PoolStatus
}

// LevelPools computes the target and each node's role.
//
// Pools with no capacity are dropped: a gateway or a probe donates no disk, and
// a peer whose capacity record has not arrived is UNKNOWN rather than empty.
// Reading "has not reported" as "holds nothing" would aim every surplus byte at
// a node that merely runs an older build -- the same mistake the site's report
// avoids by excluding a NULL used_bytes.
func LevelPools(pools []Pool) Levelling {
	usable := make([]Pool, 0, len(pools))
	for _, pool := range pools {
		if pool.PeerID == "" || pool.Capacity <= 0 {
			continue
		}
		if pool.Used < 0 {
			pool.Used = 0
		}
		usable = append(usable, pool)
	}
	out := Levelling{Target: LevelTarget(usable)}
	for _, pool := range usable {
		target := out.Target
		if pool.Capacity < target {
			// A node at its configured capacity leaves the levelling set rather
			// than becoming a permanent deficit that can never be closed.
			target = pool.Capacity
		}
		status := PoolStatus{Pool: pool, Target: target, Delta: pool.Used - target}
		status.Band = int64(float64(target) * LevelDeadband)
		if status.Band < MinLevelMove {
			status.Band = MinLevelMove
		}
		switch {
		case status.Delta > status.Band:
			status.Role = RoleSource
		case -status.Delta > status.Band:
			// Headroom needs no separate test: the target is already capped at
			// this node's capacity, so a node below its target by more than the
			// deadband has at least that much room by construction.
			status.Role = RoleSink
		default:
			status.Role = RoleBalanced
		}
		out.Nodes = append(out.Nodes, status)
	}
	sort.SliceStable(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Delta != out.Nodes[j].Delta {
			return out.Nodes[i].Delta > out.Nodes[j].Delta
		}
		return out.Nodes[i].PeerID < out.Nodes[j].PeerID
	})
	return out
}

// LevelTarget is the byte count every node should converge on: the mean, except
// that a node cannot exceed its own capacity. Any node whose capacity sits below
// the mean is pinned to its capacity and the remainder is shared among the rest,
// which is what makes the plan converge instead of forever chasing a 10 GB node
// toward a 4 TB one's share.
func LevelTarget(pools []Pool) int64 {
	if len(pools) == 0 {
		return 0
	}
	var remaining int64
	open := make([]Pool, 0, len(pools))
	for _, pool := range pools {
		remaining += pool.Used
		open = append(open, pool)
	}
	var pinned int64
	for len(open) > 0 {
		share := (remaining - pinned) / int64(len(open))
		kept := open[:0]
		capped := false
		for _, pool := range open {
			if pool.Capacity < share {
				pinned += pool.Capacity
				capped = true
				continue
			}
			kept = append(kept, pool)
		}
		if !capped {
			return share
		}
		open = append([]Pool(nil), kept...)
	}
	// Every node is at or over its capacity, so there is no share to compute
	// and nothing this mover can do about it. Zero means "no target", and every
	// node then reads as balanced rather than as a source with nowhere to send.
	return 0
}

// Sources are the nodes holding more than the target, fattest first.
func (l Levelling) Sources() []PoolStatus { return l.withRole(RoleSource) }

// Sinks are the nodes holding less than the target and able to take more,
// emptiest first.
func (l Levelling) Sinks() []PoolStatus {
	sinks := l.withRole(RoleSink)
	sort.SliceStable(sinks, func(i, j int) bool { return sinks[i].Delta < sinks[j].Delta })
	return sinks
}

func (l Levelling) withRole(role Role) []PoolStatus {
	var out []PoolStatus
	for _, node := range l.Nodes {
		if node.Role == role {
			out = append(out, node)
		}
	}
	return out
}

// WithoutHolder returns the chunk as it would stand if one peer stopped holding
// one shard of it.
//
// The mover uses it to answer the only question that authorises a delete: would
// this chunk still be durable with the source gone. Expressed as a
// transformation of the snapshot rather than as arithmetic on a holder count,
// so the answer comes from the SAME DistinctHolders and SurvivesHolderLosses
// the rest of the system judges durability with. A second implementation of a
// durability rule is a second chance to get it wrong.
func WithoutHolder(shards []Shard, shardID, peerID string) []Shard {
	out := make([]Shard, len(shards))
	for i, shard := range shards {
		out[i] = shard
		out[i].Holders = nil
		for _, holder := range shard.Holders {
			if shard.ID == shardID && holder == peerID {
				continue
			}
			out[i].Holders = append(out[i].Holders, holder)
		}
	}
	return out
}
