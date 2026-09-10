package dht

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// The d=3 node-disjoint lookup (§7.3).
//
// WHAT DISJOINT PATHS BUY AND DO NOT BUY, because this is routinely overstated.
// They buy AVAILABILITY AGAINST REFUSAL: an adversary must control at least one
// node on EVERY path, and the paths share no nodes. They buy almost nothing
// against forgery, because every record class is signed and self-validating -- a
// lying node can refuse or delay, not substitute. d=3 is a censorship-resistance
// parameter, not an integrity parameter, and raising it does not make records
// more trustworthy.
//
// GO-2024-3218 (T4.7). The advisory named in this repo's SECURITY.md is exactly
// the residual: hostile peers can attempt to hide provider records, and there is
// no upstream fix. Withholding is an availability attack that signatures cannot
// touch. The design constraint this code states, and TestDisjointPathsSurvive
// OneHostilePathPerLookup tests, is: a lookup must not depend on any single
// node, so a withholding node can suppress a record only by being present on all
// d paths -- and the disjointness invariant makes "present on all d paths"
// require d distinct identities that all get claimed into different paths. It
// does NOT make withholding impossible, and this package does not claim it does.

// UnsafeDirectLookup is a compile-time visible statement of a known-unsafe mode.
//
// R4(b) requires client lookups to traverse a circuit so the storing node sees a
// relay rather than the client. Circuits are P5. Until they exist, lookups issued
// through this package go DIRECT, which means the r=8 storing nodes for a key
// learn the querying node's address alongside its interest. P4's phase
// definition permits this and requires the code to LOG it rather than pretend
// otherwise -- so callers must pass this mode explicitly and Lookup records it in
// the evidence.
const UnsafeDirectLookup = "direct-lookup-no-circuit: the storing node learns the querying address (R4b unmet until P5)"

// NodeID identifies a peer in a lookup.
type NodeID [32]byte

// Response is what one peer returned for a FIND_VALUE.
type Response struct {
	// Closer are candidate contacts nearer the key.
	Closer []Contact
	// Wire is a record encoding, or nil if the peer holds none.
	Wire []byte
	// Refused is set when the peer answered but declined to serve.
	Refused bool
}

// RPC issues one FIND_VALUE against one contact.
// The PATH INDEX is an argument, and it is what makes R4(b) expressible.
//
// Without it an RPC cannot know which of the d disjoint paths it is serving, so
// it cannot bind that path to its own circuit -- and d paths sharing one circuit
// is d paths sharing one terminal relay. The node-disjointness this package
// works to produce would then exist only at the DHT layer, while a single relay
// watched every one of them. See CircuitRPC.
type RPC func(ctx context.Context, path int, to Contact, key Key) (Response, error)

// PathEvidence is what one path observed.
//
// It is returned to the caller rather than reduced to a boolean because §7.7's
// routing-manipulation row is explicit that a hostile node can return FEWER or
// SLOWER valid entries: degradation is cheap and looks like a slow lookup, not
// an attack. Per-path evidence is what lets a client see one path diverging from
// the other two.
type PathEvidence struct {
	Path     int
	Hops     int
	Queried  int
	Timeouts int
	Refusals int
	// ClosestReached is the best distance this path got to.
	ClosestReached Key
	// Records is how many valid records this path returned.
	Records int
}

// LookupResult is the merged answer plus the per-path evidence.
type LookupResult struct {
	// Wires are the distinct valid record encodings found.
	Wires [][]byte
	// Evidence is one entry per path.
	Evidence []PathEvidence
	// UnsafeModes lists known-unsafe modes this lookup ran in.
	UnsafeModes []string
}

// LookupConfig parameterises a lookup.
type LookupConfig struct {
	Paths       int // d
	Concurrency int // alpha
	BucketSize  int // k
	// Validate checks a returned record. A lookup that skipped validation would
	// return whatever the last peer said.
	Validate func(key Key, wire []byte) error
	// OverCircuit reports whether lookups run over a circuit. False until P5,
	// and false is RECORDED in the result rather than silently tolerated.
	OverCircuit bool
}

func (c LookupConfig) withDefaults() LookupConfig {
	if c.Paths <= 0 {
		c.Paths = DisjointPaths
	}
	if c.Concurrency <= 0 {
		c.Concurrency = Concurrency
	}
	if c.BucketSize <= 0 {
		c.BucketSize = BucketSize
	}
	return c
}

// claimSet is the global disjointness state, shared across all d paths.
//
// claim() is a test-and-set executed at the moment a candidate is admitted to
// ANY frontier. It is what makes the invariant hold by construction:
//
//	forall i != j:  P[i].queried  intersect  P[j].queried  =  empty
//
// The invariant is over QUERIED NODES, not over records returned. Two paths
// reaching the same record through disjoint node sets is the success case, not
// a violation.
type claimSet struct {
	mu      sync.Mutex
	claimed map[NodeID]int // node -> path that owns it
}

func newClaimSet() *claimSet { return &claimSet{claimed: map[NodeID]int{}} }

func (c *claimSet) claim(id NodeID, path int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, taken := c.claimed[id]; taken {
		return false
	}
	c.claimed[id] = path
	return true
}

// owner reports which path claimed a node, for the disjointness assertion.
func (c *claimSet) owner(id NodeID) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.claimed[id]
	return p, ok
}

// ErrNoSeeds is returned when the local table has nothing to start from.
var ErrNoSeeds = errors.New("axon/dht: no verified seeds for a lookup")

// Lookup runs d node-disjoint iterative lookups for a key.
func Lookup(ctx context.Context, t *Table, key Key, rpc RPC, cfg LookupConfig) (LookupResult, error) {
	cfg = cfg.withDefaults()
	res := LookupResult{Evidence: make([]PathEvidence, cfg.Paths)}
	if !cfg.OverCircuit {
		res.UnsafeModes = append(res.UnsafeModes, UnsafeDirectLookup)
	}

	// Seed. Take the 3d closest VERIFIED entries and deal them round-robin, so
	// no two paths begin in the same bucket-neighbourhood and one poisoned
	// bucket cannot seed all three.
	seeds := t.Closest(key, 3*cfg.Paths, true)
	if len(seeds) == 0 {
		return res, ErrNoSeeds
	}

	claims := newClaimSet()
	frontiers := make([][]Contact, cfg.Paths)
	for i := range frontiers {
		for j := i; j < len(seeds); j += cfg.Paths {
			if claims.claim(seeds[j].NodeIDPub, i) {
				frontiers[i] = append(frontiers[i], seeds[j])
			}
		}
	}

	var (
		mu    sync.Mutex
		wires [][]byte
		wg    sync.WaitGroup
	)
	for i := 0; i < cfg.Paths; i++ {
		wg.Add(1)
		go func(path int) {
			defer wg.Done()
			ev, found := runPath(ctx, path, key, frontiers[path], claims, rpc, cfg)
			mu.Lock()
			res.Evidence[path] = ev
			wires = append(wires, found...)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	res.Wires = dedupeWires(wires)
	return res, nil
}

func runPath(ctx context.Context, path int, key Key, frontier []Contact, claims *claimSet, rpc RPC, cfg LookupConfig) (PathEvidence, [][]byte) {
	ev := PathEvidence{Path: path}
	queried := map[NodeID]bool{}
	var found [][]byte

	best := Key{}
	for i := range best {
		best[i] = 0xff
	}

	for len(frontier) > 0 {
		if ctx.Err() != nil {
			break
		}
		sort.Slice(frontier, func(i, j int) bool {
			return Distance(frontier[i].KadID, key).Less(Distance(frontier[j].KadID, key))
		})

		batch := frontier
		if len(batch) > cfg.Concurrency {
			batch = batch[:cfg.Concurrency]
		}
		frontier = frontier[len(batch):]
		ev.Hops++

		type outcome struct {
			c    Contact
			resp Response
			err  error
		}
		outs := make([]outcome, len(batch))
		var wg sync.WaitGroup
		for i, c := range batch {
			wg.Add(1)
			go func(i int, c Contact) {
				defer wg.Done()
				r, err := rpc(ctx, path, c, key)
				outs[i] = outcome{c: c, resp: r, err: err}
			}(i, c)
		}
		wg.Wait()

		improved := false
		for _, o := range outs {
			queried[o.c.NodeIDPub] = true
			ev.Queried++
			if o.err != nil {
				ev.Timeouts++
				continue
			}
			if o.resp.Refused {
				ev.Refusals++
			}
			if d := Distance(o.c.KadID, key); d.Less(best) {
				best, improved = d, true
			}

			for _, cand := range o.resp.Closer {
				// DISJOINTNESS: a candidate enters a frontier only via claim,
				// which succeeds at most once across all paths.
				if !claims.claim(cand.NodeIDPub, path) {
					continue
				}
				frontier = append(frontier, cand)
			}
			if len(o.resp.Wire) > 0 {
				if cfg.Validate == nil || cfg.Validate(key, o.resp.Wire) == nil {
					found = append(found, o.resp.Wire)
					ev.Records++
				}
			}
		}
		// Converged: no response improved the best distance this round.
		if !improved {
			break
		}
	}

	ev.ClosestReached = best
	return ev, found
}

func dedupeWires(in [][]byte) [][]byte {
	seen := map[[32]byte]struct{}{}
	out := make([][]byte, 0, len(in))
	for _, w := range in {
		d := CanonicalDigest(w)
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, w)
	}
	return out
}
