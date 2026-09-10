package dht

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Circuit-borne lookups — R4(b).
//
// THE PROPERTY. §7's lookups reach the r=8 nodes that store a key. Run directly,
// those nodes learn the querying node's ADDRESS alongside its INTEREST: who
// wanted this name, this descriptor, this object. R4(b) requires the lookup to
// traverse a circuit so the storing node sees a relay instead.
//
// WHY THE PATH INDEX EXISTS. A lookup runs d node-disjoint paths so that no
// single DHT node can suppress a record. Carrying all d over ONE circuit throws
// that away at the layer that matters: the d paths would arrive from one
// terminal relay, and that relay — plus anyone watching it — sees the whole
// lookup, its progress and its result. Disjointness at the DHT layer with
// convergence at the circuit layer is not disjointness.
//
// So CircuitRPC binds path i to circuit i and REFUSES to serve two paths from
// one circuit. It is a refusal rather than a warning because the failure is
// silent by nature: a lookup over one circuit returns the same answer as a
// lookup over d, just less anonymously, and nothing in the result would say so.
//
// WHAT THIS DOES NOT DO. It does not implement the wire protocol. Sending a
// FIND_NODE over a circuit and reading the reply needs the session layer, which
// is P23 and `[NEEDS RESEARCH]`; §7's own note says lookups stay direct until
// something carries them. This is the BINDING and the REFUSALS — the part that
// decides which circuit a query may use and what happens when there is not one.
// Supply a Dispatcher and the lookups are circuit-borne; supply none and Lookup
// still records UnsafeDirectLookup, which is the honest state today.

var (
	// ErrNoCircuit means no circuit was available for a path. The lookup fails
	// rather than falling back to a direct query: a silent fallback is exactly
	// how R4(b) comes to look met while being unmet, and the caller that wanted
	// anonymity would never learn it did not get it.
	ErrNoCircuit = errors.New("axon/dht: no circuit available for this lookup path")
	// ErrCircuitReused means two paths were handed the same circuit. See above.
	ErrCircuitReused = errors.New("axon/dht: two lookup paths were given the same circuit")
	// ErrTerminalReused means two paths' circuits end at the same relay. The
	// circuits differ; the observer does not.
	ErrTerminalReused = errors.New("axon/dht: two lookup paths share a terminal relay")
)

// CircuitID identifies one circuit. Opaque here: this package must not learn how
// circuits are built, only that two of them are different.
type CircuitID uint64

// Circuit is what one lookup path sends over.
type Circuit interface {
	ID() CircuitID
	// Terminal is the last hop — the identity the storing node actually sees.
	// Two paths may not share one, because the point of separate circuits is a
	// separate observer at the far end.
	Terminal() NodeID
	// Query sends one lookup request and waits for the reply.
	Query(ctx context.Context, to Contact, key Key) (Response, error)
}

// Dispatcher hands out one circuit per lookup path.
//
// It is an interface so that this package does not import the tunnel pool: a
// DHT that knew how to build circuits would be a DHT that could be asked to,
// and §7's job is to find records, not to make paths.
type Dispatcher interface {
	// ForPath returns the circuit path i must use. Called once per path per
	// lookup, and expected to return a DIFFERENT circuit each time.
	ForPath(ctx context.Context, path int) (Circuit, error)
}

// CircuitRPC adapts a Dispatcher into the RPC that Lookup takes.
//
// One CircuitRPC serves ONE lookup. It holds the per-path assignment for the
// duration and enforces distinctness across it; reusing an instance across two
// lookups would let the second lookup inherit the first's circuits, which is
// linkability between two searches the caller made separately.
func CircuitRPC(d Dispatcher) RPC {
	var mu sync.Mutex
	byPath := map[int]Circuit{}
	usedCircuit := map[CircuitID]int{}
	usedTerminal := map[NodeID]int{}

	return func(ctx context.Context, path int, to Contact, key Key) (Response, error) {
		mu.Lock()
		c, ok := byPath[path]
		if !ok {
			var err error
			c, err = d.ForPath(ctx, path)
			if err != nil {
				mu.Unlock()
				return Response{}, fmt.Errorf("%w: path %d: %v", ErrNoCircuit, path, err)
			}
			if c == nil {
				mu.Unlock()
				return Response{}, fmt.Errorf("%w: path %d", ErrNoCircuit, path)
			}
			if other, dup := usedCircuit[c.ID()]; dup {
				mu.Unlock()
				return Response{}, fmt.Errorf("%w: paths %d and %d both got circuit %d",
					ErrCircuitReused, other, path, c.ID())
			}
			if other, dup := usedTerminal[c.Terminal()]; dup {
				// Distinct circuits that converge on one terminal relay give
				// that relay the same view a single shared circuit would.
				mu.Unlock()
				return Response{}, fmt.Errorf("%w: paths %d and %d both end at %s",
					ErrTerminalReused, other, path, terminalKey(c))
			}
			byPath[path] = c
			usedCircuit[c.ID()] = path
			usedTerminal[c.Terminal()] = path
		}
		mu.Unlock()

		// The query itself is outside the lock: d paths run concurrently and
		// serialising them here would turn a parallel lookup into a sequential
		// one while telling nobody.
		return c.Query(ctx, to, key)
	}
}

// terminalKey renders a terminal for an error message without slicing an
// unaddressable array return.
func terminalKey(c Circuit) string {
	t := c.Terminal()
	return fmt.Sprintf("%x", t[:8])
}

// CircuitConfig returns a LookupConfig that records the lookup as circuit-borne.
//
// It exists so that OverCircuit and the RPC cannot be set independently.
// Claiming OverCircuit while passing a direct RPC would suppress
// UnsafeDirectLookup from the evidence without changing what actually happened —
// and the evidence is the only thing a caller has to judge the answer by.
func CircuitConfig(base LookupConfig) LookupConfig {
	base.OverCircuit = true
	return base
}
