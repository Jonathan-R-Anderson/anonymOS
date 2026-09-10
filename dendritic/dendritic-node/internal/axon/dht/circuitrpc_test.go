package dht

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// fakeCircuit is a circuit that records what was asked over it.
type fakeCircuit struct {
	id       CircuitID
	terminal NodeID
	mu       sync.Mutex
	asked    []NodeID
	resp     Response
	err      error
}

func (c *fakeCircuit) ID() CircuitID    { return c.id }
func (c *fakeCircuit) Terminal() NodeID { return c.terminal }
func (c *fakeCircuit) Query(_ context.Context, to Contact, _ Key) (Response, error) {
	c.mu.Lock()
	c.asked = append(c.asked, to.NodeIDPub)
	c.mu.Unlock()
	return c.resp, c.err
}

func nodeID(b byte) NodeID {
	var n NodeID
	n[0] = b
	return n
}

// oneCircuitPerPath is the honest dispatcher: a fresh circuit each time.
type oneCircuitPerPath struct {
	mu   sync.Mutex
	made []*fakeCircuit
	err  error
}

func (d *oneCircuitPerPath) ForPath(_ context.Context, path int) (Circuit, error) {
	if d.err != nil {
		return nil, d.err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	c := &fakeCircuit{id: CircuitID(100 + path), terminal: nodeID(byte(200 + path))}
	d.made = append(d.made, c)
	return c, nil
}

// TestEachPathGetsItsOwnCircuit is R4(b)'s point.
func TestEachPathGetsItsOwnCircuit(t *testing.T) {
	d := &oneCircuitPerPath{}
	rpc := CircuitRPC(d)
	ctx := context.Background()

	for path := 0; path < 3; path++ {
		for q := 0; q < 4; q++ {
			if _, err := rpc(ctx, path, Contact{NodeIDPub: nodeID(byte(q))}, Key{}); err != nil {
				t.Fatalf("path %d query %d: %v", path, q, err)
			}
		}
	}
	if len(d.made) != 3 {
		t.Fatalf("dispatcher made %d circuits for 3 paths -- one per PATH, not per query", len(d.made))
	}
	// Each circuit carried only its own path's four queries.
	for i, c := range d.made {
		if len(c.asked) != 4 {
			t.Fatalf("circuit %d carried %d queries, want 4", i, len(c.asked))
		}
	}
}

// sharedCircuit hands every path the same circuit. The failure this catches is
// silent by nature: the lookup would return the right answer, from one terminal
// relay that saw all of it.
type sharedCircuit struct{ c *fakeCircuit }

func (d *sharedCircuit) ForPath(context.Context, int) (Circuit, error) { return d.c, nil }

func TestTwoPathsMayNotShareACircuit(t *testing.T) {
	d := &sharedCircuit{c: &fakeCircuit{id: 7, terminal: nodeID(9)}}
	rpc := CircuitRPC(d)
	ctx := context.Background()

	if _, err := rpc(ctx, 0, Contact{NodeIDPub: nodeID(1)}, Key{}); err != nil {
		t.Fatalf("first path refused: %v", err)
	}
	_, err := rpc(ctx, 1, Contact{NodeIDPub: nodeID(2)}, Key{})
	if !errors.Is(err, ErrCircuitReused) {
		t.Fatalf("a second path reused circuit 7 and was allowed: %v", err)
	}
}

// distinctCircuitsSameExit is the subtler case: different circuits, one exit.
type distinctCircuitsSameExit struct{ n int }

func (d *distinctCircuitsSameExit) ForPath(context.Context, int) (Circuit, error) {
	d.n++
	// Different id, SAME terminal.
	return &fakeCircuit{id: CircuitID(d.n), terminal: nodeID(42)}, nil
}

func TestTwoPathsMayNotShareATerminalRelay(t *testing.T) {
	rpc := CircuitRPC(&distinctCircuitsSameExit{})
	ctx := context.Background()

	if _, err := rpc(ctx, 0, Contact{NodeIDPub: nodeID(1)}, Key{}); err != nil {
		t.Fatalf("first path refused: %v", err)
	}
	// The circuits differ, so the reuse check above passes. The OBSERVER does
	// not differ, which is the thing that actually matters.
	_, err := rpc(ctx, 1, Contact{NodeIDPub: nodeID(2)}, Key{})
	if !errors.Is(err, ErrTerminalReused) {
		t.Fatalf("two paths ended at the same relay and were allowed: %v", err)
	}
}

// TestNoCircuitIsAFailureNotAFallback is the most important refusal here.
func TestNoCircuitIsAFailureNotAFallback(t *testing.T) {
	rpc := CircuitRPC(&oneCircuitPerPath{err: errors.New("pool degraded")})
	_, err := rpc(context.Background(), 0, Contact{NodeIDPub: nodeID(1)}, Key{})
	if !errors.Is(err, ErrNoCircuit) {
		t.Fatalf("a missing circuit gave %v, want ErrNoCircuit", err)
	}
	// A silent fallback to a direct query is how R4(b) comes to LOOK met while
	// being unmet: the answer is identical and nothing records that the storing
	// node learned the client's address.
	if err != nil && errors.Is(err, ErrCircuitReused) {
		t.Fatal("wrong error class")
	}
}

// TestNilCircuitIsRefused covers the dispatcher that returns (nil, nil).
func TestNilCircuitIsRefused(t *testing.T) {
	rpc := CircuitRPC(dispatcherFunc(func(context.Context, int) (Circuit, error) {
		return nil, nil
	}))
	if _, err := rpc(context.Background(), 0, Contact{NodeIDPub: nodeID(1)}, Key{}); !errors.Is(err, ErrNoCircuit) {
		t.Fatalf("a nil circuit with no error gave %v", err)
	}
}

type dispatcherFunc func(context.Context, int) (Circuit, error)

func (f dispatcherFunc) ForPath(ctx context.Context, p int) (Circuit, error) { return f(ctx, p) }

// TestCircuitConfigAndEvidenceAgree is the honesty check.
//
// OverCircuit is what suppresses UnsafeDirectLookup from a lookup's evidence.
// If it could be set independently of the RPC, a caller could claim a
// circuit-borne lookup while querying directly — and the evidence is the only
// thing anyone has to judge the answer by.
func TestCircuitConfigAndEvidenceAgree(t *testing.T) {
	base := LookupConfig{Paths: 3}
	if base.OverCircuit {
		t.Fatal("OverCircuit defaults to true; direct lookups would not be recorded")
	}
	if !CircuitConfig(base).OverCircuit {
		t.Fatal("CircuitConfig did not mark the lookup as circuit-borne")
	}

	// And the default, unmarked config still carries the warning into the
	// result -- the state the network is actually in today.
	tbl := NewTable(Key{})
	res, err := Lookup(context.Background(), tbl, Key{},
		func(context.Context, int, Contact, Key) (Response, error) { return Response{}, nil },
		base)
	if !errors.Is(err, ErrNoSeeds) {
		t.Fatalf("expected ErrNoSeeds from an empty table, got %v", err)
	}
	found := false
	for _, m := range res.UnsafeModes {
		if m == UnsafeDirectLookup {
			found = true
		}
	}
	if !found {
		t.Fatalf("a direct lookup did not record UnsafeDirectLookup: %v", res.UnsafeModes)
	}
}

// TestConcurrentPathsDoNotSerialise checks the lock scope.
//
// The distinctness bookkeeping is under a mutex; the QUERY must not be, or d
// concurrent paths become one sequential path and the lookup gets slower with
// no notice to anyone.
func TestConcurrentPathsDoNotSerialise(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan int, 3)

	rpc := CircuitRPC(dispatcherFunc(func(_ context.Context, path int) (Circuit, error) {
		return &blockingCircuit{
			id: CircuitID(path), terminal: nodeID(byte(path)),
			entered: entered, release: release,
		}, nil
	}))

	var wg sync.WaitGroup
	for path := 0; path < 3; path++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			_, _ = rpc(context.Background(), p, Contact{NodeIDPub: nodeID(byte(p))}, Key{})
		}(path)
	}
	// All three must be inside Query at once. If the query were under the
	// mutex, only one would arrive and this blocks until the test times out.
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-context.Background().Done():
		}
	}
	close(release)
	wg.Wait()
}

type blockingCircuit struct {
	id       CircuitID
	terminal NodeID
	entered  chan int
	release  chan struct{}
}

func (c *blockingCircuit) ID() CircuitID    { return c.id }
func (c *blockingCircuit) Terminal() NodeID { return c.terminal }
func (c *blockingCircuit) Query(context.Context, Contact, Key) (Response, error) {
	c.entered <- int(c.id)
	<-c.release
	return Response{}, nil
}

// TestLookupCarriesThePathIndex proves the signature change reaches runPath.
func TestLookupCarriesThePathIndex(t *testing.T) {
	var mu sync.Mutex
	seen := map[int]bool{}

	tbl := NewTable(Key{})
	for i := 0; i < 9; i++ {
		var kid Key
		kid[0] = byte(i + 1)
		_ = tbl.Admit(Contact{NodeIDPub: nodeID(byte(i + 1)), KadID: kid, Verified: true})
	}
	_, _ = Lookup(context.Background(), tbl, Key{},
		func(_ context.Context, path int, _ Contact, _ Key) (Response, error) {
			mu.Lock()
			seen[path] = true
			mu.Unlock()
			return Response{}, nil
		}, LookupConfig{Paths: 3})

	if len(seen) < 2 {
		t.Fatalf("the RPC saw %d distinct path indices (%v); the disjoint paths are "+
			"indistinguishable to it and cannot be bound to separate circuits",
			len(seen), seen)
	}
}
