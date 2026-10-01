package dht

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"sort"
	"sync"
	"testing"
)

// A synthetic network: every node knows the whole membership and answers
// FIND_VALUE honestly unless it is hostile.
type simNet struct {
	nodes   []Contact
	hostile map[[32]byte]bool
	// holders are the nodes that hold the record.
	holders map[[32]byte]bool
	wire    []byte
	// queried records every (path-agnostic) node that was asked, for the
	// disjointness assertion. Guarded because the d paths call rpc
	// concurrently, which is the production behaviour under test.
	mu      sync.Mutex
	queried map[[32]byte]int
}

func newSimNet(t *testing.T, n int, srv SRV, seed int64) *simNet {
	t.Helper()
	s := &simNet{
		hostile: map[[32]byte]bool{},
		holders: map[[32]byte]bool{},
		queried: map[[32]byte]int{},
		wire:    []byte("the record everybody is looking for"),
	}
	rng := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		addr := netip.AddrFrom4([4]byte{byte(10 + rng.Intn(200)), byte(rng.Intn(256)), byte(rng.Intn(256)), 1})
		prefix, _ := PrefixFor(addr)
		pub := mkPub(uint64(i) + 1)
		id, err := DeriveKadID(pub, srv, prefix)
		if err != nil {
			t.Fatal(err)
		}
		s.nodes = append(s.nodes, Contact{
			NodeIDPub: pub, KadID: id, Addr: addr, Prefix: prefix,
			ASN: uint32(1000 + i), Verified: true,
		})
	}
	return s
}

// closestTo returns the n nodes closest to a key across the whole network.
func (s *simNet) closestTo(key Key, n int) []Contact {
	out := append([]Contact(nil), s.nodes...)
	sort.Slice(out, func(i, j int) bool {
		return Distance(out[i].KadID, key).Less(Distance(out[j].KadID, key))
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// rpc is the network's FIND_VALUE. A hostile node WITHHOLDS: it answers, it
// returns plausible closer nodes, and it simply never mentions the record. This
// is GO-2024-3218's shape exactly -- signatures cannot touch it.
func (s *simNet) rpc(_ context.Context, _ int, to Contact, key Key) (Response, error) {
	s.mu.Lock()
	s.queried[to.NodeIDPub]++
	s.mu.Unlock()
	resp := Response{Closer: s.closestTo(key, BucketSize)}
	if s.hostile[to.NodeIDPub] {
		resp.Refused = true
		return resp, nil
	}
	if s.holders[to.NodeIDPub] {
		resp.Wire = s.wire
	}
	return resp, nil
}

func (s *simNet) seedTable(t *testing.T, self Key, n int) *Table {
	t.Helper()
	tbl := NewTable(self)
	for i, c := range s.nodes {
		if i >= n {
			break
		}
		_ = tbl.Admit(c)
	}
	return tbl
}

// TestLookupFindsTheRecordAndReportsTheUnsafeMode.
func TestLookupFindsTheRecordAndReportsTheUnsafeMode(t *testing.T) {
	srv := mkSRV(0x60)
	net := newSimNet(t, 200, srv, 1)
	key := MustDeriveKey(ClassRelay, []byte("target"))
	for _, h := range net.closestTo(key, Replicas) {
		net.holders[h.NodeIDPub] = true
	}
	tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 60)

	res, err := Lookup(context.Background(), tbl, key, net.rpc, LookupConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Wires) == 0 {
		t.Fatal("lookup found nothing in an entirely honest network")
	}
	// R4b is unmet until P5, and the code must SAY so rather than pretend.
	if len(res.UnsafeModes) != 1 || res.UnsafeModes[0] != UnsafeDirectLookup {
		t.Fatalf("unsafe modes = %v, want the direct-lookup declaration", res.UnsafeModes)
	}
	if len(res.Evidence) != DisjointPaths {
		t.Fatalf("evidence for %d paths, want %d", len(res.Evidence), DisjointPaths)
	}
}

// TestPathsAreNodeDisjoint is §7.3's invariant, stated exactly:
//
//	forall i != j:  P[i].queried  intersect  P[j].queried  =  empty
func TestPathsAreNodeDisjoint(t *testing.T) {
	srv := mkSRV(0x61)
	key := MustDeriveKey(ClassRelay, []byte("target"))

	for trial := 0; trial < 50; trial++ {
		net := newSimNet(t, 300, srv, int64(trial))
		for _, h := range net.closestTo(key, Replicas) {
			net.holders[h.NodeIDPub] = true
		}
		tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 80)

		if _, err := Lookup(context.Background(), tbl, key, net.rpc, LookupConfig{}); err != nil {
			t.Fatal(err)
		}
		for id, n := range net.queried {
			if n > 1 {
				t.Fatalf("trial %d: node %x was queried %d times; the paths are not disjoint",
					trial, id[:4], n)
			}
		}
	}
}

// TestDisjointPathsSurviveWithholdingNodes is T4.7: GO-2024-3218 (provider-record
// hiding, no upstream fix) is met by a STATED DESIGN CONSTRAINT with a test,
// not by advisory suppression.
//
// The constraint: a lookup must not depend on any single node. A withholding
// node suppresses the record only by being present on ALL d paths, and the
// disjointness invariant means that requires d distinct identities that each get
// claimed into a different path. This does NOT make withholding impossible --
// nothing does, which is why the advisory has no upstream fix -- it makes it
// cost a presence on every path rather than on one.
func TestDisjointPathsSurviveWithholdingNodes(t *testing.T) {
	srv := mkSRV(0x62)
	key := MustDeriveKey(ClassRelay, []byte("censored record"))

	found, trials := 0, 200
	for trial := 0; trial < trials; trial++ {
		net := newSimNet(t, 300, srv, int64(trial+1000))
		replicas := net.closestTo(key, Replicas)
		for _, h := range replicas {
			net.holders[h.NodeIDPub] = true
		}
		// Make a MINORITY of the replicas withhold. The honest ones still
		// answer, and any path reaching one of them returns the record.
		for i := 0; i < len(replicas)/2; i++ {
			net.hostile[replicas[i].NodeIDPub] = true
		}
		tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 80)

		res, err := Lookup(context.Background(), tbl, key, net.rpc, LookupConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Wires) > 0 {
			found++
		}
	}
	rate := float64(found) / float64(trials)
	t.Logf("T4.7: with half the replica set withholding, %d/%d lookups returned the record (%.1f%%)",
		found, trials, rate*100)
	if rate < 0.95 {
		t.Fatalf("withholding by half the replica set suppressed %.1f%% of lookups", (1-rate)*100)
	}
}

// TestAllReplicasWithholdingSuppressesTheRecord is the other half of T4.7, and
// it asserts the LIMIT rather than the defence. If every replica withholds the
// record is gone, and no number of disjoint paths recovers it. Stating this in
// a test is the difference between meeting the advisory with a design constraint
// and suppressing it.
func TestAllReplicasWithholdingSuppressesTheRecord(t *testing.T) {
	srv := mkSRV(0x63)
	key := MustDeriveKey(ClassRelay, []byte("fully censored"))
	net := newSimNet(t, 300, srv, 7)
	for _, h := range net.closestTo(key, Replicas) {
		net.holders[h.NodeIDPub] = true
		net.hostile[h.NodeIDPub] = true
	}
	tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 80)

	res, err := Lookup(context.Background(), tbl, key, net.rpc, LookupConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Wires) != 0 {
		t.Fatal("a record every replica withheld was somehow returned")
	}
	// The evidence must make the refusals visible, so a client sees a censored
	// lookup rather than an empty one.
	refusals := 0
	for _, ev := range res.Evidence {
		refusals += ev.Refusals
	}
	if refusals == 0 {
		t.Fatal("total suppression produced no refusal evidence; it is indistinguishable from absence")
	}
	t.Logf("T4.7 limit: full replica-set withholding suppresses the record; %d refusals recorded across %d paths",
		refusals, len(res.Evidence))
}

// TestLookupWithTwentyPercentAdversarial is E4.3: with 20 % adversarial
// colluding nodes, d=3 lookups return the honest value in >= 95 % of trials.
func TestLookupWithTwentyPercentAdversarial(t *testing.T) {
	srv := mkSRV(0x64)
	key := MustDeriveKey(ClassRelay, []byte("contested key"))

	const trials = 1000
	found := 0
	for trial := 0; trial < trials; trial++ {
		net := newSimNet(t, 500, srv, int64(trial+50_000))
		for _, h := range net.closestTo(key, Replicas) {
			net.holders[h.NodeIDPub] = true
		}
		// 20 % of the whole population is adversarial and withholds. Which
		// nodes those are is independent of the key, because SRV rotation means
		// the adversary cannot choose where they land.
		rng := rand.New(rand.NewSource(int64(trial)))
		for _, c := range net.nodes {
			if rng.Float64() < 0.20 {
				net.hostile[c.NodeIDPub] = true
			}
		}
		tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 100)

		res, err := Lookup(context.Background(), tbl, key, net.rpc, LookupConfig{})
		if err != nil {
			continue
		}
		if len(res.Wires) > 0 {
			found++
		}
	}
	rate := float64(found) / float64(trials)
	t.Logf("E4.3: 20%% adversarial, d=%d -> honest value returned in %d/%d trials (%.2f%%)",
		DisjointPaths, found, trials, rate*100)
	if rate < 0.95 {
		t.Fatalf("E4.3 falsified: %.2f%% < 95%%", rate*100)
	}
}

// TestLookupValidatesReturnedRecords: a lookup that skipped validation would
// return whatever the last peer said.
func TestLookupValidatesReturnedRecords(t *testing.T) {
	srv := mkSRV(0x65)
	key := MustDeriveKey(ClassRelay, []byte("target"))
	net := newSimNet(t, 200, srv, 3)
	for _, h := range net.closestTo(key, Replicas) {
		net.holders[h.NodeIDPub] = true
	}
	tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 60)

	res, err := Lookup(context.Background(), tbl, key, net.rpc, LookupConfig{
		Validate: func(Key, []byte) error { return errors.New("nope") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Wires) != 0 {
		t.Fatal("records that failed validation were returned")
	}
}

// TestSeedsAreDealtAcrossPaths: one poisoned bucket must not seed all three
// paths.
func TestSeedsAreDealtAcrossPaths(t *testing.T) {
	srv := mkSRV(0x66)
	key := MustDeriveKey(ClassRelay, []byte("target"))
	net := newSimNet(t, 200, srv, 11)
	tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 60)

	res, err := Lookup(context.Background(), tbl, key, net.rpc, LookupConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range res.Evidence {
		if ev.Queried == 0 {
			t.Fatalf("path %d queried nobody; the seeds were not dealt across paths", ev.Path)
		}
	}
}

// TestLookupWithNoVerifiedSeedsFails: an unverified table cannot start a lookup,
// because unverified entries may make progress but may not be trusted to seed
// one.
func TestLookupWithNoVerifiedSeedsFails(t *testing.T) {
	srv := mkSRV(0x67)
	net := newSimNet(t, 50, srv, 13)
	tbl := NewTable(MustDeriveKey(ClassRelay, []byte("self")))
	for _, c := range net.nodes {
		c.Verified = false
		_ = tbl.Admit(c)
	}
	_, err := Lookup(context.Background(), tbl, MustDeriveKey(ClassRelay, []byte("k")), net.rpc, LookupConfig{})
	if !errors.Is(err, ErrNoSeeds) {
		t.Fatalf("err = %v, want ErrNoSeeds", err)
	}
}

// TestOverCircuitSuppressesTheUnsafeDeclaration: once P5 lands and lookups run
// over circuits, the declaration goes away on its own.
func TestOverCircuitSuppressesTheUnsafeDeclaration(t *testing.T) {
	srv := mkSRV(0x68)
	net := newSimNet(t, 100, srv, 17)
	tbl := net.seedTable(t, MustDeriveKey(ClassRelay, []byte("self")), 40)

	res, err := Lookup(context.Background(), tbl, MustDeriveKey(ClassRelay, []byte("k")),
		net.rpc, LookupConfig{OverCircuit: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.UnsafeModes) != 0 {
		t.Fatalf("unsafe modes = %v, want none over a circuit", res.UnsafeModes)
	}
}
