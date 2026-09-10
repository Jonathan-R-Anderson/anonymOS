package dht

import (
	"context"
	"net/netip"
	"testing"
)

// E4.1: on 30 nodes, a record put in epoch n is retrievable in epoch n+1 with
// >= 99 % success over 10^3 trials.
//
// SCOPE, STATED PLAINLY: this is a SIMULATED 30-node network in one process. It
// exercises the real derivation, the real routing table, the real admission
// caps and the real disjoint-path lookup, but not real sockets, real churn or
// real latency. E4.1 as written targets the `axon-lab` fleet; this test
// discharges the algorithmic half of it and nothing more. A green result here
// is a necessary condition for E4.1, not the criterion itself.

// epochSim is a 30-node network that can be rotated to a new SRV.
type epochSim struct {
	pubs    [][32]byte
	prefix  []NetworkPrefix
	asn     []uint32
	kadIDs  []Key
	holders map[[32]byte]bool
	wire    []byte
}

func newEpochSim(t *testing.T, n int, srv SRV) *epochSim {
	t.Helper()
	s := &epochSim{holders: map[[32]byte]bool{}, wire: []byte("record")}
	for i := 0; i < n; i++ {
		// 30 nodes in 30 distinct /24s and 30 distinct ASNs, so the admission
		// caps never bind and the measurement is about rotation rather than
		// about diversity refusals.
		addr := netip.AddrFrom4([4]byte{198, 51, byte(i), 1})
		p, err := PrefixFor(addr)
		if err != nil {
			t.Fatal(err)
		}
		s.pubs = append(s.pubs, mkPub(uint64(i)+1))
		s.prefix = append(s.prefix, p)
		s.asn = append(s.asn, uint32(64000+i))
	}
	s.rotate(t, srv)
	return s
}

// rotate recomputes every node's position under a new SRV. This is the epoch
// boundary: every position moves at once.
func (s *epochSim) rotate(t *testing.T, srv SRV) {
	t.Helper()
	s.kadIDs = s.kadIDs[:0]
	for i := range s.pubs {
		id, err := DeriveKadID(s.pubs[i], srv, s.prefix[i])
		if err != nil {
			t.Fatal(err)
		}
		s.kadIDs = append(s.kadIDs, id)
	}
}

func (s *epochSim) contacts() []Contact {
	out := make([]Contact, len(s.pubs))
	for i := range s.pubs {
		out[i] = Contact{
			NodeIDPub: s.pubs[i], KadID: s.kadIDs[i],
			Prefix: s.prefix[i], ASN: s.asn[i], Verified: true,
		}
	}
	return out
}

// closest returns the r nodes nearest a key under the current epoch.
func (s *epochSim) closest(key Key, r int) [][32]byte {
	cs := s.contacts()
	for i := range cs {
		for j := i + 1; j < len(cs); j++ {
			if Distance(cs[j].KadID, key).Less(Distance(cs[i].KadID, key)) {
				cs[i], cs[j] = cs[j], cs[i]
			}
		}
	}
	if len(cs) > r {
		cs = cs[:r]
	}
	out := make([][32]byte, len(cs))
	for i := range cs {
		out[i] = cs[i].NodeIDPub
	}
	return out
}

func (s *epochSim) rpc(_ context.Context, _ int, to Contact, key Key) (Response, error) {
	resp := Response{}
	cs := s.contacts()
	for i := range cs {
		for j := i + 1; j < len(cs); j++ {
			if Distance(cs[j].KadID, key).Less(Distance(cs[i].KadID, key)) {
				cs[i], cs[j] = cs[j], cs[i]
			}
		}
	}
	if len(cs) > BucketSize {
		cs = cs[:BucketSize]
	}
	resp.Closer = cs
	if s.holders[to.NodeIDPub] {
		resp.Wire = s.wire
	}
	return resp, nil
}

// TestRecordSurvivesTheEpochBoundary is E4.1's algorithmic half.
//
// The mechanism it exercises is the one P4 requires: a publisher republishes to
// the NEW r-closest set after rotation. Without that republication a record put
// in epoch n is simply not where anyone looks in epoch n+1 -- rotation moves the
// replica set, and the record does not follow by itself.
func TestRecordSurvivesTheEpochBoundary(t *testing.T) {
	const (
		nodes  = 30
		trials = 1000
	)
	srvN := mkSRV(0xE1)
	srvN1 := mkSRV(0xE2)

	success := 0
	movedTotal := 0
	for trial := 0; trial < trials; trial++ {
		sim := newEpochSim(t, nodes, srvN)

		// PUT in epoch n: the r closest nodes hold it.
		key := MustDeriveKey(ClassRelay, []byte{byte(trial), byte(trial >> 8), 0xAB})
		before := sim.closest(key, Replicas)
		for _, h := range before {
			sim.holders[h] = true
		}

		// The epoch turns. Every position moves.
		sim.rotate(t, srvN1)

		// Republication: the publisher puts to the NEW r-closest set. The old
		// holders keep their copy until it expires, which is what makes the
		// boundary survivable rather than a cliff.
		after := sim.closest(key, Replicas)
		for _, h := range after {
			sim.holders[h] = true
		}

		moved := 0
		beforeSet := map[[32]byte]bool{}
		for _, h := range before {
			beforeSet[h] = true
		}
		for _, h := range after {
			if !beforeSet[h] {
				moved++
			}
		}
		movedTotal += moved

		// GET in epoch n+1 from a node that was not involved in the put.
		tbl := NewTable(sim.kadIDs[0])
		for _, c := range sim.contacts() {
			_ = tbl.Admit(c)
		}
		res, err := Lookup(context.Background(), tbl, key, sim.rpc, LookupConfig{})
		if err != nil {
			continue
		}
		if len(res.Wires) > 0 {
			success++
		}
	}

	rate := float64(success) / float64(trials)
	t.Logf("E4.1 (simulated, %d nodes): %d/%d retrievals across the epoch boundary (%.2f%%); "+
		"on average %.1f of %d replica slots changed hands at the boundary",
		nodes, success, trials, rate*100, float64(movedTotal)/float64(trials), Replicas)
	if rate < 0.99 {
		t.Fatalf("E4.1 falsified in simulation: %.2f%% < 99%%", rate*100)
	}
}

// TestReplicaSetChurnAtTheBoundary measures how much of a key's replica set
// changes hands at rotation, across network sizes.
//
// WHY THIS AND NOT A RETRIEVAL-CLIFF CONTROL. The obvious control -- "skip
// republication and watch retrieval collapse" -- does not work at 30 nodes and
// would be a misleading test if written anyway: r=8 is over a quarter of a
// 30-node network, a lookup reaches nearly everyone in two hops, and any holder
// answers regardless of where it now sits. Retrieval stays at 100 % for reasons
// that have nothing to do with republication working.
//
// What IS measurable at every scale is the churn itself: the fraction of the
// replica set that is new after rotation. That number is the reason a
// republication scheduler has to exist, and it converges to 1 as the network
// grows -- at which point skipping republication does become a cliff.
func TestReplicaSetChurnAtTheBoundary(t *testing.T) {
	srvN, srvN1 := mkSRV(0xE3), mkSRV(0xE4)

	for _, nodes := range []int{30, 100, 500} {
		const trials = 200
		movedTotal := 0
		for trial := 0; trial < trials; trial++ {
			sim := newEpochSim(t, nodes, srvN)
			key := MustDeriveKey(ClassRelay, []byte{byte(trial), byte(nodes), 0xCD})

			before := map[[32]byte]bool{}
			for _, h := range sim.closest(key, Replicas) {
				before[h] = true
			}
			sim.rotate(t, srvN1)
			for _, h := range sim.closest(key, Replicas) {
				if !before[h] {
					movedTotal++
				}
			}
		}
		churn := float64(movedTotal) / float64(trials) / float64(Replicas)
		t.Logf("replica-set churn at rotation, N=%3d: %.1f%% of the %d slots are new",
			nodes, churn*100, Replicas)

		// Rotation that did not move the replica set would mean SRV is not
		// actually reaching the derivation -- the failure this guards against.
		if churn < 0.5 {
			t.Fatalf("N=%d: only %.1f%% of the replica set changed at the boundary; "+
				"positions are not rotating", nodes, churn*100)
		}
	}
}
