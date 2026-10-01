package facilitation

import (
	"context"
	"crypto/ed25519"
	"testing"
)

// A tiny in-memory network: each node holds one shard and answers challenges
// for it. Enough to run the loop end to end without any transport.
type memNet struct {
	agents map[[32]byte]*Agent
	data   map[[32]byte][]byte // assignmentID -> shard bytes
	chunk  int
	drops  map[[32]byte]bool // nodes that answer with the wrong data
}

func (m *memNet) Challenge(ctx context.Context, target [32]byte, c StorageChallenge) (StorageResponse, error) {
	a := m.agents[target]
	payload := m.data[c.AssignmentID]
	if m.drops[target] {
		payload = make([]byte, len(payload)) // "still here, honest" — but zeroed
	}
	return a.AnswerStorageChallenge(c, payload, m.chunk)
}

func buildNet(t *testing.T, n int) (*memNet, []*Agent, [][32]byte, []Assignment) {
	t.Helper()
	net := &memNet{agents: map[[32]byte]*Agent{}, data: map[[32]byte][]byte{},
		chunk: 4096, drops: map[[32]byte]bool{}}
	var agents []*Agent
	var ids [][32]byte
	var assignments []Assignment
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		a := NewAgent(pub, priv)
		net.agents[a.NodeID()] = a
		agents = append(agents, a)
		ids = append(ids, a.NodeID())

		data := make([]byte, 20*1024)
		for j := range data {
			data[j] = byte((i + 1) * (j + 1) % 251)
		}
		var assignment [32]byte
		assignment[0], assignment[31] = byte(i+1), byte(i+1)
		net.data[assignment] = data
		chunks, leaves := ChunkShard(data, net.chunk)
		assignments = append(assignments, Assignment{
			NodeID: a.NodeID(), AssignmentID: assignment,
			ShardRoot: BuildTree(leaves).Root, NumChunks: len(chunks),
			Bytes: uint64(len(data)),
		})
	}
	return net, agents, ids, assignments
}

func seedFrom(b byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = b ^ byte(i)
	}
	return s
}

func TestChallengerSelectionIsDeterministicAndExcludesProvider(t *testing.T) {
	_, _, ids, assignments := buildNet(t, 8)
	seed := seedFrom(0x11)
	a := assignments[0]

	first := DesignatedChallengers(seed, 1, a, ids)
	second := DesignatedChallengers(seed, 1, a, ids)
	if len(first) != ChallengersPerAssignment {
		t.Fatalf("want %d challengers, got %d", ChallengersPerAssignment, len(first))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatal("challenger draw is not deterministic")
		}
		if first[i] == a.NodeID {
			t.Fatal("provider drawn to audit itself")
		}
	}
	// Candidate ordering must not change the outcome.
	rev := make([][32]byte, len(ids))
	for i := range ids {
		rev[i] = ids[len(ids)-1-i]
	}
	third := DesignatedChallengers(seed, 1, a, rev)
	for i := range first {
		if first[i] != third[i] {
			t.Fatal("challenger draw depends on candidate order")
		}
	}
	// No duplicates — three seats must mean three distinct nodes.
	seen := map[[32]byte]bool{}
	for _, c := range first {
		if seen[c] {
			t.Fatal("the same node drawn twice for one assignment")
		}
		seen[c] = true
	}
}

// The point of deriving from randomness: a provider cannot know or arrange its
// auditors ahead of time, and the set moves every epoch.
func TestChallengerSetChangesWithEpochAndSeed(t *testing.T) {
	_, _, ids, assignments := buildNet(t, 12)
	a := assignments[0]
	base := DesignatedChallengers(seedFrom(0x22), 1, a, ids)
	nextEpoch := DesignatedChallengers(seedFrom(0x22), 2, a, ids)
	otherSeed := DesignatedChallengers(seedFrom(0x33), 1, a, ids)

	same := func(x, y [][32]byte) bool {
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
		return true
	}
	if same(base, nextEpoch) {
		t.Error("challenger set is identical across epochs — auditors would be permanent")
	}
	if same(base, otherSeed) {
		t.Error("challenger set does not depend on the seed")
	}
}

// Every assignment must actually get audited, and the duty must spread out
// rather than landing on a handful of nodes.
func TestEveryAssignmentIsCoveredAndDutyIsSpread(t *testing.T) {
	_, _, ids, assignments := buildNet(t, 10)
	seed := seedFrom(0x44)
	load := map[[32]byte]int{}
	for _, a := range assignments {
		set := DesignatedChallengers(seed, 5, a, ids)
		if len(set) != ChallengersPerAssignment {
			t.Fatalf("assignment %x got %d challengers", a.AssignmentID[:4], len(set))
		}
		for _, c := range set {
			load[c]++
		}
	}
	total := len(assignments) * ChallengersPerAssignment
	ideal := float64(total) / float64(len(ids))
	for id, n := range load {
		if float64(n) > ideal*3 {
			t.Errorf("node %x draws %d of %d challenges — duty is concentrated", id[:4], n, total)
		}
	}
	if len(load) < len(ids)/2 {
		t.Errorf("only %d of %d nodes drew any duty", len(load), len(ids))
	}
}

func TestRunEpochChallengesAndPasses(t *testing.T) {
	net, agents, ids, assignments := buildNet(t, 6)
	seed := seedFrom(0x55)
	store, err := OpenReceiptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	s := &Scheduler{Agent: agents[0], Store: store, Transport: net}
	results, err := s.RunEpoch(context.Background(), seed, 7, assignments, ids)
	if err != nil {
		t.Fatalf("RunEpoch: %v", err)
	}
	if len(results) == 0 {
		t.Skip("this node drew no duty for this seed — selection is random by design")
	}
	for _, r := range results {
		if r.Err != nil || !r.Passed {
			t.Fatalf("honest peer failed its audit: %v", r.Err)
		}
		if r.Challenge.TargetNodeID == agents[0].NodeID() {
			t.Fatal("challenged itself")
		}
	}
}

// A node that no longer holds the data must fail, and must not be able to
// produce a receipt for it.
func TestRunEpochCatchesANodeThatLostTheData(t *testing.T) {
	net, agents, ids, assignments := buildNet(t, 6)
	seed := seedFrom(0x66)

	// Find an assignment this node is actually drawn to audit, then break it.
	me := agents[0]
	s := &Scheduler{Agent: me, Transport: net}
	mine := s.MyAssignments(seed, 9, assignments, ids)
	if len(mine) == 0 {
		t.Skip("no duty drawn for this seed")
	}
	net.drops[mine[0].NodeID] = true

	results, err := s.RunEpoch(context.Background(), seed, 9, assignments, ids)
	if err != nil {
		t.Fatal(err)
	}
	var checked bool
	for _, r := range results {
		if r.Assignment.NodeID != mine[0].NodeID {
			continue
		}
		checked = true
		if r.Passed {
			t.Fatal("a node that lost the data passed its audit")
		}
		if r.Err != ErrProofFailed {
			t.Fatalf("expected a failed proof, got %v", r.Err)
		}
	}
	if !checked {
		t.Fatal("the broken assignment was not challenged")
	}
}

// Provider side: answering a real challenge produces a spooled receipt, and a
// witness attestation lands on it.
func TestAnswerChallengeSpoolsAttestedReceipt(t *testing.T) {
	net, agents, _, assignments := buildNet(t, 4)
	seed := seedFrom(0x77)
	provider, challenger, witness := agents[1], agents[0], agents[2]
	a := assignments[1]

	store, err := OpenReceiptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	c := challenger.IssueStorageChallenge(a.NodeID, a.AssignmentID, a.ShardRoot, seed,
		3, a.NumChunks, ChunksPerChallenge)

	s := &Scheduler{
		Agent: provider, Store: store, Transport: net,
		Attest: func(ctx context.Context, sr *SignedReceipt, ch StorageChallenge,
			resp StorageResponse, provenBytes uint64) error {
			sig, err := witness.AttestationFor(ch, resp, provenBytes)
			if err != nil {
				return err
			}
			if !sr.AddWitness(witness.Pub, sig) {
				t.Fatal("witness attestation rejected by the receipt")
			}
			return nil
		},
	}
	sr, _, err := s.AnswerChallenge(context.Background(), c, net.data[a.AssignmentID], net.chunk, a.Bytes)
	if err != nil {
		t.Fatalf("AnswerChallenge: %v", err)
	}
	if len(sr.Witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(sr.Witnesses))
	}
	if sr.Receipt.Quantity != a.Bytes {
		t.Fatal("receipt quantity is not the proven shard size")
	}

	spooled, err := store.ListEpoch(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(spooled) != 1 || spooled[0].Hash() != sr.Hash() {
		t.Fatal("receipt was not spooled")
	}
	if len(spooled[0].Witnesses) != 1 {
		t.Fatal("attestation did not persist with the receipt")
	}
}

// Witness and provider must derive the SAME receipt from the same evidence,
// otherwise the attestation signs a different hash and silently never counts.
func TestWitnessAndProviderDeriveTheSameReceipt(t *testing.T) {
	net, agents, _, assignments := buildNet(t, 4)
	provider, challenger := agents[2], agents[0]
	a := assignments[2]
	c := challenger.IssueStorageChallenge(a.NodeID, a.AssignmentID, a.ShardRoot,
		seedFrom(0x88), 4, a.NumChunks, ChunksPerChallenge)
	resp, err := net.Challenge(context.Background(), a.NodeID, c)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := provider.BuildReceipt(c, resp, a.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if CanonicalReceiptHash(ReceiptFor(c, resp, a.Bytes)) != sr.Hash() {
		t.Fatal("witness-side derivation differs from what the provider signed")
	}
}

func TestRunEpochRefusesAZeroSeed(t *testing.T) {
	net, agents, ids, assignments := buildNet(t, 4)
	s := &Scheduler{Agent: agents[0], Transport: net}
	var zero [32]byte
	if _, err := s.RunEpoch(context.Background(), zero, 1, assignments, ids); err != ErrNoSeed {
		t.Fatalf("a zero seed was accepted: %v", err)
	}
}
