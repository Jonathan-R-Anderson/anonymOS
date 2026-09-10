package facilitation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

// fakeStore mimics the shard store: content-addressed by sha256, like the real
// one, so ids round-trip the same way.
type fakeStore struct {
	shards     map[string][]byte
	unreadable map[string]bool
}

func newFakeStore(payloads ...[]byte) *fakeStore {
	s := &fakeStore{shards: map[string][]byte{}, unreadable: map[string]bool{}}
	for _, p := range payloads {
		sum := sha256.Sum256(p)
		s.shards[hex.EncodeToString(sum[:])] = p
	}
	return s
}

func (s *fakeStore) ListShardIDs() ([]string, error) {
	out := make([]string, 0, len(s.shards))
	for id := range s.shards {
		out = append(out, id)
	}
	return out, nil
}

func (s *fakeStore) ReadShard(id string) ([]byte, error) {
	if s.unreadable[id] {
		return nil, errors.New("disk error")
	}
	v, ok := s.shards[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func payload(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed ^ byte(i%251)
	}
	return b
}

func TestLocalAssignmentsDescribeWhatIsHeld(t *testing.T) {
	store := newFakeStore(payload(1, 10*1024), payload(2, 4096), payload(3, 100))
	var node [32]byte
	node[0] = 7

	got, err := LocalAssignments(node, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 assignments, got %d", len(got))
	}
	for _, a := range got {
		if a.NodeID != node {
			t.Fatal("assignment attributed to the wrong node")
		}
		if a.NumChunks == 0 || a.Bytes == 0 || a.ShardRoot == ([32]byte{}) {
			t.Fatalf("incomplete assignment: %+v", a)
		}
		// The root must be the one an auditor derives from the same bytes.
		data, _ := store.ReadShard(AssignmentToShardID(a.AssignmentID))
		if ShardRoot(data, AssignmentChunkSize) != a.ShardRoot {
			t.Fatal("advertised root does not match the stored bytes")
		}
	}
}

// Enumeration order must not change what is advertised.
func TestLocalAssignmentsAreStable(t *testing.T) {
	store := newFakeStore(payload(4, 8192), payload(5, 8192), payload(6, 8192))
	var node [32]byte
	first, _ := LocalAssignments(node, store)
	second, _ := LocalAssignments(node, store)
	for i := range first {
		if first[i].AssignmentID != second[i].AssignmentID || first[i].ShardRoot != second[i].ShardRoot {
			t.Fatal("assignment list is not stable across calls")
		}
	}
}

// A shard that cannot be read must not be advertised: claiming it would
// guarantee a failed audit and look like data loss rather than a disk fault.
func TestUnreadableShardsAreNotAdvertised(t *testing.T) {
	p := payload(7, 4096)
	store := newFakeStore(p, payload(8, 4096))
	sum := sha256.Sum256(p)
	store.unreadable[hex.EncodeToString(sum[:])] = true

	var node [32]byte
	got, err := LocalAssignments(node, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("unreadable shard was advertised: %d assignments", len(got))
	}
}

// Rot must surface as a mismatched root, not as a proof over the wrong data.
func TestCorruptedShardProducesADifferentRoot(t *testing.T) {
	original := payload(9, 8192)
	store := newFakeStore(original)
	var node [32]byte
	before, _ := LocalAssignments(node, store)

	id := AssignmentToShardID(before[0].AssignmentID)
	rotted := append([]byte(nil), original...)
	rotted[100] ^= 0xFF
	store.shards[id] = rotted

	after, _ := LocalAssignments(node, store)
	if after[0].ShardRoot == before[0].ShardRoot {
		t.Fatal("a corrupted shard advertised the same root")
	}
}

func TestShardIDRoundTrip(t *testing.T) {
	sum := sha256.Sum256([]byte("shard"))
	id := hex.EncodeToString(sum[:])
	a, err := ShardIDToAssignment(id)
	if err != nil {
		t.Fatal(err)
	}
	if AssignmentToShardID(a) != id {
		t.Fatal("shard id does not survive the round trip")
	}
	if _, err := ShardIDToAssignment("abcd"); err == nil {
		t.Fatal("a short id was accepted")
	}
}

// The whole node-side loop against a store: advertise, be challenged, prove,
// spool a receipt an auditor can verify.
func TestStoreBackedNodeAnswersAnAudit(t *testing.T) {
	data := payload(11, 32*1024)
	store := newFakeStore(data)

	ppub, ppriv, _ := ed25519.GenerateKey(nil)
	provider := NewAgent(ppub, ppriv)
	cpub, cpriv, _ := ed25519.GenerateKey(nil)
	challenger := NewAgent(cpub, cpriv)

	assignments, err := LocalAssignments(provider.NodeID(), store)
	if err != nil || len(assignments) != 1 {
		t.Fatalf("assignments: %v (%d)", err, len(assignments))
	}
	a := assignments[0]

	spool, err := OpenReceiptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	sched := &Scheduler{Agent: provider, Store: spool}
	responder := ChallengeResponder(sched, StoreShardLoader(store))

	c := challenger.IssueStorageChallenge(a.NodeID, a.AssignmentID, a.ShardRoot,
		seedFrom(0xA1), 21, a.NumChunks, ChunksPerChallenge)
	payloadBytes, _ := json.Marshal(c)
	answer, err := responder(context.Background(), payloadBytes)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	var resp StorageResponse
	if err := json.Unmarshal(answer, &resp); err != nil {
		t.Fatal(err)
	}
	if err := challenger.VerifyStorageResponse(c, resp); err != nil {
		t.Fatalf("auditor rejected a proof over real stored data: %v", err)
	}
	rows, err := spool.ListEpoch(21)
	if err != nil || len(rows) != 1 {
		t.Fatalf("receipt not spooled: %v (%d)", err, len(rows))
	}
	if rows[0].Receipt.Quantity != uint64(len(data)) {
		t.Fatalf("quantity %d, want the shard size %d", rows[0].Receipt.Quantity, len(data))
	}
}

func TestAdvertisableAssignmentsFitsTheRelayLimit(t *testing.T) {
	// The failure this prevents: a node holding more shards than the relay
	// accepts advertised all of them, was refused, and so advertised NOTHING —
	// leaving the node with the most to prove unable to prove any of it.
	all := make([]Assignment, MaxAdvertisedAssignments*4+137)
	for i := range all {
		all[i].AssignmentID[0] = byte(i)
		all[i].AssignmentID[1] = byte(i >> 8)
		all[i].AssignmentID[2] = byte(i >> 16)
	}
	got := AdvertisableAssignments(all, 0)
	if len(got) != MaxAdvertisedAssignments {
		t.Fatalf("advertised %d, want %d", len(got), MaxAdvertisedAssignments)
	}
}

func TestSmallNodesAdvertiseEverything(t *testing.T) {
	all := make([]Assignment, 12)
	for i := range all {
		all[i].AssignmentID[0] = byte(i)
	}
	if got := AdvertisableAssignments(all, 7); len(got) != len(all) {
		t.Fatalf("advertised %d of %d; a node under the cap must advertise all of it",
			len(got), len(all))
	}
}

func TestTheWindowCoversEveryShardOverTime(t *testing.T) {
	// Rotation is the whole justification for advertising a subset. If it did
	// not cover everything, some shards would simply never be auditable and the
	// node would be paid less than it earned, permanently.
	const total = MaxAdvertisedAssignments*3 + 41
	all := make([]Assignment, total)
	for i := range all {
		all[i].AssignmentID[0] = byte(i)
		all[i].AssignmentID[1] = byte(i >> 8)
		all[i].AssignmentID[2] = byte(i >> 16)
	}
	seen := map[[32]byte]bool{}
	for epoch := uint64(0); epoch < 8; epoch++ {
		for _, a := range AdvertisableAssignments(all, epoch) {
			seen[a.AssignmentID] = true
		}
	}
	if len(seen) != total {
		t.Fatalf("after 8 epochs only %d of %d shards had been advertised", len(seen), total)
	}
}

func TestTheWindowIsDeterministic(t *testing.T) {
	// A node must not be able to re-roll until it advertises only the shards it
	// still happens to hold.
	all := make([]Assignment, MaxAdvertisedAssignments*2)
	for i := range all {
		all[i].AssignmentID[0] = byte(i)
		all[i].AssignmentID[1] = byte(i >> 8)
	}
	first := AdvertisableAssignments(all, 5)
	second := AdvertisableAssignments(all, 5)
	for i := range first {
		if first[i].AssignmentID != second[i].AssignmentID {
			t.Fatal("two calls for the same epoch produced different windows")
		}
	}
}
