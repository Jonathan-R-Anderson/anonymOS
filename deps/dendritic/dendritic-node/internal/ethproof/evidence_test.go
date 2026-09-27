package ethproof

// Verified evidence and its durable form — roadmap P12-3.
//
// The rule under test: ONLY VERIFIED EVIDENCE ENTERS THE DATASET, and nothing
// leaves it unverified either. A DHT that could be filled with plausible
// unverifiable records would be a second source of unchecked truth, which is
// what this whole phase exists to avoid building.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type memEvidence struct {
	mu      sync.Mutex
	objects map[string][]byte
	putErr  error
}

func newMemEvidence() *memEvidence {
	return &memEvidence{objects: map[string][]byte{}}
}

func (m *memEvidence) Put(_ context.Context, key string, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	m.objects[key] = append([]byte(nil), blob...)
	return nil
}

func (m *memEvidence) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	blob, ok := m.objects[key]
	if !ok {
		return nil, errors.New("no such object")
	}
	return append([]byte(nil), blob...), nil
}

func (m *memEvidence) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

// A store with a trivial seal. The real one shares the vault's AEAD; encryption
// is not what these tests are about.
func testStore(b EvidenceBackend) *EvidenceStore {
	return &EvidenceStore{
		Backend: b,
		Seal:    func(p []byte) ([]byte, error) { return append([]byte("s:"), p...), nil },
		Open: func(c []byte) ([]byte, error) {
			if !strings.HasPrefix(string(c), "s:") {
				return nil, errors.New("not sealed by us")
			}
			return c[2:], nil
		},
	}
}

// liveEvidence builds a real record from mainnet, which is the only way to get
// a genuinely valid proof to test the storage rules against.
func liveEvidence(t *testing.T) Evidence {
	t.Helper()
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var id [32]byte
	id[31] = 1
	base := StorageSlotKey(id, 0)
	slots := [][32]byte{base, SlotAt(base, 4)}

	header, err := c.Header(ctx, "latest")
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	proof, err := c.GetProof(ctx, deployedChannelManager, slots, header.Number)
	if err != nil {
		t.Fatalf("getProof: %v", err)
	}
	m, err := VerifiedRead(ctx, c, deployedChannelManager, slots, header.Number)
	if err != nil {
		t.Fatalf("VerifiedRead: %v", err)
	}
	e, err := EvidenceFrom(1, header, "0x"+strings.Repeat("00", 31)+"01",
		deployedChannelManager, slots, proof, m)
	if err != nil {
		t.Fatalf("EvidenceFrom: %v", err)
	}
	return e
}

// ---- the rule ---------------------------------------------------------------

// Unverified evidence must not enter the dataset. Enforced by the unexported
// guard, so a caller cannot construct its way around it.
func TestUnverifiedEvidenceCannotBeStored(t *testing.T) {
	store := testStore(newMemEvidence())
	// Hand-built: every field populated, `verified` unset because nothing
	// outside this package can set it.
	hand := Evidence{
		ChainID: 1, BlockNumber: 100, BlockHash: "0xaa", StateRoot: "0xbb",
		Contract: deployedChannelManager, ChannelID: "0xcc",
	}
	if hand.Verified() {
		t.Fatal("a hand-built record claimed to be verified")
	}
	if err := store.Put(context.Background(), hand); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("Put returned %v, want ErrNotVerified", err)
	}
}

// A record whose stated value disagrees with its own proof is the forgery this
// design exists to catch.
func TestARecordThatContradictsItsOwnProofIsRefused(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	e := liveEvidence(t)

	forged := e
	forged.Values = append([]string(nil), e.Values...)
	forged.Values[0] = "0x" + strings.Repeat("ff", 32)

	if _, err := forged.Verify(); err == nil {
		t.Fatal("a record stating a value its proof does not commit to verified")
	}
}

// Tampering with the proof itself must break verification.
func TestATamperedProofInARecordIsRefused(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	e := liveEvidence(t)

	broken := e
	broken.AccountProof = append([]string(nil), e.AccountProof...)
	last := len(broken.AccountProof) - 1
	node := []byte(broken.AccountProof[last])
	node[len(node)/2] = 'a' // corrupt a hex digit
	broken.AccountProof[last] = string(node)

	if _, err := broken.Verify(); err == nil {
		t.Fatal("a record with a corrupted account proof verified")
	}
}

// The record must re-verify with no network at all. That is what makes a DHT
// holder unable to alter what it says.
func TestARecordVerifiesOffline(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	e := liveEvidence(t)

	// Round-trip through JSON, as storage does, then verify with no client.
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Evidence
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Verified() {
		t.Fatal("the verified flag survived serialisation; it must not")
	}
	again, err := decoded.Verify()
	if err != nil {
		t.Fatalf("a real record did not verify offline: %v", err)
	}
	if !again.Verified() {
		t.Fatal("Verify did not mark the record verified")
	}
	t.Logf("record: %d bytes of JSON, verifies with no network", len(raw))
}

// ---- storage ----------------------------------------------------------------

func TestStoredEvidenceRoundTrips(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	backend := newMemEvidence()
	store := testStore(backend)
	ctx := context.Background()

	e := liveEvidence(t)
	if err := store.Put(ctx, e); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(ctx, e.Key())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Verified() {
		t.Fatal("a fetched record was not re-verified")
	}
	if got.BlockNumber != e.BlockNumber || got.Values[0] != e.Values[0] {
		t.Error("the record changed across storage")
	}
}

// Storage is custody, not authority: a record altered in place must not be
// returned, however it got there.
func TestATamperedStoredRecordIsRefusedOnRead(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	backend := newMemEvidence()
	store := testStore(backend)
	ctx := context.Background()

	e := liveEvidence(t)
	if err := store.Put(ctx, e); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Somebody with write access rewrites the stored value, keeping the record
	// otherwise intact and correctly sealed.
	blob, _ := backend.Get(ctx, e.Key())
	var stored Evidence
	if err := json.Unmarshal(blob[2:], &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	stored.Values[0] = "0x" + strings.Repeat("ee", 32)
	rewritten, _ := json.Marshal(stored)
	backend.objects[e.Key()] = append([]byte("s:"), rewritten...)

	if _, err := store.Get(ctx, e.Key()); err == nil {
		t.Fatal("a rewritten record was returned as evidence")
	}
}

// A record moved to another key is not evidence about that key.
func TestARelabelledRecordIsRefused(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	backend := newMemEvidence()
	store := testStore(backend)
	ctx := context.Background()

	e := liveEvidence(t)
	if err := store.Put(ctx, e); err != nil {
		t.Fatalf("Put: %v", err)
	}
	blob, _ := backend.Get(ctx, e.Key())
	elsewhere := ChannelPrefix(1, deployedChannelManager, "0x"+strings.Repeat("77", 32)) +
		"00000000000000000001/deadbeef"
	backend.objects[elsewhere] = blob

	if _, err := store.Get(ctx, elsewhere); err == nil {
		t.Fatal("a record filed under the wrong key was accepted")
	}
}

// ---- keys -------------------------------------------------------------------

// Two records at one height — which is what a reorg produces — must both
// survive. Losing the losing side destroys the evidence that the reorg happened.
func TestAReorgProducesTwoRecordsNotOne(t *testing.T) {
	a := Evidence{ChainID: 1, BlockNumber: 500, BlockHash: "0xaaaa",
		Contract: deployedChannelManager, ChannelID: "0x01"}
	b := a
	b.BlockHash = "0xbbbb"

	if a.Key() == b.Key() {
		t.Fatal("two blocks at one height collide on one key")
	}
	if !strings.HasPrefix(a.Key(), ChannelPrefix(1, deployedChannelManager, "0x01")) {
		t.Errorf("key %q is not under its channel prefix", a.Key())
	}
}

// Zero-padded heights make a lexical listing a numeric one, which is what
// Latest relies on.
func TestKeysSortNumerically(t *testing.T) {
	mk := func(n uint64) string {
		return Evidence{ChainID: 1, BlockNumber: n, BlockHash: "0xaa",
			Contract: deployedChannelManager, ChannelID: "0x01"}.Key()
	}
	if !(mk(9) < mk(10) && mk(10) < mk(100) && mk(100) < mk(1_000_000)) {
		t.Errorf("keys do not sort numerically:\n %s\n %s\n %s", mk(9), mk(10), mk(100))
	}
}

func TestLatestPrefersTheHighestBlock(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	backend := newMemEvidence()
	store := testStore(backend)
	ctx := context.Background()

	e := liveEvidence(t)
	if err := store.Put(ctx, e); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// An unverifiable record at a HIGHER block. Latest must skip it rather than
	// return it or give up.
	junk := append([]byte("s:"), []byte(`{"chain_id":1}`)...)
	higher := Evidence{ChainID: e.ChainID, BlockNumber: e.BlockNumber + 1,
		BlockHash: "0xdead", Contract: e.Contract, ChannelID: e.ChannelID}.Key()
	backend.objects[higher] = junk

	got, ok, err := store.Latest(ctx, e.ChainID, e.Contract, e.ChannelID)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if !ok {
		t.Fatal("Latest found nothing though a good record is held")
	}
	if got.BlockNumber != e.BlockNumber {
		t.Errorf("Latest returned block %d, want the verifiable %d",
			got.BlockNumber, e.BlockNumber)
	}
}

func TestLatestOnAnEmptyStoreIsNotAnError(t *testing.T) {
	store := testStore(newMemEvidence())
	_, ok, err := store.Latest(context.Background(), 1, deployedChannelManager, "0x01")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if ok {
		t.Error("an empty store reported holding evidence")
	}
}

// A key must be canonical however the record was built. A mixed-case address
// that filed outside its own prefix would be present in the store and invisible
// to the watchtower — the worst way to lose evidence.
func TestKeysAreCanonicalRegardlessOfCase(t *testing.T) {
	lower := Evidence{ChainID: 1, BlockNumber: 7, BlockHash: "0xAABB",
		Contract: strings.ToLower(deployedChannelManager), ChannelID: "0xAB"}
	mixed := Evidence{ChainID: 1, BlockNumber: 7, BlockHash: "0xaabb",
		Contract: deployedChannelManager, ChannelID: "0xab"}

	if lower.Key() != mixed.Key() {
		t.Fatalf("case changed the key:\n %s\n %s", lower.Key(), mixed.Key())
	}
	for _, e := range []Evidence{lower, mixed} {
		if !strings.HasPrefix(e.Key(), ChannelPrefix(1, deployedChannelManager, "0xAB")) {
			t.Errorf("key %q is not under its channel prefix", e.Key())
		}
	}
}
