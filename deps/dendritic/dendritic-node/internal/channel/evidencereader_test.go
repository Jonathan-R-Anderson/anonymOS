package channel

// The watchtower on verified evidence, and how every layer fails — P12-6, P12-7.
//
// The table this works through:
//
//	corrupt stored object          reject
//	unreachable storage            unavailable, never fabricated
//	wrong state root               reject
//	invalid storage proof          reject
//	valid proof + untrusted header REJECT   <- the P12-5 boundary
//	stale index                    rebuild from the store
//	local index loss               evidence survives
//	watchtower restart             reconstruct
//	no evidence                    a failure to SEE, not a fact about the world
//	parties disagree with the id   reject
//
// The last group matters most: a watchtower that treats "I cannot see" as
// "nothing is happening" is a watchtower that does nothing during the incident
// it exists for.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

// ---- a store that can be broken --------------------------------------------

type evBackend struct {
	mu      sync.Mutex
	objects map[string][]byte
	getErr  error
	listErr error
}

func newEvBackend() *evBackend { return &evBackend{objects: map[string][]byte{}} }

func (b *evBackend) Put(_ context.Context, key string, blob []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[key] = append([]byte(nil), blob...)
	return nil
}

func (b *evBackend) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.getErr != nil {
		return nil, b.getErr
	}
	blob, ok := b.objects[key]
	if !ok {
		return nil, errors.New("no such object")
	}
	return append([]byte(nil), blob...), nil
}

func (b *evBackend) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listErr != nil {
		return nil, b.listErr
	}
	var out []string
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func evStore(b ethproof.EvidenceBackend) *ethproof.EvidenceStore {
	return &ethproof.EvidenceStore{
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

// unanchoredVerifier is the state of the world today: no trust anchor, so no
// header can be established as Ethereum mainnet's. Tests asserting
// ErrNoTrustAnchor are the ones to revisit when P12-5 lands.
func unanchoredVerifier() *ethproof.HeaderVerifier {
	return &ethproof.HeaderVerifier{
		ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key",
	}
}

// anchoredVerifier gets past the anchor check, so a test can reach the layers
// behind it. It does NOT make header verification work — nothing does yet — so
// it is only usable where no record is actually found.
func anchoredVerifier(t *testing.T) *ethproof.HeaderVerifier {
	t.Helper()
	v := unanchoredVerifier()
	if err := v.SetAnchor(ethproof.Anchor{
		Kind: ethproof.AnchorSyncCommittee, Source: "https://beaconstate.example",
	}); err != nil {
		t.Fatalf("SetAnchor: %v", err)
	}
	return v
}

func evidenceReader(t *testing.T, b *evBackend) *EvidenceChainReader {
	t.Helper()
	ix := ethproof.NewIndex()
	if _, err := ix.Rebuild(context.Background(), b); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	return &EvidenceChainReader{
		Index: ix, Store: evStore(b), Verifier: unanchoredVerifier(), ChainID: 1,
	}
}

// storeRecord files a record's JSON under its own key, sealed.
func storeRecord(t *testing.T, b *evBackend, key string, body map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := b.Put(context.Background(), key, append([]byte("s:"), raw...)); err != nil {
		t.Fatalf("put: %v", err)
	}
}

// ---- the P12-5 boundary, as the watchtower experiences it -------------------

// THE HEADLINE. A record can be internally perfect and still not be known to be
// Ethereum's, and the watchtower must not act on it.
func TestTheWatchtowerRefusesEvidenceWithoutATrustAnchor(t *testing.T) {
	backend := newEvBackend()
	var id [32]byte
	id[31] = 7
	key := "eth/1/ae70526931ff460894133201f6c8ca91bba0e177/" +
		hex.EncodeToString(id[:]) + "/00000000000000000100/aabb"
	storeRecord(t, backend, key, map[string]any{"chain_id": 1, "block_number": 256})

	reader := evidenceReader(t, backend)
	_, err := reader.ReadChannel(context.Background(),
		mustAddr(t, deployedChannelManager), id)

	if err == nil {
		t.Fatal("the watchtower read a channel with no trust anchor")
	}
	if !errors.Is(err, ethproof.ErrNoTrustAnchor) {
		t.Fatalf("got %v, want ErrNoTrustAnchor", err)
	}
}

// And the watchtower's own reaction: loud, not quiet.
func TestAnUnanchoredChainMakesTheWatchtowerFailNotSleep(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	// The channel must be one this node actually holds a state for; Check
	// returns Quiet for anything else, which is correct — a watchtower defends
	// what it can defend WITH.
	if _, err := payer.coord.Pay(context.Background(), id, intent(1),
		payTransition(1), directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	backend := newEvBackend()

	tower := &Watchtower{
		Store: payee.store, Chain: evidenceReader(t, backend),
		Contract: mustAddr(t, deployedChannelManager),
	}
	got := tower.Check(context.Background(), id)

	if got.Outcome != WatchFailed {
		t.Fatalf("outcome %q; a chain it cannot verify must not read as quiet", got.Outcome)
	}
	if got.Err == nil {
		t.Fatal("no error recorded; this must reach a human")
	}
}

// ---- no evidence is not no channel ------------------------------------------

// The distinction that stops an empty store from looking like a world in which
// every channel has ceased to exist.
func TestNoEvidenceIsNotAnAbsentChannel(t *testing.T) {
	reader := evidenceReader(t, newEvBackend())
	// Past the anchor, so this tests the distinction it is about rather than
	// the anchor refusal that guards everything.
	reader.Verifier = anchoredVerifier(t)
	var id [32]byte
	id[31] = 1

	_, err := reader.ReadChannel(context.Background(),
		mustAddr(t, deployedChannelManager), id)

	if !errors.Is(err, ErrNoVerifiedEvidence) {
		t.Fatalf("got %v, want ErrNoVerifiedEvidence", err)
	}
	if errors.Is(err, ErrChannelNotOnChain) {
		t.Fatal("an empty store reported that the channel does not exist")
	}
}

// ---- storage failures --------------------------------------------------------

// A record that cannot be opened is not a channel with unknown fields.
func TestACorruptStoredObjectIsRejected(t *testing.T) {
	backend := newEvBackend()
	var id [32]byte
	id[31] = 3
	key := "eth/1/ae70526931ff460894133201f6c8ca91bba0e177/" +
		hex.EncodeToString(id[:]) + "/00000000000000000100/aabb"
	// Not sealed by us, so Open fails.
	_ = backend.Put(context.Background(), key, []byte("garbage"))

	reader := evidenceReader(t, backend)
	if _, err := reader.ReadChannel(context.Background(),
		mustAddr(t, deployedChannelManager), id); err == nil {
		t.Fatal("a corrupt object produced a channel")
	}
}

// Unreachable storage is unavailability. It must never be fabricated into an
// answer, and it must not read as "no such channel".
func TestUnreachableStorageIsUnavailableNotEmpty(t *testing.T) {
	backend := newEvBackend()
	var id [32]byte
	id[31] = 4
	key := "eth/1/ae70526931ff460894133201f6c8ca91bba0e177/" +
		hex.EncodeToString(id[:]) + "/00000000000000000100/aabb"
	storeRecord(t, backend, key, map[string]any{"chain_id": 1})

	reader := evidenceReader(t, backend)
	backend.getErr = errors.New("every holder is unreachable")

	_, err := reader.ReadChannel(context.Background(),
		mustAddr(t, deployedChannelManager), id)
	if err == nil {
		t.Fatal("unreachable storage produced a channel")
	}
	if errors.Is(err, ErrChannelNotOnChain) {
		t.Fatal("unreachable storage reported the channel absent")
	}
}

// ---- index behaviour ---------------------------------------------------------

// Losing the local index costs a listing, not evidence.
func TestTheIndexRebuildsAfterLocalLoss(t *testing.T) {
	backend := newEvBackend()
	var id [32]byte
	id[31] = 5
	key := "eth/1/ae70526931ff460894133201f6c8ca91bba0e177/" +
		hex.EncodeToString(id[:]) + "/00000000000000000200/ccdd"
	storeRecord(t, backend, key, map[string]any{"chain_id": 1})

	// A watchtower restarting with nothing local.
	fresh := ethproof.NewIndex()
	noted, err := fresh.Rebuild(context.Background(), backend)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if noted != 1 {
		t.Fatalf("rebuilt %d entries, want 1", noted)
	}
	if _, ok := fresh.Highest(1, deployedChannelManager, hex.EncodeToString(id[:])); !ok {
		t.Fatal("the rebuilt index does not know the channel")
	}
}

// A stale index points at objects that may be gone. It must not invent them.
func TestAStaleIndexDoesNotInventEvidence(t *testing.T) {
	backend := newEvBackend()
	var id [32]byte
	id[31] = 6
	key := "eth/1/ae70526931ff460894133201f6c8ca91bba0e177/" +
		hex.EncodeToString(id[:]) + "/00000000000000000300/eeff"
	storeRecord(t, backend, key, map[string]any{"chain_id": 1})

	reader := evidenceReader(t, backend) // index built while the object existed

	// The object is dropped; the index still points at it.
	backend.mu.Lock()
	delete(backend.objects, key)
	backend.mu.Unlock()

	if _, err := reader.ReadChannel(context.Background(),
		mustAddr(t, deployedChannelManager), id); err == nil {
		t.Fatal("a stale index produced a channel for an object that is gone")
	}
}

// ---- configuration -----------------------------------------------------------

func TestAnUnconfiguredReaderRefuses(t *testing.T) {
	var id [32]byte
	for _, r := range []*EvidenceChainReader{
		{},
		{Index: ethproof.NewIndex()},
		{Index: ethproof.NewIndex(), Store: evStore(newEvBackend())},
	} {
		if _, err := r.ReadChannel(context.Background(),
			mustAddr(t, deployedChannelManager), id); err == nil {
			t.Error("an unconfigured reader returned a channel")
		}
	}
}

// The slot layout the reader decodes must be the one the acquisition layer
// asks for, or the two drift into disagreeing about which slot is which.
func TestChannelSlotsMatchesWhatTheReaderDecodes(t *testing.T) {
	var id [32]byte
	id[31] = 9
	slots := ChannelSlots(id)
	if len(slots) != slotCount {
		t.Fatalf("ChannelSlots returned %d, the reader decodes %d", len(slots), slotCount)
	}
	base := ethproof.StorageSlotKey(id, 0)
	if slots[0] != base {
		t.Error("slot 0 is not the channel's base slot")
	}
	if slots[slotNonce] != ethproof.SlotAt(base, uint64(slotNonce)) {
		t.Error("the nonce slot is not where the reader looks for it")
	}
	// Every slot distinct: a duplicate would silently read one field as another.
	seen := map[[32]byte]bool{}
	for i, s := range slots {
		if seen[s] {
			t.Fatalf("slot %d duplicates an earlier one", i)
		}
		seen[s] = true
	}
}

// The reader must satisfy the interface the watchtower already uses, so
// swapping the chain out is a substitution rather than a redesign.
func TestTheReaderIsADropInChainReader(t *testing.T) {
	var r ChainReader = &EvidenceChainReader{}
	if r == nil {
		t.Fatal("unreachable")
	}
}
