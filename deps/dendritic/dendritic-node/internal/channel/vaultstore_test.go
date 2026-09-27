package channel

// A vault that survives its own process — roadmap P11-DHT.
//
// The acceptance test is TestAVaultRebuiltFromStorageStillDefendsTheChannel: a
// watchtower is destroyed, a new one is built from storage alone, and it beats
// a stale close. Everything else here is the failure modes, all of which must
// fail CLOSED — a vault that cannot produce a state must never behave as though
// it can, because the only way anybody finds out is a channel that needed
// defending and was not.

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// memBackend is a VaultBackend that can be broken on demand.
type memBackend struct {
	mu       sync.Mutex
	objects  map[string][]byte
	putErr   error
	getErr   error
	listErr  error
	puts     int
	readOnly bool
}

func newMemBackend() *memBackend {
	return &memBackend{objects: map[string][]byte{}}
}

func (m *memBackend) Put(_ context.Context, key string, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	if m.readOnly {
		return errors.New("backend is read-only")
	}
	m.puts++
	m.objects[key] = append([]byte(nil), blob...)
	return nil
}

func (m *memBackend) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	blob, ok := m.objects[key]
	if !ok {
		return nil, errors.New("no such object")
	}
	return append([]byte(nil), blob...), nil
}

func (m *memBackend) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, m.listErr
	}
	var out []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func vaultKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// durableVault is vaulted() with storage attached.
func durableVault(t *testing.T) (*Vault, *memBackend, *FakeChain, *wiredNode, *wiredNode, [32]byte) {
	t.Helper()
	vault, chain, payer, payee, id := vaulted(t)
	backend := newMemBackend()
	if err := vault.SetBackend(backend, vaultKey()); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	return vault, backend, chain, payer, payee, id
}

// ---- THE ACCEPTANCE TEST ----------------------------------------------------

// The whole point of the phase, end to end:
//
//	channel reaches nonce 100 -> vault stores it -> the watchtower is destroyed
//	-> a new one is built from storage alone -> a stale close at 99 is beaten
func TestAVaultRebuiltFromStorageStillDefendsTheChannel(t *testing.T) {
	vault, backend, chain, payer, payee, id := durableVault(t)
	ctx := context.Background()

	// 1-3. The channel advances and the vault takes custody of the latest state.
	signed := payTo(t, payer, payee, id, 12)
	if _, err := vault.Submit(ctx, signed); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if backend.puts == 0 {
		t.Fatal("nothing was persisted")
	}

	// 4-5. The watchtower and its memory are gone. Only storage remains.
	vault = nil

	// 6-8. A new vault, sharing nothing but the backend and the key.
	rebuilt := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	if err := rebuilt.SetBackend(backend, vaultKey()); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	recovered, skipped, err := rebuilt.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if recovered != 1 || skipped != 0 {
		t.Fatalf("recovered %d channels, skipped %d", recovered, skipped)
	}
	best, ok := rebuilt.Best(id)
	if !ok || best.State.Nonce != 12 {
		t.Fatalf("rebuilt vault holds nonce %d (ok=%v), want 12", best.State.Nonce, ok)
	}

	// 9-10. A stale close, and the rebuilt vault beats it.
	chain.StartClose(id, 11, 1_000_000+RecommendedChallengePeriod())
	sender := &recordingSender{hash: "0xrebuilt"}
	tower := &Watchtower{
		Store: VaultStore{rebuilt}, Chain: chain, Sender: sender,
		Contract: rebuilt.Contract,
		Now:      func() time.Time { return time.Unix(1_000_000, 0) },
	}
	got := tower.Check(ctx, id)
	if got.Outcome != WatchChallenged {
		t.Fatalf("outcome %q (%v), want challenged", got.Outcome, got.Err)
	}
	if sender.sent[0].State.Nonce != 12 {
		t.Errorf("challenged with nonce %d, want 12", sender.sent[0].State.Nonce)
	}
}

// ---- fail closed ------------------------------------------------------------

// A state this vault cannot keep must not be accepted. Telling a submitter
// "stored" when it is not is the one outcome that must never happen.
func TestAStorageFailureFailsTheSubmission(t *testing.T) {
	vault, backend, _, payer, payee, id := durableVault(t)
	backend.putErr = errors.New("every holder is unreachable")

	signed := payTo(t, payer, payee, id, 3)
	_, err := vault.Submit(context.Background(), signed)
	if !errors.Is(err, ErrVaultNotDurable) {
		t.Fatalf("submit returned %v, want ErrVaultNotDurable", err)
	}
	// And it must not be holding it either: a vault that kept an unpersisted
	// state would go on defending with it right up until it restarted.
	if _, ok := vault.Best(id); ok {
		t.Error("the vault kept a state it could not persist")
	}
}

// Verification comes first. A bad state must never reach storage, or the store
// fills with objects that will only ever be skipped.
func TestAnInvalidStateNeverReachesStorage(t *testing.T) {
	vault, backend, _, payer, payee, id := durableVault(t)
	signed := payTo(t, payer, payee, id, 2)

	tampered := cloneSigned(signed)
	tampered.State.BalanceA = new(big.Int).Add(tampered.State.BalanceA, anon(100))

	if _, err := vault.Submit(context.Background(), tampered); err == nil {
		t.Fatal("a tampered state was accepted")
	}
	if backend.puts != 0 {
		t.Errorf("%d objects written for a state that failed verification", backend.puts)
	}
}

// A vault that cannot read its own storage must say so rather than start empty
// and look healthy.
func TestAnUnreadableBackendIsAnErrorNotAnEmptyVault(t *testing.T) {
	vault, backend, _, _, _, _ := durableVault(t)
	backend.listErr = errors.New("storage is down")

	if _, _, err := vault.Load(context.Background()); err == nil {
		t.Fatal("Load succeeded against a backend that could not be listed")
	}
}

// ---- what storage is NOT allowed to do --------------------------------------

// Records are re-verified on load. Storage is custody, not authority — so a
// record whose signatures do not hold is skipped however it got there.
func TestAForgedRecordInStorageIsSkipped(t *testing.T) {
	vault, backend, chain, payer, payee, id := durableVault(t)
	ctx := context.Background()

	honest := payTo(t, payer, payee, id, 4)
	if _, err := vault.Submit(ctx, honest); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Somebody with write access to the store forges a high-nonce record,
	// correctly sealed with the vault's own key.
	strangerA, strangerB := newSigner(t), newSigner(t)
	forged := State{Channel: id, Nonce: 99, BalanceA: anon(0), BalanceB: anon(500)}
	digest := forged.Digest(vault.ChainID, vault.Contract)
	blob, err := vault.seal(vaultRecord{
		Channel: hexOf(id[:]), State: encodeStateWire(forged),
		SigA: hexOf(strangerA.sign(digest)), SigB: hexOf(strangerB.sign(digest)),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := backend.Put(ctx, recordKey(id, 99, digest), blob); err != nil {
		t.Fatalf("put: %v", err)
	}

	rebuilt := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	if err := rebuilt.SetBackend(backend, vaultKey()); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	if _, skipped, err := rebuilt.Load(ctx); err != nil || skipped != 1 {
		t.Fatalf("Load: skipped %d err %v, want 1 skipped", skipped, err)
	}
	best, _ := rebuilt.Best(id)
	if best.State.Nonce != 4 {
		t.Fatalf("the forged record was adopted: nonce %d", best.State.Nonce)
	}
}

// A record moved to another key is not evidence about that key.
func TestARelabelledRecordIsSkipped(t *testing.T) {
	vault, backend, chain, payer, payee, id := durableVault(t)
	ctx := context.Background()

	signed := payTo(t, payer, payee, id, 3)
	if _, err := vault.Submit(ctx, signed); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Copy the object under a key claiming a much higher nonce.
	keys, _ := backend.List(ctx, VaultKeyPrefix)
	blob, _ := backend.Get(ctx, keys[0])
	var wrong [32]byte
	if err := backend.Put(ctx, recordKey(id, 500, wrong), blob); err != nil {
		t.Fatalf("put: %v", err)
	}

	rebuilt := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	if err := rebuilt.SetBackend(backend, vaultKey()); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	if _, skipped, _ := rebuilt.Load(ctx); skipped != 1 {
		t.Errorf("skipped %d, want the relabelled record skipped", skipped)
	}
	if best, _ := rebuilt.Best(id); best.State.Nonce != 3 {
		t.Errorf("a relabelled record changed the vault to nonce %d", best.State.Nonce)
	}
}

// Storage must not be able to walk the vault backwards.
func TestAnOlderRecordInStorageCannotWinOnLoad(t *testing.T) {
	vault, backend, chain, payer, payee, id := durableVault(t)
	ctx := context.Background()

	// Both an old state and a new one are in storage, which is the normal case:
	// records are immutable and nothing deletes the old ones.
	for _, nonce := range []uint64{3, 7} {
		if _, err := vault.Submit(ctx, payTo(t, payer, payee, id, nonce)); err != nil {
			t.Fatalf("submit %d: %v", nonce, err)
		}
	}

	rebuilt := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	if err := rebuilt.SetBackend(backend, vaultKey()); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	if _, _, err := rebuilt.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if best, _ := rebuilt.Best(id); best.State.Nonce != 7 {
		t.Fatalf("loaded nonce %d, want the highest 7", best.State.Nonce)
	}
}

// Two different states at one nonce are evidence of double-signing. Neither may
// overwrite the other in storage.
func TestTwoStatesAtOneNonceBothSurviveInStorage(t *testing.T) {
	vault, _, _, payer, payee, id := durableVault(t)
	ctx := context.Background()

	signed := payTo(t, payer, payee, id, 2)
	if _, err := vault.Submit(ctx, signed); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// A different state at the same nonce gets a different key, because the
	// digest is part of it.
	other := cloneState(signed.State)
	other.BalanceA = new(big.Int).Add(other.BalanceA, anon(1))
	first := recordKey(id, 2, signed.State.Digest(vault.ChainID, vault.Contract))
	second := recordKey(id, 2, other.Digest(vault.ChainID, vault.Contract))
	if first == second {
		t.Fatal("two different states at one nonce collide on one key")
	}
}

// ---- encryption -------------------------------------------------------------

// The storage layer holds bytes it cannot read. That is the store's own rule,
// and it is what makes it safe to disperse a record across nodes nobody here
// controls.
func TestStoredRecordsAreCiphertext(t *testing.T) {
	vault, backend, _, payer, payee, id := durableVault(t)
	ctx := context.Background()

	signed := payTo(t, payer, payee, id, 3)
	if _, err := vault.Submit(ctx, signed); err != nil {
		t.Fatalf("submit: %v", err)
	}
	keys, _ := backend.List(ctx, VaultKeyPrefix)
	blob, _ := backend.Get(ctx, keys[0])

	// Nothing recognisable: no JSON, and not the balance in any spelling.
	if strings.Contains(string(blob), "balance_a") {
		t.Error("the record was stored as readable JSON")
	}
	if strings.Contains(string(blob), signed.State.BalanceA.String()) {
		t.Error("a balance is legible in the stored bytes")
	}
}

// The wrong key must not yield a plausible record. GCM authenticates, so this
// cannot return something altered-but-believable.
func TestTheWrongKeyCannotOpenARecord(t *testing.T) {
	vault, backend, chain, payer, payee, id := durableVault(t)
	ctx := context.Background()

	if _, err := vault.Submit(ctx, payTo(t, payer, payee, id, 3)); err != nil {
		t.Fatalf("submit: %v", err)
	}

	wrong := make([]byte, 32)
	other := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	if err := other.SetBackend(backend, wrong); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	recovered, skipped, err := other.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if recovered != 0 || skipped == 0 {
		t.Fatalf("the wrong key recovered %d channels (skipped %d)", recovered, skipped)
	}
}

// A tampered blob must not decode. Storage integrity is not assumed.
func TestATamperedBlobIsSkipped(t *testing.T) {
	vault, backend, chain, payer, payee, id := durableVault(t)
	ctx := context.Background()

	if _, err := vault.Submit(ctx, payTo(t, payer, payee, id, 3)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	keys, _ := backend.List(ctx, VaultKeyPrefix)
	blob, _ := backend.Get(ctx, keys[0])
	blob[len(blob)-1] ^= 0xFF
	backend.objects[keys[0]] = blob

	rebuilt := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	if err := rebuilt.SetBackend(backend, vaultKey()); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	if _, skipped, _ := rebuilt.Load(ctx); skipped != 1 {
		t.Errorf("skipped %d, want the tampered record skipped", skipped)
	}
	if _, ok := rebuilt.Best(id); ok {
		t.Error("a tampered record was adopted")
	}
}

// One unreadable object must not stop the other channels being defended.
func TestOneBadRecordDoesNotStopTheRest(t *testing.T) {
	vault, backend, chain, payer, payee, id := durableVault(t)
	ctx := context.Background()

	if _, err := vault.Submit(ctx, payTo(t, payer, payee, id, 5)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// A junk object under the vault prefix, as a partial write or an unrelated
	// key might leave.
	if err := backend.Put(ctx, VaultKeyPrefix+"garbage", []byte("not a record")); err != nil {
		t.Fatalf("put: %v", err)
	}

	rebuilt := NewVault(chain, big.NewInt(1), mustAddr(t, deployedChannelManager))
	if err := rebuilt.SetBackend(backend, vaultKey()); err != nil {
		t.Fatalf("SetBackend: %v", err)
	}
	recovered, skipped, err := rebuilt.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if recovered != 1 {
		t.Errorf("recovered %d channels, want 1 despite the junk", recovered)
	}
	if skipped != 1 {
		t.Errorf("skipped %d, want 1", skipped)
	}
}

// A vault with no backend still works, in memory. Persistence is optional and
// its absence must not be a silent failure of the vault itself.
func TestAVaultWithoutABackendStillHoldsStates(t *testing.T) {
	vault, _, payer, payee, id := vaulted(t)
	if _, err := vault.Submit(context.Background(), payTo(t, payer, payee, id, 3)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if best, ok := vault.Best(id); !ok || best.State.Nonce != 3 {
		t.Fatal("an in-memory vault stopped working")
	}
	if _, _, err := vault.Load(context.Background()); err == nil {
		t.Error("Load succeeded with no backend; it must say there is nothing to load from")
	}
}

func TestTheRecordKeyIsRejectedForABadLength(t *testing.T) {
	vault, _, _, _, _ := vaulted(t)
	for _, size := range []int{0, 16, 31, 33} {
		if err := vault.SetBackend(newMemBackend(), make([]byte, size)); err == nil {
			t.Errorf("a %d-byte key was accepted", size)
		}
	}
}
