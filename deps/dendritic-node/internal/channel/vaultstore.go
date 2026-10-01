package channel

// Making the vault survive its own process — roadmap P11-DHT.
//
// P11 built a vault that verifies everything and holds it in memory. A restart
// therefore loses every state it was defending with, which means the watchtower
// comes back believing it has nothing to challenge WITH while still believing
// it has channels to challenge FOR. That is the worst arrangement available: it
// looks like a working watchtower.
//
// WHY THE DHT AND NOT A FILE
// --------------------------
// A co-signed state is small, immutable, cryptographically self-describing, and
// — unlike the Ethereum node's database — NOT re-derivable from anywhere. If it
// is lost, nobody can prove what a channel is worth. That is precisely the
// shape the site's erasure-coded store is good at, and at 6+3 over 1 MiB chunks
// the 1.5x overhead on a few hundred bytes is irrelevant.
//
// THE HIERARCHY, WHICH THIS DOES NOT CHANGE
// -----------------------------------------
//	Ethereum         authoritative on what a channel IS
//	co-signed state  authoritative on what the parties AGREED
//	this store       durable custody of the evidence, and nothing more
//
// The DHT is not consulted to decide anything. A record it returns is re-
// verified from scratch before it is believed, exactly as a record arriving
// from a stranger over the network would be — because that is what it is. The
// storage layer holds ciphertext it cannot read and has no say in what is true.
//
// ORDER OF OPERATIONS, AND WHY
// ----------------------------
//	verify  ->  persist  ->  activate
//
// Persisting BEFORE activating is the safe order. Crashing between them leaves
// a state in the store that memory has not adopted, and recovery finds it. The
// reverse order leaves a vault claiming to hold a state it cannot produce, and
// the only way anybody discovers that is a channel that needed defending and
// was not.
//
// So a persistence failure is a SUBMISSION failure. The submitter is told, and
// can try again or try another vault. Accepting a state this vault cannot keep
// would be worse than refusing it.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ErrVaultNotDurable is returned when a state verified but could not be stored.
//
// Deliberately distinct from a verification failure: one means the submitter is
// wrong, the other means this vault is broken. Conflating them would have an
// operator chasing a peer's signatures while their own storage was down.
var ErrVaultNotDurable = errors.New("vault: verified but could not be persisted")

// VaultBackend is durable custody for vault records.
//
// Three methods, all content-addressed by key. Satisfied by the site's
// erasure-coded store; an interface so the vault can be exercised without one
// and so nothing in this package has to know how a shard works.
type VaultBackend interface {
	// Put stores a blob. Keys are never reused for different content — see
	// recordKey — so an implementation may treat writes as immutable.
	Put(ctx context.Context, key string, blob []byte) error
	// Get returns what Put stored, or an error. It MUST NOT return partial or
	// unverified bytes; the store's own SHA-256 check covers that.
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns every key under a prefix.
	List(ctx context.Context, prefix string) ([]string, error)
}

// VaultKeyPrefix namespaces vault records in whatever bucket they live in.
const VaultKeyPrefix = "vault/"

// recordKey names one state immutably.
//
//	vault/<channel>/<nonce>/<digest>
//
// The digest is in the key so that two DIFFERENT states at one nonce produce
// two objects rather than one silently replacing the other. A counterparty who
// signed twice at one nonce has produced evidence of exactly that, and evidence
// is not something to overwrite.
//
// The nonce is zero-padded so that lexical ordering — which is what a prefix
// listing gives — is numeric ordering.
func recordKey(id [32]byte, nonce uint64, digest [32]byte) string {
	return fmt.Sprintf("%s%s/%020d/%s", VaultKeyPrefix,
		hex.EncodeToString(id[:]), nonce, hex.EncodeToString(digest[:]))
}

// channelPrefix is every record for one channel.
func channelPrefix(id [32]byte) string {
	return VaultKeyPrefix + hex.EncodeToString(id[:]) + "/"
}

// vaultRecord is what gets encrypted and stored.
//
// The wire form of the state plus both signatures, and nothing else. Notably
// ABSENT: the parties and the deposits. Those come from the chain at load time,
// because a record that carried its own idea of who the parties were could be
// used to make this vault verify a signature against an address the record
// chose. The stored bytes are evidence; the chain remains the authority on what
// they are evidence about.
type vaultRecord struct {
	Channel string      `json:"channel"`
	State   storedState `json:"state"`
	SigA    string      `json:"sig_a"`
	SigB    string      `json:"sig_b"`
}

// SetBackend gives a vault durable custody.
//
// Also takes the 32-byte key its records are encrypted under. The store holds
// ciphertext and cannot read it, which is the storage layer's own rule; the
// consequence is that LOSING THIS KEY LOSES THE VAULT, and it must be kept
// wherever the operator keeps things that cannot be regenerated.
func (v *Vault) SetBackend(backend VaultBackend, key []byte) error {
	if backend == nil {
		return errors.New("vault: no backend")
	}
	if len(key) != 32 {
		return fmt.Errorf("vault: the record key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.backend = backend
	v.aead = aead
	return nil
}

// seal encrypts a record for storage.
func (v *Vault) seal(record vaultRecord) ([]byte, error) {
	plain, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return v.aead.Seal(nonce, nonce, plain, nil), nil
}

// open decrypts a stored record.
//
// A failure here is tampering or the wrong key, and either way the bytes are
// not a record. GCM's authentication means this cannot return something
// plausible-but-altered.
func (v *Vault) open(blob []byte) (vaultRecord, error) {
	var out vaultRecord
	size := v.aead.NonceSize()
	if len(blob) < size {
		return out, errors.New("vault: stored record is too short to be one")
	}
	plain, err := v.aead.Open(nil, blob[:size], blob[size:], nil)
	if err != nil {
		return out, fmt.Errorf("vault: stored record does not authenticate: %w", err)
	}
	if err := json.Unmarshal(plain, &out); err != nil {
		return out, fmt.Errorf("vault: stored record is not readable: %w", err)
	}
	return out, nil
}

// persist writes a verified state to the backend.
//
// Called with the vault's lock NOT held: a network round trip under the mutex
// would stall every other channel's submission behind one slow write.
func (v *Vault) persist(ctx context.Context, signed SignedState) error {
	v.mu.RLock()
	backend, aead := v.backend, v.aead
	v.mu.RUnlock()
	if backend == nil || aead == nil {
		return nil // in-memory vault; nothing to do
	}

	digest := signed.State.Digest(v.ChainID, v.Contract)
	blob, err := v.seal(vaultRecord{
		Channel: hex.EncodeToString(signed.State.Channel[:]),
		State:   encodeStateWire(signed.State),
		SigA:    hex.EncodeToString(signed.SigA),
		SigB:    hex.EncodeToString(signed.SigB),
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVaultNotDurable, err)
	}
	key := recordKey(signed.State.Channel, signed.State.Nonce, digest)
	if err := backend.Put(ctx, key, blob); err != nil {
		return fmt.Errorf("%w: %v", ErrVaultNotDurable, err)
	}
	return nil
}

// Load rebuilds the vault from durable storage.
//
// Every record is re-verified from scratch — hash, digest, both signatures,
// conservation, and the parties read from the CHAIN. Nothing is trusted for
// having been in the store, because the store is custody and not authority.
//
// Returns the number of channels recovered. An unreadable record is skipped
// and counted rather than fatal: one corrupt object must not stop a watchtower
// from defending the other forty channels, and the alternative — refusing to
// start — is an outage during exactly the incident that produced the corruption.
func (v *Vault) Load(ctx context.Context) (recovered int, skipped int, err error) {
	v.mu.RLock()
	backend := v.backend
	v.mu.RUnlock()
	if backend == nil {
		return 0, 0, errors.New("vault: no backend to load from")
	}

	keys, err := backend.List(ctx, VaultKeyPrefix)
	if err != nil {
		return 0, 0, fmt.Errorf("vault: listing stored records: %w", err)
	}
	// Highest nonce last, so a later record simply replaces an earlier one and
	// the monotonic rule in Submit does the rest.
	sort.Strings(keys)

	for _, key := range keys {
		signed, ok := v.loadOne(ctx, backend, key)
		if !ok {
			skipped++
			continue
		}
		// Straight back through Submit: the same verification, the same chain
		// read, the same monotonic rule. A separate "trusted" path for records
		// this vault wrote itself is exactly how a store becomes an authority.
		if _, err := v.submitVerified(ctx, signed); err != nil {
			if !errors.Is(err, ErrStaleDeposit) {
				skipped++
			}
			continue
		}
	}
	return len(v.IDs()), skipped, nil
}

// loadOne fetches and decodes a single record. Any failure means skip it.
func (v *Vault) loadOne(ctx context.Context, backend VaultBackend, key string) (SignedState, bool) {
	if !strings.HasPrefix(key, VaultKeyPrefix) {
		return SignedState{}, false
	}
	blob, err := backend.Get(ctx, key)
	if err != nil {
		return SignedState{}, false
	}
	record, err := v.open(blob)
	if err != nil {
		return SignedState{}, false
	}
	state, err := decodeStateWire(record.State)
	if err != nil {
		return SignedState{}, false
	}
	sigA, err := hex.DecodeString(record.SigA)
	if err != nil {
		return SignedState{}, false
	}
	sigB, err := hex.DecodeString(record.SigB)
	if err != nil {
		return SignedState{}, false
	}
	// The key names a channel and a nonce. If the record inside disagrees, the
	// object has been moved or rewritten, and it is not evidence of anything.
	if key != recordKey(state.Channel, state.Nonce, state.Digest(v.ChainID, v.Contract)) {
		return SignedState{}, false
	}
	return SignedState{State: state, SigA: sigA, SigB: sigB}, true
}
