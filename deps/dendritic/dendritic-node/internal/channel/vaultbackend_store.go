package channel

// The site's erasure-coded store, as a vault backend — roadmap P11-DHT.
//
// The only file in this package that knows the DHT exists. Everything else
// works against VaultBackend, so the payment code has exactly one door into
// storage and it is this one — the same arrangement internal/ui uses for the
// dashboard, and for the same reason.
//
// WHAT THE STORE GIVES A VAULT
// ----------------------------
//	6 data + 3 parity shards over 1 MiB chunks   survives three holder losses
//	SHA-256 over the whole object, checked on read
//	ciphertext only; storage nodes hold bytes they cannot read
//
// A vault record is a few hundred bytes, so the 1.5x erasure overhead is
// irrelevant and every record lands in a single chunk. This is the opposite of
// the Ethereum-database idea it replaced: small, precious, and not re-derivable
// from anywhere.

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// VaultBucket is where vault records live.
//
// Its own bucket so an operator can see, size and reason about the payment
// evidence separately from the site's content — and so a policy applied to one
// cannot silently apply to the other.
const VaultBucket = "channel-vault"

// StoreBackend adapts *store.Store to VaultBackend.
type StoreBackend struct {
	Store  *store.Store
	Bucket string
}

// NewStoreBackend wires a vault to the site's store.
func NewStoreBackend(s *store.Store) *StoreBackend {
	return &StoreBackend{Store: s, Bucket: VaultBucket}
}

func (b *StoreBackend) bucket() string {
	if b.Bucket == "" {
		return VaultBucket
	}
	return b.Bucket
}

// Put stores one record.
//
// The bytes are already sealed by the vault — this layer never sees a channel
// state, which is what the store's own "content is already ciphertext" rule
// requires and what makes it safe for a record to be dispersed across nodes
// nobody in this system controls.
func (b *StoreBackend) Put(_ context.Context, key string, blob []byte) error {
	if b.Store == nil {
		return fmt.Errorf("vault: no store configured")
	}
	if _, err := b.Store.PutObject(b.bucket(), key, "application/octet-stream",
		bytes.NewReader(blob)); err != nil {
		return fmt.Errorf("vault: storing %s: %w", key, err)
	}
	return nil
}

// Get returns one record.
//
// GetObject reconstructs from whatever shards it can reach — local first, then
// peers — and verifies SHA-256 over the reassembled object before returning. A
// record that cannot be rebuilt is an error rather than short bytes, which is
// the behaviour a vault needs: half a state is not a state.
func (b *StoreBackend) Get(_ context.Context, key string) ([]byte, error) {
	if b.Store == nil {
		return nil, fmt.Errorf("vault: no store configured")
	}
	var buf bytes.Buffer
	if _, err := b.Store.GetObject(b.bucket(), key, &buf); err != nil {
		return nil, fmt.Errorf("vault: reading %s: %w", key, err)
	}
	return buf.Bytes(), nil
}

// List returns every record key under a prefix.
func (b *StoreBackend) List(_ context.Context, prefix string) ([]string, error) {
	if b.Store == nil {
		return nil, fmt.Errorf("vault: no store configured")
	}
	manifests, err := b.Store.ListObjects(b.bucket(), prefix)
	if err != nil {
		return nil, fmt.Errorf("vault: listing %s: %w", prefix, err)
	}
	keys := make([]string, 0, len(manifests))
	for _, m := range manifests {
		keys = append(keys, m.Key)
	}
	return keys, nil
}

var (
	_ VaultBackend = (*StoreBackend)(nil)
	_ io.Reader    = (*bytes.Reader)(nil)
)
