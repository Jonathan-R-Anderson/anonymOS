package p2p

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	record "github.com/libp2p/go-libp2p-record"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// objectManifestNamespace is the DHT namespace for object manifests. A manifest
// is the chunk->shard map (no key material, no plaintext) that lets a DIFFERENT
// node reassemble an object by content -- the piece that was previously trapped
// in each node's local BoltDB, which is why the coordinator's build context
// could never cross from the bridge to a worker.
const objectManifestNamespace = "syndichan-object-manifest"

// manifestFetchTimeout budgets a DHT GetValue for a manifest.
//
// RE-DERIVED FOR AXON (T11.2), on the same basis as store.shardFetchTimeout: a
// worst-case 3-hop build (§8.4, 35 s) plus a d=3 disjoint lookup (§7.3), which
// issues up to 9 concurrent RPCs and is bounded by its slowest path rather than
// by their sum. Same caveat: derived from the SPECIFIED budgets, not measured on
// a real network.
const manifestFetchTimeout = 90 * time.Second

// objectManifestKey addresses a manifest by a hash of its (bucket, key), so both
// the publisher and a fetcher that knows the object's bucket+key compute the same
// DHT key without coordination.
func objectManifestKey(bucket, key string) string {
	sum := sha256.Sum256([]byte(bucket + "\x00" + key))
	return "/" + objectManifestNamespace + "/" + hex.EncodeToString(sum[:])
}

// objectManifestValidator accepts a manifest record only if it is well-formed and
// stored under the key derived from its own bucket+key. It carries no signature:
// the real integrity guarantee is content-addressing -- the fetcher reassembles
// the object and rejects it unless sha256(bytes) matches the manifest's digest --
// so a forged manifest can at worst cause a fetch to fail, never corruption.
type objectManifestValidator struct{}

func (objectManifestValidator) Validate(key string, value []byte) error {
	prefix := "/" + objectManifestNamespace + "/"
	if !strings.HasPrefix(key, prefix) {
		return errors.New("invalid object manifest key")
	}
	want := strings.TrimPrefix(key, prefix)
	var m store.Manifest
	if len(value) > 512<<10 || json.Unmarshal(value, &m) != nil {
		return errors.New("invalid object manifest encoding")
	}
	if m.Version != store.FormatVersion || len(m.Chunks) == 0 {
		return errors.New("malformed object manifest")
	}
	sum := sha256.Sum256([]byte(m.Bucket + "\x00" + m.Key))
	if hex.EncodeToString(sum[:]) != want {
		return errors.New("object manifest stored under the wrong key")
	}
	return nil
}

func (objectManifestValidator) Select(_ string, values [][]byte) (int, error) {
	// Records for one key are content-equivalent (deterministic chunking + RS),
	// so any well-formed one will do.
	for i, value := range values {
		var m store.Manifest
		if json.Unmarshal(value, &m) == nil && len(m.Chunks) > 0 {
			return i, nil
		}
	}
	return 0, errors.New("no valid object manifest")
}

// configureObjectManifestRecords registers the manifest validator so manifest
// records can be put and got. Called once at node creation.
func (n *Node) configureObjectManifestRecords() error {
	namespaces, ok := n.dht.Validator.(record.NamespacedValidator)
	if !ok {
		return errors.New("DHT does not use namespaced validation")
	}
	namespaces[objectManifestNamespace] = objectManifestValidator{}
	return nil
}

// PublishManifest advertises an object's manifest to the DHT so another node can
// reassemble it by bucket+key. Best-effort; a network with nowhere to put it yet
// simply fails and is retried on the next store/advertise.
func (n *Node) PublishManifest(ctx context.Context, manifest store.Manifest) error {
	value, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return n.dht.PutValue(ctx, objectManifestKey(manifest.Bucket, manifest.Key), value)
}

// FetchManifest retrieves an object's manifest from the DHT. It satisfies the
// store's manifest-fetcher hook, so store.GetObject transparently reassembles an
// object this node never stored (the DCS worker fetching the build context).
func (n *Node) FetchManifest(bucket, key string) (*store.Manifest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), manifestFetchTimeout)
	defer cancel()
	dhtKey := objectManifestKey(bucket, key)
	value, err := n.dht.GetValue(ctx, dhtKey)
	if err != nil {
		return nil, err
	}
	if err := (objectManifestValidator{}).Validate(dhtKey, value); err != nil {
		return nil, err
	}
	var manifest store.Manifest
	if err := json.Unmarshal(value, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
