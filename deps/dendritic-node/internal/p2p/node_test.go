package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/rabbiit/maniwani/storage-client/internal/store"
)

func TestLeaseSignatureAndBinding(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{coordKey: publicKey}
	header := requestHeader{ObjectID: stringOf('a', 64), ShardID: stringOf('b', 64), Size: 65536}
	lease := &Lease{
		Version: 1, ObjectID: header.ObjectID, ShardID: header.ShardID,
		Size: header.Size, Recipient: "recipient", ExpiresAt: time.Now().Unix() + 300,
	}
	lease.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, leaseMessage(*lease)))
	if err := node.validateLeaseForRecipient(lease, header, "recipient"); err != nil {
		t.Fatal(err)
	}
	lease.Size++
	if err := node.validateLeaseForRecipient(lease, header, "recipient"); err == nil {
		t.Fatal("altered lease was accepted")
	}
}

func TestEncryptedShardTransferRequiresValidLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openStorage := func() (*store.Store, string) {
		dir := t.TempDir()
		storage, err := store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { storage.Close() })
		return storage, dir
	}
	sourceStore, sourceDir := openStorage()
	targetStore, targetDir := openStorage()
	logger := log.New(io.Discard, "", 0)
	source, err := openNode(ctx, sourceDir, []string{"/ip4/127.0.0.1/tcp/0"}, sourceStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := openNode(ctx, targetDir, []string{"/ip4/127.0.0.1/tcp/0"}, targetStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := source.host.Connect(ctx, peer.AddrInfo{ID: target.host.ID(), Addrs: target.host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	if err := sourceStore.CreateBucket("transfer-test"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject(
		"transfer-test", "object.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{1, 3, 3, 7}, 1000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ref := manifest.Chunks[0].Shards[0]
	value, err := sourceStore.ReadShard(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target.coordKey = publicKey
	lease := &Lease{
		Version: 1, ObjectID: manifest.ObjectID, ShardID: ref.ID,
		Size: int64(len(value)), Recipient: target.ID(), ExpiresAt: time.Now().Unix() + 300,
	}
	lease.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, leaseMessage(*lease)))
	if err := source.storeOnPeer(ctx, target.host.ID(), manifest.ObjectID, ref.ID, value, lease); err != nil {
		t.Fatal(err)
	}
	stored, err := targetStore.ReadShard(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, value) {
		t.Fatal("transferred shard differs")
	}
}

func stringOf(value byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return string(result)
}

// Objects written while the node had no peers must still reach a peer that
// connects later. DistributeManifest runs once, at PUT time; with nobody
// connected it takes the "retained locally" branch and nothing ever pushed
// those shards again. A node could then be fully peered, advertising and
// heartbeating while every volunteer's shard directory stayed empty.
func TestBackfillPushesShardsStoredWhilePeerless(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openStorage := func() (*store.Store, string) {
		dir := t.TempDir()
		storage, err := store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { storage.Close() })
		return storage, dir
	}
	sourceStore, sourceDir := openStorage()
	targetStore, targetDir := openStorage()
	logger := log.New(io.Discard, "", 0)
	source, err := openNode(ctx, sourceDir, []string{"/ip4/127.0.0.1/tcp/0"}, sourceStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := openNode(ctx, targetDir, []string{"/ip4/127.0.0.1/tcp/0"}, targetStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	// Written with no peer connected -- the "retained locally" case.
	if err := sourceStore.CreateBucket("backfill"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject(
		"backfill", "object.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{7, 4, 1, 9}, 1000)),
	)
	if err != nil {
		t.Fatal(err)
	}

	// With no peers there is nowhere to push, so the pass must be a no-op --
	// in particular it must not mark the object done and skip it forever.
	source.replicateOnce(ctx)
	peerless, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !peerless.LastAttempt.IsZero() {
		t.Fatal("backfill attempted an object while no peer was connected")
	}
	for _, shard := range peerless.Shards {
		if len(shard.Holders) != 0 {
			t.Fatalf("shard %s claims holders %v with no peer connected", shard.ShardID, shard.Holders)
		}
	}

	// Coordinator stand-in: leases whatever the source asks for.
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Both ends verify the coordinator's signature: the recipient on receipt,
	// and the requester before it bothers sending anything.
	source.coordKey = publicKey
	target.coordKey = publicKey
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request leaseRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxHeaderBytes)).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lease := Lease{
			Version: 1, ObjectID: request.ObjectID, ShardID: request.ShardID,
			Size: request.Size, Recipient: request.Recipient,
			ExpiresAt: time.Now().Unix() + 300,
		}
		lease.Signature = base64.RawStdEncoding.EncodeToString(
			ed25519.Sign(privateKey, leaseMessage(lease)),
		)
		_ = json.NewEncoder(w).Encode(lease)
	}))
	defer coordinator.Close()
	previous := leaseURL
	leaseURL = coordinator.URL
	defer func() { leaseURL = previous }()

	if err := source.host.Connect(ctx, peer.AddrInfo{ID: target.host.ID(), Addrs: target.host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	source.replicateOnce(ctx)

	// The shards of an object stored before the peer existed are now on it.
	ref := manifest.Chunks[0].Shards[0]
	expected, err := sourceStore.ReadShard(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := targetStore.ReadShard(ref.ID)
	if err != nil {
		t.Fatalf("shard was never backfilled to the peer: %v", err)
	}
	if !bytes.Equal(stored, expected) {
		t.Fatal("backfilled shard differs from the original")
	}
	// The peer that took it is recorded, so a reader can find it and the repair
	// loop can later notice if it stops answering.
	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	holders := 0
	for _, shard := range row.Shards {
		if shard.ShardID == ref.ID {
			holders = len(shard.Holders)
			if holders == 1 && shard.Holders[0] != target.ID() {
				t.Fatalf("shard recorded against %s, not the peer that took it", shard.Holders[0])
			}
		}
	}
	if holders != 1 {
		t.Fatalf("shard has %d recorded holders, want 1", holders)
	}

	// And it is NOT retired from the queue. One peer cannot hold three distinct
	// shards of a 3+2 chunk without stacking siblings on one host, so the object
	// is still unrecoverable if this node dies. The old code marked it done here
	// regardless of what landed -- which is exactly why the production counter
	// drained while every volunteer's shard directory stayed empty.
	if !row.UnderReplicated() {
		t.Fatal("an object with one remote shard of three claimed to be durable")
	}
	queued, err := sourceStore.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0].ObjectID != manifest.ObjectID {
		t.Fatal("object was retired from the queue with only 1 of 3 shards off-node")
	}
}

// A cache-only node keeps what it caches of its OWN content and hosts nothing
// for anyone else, so its disk grows with the site rather than with the network.
func TestCacheOnlyNodeRefusesToHostForeignShards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openStorage := func() (*store.Store, string) {
		dir := t.TempDir()
		storage, err := store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { storage.Close() })
		return storage, dir
	}
	sourceStore, sourceDir := openStorage()
	targetStore, targetDir := openStorage()
	logger := log.New(io.Discard, "", 0)
	source, err := openNode(ctx, sourceDir, []string{"/ip4/127.0.0.1/tcp/0"}, sourceStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := openNode(ctx, targetDir, []string{"/ip4/127.0.0.1/tcp/0"}, targetStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	target.SetCacheOnly(true)

	if err := source.host.Connect(ctx, peer.AddrInfo{ID: target.host.ID(), Addrs: target.host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	if err := sourceStore.CreateBucket("cache-only"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject(
		"cache-only", "object.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{2, 4, 6, 8}, 1000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ref := manifest.Chunks[0].Shards[0]
	value, err := sourceStore.ReadShard(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A VALID lease must still be refused -- the point is that this node hosts
	// nothing for anyone, not that the request was malformed.
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target.coordKey = publicKey
	lease := &Lease{
		Version: 1, ObjectID: manifest.ObjectID, ShardID: ref.ID,
		Size: int64(len(value)), Recipient: target.ID(), ExpiresAt: time.Now().Unix() + 300,
	}
	lease.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, leaseMessage(*lease)))

	err = source.storeOnPeer(ctx, target.host.ID(), manifest.ObjectID, ref.ID, value, lease)
	if err == nil {
		t.Fatal("cache-only node accepted a foreign shard")
	}
	if _, readErr := targetStore.ReadShard(ref.ID); readErr == nil {
		t.Fatal("cache-only node persisted a foreign shard")
	}
}
