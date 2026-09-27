package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketBuckets     = []byte("buckets")
	bucketObjects     = []byte("objects")
	bucketDenied      = []byte("denied")
	bucketRemote      = []byte("remote_shards")
	bucketSettings    = []byte("settings")
	bucketPolicies    = []byte("bucket_policies")
	keyCapacity       = []byte("capacity_bytes")
	ErrDigestMismatch = errors.New("object payload digest mismatch")
)

const (
	MinCapacityBytes int64 = 64 << 20
	MaxCapacityBytes int64 = 8 << 50
)

// shardFetchTimeout budgets a single missing-shard fetch.
//
// RE-DERIVED FOR AXON (T11.2). The old figure existed to outlast a cold I2P dial
// (p2p.i2pDialTimeout, 2m) and that dial no longer happens. The AXON budget is
// built from §8.4's circuit state machine instead:
//
//	link to the guard                          5 s
//	CREATE                                    10 s
//	EXTEND x2                                 20 s
//	                                     -----------
//	worst-case 3-hop build                    35 s   (§8.4 hard ceiling)
//	one BULK round trip for the shard        ~10 s   (§9.3: 6 relay hops)
//	one retry on a different path             45 s
//	                                     -----------
//	                                          90 s
//
// A miss triggers DHT discovery of a StorageLocation and then a build, so the
// budget has to cover a build it did not already have.
//
// NOT A MEASUREMENT. T11.2 asks for a figure re-derived from MEASURED AXON
// circuit latency, and no AXON circuit has been built on a real network — the
// only measurement in hand is E5.2's in-process throughput. This is derived from
// the SPECIFIED budgets, which is weaker, and it must be re-derived again from
// `axon-lab` before T11.2 can be called discharged. Relaxing it instead of
// re-deriving it would hide exactly the latency regression the criterion exists
// to catch.
const shardFetchTimeout = 90 * time.Second

type Store struct {
	dir          string
	db           *bolt.DB
	dataShards   int
	parityShards int
	chunkBytes   int
	capacity     int64
	mu           sync.RWMutex
	allocationMu sync.Mutex
	// usedBytes is the running total of stored shard bytes, maintained
	// incrementally so the write path never measures the tree. Guarded by
	// allocationMu, together with usedLoaded and inflight.
	//
	// It exists because ensureCapacity used to call UsedBytes() -- a
	// filepath.Walk + lstat over every shard -- once per NEW shard, inside the
	// global allocation lock. On a node holding ~100k shards that was ~0.7s per
	// shard and, at 6 data + 3 parity shards per MiB, nine full walks per MiB of
	// unique data: measured unique-write throughput of ~170 KiB/s, degrading as
	// the tree grew, with concurrent PUTs serialised behind the lock. Uploads
	// then outran the client's socket timeout and surfaced as connection errors.
	usedBytes  int64
	usedLoaded bool
	// inflight counts writers currently materialising each shard ID. The last
	// one to leave folds the shard's size into usedBytes exactly once; see
	// finishShardWrite.
	inflight map[string]int
	// walks counts completed tree measurements. Read atomically; it is the hook
	// the regression test uses to assert writes do not walk.
	walks         int64
	closeOnce     sync.Once
	closed        chan struct{}
	fetchShard    func(ctx context.Context, shardID string, hints []string) ([]byte, error)
	fetchManifest func(bucket, key string) (*Manifest, error)
	advertise     func(string)
	distribute    func(Manifest)
}

func Open(dir string, dataShards, parityShards, chunkBytes int, capacity int64) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "shards"), 0700); err != nil {
		return nil, err
	}
	metaPath := filepath.Join(dir, "metadata.db")
	db, err := bolt.Open(metaPath, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		// bbolt reports a held file lock as the bare word "timeout", which reads
		// like a network stall. Say what it actually is: a second node on the
		// same data_dir. Only one process may own a data_dir at a time.
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%s is locked by another syndichan-node already running on data_dir %s — "+
				"stop it first (ps aux | grep syndichan-node) or point this instance at a different data_dir", metaPath, dir)
		}
		return nil, err
	}
	s := &Store{
		dir: dir, db: db, dataShards: dataShards,
		parityShards: parityShards, chunkBytes: chunkBytes, capacity: capacity,
		inflight: make(map[string]int), closed: make(chan struct{}),
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{
			bucketBuckets, bucketObjects, bucketDenied, bucketRemote,
			bucketSettings, bucketPolicies, bucketPlacement, bucketPlacementIndex,
			bucketRecall, bucketRevocationNonces,
		} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		settings := tx.Bucket(bucketSettings)
		if existing := settings.Get(keyCapacity); len(existing) == 8 {
			persisted := int64(binary.BigEndian.Uint64(existing))
			if persisted >= MinCapacityBytes && persisted <= MaxCapacityBytes {
				s.capacity = persisted
				return nil
			}
		}
		return settings.Put(keyCapacity, encodeInt64(capacity))
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	// Measure once at startup so the first write does not pay for it, then keep
	// the number honest in the background rather than on the write path. A
	// failed measurement is not fatal -- Open never used to touch the shard
	// tree, so refusing to start on it would be a new way to lose a node; the
	// counter simply stays unloaded and the next reader measures it.
	_ = s.reconcileUsedBytes()
	go s.reconcileLoop(usageReconcileInterval)
	return s, nil
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return s.db.Close()
}

// SetShardFetcher supplies the cross-node shard read.
//
// The fetcher takes holder HINTS: peer IDs the placement ledger recorded as
// having confirmed the shard. Without them a miss degrades into a search --
// every peer that ever connected, tried serially, each one worth a cold I2P
// dial -- and the DHT provider lookup that actually knows the answer is
// consulted last, frequently after the budget is already spent.
func (s *Store) SetShardFetcher(fetcher func(ctx context.Context, shardID string, hints []string) ([]byte, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetchShard = fetcher
}

// SetManifestFetcher supplies the fallback used when an object's manifest is not
// held locally: it fetches the chunk->shard map from the DHT so GetObject can
// reassemble an object this node never stored (a DCS worker reading a build
// context the bridge published).
func (s *Store) SetManifestFetcher(fetcher func(bucket, key string) (*Manifest, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetchManifest = fetcher
}

func (s *Store) SetShardAdvertiser(advertiser func(string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advertise = advertiser
}

func (s *Store) SetObjectDistributor(distributor func(Manifest)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.distribute = distributor
}

func objectKey(bucket, key string) []byte { return []byte(bucket + "\x00" + key) }

func (s *Store) CreateBucket(name string) error {
	if !validBucket(name) {
		return errors.New("invalid bucket name")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBuckets).Put([]byte(name), []byte(time.Now().UTC().Format(time.RFC3339Nano)))
	})
}

func validBucket(name string) bool {
	if len(name) < 3 || len(name) > 63 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func (s *Store) BucketExists(name string) bool {
	var found bool
	s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(bucketBuckets).Get([]byte(name)) != nil
		return nil
	})
	return found
}

func (s *Store) ListBuckets() ([]string, error) {
	var result []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBuckets).ForEach(func(k, _ []byte) error {
			result = append(result, string(k))
			return nil
		})
	})
	sort.Strings(result)
	return result, err
}

func (s *Store) DeleteBucket(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		prefix := []byte(name + "\x00")
		cursor := tx.Bucket(bucketObjects).Cursor()
		if key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix) {
			return errors.New("bucket is not empty")
		}
		if err := tx.Bucket(bucketPolicies).Delete([]byte(name)); err != nil {
			return err
		}
		return tx.Bucket(bucketBuckets).Delete([]byte(name))
	})
}

func (s *Store) SetBucketPolicy(bucket string, policy []byte) error {
	if !s.BucketExists(bucket) {
		return errors.New("bucket does not exist")
	}
	value := append([]byte(nil), policy...)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPolicies).Put([]byte(bucket), value)
	})
}

func (s *Store) BucketPolicy(bucket string) ([]byte, error) {
	var policy []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketPolicies).Get([]byte(bucket))
		if value != nil {
			policy = append([]byte(nil), value...)
		}
		return nil
	})
	return policy, err
}

func (s *Store) DeleteBucketPolicy(bucket string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPolicies).Delete([]byte(bucket))
	})
}

func (s *Store) PutObject(bucket, key, contentType string, r io.Reader) (*Manifest, error) {
	return s.putObject(bucket, key, contentType, r, "", true)
}

func (s *Store) PutObjectVerified(bucket, key, contentType string, r io.Reader, expectedSHA256 string) (*Manifest, error) {
	return s.putObject(bucket, key, contentType, r, strings.ToLower(expectedSHA256), true)
}

func (s *Store) PutTemporaryObject(bucket, key string, r io.Reader, expectedSHA256 string) (*Manifest, error) {
	return s.putObject(bucket, key, "application/octet-stream", r, strings.ToLower(expectedSHA256), false)
}

func (s *Store) putObject(bucket, key, contentType string, r io.Reader, expectedSHA256 string, distribute bool) (*Manifest, error) {
	if !s.BucketExists(bucket) {
		return nil, os.ErrNotExist
	}
	if key == "" || strings.ContainsRune(key, '\x00') {
		return nil, errors.New("invalid object key")
	}
	encoder, err := reedsolomon.New(s.dataShards, s.parityShards)
	if err != nil {
		return nil, err
	}
	manifest := &Manifest{
		Version: FormatVersion, Bucket: bucket, Key: key, ContentType: contentType,
		DataShards: s.dataShards, ParityShards: s.parityShards, ChunkBytes: s.chunkBytes,
		CreatedAt: time.Now().UTC(),
	}
	plainHash := sha256.New()
	buffer := make([]byte, s.chunkBytes)
	for index := 0; ; index++ {
		n, readErr := io.ReadFull(r, buffer)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return nil, readErr
		}
		// The node stores bytes it cannot read -- content is already ciphertext
		// from the coordinator. Copy the chunk before splitting: the read buffer
		// is reused on the next iteration and Split may alias it.
		stored := append([]byte(nil), buffer[:n]...)
		plainHash.Write(stored)
		manifest.PlainSize += int64(n)
		shards, err := encoder.Split(stored)
		if err != nil {
			return nil, err
		}
		if err := encoder.Encode(shards); err != nil {
			return nil, err
		}
		chunk := ChunkManifest{
			Index: index, CipherLength: len(stored),
			ShardSize: len(shards[0]),
		}
		for shardIndex, shard := range shards {
			id := digest(shard)
			if err := s.writeShard(id, shard); err != nil {
				return nil, err
			}
			chunk.Shards = append(chunk.Shards, ShardRef{ID: id, Index: shardIndex, Size: len(shard)})
		}
		manifest.Chunks = append(manifest.Chunks, chunk)
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	manifest.PlainSHA256 = hex.EncodeToString(plainHash.Sum(nil))
	if expectedSHA256 != "" && manifest.PlainSHA256 != expectedSHA256 {
		s.removeUnreferenced(manifestShardIDs(*manifest))
		return nil, ErrDigestMismatch
	}
	idBytes, err := canonicalManifest(manifest)
	if err != nil {
		return nil, err
	}
	manifest.ObjectID = digest(idBytes)
	if s.IsRejected("object", manifest.ObjectID) {
		return nil, errors.New("object was rejected by this node")
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	var oldShards []string
	err = s.db.Update(func(tx *bolt.Tx) error {
		if old := tx.Bucket(bucketObjects).Get(objectKey(bucket, key)); old != nil {
			var previous Manifest
			if err := json.Unmarshal(old, &previous); err != nil {
				return err
			}
			oldShards = manifestShardIDs(previous)
		}
		return tx.Bucket(bucketObjects).Put(objectKey(bucket, key), encoded)
	})
	if err == nil {
		s.removeUnreferenced(oldShards)
		if distribute {
			// Enrol the object in the durable dispersal queue BEFORE handing it
			// to the distributor, and in the same synchronous breath as the
			// manifest commit. The queue used to be an in-memory set marked on
			// ATTEMPT, so a process that died between the commit and the push
			// left an object nothing would ever look at again.
			//
			// The write is acked here, with nine shards on local disk and zero
			// confirmed remote holders. That is deliberate: a peer push needs a
			// coordinator lease over an I2P outproxy and a cold I2P dial takes
			// 20-60s, so blocking the S3 PUT on six confirmed remote shards
			// would put minutes on the site's upload path and would fail
			// outright whenever the network is young. What must never happen is
			// claiming a durability that does not exist, which is why the row
			// starts life under-replicated and only DurableRemoteHolders
			// distinct confirmed holders per chunk clear it.
			if placementErr := s.RecordObjectPlacement(*manifest); placementErr != nil {
				return manifest, placementErr
			}
		}
		s.mu.RLock()
		distributor := s.distribute
		s.mu.RUnlock()
		if distribute && distributor != nil {
			go distributor(*manifest)
		}
	}
	return manifest, err
}

func canonicalManifest(manifest *Manifest) ([]byte, error) {
	copyValue := *manifest
	copyValue.ObjectID = ""
	return json.Marshal(copyValue)
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (s *Store) shardPath(id string) string {
	return filepath.Join(s.dir, "shards", id[:2], id)
}

func (s *Store) writeShard(id string, value []byte) error {
	if len(id) != 64 || digest(value) != id {
		return errors.New("invalid shard digest")
	}
	path := s.shardPath(id)

	// Only the dedup check and the capacity decision need the global lock. The
	// file work below (mkdir, temp file, write, fsync, rename) runs unlocked so
	// concurrent PUTs overlap on I/O instead of queueing behind one another.
	//
	// Releasing the lock before the rename is safe because the store is
	// content-addressed: two writers of the same ID write to distinct temp files
	// and rename byte-identical content onto the same final name, so whichever
	// rename lands last leaves the correct bytes in place.
	//
	// The accounting is what needs care, since both writers see "absent" at the
	// stat and both go on to rename. Resolved with the inflight refcount: each
	// admitted writer claims a slot under the lock, and the LAST writer for that
	// ID to finish re-stats the final path under the lock and adds the size once
	// (finishShardWrite). A writer arriving after the rename takes the dedup
	// early-return above and adds nothing, so every stored shard is counted
	// exactly once regardless of how the racing writers interleave or which of
	// them failed.
	s.allocationMu.Lock()
	if _, err := os.Stat(path); err == nil {
		s.allocationMu.Unlock()
		return nil
	}
	if err := s.ensureCapacityLocked(int64(len(value))); err != nil {
		s.allocationMu.Unlock()
		return err
	}
	s.inflight[id]++
	s.allocationMu.Unlock()

	err := materializeShard(path, value)
	s.finishShardWrite(id, path)
	if err != nil {
		return err
	}

	s.mu.RLock()
	advertiser := s.advertise
	s.mu.RUnlock()
	if advertiser != nil {
		go advertiser(id)
	}
	return nil
}

// materializeShard writes value to path durably and atomically. It holds no
// store lock: it touches only this writer's own temp file plus a rename onto a
// content-addressed name.
func materializeShard(path string, value []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".incoming-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(value); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

// finishShardWrite releases this writer's claim on id. The last writer out
// decides the accounting from what is actually on disk, so a shard that any of
// the racing writers managed to store is counted once and a shard none of them
// stored is not counted at all.
func (s *Store) finishShardWrite(id, path string) {
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	s.inflight[id]--
	if s.inflight[id] > 0 {
		return
	}
	delete(s.inflight, id)
	if !s.usedLoaded {
		// Never measured, so there is no counter to keep current; the next
		// measurement will pick the shard up.
		return
	}
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		s.usedBytes += info.Size()
	}
}

// ensureCapacityLocked reports whether incoming bytes still fit. The caller must
// hold allocationMu.
func (s *Store) ensureCapacityLocked(incoming int64) error {
	used, err := s.usedBytesLocked()
	if err != nil {
		return err
	}
	if used+incoming > s.capacity {
		return errors.New("storage capacity exceeded")
	}
	return nil
}

func (s *Store) Capacity() int64 {
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	return s.capacity
}

// SetCapacity changes the amount of disk space made available to the node.
// Reducing the allocation never deletes data implicitly; the user must first
// remove stored items until usage is at or below the requested limit.
func (s *Store) SetCapacity(capacity int64) error {
	if capacity < MinCapacityBytes || capacity > MaxCapacityBytes {
		return fmt.Errorf(
			"storage allocation must be between %d MiB and %d TiB",
			MinCapacityBytes>>20, MaxCapacityBytes>>40,
		)
	}
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	used, err := s.usedBytesLocked()
	if err != nil {
		return err
	}
	if capacity < used {
		return fmt.Errorf("storage allocation cannot be below current usage of %d bytes", used)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSettings).Put(keyCapacity, encodeInt64(capacity))
	}); err != nil {
		return err
	}
	s.capacity = capacity
	return nil
}

func encodeInt64(value int64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, uint64(value))
	return encoded
}

// UsedBytes reports stored shard bytes. It is a counter read, not a measurement:
// callers poll it (the management UI, the capacity advertisement, the placement
// admission check) and each poll used to walk the whole shard tree.
func (s *Store) UsedBytes() (int64, error) {
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	return s.usedBytesLocked()
}

// usedBytesLocked returns the cached usage, measuring the tree only if it has
// never been measured. The caller must hold allocationMu.
func (s *Store) usedBytesLocked() (int64, error) {
	if s.usedLoaded {
		return s.usedBytes, nil
	}
	total, err := s.measureUsedBytes()
	if err != nil {
		return 0, err
	}
	s.usedBytes = total
	s.usedLoaded = true
	return total, nil
}

// measureUsedBytes walks the shard tree and lstats every entry. This is the
// expensive operation the cache exists to keep off the write path: seconds on a
// node holding hundreds of thousands of shards. Call it from Open and from the
// reconcile loop only.
func (s *Store) measureUsedBytes() (int64, error) {
	var total int64
	err := filepath.Walk(filepath.Join(s.dir, "shards"), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			// A shard deleted while the walk is in progress used to abort the
			// whole measurement, and that error propagated out of writeShard and
			// failed an unrelated upload. A vanished entry simply contributes
			// nothing.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		// Count only content-addressed shard names, matching what the
		// incremental accounting adds and subtracts. In particular this skips
		// the .incoming-* temp files of writes in flight, which would otherwise
		// be counted here and then counted again as shards after their rename.
		if info.Mode().IsRegular() && len(info.Name()) == 64 {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	atomic.AddInt64(&s.walks, 1)
	return total, nil
}

// walkCount reports how many full tree measurements have run. Test hook.
func (s *Store) walkCount() int64 { return atomic.LoadInt64(&s.walks) }

// usageReconcileInterval is how often the cached usage is re-derived from disk.
// Low frequency on purpose: incremental accounting is exact for every path that
// goes through this package, and the reconcile is only there to absorb what does
// not -- a crash between rename and accounting, a delete that lands on a shard
// while it is still being written, or files an operator moved. Those all drift
// the counter DOWN, the safe direction: an under-count never refuses a write on
// a store that has room, and the next reconcile restores the truth.
const usageReconcileInterval = time.Hour

func (s *Store) reconcileLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			_ = s.reconcileUsedBytes()
		}
	}
}

// reconcileUsedBytes re-derives the cached usage by measuring the tree. The walk
// runs without allocationMu held so an hourly multi-second measurement does not
// stall writers; the result is adopted only if no write is in flight, because a
// shard renamed after the walk passed its directory would be counted by its
// writer and missed by the walk. A skipped reconcile just waits for the next
// tick -- drift correction is not time critical.
func (s *Store) reconcileUsedBytes() error {
	total, err := s.measureUsedBytes()
	if err != nil {
		return err
	}
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	if len(s.inflight) > 0 {
		return nil
	}
	s.usedBytes = total
	s.usedLoaded = true
	return nil
}

// releaseUsedBytes discounts a shard that has just been removed from disk.
func (s *Store) releaseUsedBytes(size int64) {
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	if !s.usedLoaded {
		return
	}
	s.usedBytes -= size
	if s.usedBytes < 0 {
		s.usedBytes = 0
	}
}

func (s *Store) getManifest(bucket, key string) (*Manifest, error) {
	var encoded []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketObjects).Get(objectKey(bucket, key))
		if value == nil {
			return os.ErrNotExist
		}
		encoded = append([]byte(nil), value...)
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		// Not stored here: try to pull the manifest from the DHT so an object
		// this node never held can still be reassembled by content.
		s.mu.RLock()
		fetcher := s.fetchManifest
		s.mu.RUnlock()
		if fetcher != nil {
			if manifest, ferr := fetcher(bucket, key); ferr == nil && manifest != nil {
				return manifest, nil
			}
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (s *Store) HeadObject(bucket, key string) (*Manifest, error) {
	return s.getManifest(bucket, key)
}

func (s *Store) GetObject(bucket, key string, w io.Writer) (*Manifest, error) {
	manifest, err := s.getManifest(bucket, key)
	if err != nil {
		return nil, err
	}
	encoder, err := reedsolomon.New(manifest.DataShards, manifest.ParityShards)
	if err != nil {
		return nil, err
	}
	verifyHash := sha256.New()
	for _, chunk := range manifest.Chunks {
		shards, err := s.gatherChunk(*manifest, chunk)
		if err != nil {
			return nil, err
		}
		if err := encoder.Reconstruct(shards); err != nil {
			return nil, fmt.Errorf("reconstruct chunk %d: %w", chunk.Index, err)
		}
		// The reassembled bytes are the coordinator's ciphertext; the node emits
		// them as-is (it holds no key to decrypt).
		var data []byte
		for i := 0; i < manifest.DataShards; i++ {
			data = append(data, shards[i]...)
		}
		data = data[:chunk.CipherLength]
		verifyHash.Write(data)
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
	}
	if hex.EncodeToString(verifyHash.Sum(nil)) != manifest.PlainSHA256 {
		return nil, errors.New("stored object digest mismatch")
	}
	return manifest, nil
}

// gatherChunk collects enough shards of one chunk for Reed-Solomon to rebuild
// it, reading local disk first and the network only for what is missing.
//
// WHY THIS IS NOT THE OLD LOOP
// ----------------------------
// The old loop fetched all dataShards+parityShards refs, serially, taking the
// full shardFetchTimeout (3 minutes) on every miss. That was free while the
// origin kept all nine shards locally and the remote branch was dead code. The
// moment shards actually live on other nodes it is the hot path, and the
// arithmetic does not survive contact: a 40 MB object is 39 chunks x 9 = 351
// acquisitions, and at an optimistic 2s per I2P fetch that is 11.7 minutes
// against the S3 server's 10-minute WriteTimeout -- over budget before a single
// failure, and one dead peer alone costs 3 minutes.
//
// So: read every local copy first (cheap, and usually enough), stop the instant
// dataShards distinct indexes are in hand, and fetch the remainder CONCURRENTLY
// with a shared context that is cancelled as soon as the quorum is met. Fetching
// 9 when 6 decode is 50% wasted network on every read.
func (s *Store) gatherChunk(manifest Manifest, chunk ChunkManifest) ([][]byte, error) {
	total := manifest.DataShards + manifest.ParityShards
	if total <= 0 || manifest.DataShards <= 0 {
		return nil, fmt.Errorf("chunk %d: invalid erasure layout %d+%d",
			chunk.Index, manifest.DataShards, manifest.ParityShards)
	}
	shards := make([][]byte, total)
	var missing []ShardRef
	present := 0
	for _, ref := range chunk.Shards {
		// A manifest can arrive from the DHT, where records are deliberately
		// unsigned and the validator checks only version, non-empty chunks and
		// key derivation. An out-of-range Index would panic on the assignment
		// below, which is a remote crash primitive, not a bad read.
		if ref.Index < 0 || ref.Index >= total {
			return nil, fmt.Errorf("chunk %d: shard index %d outside 0..%d",
				chunk.Index, ref.Index, total-1)
		}
		if shards[ref.Index] != nil {
			continue
		}
		value, err := os.ReadFile(s.shardPath(ref.ID))
		if err == nil && digest(value) == ref.ID {
			shards[ref.Index] = value
			present++
			continue
		}
		// Reached either because the file is absent or because it is present
		// and rotted. The old code only fetched on a read ERROR, so a corrupt
		// but readable shard was silently dropped and never repaired from a
		// peer holding a good copy one hop away.
		missing = append(missing, ref)
	}
	if present >= manifest.DataShards || len(missing) == 0 {
		return shards, nil
	}

	s.mu.RLock()
	fetcher := s.fetchShard
	s.mu.RUnlock()
	if fetcher == nil {
		return shards, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), shardFetchTimeout)
	defer cancel()
	type result struct {
		ref   ShardRef
		value []byte
	}
	results := make(chan result, len(missing))
	var wg sync.WaitGroup
	for _, ref := range missing {
		wg.Add(1)
		go func(ref ShardRef) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			value, err := fetcher(ctx, ref.ID, s.HoldersForShard(ref.ID))
			if err != nil || digest(value) != ref.ID {
				return
			}
			select {
			case results <- result{ref: ref, value: value}:
			case <-ctx.Done():
			}
		}(ref)
	}
	go func() { wg.Wait(); close(results) }()

	for item := range results {
		if shards[item.ref.Index] == nil {
			shards[item.ref.Index] = item.value
			present++
			// Keep a copy so the next read of this object is local. This is a
			// cache, and it is why the origin refills itself on read: there is
			// no eviction anywhere in this package, so a node that reads foreign
			// objects grows forever. Left as-is deliberately -- adding eviction
			// here without a reference model would delete shards this node is
			// the only holder of.
			_ = s.writeShard(item.ref.ID, item.value)
		}
		if present >= manifest.DataShards {
			// Quorum. Cancel the stragglers rather than paying for them.
			cancel()
			break
		}
	}
	// No sender can block: results is buffered to len(missing), so breaking out
	// of the range above strands nothing.
	return shards, nil
}

func (s *Store) ListObjects(bucket, prefix string) ([]Manifest, error) {
	var result []Manifest
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketObjects).Cursor()
		seek := []byte(bucket + "\x00" + prefix)
		bucketPrefix := []byte(bucket + "\x00")
		for k, v := cursor.Seek(seek); k != nil && bytes.HasPrefix(k, bucketPrefix); k, v = cursor.Next() {
			var manifest Manifest
			if err := json.Unmarshal(v, &manifest); err != nil {
				return err
			}
			if strings.HasPrefix(manifest.Key, prefix) {
				result = append(result, manifest)
			}
		}
		return nil
	})
	return result, err
}

func (s *Store) DeleteObject(bucket, key string) error {
	var candidates []string
	var objectID string
	err := s.db.Update(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketObjects).Get(objectKey(bucket, key))
		if value != nil {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			candidates = manifestShardIDs(manifest)
			objectID = manifest.ObjectID
		}
		return tx.Bucket(bucketObjects).Delete(objectKey(bucket, key))
	})
	if err == nil {
		s.removeUnreferenced(candidates)
		if objectID != "" {
			// RECALL BEFORE FORGET. forgetPlacement destroys the holder list,
			// and the holder list is the only record anywhere of which peers
			// hold shards of this object -- the peers keep a row keyed by shard
			// id and do not know who else has a piece. Capturing it into a
			// recall tombstone FIRST is what makes the shards reachable after
			// the object is gone; doing it in the other order (which is what
			// this did) leaves the bytes on peers and no way to name them.
			//
			// RetirePlacement does both, in that order. Forgetting is still
			// required: otherwise the dispersal pass keeps trying to place
			// shards of an object that no longer exists, forever.
			_ = s.RetirePlacement(objectID, "object deleted")
		}
	}
	return err
}

func (s *Store) CleanupObjectPrefix(prefix string) error {
	var targets [][2]string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			if strings.HasPrefix(manifest.Key, prefix) {
				targets = append(targets, [2]string{manifest.Bucket, manifest.Key})
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := s.DeleteObject(target[0], target[1]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) IsRejected(kind, id string) bool {
	var rejected bool
	s.db.View(func(tx *bolt.Tx) error {
		rejected = tx.Bucket(bucketDenied).Get([]byte(kind+"\x00"+id)) != nil
		return nil
	})
	return rejected
}

func (s *Store) Reject(kind, id string) error {
	if kind != "object" && kind != "shard" {
		return errors.New("invalid rejection kind")
	}
	if !IsContentID(id) {
		return errors.New("invalid content ID")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDenied).Put([]byte(kind+"\x00"+id), []byte(time.Now().UTC().Format(time.RFC3339Nano)))
	})
}

func (s *Store) RejectAndRemove(kind, id string) error {
	if err := s.Reject(kind, id); err != nil {
		return err
	}
	var candidates []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		if kind == "shard" {
			candidates = append(candidates, id)
			return tx.Bucket(bucketRemote).Delete([]byte(id))
		}
		objects := tx.Bucket(bucketObjects)
		var objectKeys [][]byte
		if err := objects.ForEach(func(key, value []byte) error {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			if manifest.ObjectID != id {
				return nil
			}
			objectKeys = append(objectKeys, append([]byte(nil), key...))
			for _, chunk := range manifest.Chunks {
				for _, shard := range chunk.Shards {
					candidates = append(candidates, shard.ID)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range objectKeys {
			if err := objects.Delete(key); err != nil {
				return err
			}
		}
		remote := tx.Bucket(bucketRemote)
		var remoteKeys [][]byte
		if err := remote.ForEach(func(key, value []byte) error {
			var shard RemoteShard
			if err := json.Unmarshal(value, &shard); err != nil {
				return err
			}
			if shard.ObjectID == id {
				remoteKeys = append(remoteKeys, append([]byte(nil), key...))
				candidates = append(candidates, shard.ID)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range remoteKeys {
			if err := remote.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if kind == "object" {
		// Same ordering rule as DeleteObject: the operator rejecting an object
		// from the dashboard is exactly the case where its shards most need
		// recalling, so capture the holders before the list is destroyed.
		_ = s.RetirePlacement(id, "object rejected by this node")
	}
	for _, shardID := range candidates {
		if err := s.removeUnreferenced([]string{shardID}); err != nil {
			return err
		}
	}
	return nil
}

func manifestShardIDs(manifest Manifest) []string {
	var result []string
	for _, chunk := range manifest.Chunks {
		for _, shard := range chunk.Shards {
			result = append(result, shard.ID)
		}
	}
	return result
}

// removeUnreferenced deletes shards no manifest still points at. It is the only
// place shard files are removed -- RejectAndRemove and DeleteObject both come
// through here -- so it is also the only place that has to discount them. A
// removal that is not discounted drifts the counter upward forever and
// eventually refuses writes on a store that has room.
func (s *Store) removeUnreferenced(candidates []string) error {
	for _, shardID := range candidates {
		referenced, err := s.shardReferenced(shardID)
		if err != nil {
			return err
		}
		if referenced {
			continue
		}
		path := s.shardPath(shardID)
		// Size has to be read before the unlink; afterwards there is nothing
		// left to ask.
		info, statErr := os.Stat(path)
		if err := os.Remove(path); err != nil {
			continue
		}
		if statErr == nil && info.Mode().IsRegular() {
			s.releaseUsedBytes(info.Size())
		}
	}
	return nil
}

func (s *Store) shardReferenced(shardID string) (bool, error) {
	var referenced bool
	err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketRemote).Get([]byte(shardID)) != nil {
			referenced = true
			return nil
		}
		return tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			if referenced {
				return nil
			}
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			for _, chunk := range manifest.Chunks {
				for _, shard := range chunk.Shards {
					if shard.ID == shardID {
						referenced = true
						return nil
					}
				}
			}
			return nil
		})
	})
	return referenced, err
}

func (s *Store) PutRemoteShard(shard RemoteShard, value []byte) error {
	if len(shard.ID) != 64 || digest(value) != shard.ID || int64(len(value)) != shard.Size {
		return errors.New("remote shard failed content-address verification")
	}
	if s.IsRejected("shard", shard.ID) || s.IsRejected("object", shard.ObjectID) {
		return errors.New("shard or object is rejected by this node")
	}
	// Scoped recall refusal: this OBJECT's copy was recalled recently. Checked
	// separately from the moderation denylist above because it is per-object and
	// expires -- a different object's shard with the same content address is
	// still welcome here, which is exactly what the permanent denylist got wrong.
	if s.RecallRefused(shard.ObjectID, shard.ID) {
		return errors.New("this object's copy of the shard was recalled recently")
	}
	if err := s.writeShard(shard.ID, value); err != nil {
		return err
	}
	shard.CreatedAt = time.Now().UTC()
	encoded, err := json.Marshal(shard)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRemote).Put([]byte(shard.ID), encoded)
	})
}

func (s *Store) ReadShard(id string) ([]byte, error) {
	if len(id) != 64 {
		return nil, errors.New("invalid shard ID")
	}
	value, err := os.ReadFile(s.shardPath(id))
	if err != nil {
		return nil, err
	}
	if digest(value) != id {
		return nil, errors.New("stored shard digest mismatch")
	}
	return value, nil
}

func (s *Store) ListShardIDs() ([]string, error) {
	var result []string
	err := filepath.Walk(filepath.Join(s.dir, "shards"), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && len(info.Name()) == 64 {
			result = append(result, info.Name())
		}
		return nil
	})
	return result, err
}

func (s *Store) ListStored() ([]StoredItem, error) {
	var result []StoredItem
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			result = append(result, StoredItem{
				Kind: "object", ID: manifest.ObjectID, DisplayName: manifest.Bucket + "/" + manifest.Key,
				ContentType: manifest.ContentType, Size: manifest.PlainSize, LocalObject: true,
				Rejected:  tx.Bucket(bucketDenied).Get([]byte("object\x00"+manifest.ObjectID)) != nil,
				CreatedAt: manifest.CreatedAt,
			})
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(bucketRemote).ForEach(func(_, value []byte) error {
			var shard RemoteShard
			if err := json.Unmarshal(value, &shard); err != nil {
				return err
			}
			result = append(result, StoredItem{
				Kind: "shard", ID: shard.ID, DisplayName: "Encrypted shard " + shard.ID[:12],
				Size: shard.Size, Rejected: tx.Bucket(bucketDenied).Get([]byte("shard\x00"+shard.ID)) != nil,
				CreatedAt: shard.CreatedAt,
			})
			return nil
		})
	})
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, err
}

// IsContentID reports whether id is a well-formed content address: exactly 64
// LOWERCASE HEX characters, nothing else.
//
// A length check alone is not this. Sixty-four characters of "../" escape the
// shard directory entirely, because shardPath runs them through filepath.Join
// which cleans the path — so a length-only check turns shard deletion into
// arbitrary file deletion. That was reachable from the network: a validly
// signed revocation carrying such an id unlinked a holder's p2p.key in a live
// two-node test, and the holder answered "deleted: true".
//
// Every path that turns a caller-supplied id into a filesystem path must call
// this. It lives here, at the store boundary, rather than only in the protocol
// handler, because the dashboard's reject path reaches the same sink without
// passing through the handler at all.
func IsContentID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
