package facilitation

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The node's receipt spool.
//
// Receipts are earnings evidence, so they must survive a restart: an epoch is
// settled well after the work happened, and a node that loses its receipts is
// simply not paid for that window. They live in their own bbolt file rather
// than the shard store's metadata.db — one process may hold a bbolt file at a
// time, and coupling the spool to the shard store would mean a corrupt or
// locked receipt DB could stop the node serving data.
//
// Keys are epoch(8B big-endian) || receiptHash(32B). That ordering makes
// "everything for epoch N" a prefix scan, which is the only query the
// aggregator handoff and pruning need.

const receiptsBucket = "receipts"

// ReceiptStore is a durable, concurrency-safe spool of signed receipts.
type ReceiptStore struct {
	db *bolt.DB
	mu sync.Mutex
}

// OpenReceiptStore opens (or creates) the spool under dir.
func OpenReceiptStore(dir string) (*ReceiptStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "facilitation-receipts.db")
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		// Same trap as the shard store: bbolt reports a held lock as the bare
		// word "timeout", which reads like a network problem.
		if err == bolt.ErrTimeout {
			return nil, fmt.Errorf("%s is locked by another syndichan-node on this data_dir", path)
		}
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(receiptsBucket))
		return e
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &ReceiptStore{db: db}, nil
}

func (s *ReceiptStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func receiptKey(epoch uint64, hash [32]byte) []byte {
	key := make([]byte, 8+32)
	binary.BigEndian.PutUint64(key[:8], epoch)
	copy(key[8:], hash[:])
	return key
}

// Put stores (or replaces) a receipt. Replacement is intentional: the same
// receipt gains witness attestations over time, and the later copy carries
// more of them. Keying on the canonical hash means added witnesses update the
// existing row instead of creating a duplicate the aggregator would reject.
func (s *ReceiptStore) Put(sr SignedReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, err := json.Marshal(sr)
	if err != nil {
		return err
	}
	key := receiptKey(sr.Receipt.Epoch, sr.Hash())
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(receiptsBucket)).Put(key, blob)
	})
}

// Get returns one receipt by epoch and hash.
func (s *ReceiptStore) Get(epoch uint64, hash [32]byte) (SignedReceipt, bool, error) {
	var out SignedReceipt
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		blob := tx.Bucket([]byte(receiptsBucket)).Get(receiptKey(epoch, hash))
		if blob == nil {
			return nil
		}
		found = true
		return json.Unmarshal(blob, &out)
	})
	return out, found, err
}

// ListEpoch returns every receipt recorded for an epoch.
func (s *ReceiptStore) ListEpoch(epoch uint64) ([]SignedReceipt, error) {
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, epoch)
	var out []SignedReceipt
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte(receiptsBucket)).Cursor()
		for k, v := c.Seek(prefix); k != nil && len(k) >= 8 &&
			binary.BigEndian.Uint64(k[:8]) == epoch; k, v = c.Next() {
			var sr SignedReceipt
			if err := json.Unmarshal(v, &sr); err != nil {
				// One unreadable row must not hide the rest of the epoch's
				// earnings; skip it and keep going.
				continue
			}
			out = append(out, sr)
		}
		return nil
	})
	return out, err
}

// Count returns how many receipts are spooled for an epoch.
func (s *ReceiptStore) Count(epoch uint64) (int, error) {
	rows, err := s.ListEpoch(epoch)
	return len(rows), err
}

// Epochs lists the epochs that currently hold receipts, ascending.
func (s *ReceiptStore) Epochs() ([]uint64, error) {
	var out []uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte(receiptsBucket)).Cursor()
		var last uint64
		first := true
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if len(k) < 8 {
				continue
			}
			epoch := binary.BigEndian.Uint64(k[:8])
			if first || epoch != last {
				out = append(out, epoch)
				last = epoch
				first = false
			}
		}
		return nil
	})
	return out, err
}

// PruneBefore deletes receipts for epochs strictly older than `epoch`, and
// returns how many rows went. Callers should only prune well past settlement:
// a receipt is the node's only evidence if a payout is disputed, so pruning
// early trades disk for the ability to argue.
func (s *ReceiptStore) PruneBefore(epoch uint64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(receiptsBucket))
		c := b.Cursor()
		var doomed [][]byte
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if len(k) < 8 || binary.BigEndian.Uint64(k[:8]) >= epoch {
				continue
			}
			// Copy: the key is only valid inside the transaction.
			key := make([]byte, len(k))
			copy(key, k)
			doomed = append(doomed, key)
		}
		for _, key := range doomed {
			if err := b.Delete(key); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
