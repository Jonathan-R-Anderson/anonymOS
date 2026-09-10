package dcs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Who deployed which container, remembered across restarts.
//
// This used to live only in a map on the Agent, and the consequence was severe
// and silent: a worker restart wiped it, so every container already running
// became permanently un-destroyable. HandleDestroy refuses any container it
// cannot attribute — correctly, since one deployer must not be able to kill
// another's work — and after a restart it could attribute none of them. Six
// deliberately vulnerable containers were found still up after forty hours for
// exactly this reason, and because the worker still counted them against their
// owner, the accounts that started them could not launch anything else either.
//
// The file is written on every change rather than at shutdown. A worker that
// crashes is precisely the case this exists for, and state flushed on a clean
// exit is state you do not have when it matters.

type ownershipRecord struct {
	Owner   string `json:"owner"`
	Compose string `json:"compose,omitempty"`
}

type ownershipStore struct {
	path    string
	mu      sync.Mutex
	records map[string]ownershipRecord
}

func newOwnershipStore(path string) *ownershipStore {
	s := &ownershipStore{path: path, records: map[string]ownershipRecord{}}
	s.load()
	return s
}

func (s *ownershipStore) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var records map[string]ownershipRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		// Corrupt state is dropped rather than repaired. Guessing an owner
		// would let the wrong node tear down someone's container, which is the
		// one outcome the ownership check exists to prevent.
		return
	}
	s.mu.Lock()
	s.records = records
	s.mu.Unlock()
}

// flush writes the file. Errors are returned for the caller to log; they are
// never fatal, because failing a deploy over a bookkeeping write would trade a
// recoverable leak for an outage.
func (s *ownershipStore) flush() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	raw, err := json.Marshal(s.records)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	// Written via a temp file and renamed: a half-written map is worse than an
	// old one, since it would orphan every container listed after the cut.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *ownershipStore) set(containerID, owner, compose string) {
	s.mu.Lock()
	s.records[containerID] = ownershipRecord{Owner: owner, Compose: compose}
	s.mu.Unlock()
}

func (s *ownershipStore) setCompose(containerID, compose string) {
	s.mu.Lock()
	record := s.records[containerID]
	record.Compose = compose
	s.records[containerID] = record
	s.mu.Unlock()
}

func (s *ownershipStore) owner(containerID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[containerID]
	return record.Owner, ok
}

func (s *ownershipStore) compose(containerID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[containerID]
	if !ok || record.Compose == "" {
		return "", false
	}
	return record.Compose, true
}

func (s *ownershipStore) forget(containerID string) {
	s.mu.Lock()
	delete(s.records, containerID)
	s.mu.Unlock()
}
