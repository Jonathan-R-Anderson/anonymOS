// Package contain holds the operator-set containment list.
//
// It exists because an incident-response drill (internal/axon/incident, E16.4)
// found that a responder could not eject a compromised relay: dht.Table had
// Admit and no counterpart, peer.Peerbook had Observe and no counterpart, and
// profile.Forget dropped observations while leaving the peer exactly as
// selectable as before.
//
// REMOVAL ALONE WOULD HAVE BEEN THEATRE. Table.Admit re-inserts on the next
// FIND_NODE that mentions a peer and Peerbook.Observe re-creates an entry on
// the next probe, so an eject-only API would let a responder watch a relay walk
// straight back in while believing it contained. Containment is therefore
// removal AND refusal, and this package is the refusal.
//
// THREE RULES, AND THEY ARE THE WHOLE DESIGN.
//
// 1. OPERATOR-SET, NEVER AUTOMATIC. Nothing in this tree may add an entry from
// observed behaviour. §7's P3 note and the incident procedure's own step 0 say
// why: treating churn as compromise ejects honest relays, which is a partition
// you performed on yourself, and on a network of nine nodes it is a partition
// that ends the network. A relay that is slow, or newly unreachable, is an
// ordinary event the path selector already routes around. Deny takes a REASON
// for the same purpose -- an entry nobody can explain later is an entry nobody
// can safely remove.
//
// 2. IT PERSISTS. The procedure's containment step was "restart the node",
// because the routing table and peerbook are in memory. An in-memory denial
// would be erased by the very act prescribed to enforce it, and would lapse
// silently on any unrelated crash. So the list is written to disk, atomically,
// and containment survives the restart rather than being undone by it.
//
// 3. IT IS BOUNDED. An unbounded list is a memory leak and, worse, a lever: an
// adversary who can induce denials can shrink a node's view until it is
// partitioned, which is the outcome containment exists to prevent. MaxEntries
// is a refusal, not an eviction -- silently dropping the OLDEST denial to admit
// a new one would quietly un-contain the first relay somebody worried about.
//
// WHAT THIS IS NOT. It is not a reputation system, not a shared blocklist, and
// not evidence. It is one operator's local decision, auditable because every
// entry carries who-said-what-and-when, and reversible with Allow.
package contain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// FileName sits beside the rest of the node's state.
	FileName = "contained-peers.json"

	// Format is stored in the file. An unknown version is refused rather than
	// guessed at: a misparsed containment list is a node that believes it has
	// contained something it has not.
	Format = 1

	// MaxEntries bounds the list. See rule 3.
	MaxEntries = 512

	// MaxReasonBytes bounds one reason string.
	MaxReasonBytes = 512
)

var (
	// ErrNoID is returned for an empty peer id.
	ErrNoID = errors.New("axon/contain: no peer id")
	// ErrNoReason is returned when a denial carries no reason. Deliberately an
	// error and not a default: "no reason given" is how a list becomes
	// unauditable, and the responder who adds an entry is the only person who
	// still knows why.
	ErrNoReason = errors.New("axon/contain: a denial must carry a reason")
	// ErrFull is returned when the list is at MaxEntries.
	ErrFull = errors.New("axon/contain: containment list is full")
)

// Entry is one contained peer.
type Entry struct {
	// ID is the peer identifier, as the consulting structure spells it: hex of
	// dht.Contact.NodeIDPub, or peer.Peerbook's node id string. Normalised to
	// lower case so the two cannot disagree about the same peer.
	ID string `json:"id"`
	// Reason is why, in the responder's words.
	Reason string `json:"reason"`
	// At is when it was added.
	At time.Time `json:"at"`
}

// List is a set of contained peers. Safe for concurrent use.
type List struct {
	mu sync.RWMutex
	m  map[string]Entry
}

// New returns an empty list.
func New() *List { return &List{m: map[string]Entry{}} }

// Normalise renders an id the way this package stores it, so a caller holding
// bytes and a caller holding a string agree.
func Normalise(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

// Deny contains a peer. Idempotent: re-denying an already-denied peer refreshes
// the reason rather than failing, because a responder learning more mid-incident
// should be able to write it down.
func (l *List) Deny(id, reason string, at time.Time) error {
	id = Normalise(id)
	if id == "" {
		return ErrNoID
	}
	if strings.TrimSpace(reason) == "" {
		return ErrNoReason
	}
	if len(reason) > MaxReasonBytes {
		reason = reason[:MaxReasonBytes]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.m[id]; !exists && len(l.m) >= MaxEntries {
		return fmt.Errorf("%w: %d entries", ErrFull, len(l.m))
	}
	l.m[id] = Entry{ID: id, Reason: reason, At: at.UTC()}
	return nil
}

// Allow releases a peer. Reports whether it was contained.
func (l *List) Allow(id string) bool {
	id = Normalise(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.m[id]
	delete(l.m, id)
	return ok
}

// Denied reports whether a peer is contained.
//
// A nil list denies nothing, so a structure with no containment list wired in
// behaves exactly as it did before this package existed.
func (l *List) Denied(id string) bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.m[Normalise(id)]
	return ok
}

// Entries returns every entry, oldest first, for an operator to read.
func (l *List) Entries() []Entry {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.m))
	for _, e := range l.m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Len is how many peers are contained.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.m)
}

// Path is where the list lives for a given data directory.
func Path(dataDir string) string { return filepath.Join(dataDir, FileName) }

type file struct {
	Format  int     `json:"format"`
	Entries []Entry `json:"entries"`
}

// Save writes the list atomically.
//
// Temp file and rename, for the same reason the bootstrap cache does it: a
// truncate-then-write interrupted leaves a zero-length file, and the node that
// reads it next is a node that believes nothing is contained.
func (l *List) Save(dataDir string) error {
	body, err := json.MarshalIndent(file{Format: Format, Entries: l.Entries()}, "", "  ")
	if err != nil {
		return fmt.Errorf("axon/contain: encoding: %w", err)
	}
	body = append(body, '\n')

	path := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("axon/contain: directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), FileName+".tmp*")
	if err != nil {
		return fmt.Errorf("axon/contain: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("axon/contain: writing: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("axon/contain: syncing: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("axon/contain: closing: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("axon/contain: permissions: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("axon/contain: replacing: %w", err)
	}
	return nil
}

// Load reads the list. A missing file is an EMPTY list and not an error, which
// is the ordinary first-run case.
//
// A file that exists and cannot be read IS an error, and the caller must not
// proceed as though nothing were contained: that is the failure mode where a
// node quietly re-admits every relay an operator ejected.
func Load(dataDir string) (*List, error) {
	body, err := os.ReadFile(Path(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, fmt.Errorf("axon/contain: reading: %w", err)
	}
	var f file
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("axon/contain: unreadable: %w", err)
	}
	if f.Format != Format {
		return nil, fmt.Errorf("axon/contain: format %d is not %d", f.Format, Format)
	}
	l := New()
	for _, e := range f.Entries {
		id := Normalise(e.ID)
		if id == "" {
			continue
		}
		if len(l.m) >= MaxEntries {
			return nil, fmt.Errorf("%w: file holds more than %d", ErrFull, MaxEntries)
		}
		l.m[id] = Entry{ID: id, Reason: e.Reason, At: e.At}
	}
	return l, nil
}

// DenyAll contains a node under every spelling of its identity, ALL OR NOTHING.
//
// Pair it with link.ContainmentIDs, which returns the two spellings one node
// has -- AXON hex for the routing table and peerbook, libp2p base58 for the
// bootstrap path and storage.
//
// ATOMIC, and that is the whole reason this is not a loop at the call site. A
// partial containment is the worst outcome available here: the responder sees
// no error, believes the host is contained, and it keeps returning through
// whichever structure got the id that did not land. So the cap is checked
// against the full set first, and either every spelling is denied or none is.
func (l *List) DenyAll(ids []string, reason string, at time.Time) error {
	if len(ids) == 0 {
		return ErrNoID
	}
	if strings.TrimSpace(reason) == "" {
		return ErrNoReason
	}
	if len(reason) > MaxReasonBytes {
		reason = reason[:MaxReasonBytes]
	}

	normalised := make([]string, 0, len(ids))
	for _, id := range ids {
		id = Normalise(id)
		if id == "" {
			return ErrNoID
		}
		normalised = append(normalised, id)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Count only the ids that are NOT already held, so re-denying a node that
	// is already contained cannot fail on the cap.
	adding := 0
	for _, id := range normalised {
		if _, exists := l.m[id]; !exists {
			adding++
		}
	}
	if len(l.m)+adding > MaxEntries {
		return fmt.Errorf("%w: %d entries, %d more needed", ErrFull, len(l.m), adding)
	}
	for _, id := range normalised {
		l.m[id] = Entry{ID: id, Reason: reason, At: at.UTC()}
	}
	return nil
}

// AllowAll releases every spelling. Reports how many were contained.
func (l *List) AllowAll(ids []string) int {
	released := 0
	for _, id := range ids {
		if l.Allow(id) {
			released++
		}
	}
	return released
}
