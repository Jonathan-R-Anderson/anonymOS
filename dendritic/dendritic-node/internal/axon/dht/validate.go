package dht

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Validation, conflict resolution, and rollback resistance (§7.6).

// SizeBound is the class's maximum wire size.
func SizeBound(c RecordClass) int {
	switch c {
	case ClassRelay:
		return MaxRelayDescriptor
	case ClassDesc:
		return MaxServiceDescriptor
	case ClassDomain:
		return MaxDomainRecord
	case ClassLocation:
		return MaxStorageLocation
	case ClassSnapshot:
		return MaxRegistrySnapshot
	case ClassIntro:
		return MaxIntroPoint
	default:
		return 0
	}
}

// TTLBound is the longest lifetime the class may claim.
func TTLBound(c RecordClass) time.Duration {
	switch c {
	case ClassRelay:
		return TTLRelayDescriptor
	case ClassDesc:
		return TTLServiceDescriptor
	case ClassDomain:
		return TTLDomainRecord
	case ClassLocation:
		return TTLStorageEntry
	case ClassSnapshot:
		return TTLRegistrySnapshot
	case ClassIntro:
		return TTLIntroPoint
	default:
		return 0
	}
}

// ChainVerifier proves a RegistrySnapshot against the chain.
//
// It is an interface because §7.1 makes the snapshot self-verifying and
// UNRESTRICTED: anyone may publish, and correctness is decided by the light
// client, not by who signed. A nil verifier means the node cannot check, and a
// node that cannot check must REJECT rather than accept -- otherwise "anyone may
// publish" becomes "anyone may publish anything".
type ChainVerifier interface {
	VerifySnapshot(s *RegistrySnapshot) error
}

// Validator checks a record against its key, its class rules, and the floor.
type Validator struct {
	// Now is injectable for tests.
	Now func() time.Time
	// Floor supplies rollback resistance. Nil disables it, which is a valid
	// configuration for a fresh node and is exactly the residual §7.6 names.
	Floor *SeqFloor
	// Chain verifies RegistrySnapshot records. Nil means snapshots are refused.
	Chain ChainVerifier
	// DomainAuthorised reports whether a DomainIdentity is bound to a name hash
	// in the current registry snapshot. Nil means DomainRecords are refused,
	// for the same reason as Chain.
	DomainAuthorised func(nameHash, domainIDPub []byte, snapshotRoot []byte, proof []byte) error
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Validate is the full check: size, canonical encoding, key derivation,
// signature, freshness, and the sequence floor.
//
// ORDER MATTERS. Size is checked before decoding so an oversized record cannot
// cost the decoder any work; key derivation is checked before signature
// verification so a record aimed at the wrong key is rejected without an
// Ed25519 verification the attacker got us to perform for free.
func (v *Validator) Validate(class RecordClass, key Key, wire []byte) (Record, error) {
	bound := SizeBound(class)
	if bound == 0 {
		return nil, ErrUnknownClass
	}
	if len(wire) > bound {
		return nil, fmt.Errorf("%w: %d > %d for class %s", ErrOversize, len(wire), bound, class)
	}
	if err := IsCanonical(class, wire); err != nil {
		return nil, err
	}
	rec, err := DecodeRecord(class, wire)
	if err != nil {
		return nil, err
	}
	if rec.Class() != class {
		return nil, ErrWrongRecordType
	}

	// THE RULE THAT MAKES SIX CLASSES SAFE OVER ONE TABLE: recompute the key
	// from the record's own fields and refuse a mismatch.
	derived, err := rec.DerivedKey()
	if err != nil {
		return nil, err
	}
	if derived != key {
		return nil, fmt.Errorf("%w: arrived at %s, derives to %s", ErrWrongKey, key, derived)
	}

	now := v.now()
	if err := v.checkFreshness(rec, now); err != nil {
		return nil, err
	}
	if err := v.checkAuthorisation(rec); err != nil {
		return nil, err
	}
	if v.Floor != nil {
		if err := v.Floor.Check(key, rec.Seq()); err != nil {
			return nil, err
		}
	}
	return rec, nil
}

func (v *Validator) checkFreshness(rec Record, now time.Time) error {
	// StorageLocation is a set of independently-expiring entries; the record
	// itself has no single lifetime to bound. Entry expiry is enforced in the
	// merge.
	if rec.Class() == ClassLocation {
		return nil
	}
	issued, expires := issuedExpires(rec)
	if expires <= now.Unix() {
		return fmt.Errorf("%w: expired at %d, now %d", ErrExpired, expires, now.Unix())
	}
	if bound := TTLBound(rec.Class()); bound > 0 && expires-issued > int64(bound/time.Second) {
		return fmt.Errorf("%w: %ds > %s for class %s",
			ErrOverLongTTL, expires-issued, bound, rec.Class())
	}
	return nil
}

func issuedExpires(rec Record) (int64, int64) {
	switch r := rec.(type) {
	case *RelayDescriptor:
		return r.IssuedAt, r.ExpiresAt
	case *ServiceDescriptor:
		return r.IssuedAt, r.ExpiresAt
	case *DomainRecord:
		return r.IssuedAt, r.ExpiresAt
	case *RegistrySnapshot:
		return r.IssuedAt, r.ExpiresAt
	case *IntroPointRecord:
		return r.IssuedAt, r.ExpiresAt
	default:
		return 0, 0
	}
}

// checkAuthorisation applies each class's "who may write" rule from §7.1.
func (v *Validator) checkAuthorisation(rec Record) error {
	switch r := rec.(type) {
	case *RelayDescriptor:
		// Only the holder of the NodeIdentity whose pubkey is in the key
		// pre-image.
		return verifySig(r.NodeIDPub, r.signingBytes, r.Sig)

	case *ServiceDescriptor:
		// Anyone holding the blinded private key. The storing node verifies
		// against the pubkey from its OWN key derivation, so it authorises
		// without learning who.
		return verifySig(r.BlindedPub, r.signingBytes, r.Sig)

	case *IntroPointRecord:
		return verifySig(r.RoutingID, r.signingBytes, r.Sig)

	case *DomainRecord:
		if err := verifySig(r.DomainIDPub, r.signingBytes, r.Sig); err != nil {
			return err
		}
		// A valid signature is NOT sufficient: any keypair can sign a claim to
		// any name. The binding to the name hash must verify against the
		// registry snapshot root the record itself carries.
		if v.DomainAuthorised == nil {
			return errors.New("axon/dht: no registry snapshot available to authorise a DomainRecord")
		}
		return v.DomainAuthorised(r.NameHash, r.DomainIDPub, r.SnapshotRoot, r.InclusionProof)

	case *RegistrySnapshot:
		// The signature identifies the publisher and is explicitly NOT the
		// authorisation; the chain proof is.
		if err := verifySig(r.PublisherPub, r.signingBytes, r.Sig); err != nil {
			return err
		}
		if v.Chain == nil {
			return errors.New("axon/dht: no chain verifier available to authorise a RegistrySnapshot")
		}
		return v.Chain.VerifySnapshot(r)

	case *StorageLocation:
		if len(r.Entries) > MaxStorageEntries {
			return fmt.Errorf("%w: %d > %d", ErrTooManyEntries, len(r.Entries), MaxStorageEntries)
		}
		// Each entry is authorised by its own holder, and must be for this CID.
		for i := range r.Entries {
			if !bytesEqual(r.Entries[i].CID, r.CID) {
				return fmt.Errorf("%w: entry %d names a different CID", ErrWrongKey, i)
			}
			if err := r.Entries[i].Verify(); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
		}
		return nil
	}
	return ErrUnknownClass
}

func verifySig(pub []byte, sb func() ([]byte, error), sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signing key is %d bytes", ErrBadSignature, len(pub))
	}
	msg, err := sb()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return ErrBadSignature
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Conflict resolution
// -----------------------------------------------------------------------------

// Better implements §7.6's single-writer rule, exactly:
//
//  1. drop any record failing validate() outright   (the caller's job)
//  2. higher seq wins
//  3. tie -> lower SHA-256(canonical_encoding) wins
//  4. never: "newer wall-clock", "the one I heard first", "the larger one"
//
// Rule 3 is not decoration. Two honest replicas that disagree must converge on
// the same answer WITHOUT TALKING TO EACH OTHER, or the record oscillates
// forever and every client sees a coin flip. A wall-clock tiebreak would
// reintroduce the clock as a trust input.
//
// It returns true when a is better than b.
func Better(aSeq uint64, aWire []byte, bSeq uint64, bWire []byte) bool {
	if aSeq != bSeq {
		return aSeq > bSeq
	}
	ad, bd := CanonicalDigest(aWire), CanonicalDigest(bWire)
	for i := range ad {
		if ad[i] != bd[i] {
			return ad[i] < bd[i]
		}
	}
	return false
}

// SelectBest returns the index of the best of several encodings of one key.
func SelectBest(class RecordClass, wires [][]byte, v *Validator, key Key) (int, error) {
	best := -1
	var bestSeq uint64
	for i, w := range wires {
		rec, err := v.Validate(class, key, w)
		if err != nil {
			continue
		}
		if best < 0 || Better(rec.Seq(), w, bestSeq, wires[best]) {
			best, bestSeq = i, rec.Seq()
		}
	}
	if best < 0 {
		return 0, errors.New("axon/dht: no valid records")
	}
	return best, nil
}

// MergeStorageLocation implements §7.6's multi-writer rule.
//
//	entries <- a.entries U b.entries, keyed by holder_node_id
//	per holder: keep the entry with the higher exp and a valid sig
//	drop entries whose exp has passed
//	drop entries whose bond_ref does not verify
//	if |entries| > 64: keep the 64 with the highest bond, ties by lowest node id
//
// The bond-ordered eviction is what stops an index-poisoning flood: an attacker
// can add entries, but displacing an honest holder from a full record costs more
// bond than the honest holder posted.
//
// The residual §7.7 names and this code cannot fix: an attacker with ENOUGH bond
// can occupy the list and turn every fetch into 64 wasted dials. That is a DoS
// on retrieval latency, not on correctness.
func MergeStorageLocation(a, b *StorageLocation, now time.Time, bondOK func(entry StorageEntry) bool) *StorageLocation {
	out := &StorageLocation{Ver: a.Ver, CID: append([]byte(nil), a.CID...)}
	byHolder := map[string]StorageEntry{}

	add := func(entries []StorageEntry) {
		for _, e := range entries {
			if e.ExpiresAt <= now.Unix() {
				continue
			}
			if !bytesEqual(e.CID, out.CID) {
				continue
			}
			if err := e.Verify(); err != nil {
				continue
			}
			if bondOK != nil && !bondOK(e) {
				continue
			}
			k := string(e.HolderNodeID)
			if prev, ok := byHolder[k]; ok && prev.ExpiresAt >= e.ExpiresAt {
				continue
			}
			byHolder[k] = e
		}
	}
	add(a.Entries)
	if b != nil {
		add(b.Entries)
	}

	for _, e := range byHolder {
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		if out.Entries[i].Bond != out.Entries[j].Bond {
			return out.Entries[i].Bond > out.Entries[j].Bond
		}
		return string(out.Entries[i].HolderNodeID) < string(out.Entries[j].HolderNodeID)
	})
	if len(out.Entries) > MaxStorageEntries {
		out.Entries = out.Entries[:MaxStorageEntries]
	}
	return out
}

// -----------------------------------------------------------------------------
// Rollback resistance
// -----------------------------------------------------------------------------

// SeqFloor is §7.6's rollback guard: key -> highest seq ever validated,
// retained for 2 x MaxTTL past the record's own expiry. Costs 40 bytes per key.
//
// THE HONEST RESIDUAL, which §7.6 states and this implementation cannot remove:
// a node that has never seen the key HAS NO FLOOR, so rollback succeeds against
// freshly joined nodes and nodes whose floor aged out. The three partial
// defences -- quorum read, floor transfer on join, chain anchoring for
// DomainRecord -- are all partial, and rollback is [NEEDS RESEARCH] in general.
// A DHT without consensus cannot make "this is the newest version" decidable; it
// can only make old versions expensive to present.
type SeqFloor struct {
	mu     sync.RWMutex
	floors map[Key]floorEntry
	now    func() time.Time
}

type floorEntry struct {
	seq    uint64
	retain time.Time
}

// NewSeqFloor builds an empty floor table.
func NewSeqFloor(now func() time.Time) *SeqFloor {
	if now == nil {
		now = time.Now
	}
	return &SeqFloor{floors: map[Key]floorEntry{}, now: now}
}

// Check refuses a sequence at or below the recorded floor.
func (s *SeqFloor) Check(key Key, seq uint64) error {
	s.mu.RLock()
	e, ok := s.floors[key]
	s.mu.RUnlock()
	if !ok {
		// No floor: this is the residual, not a bug. The caller is a node that
		// has never seen this key.
		return nil
	}
	if s.now().After(e.retain) {
		return nil
	}
	if seq < e.seq {
		return fmt.Errorf("%w: seq %d < floor %d", ErrReplayedSeq, seq, e.seq)
	}
	return nil
}

// Record raises the floor for a key after a successful validation.
func (s *SeqFloor) Record(key Key, seq uint64, expiry time.Time) {
	retain := expiry.Add(2 * MaxTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.floors[key]; ok && e.seq >= seq && s.now().Before(e.retain) {
		// Keep the higher floor and extend retention.
		if retain.After(e.retain) {
			e.retain = retain
			s.floors[key] = e
		}
		return
	}
	s.floors[key] = floorEntry{seq: seq, retain: retain}
}

// Prune drops floors past their retention window.
func (s *SeqFloor) Prune() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, e := range s.floors {
		if now.After(e.retain) {
			delete(s.floors, k)
			n++
		}
	}
	return n
}

// Len is the number of tracked keys.
func (s *SeqFloor) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.floors)
}
