package dht

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Routing table, admission caps, and the sibling list (§7.2, §7.3).

// Kademlia parameters (Constitution §5).
const (
	BucketSize    = 20           // k
	Concurrency   = 3            // alpha
	DisjointPaths = 3            // d
	SiblingCount  = 2 * Replicas // s = 16
)

// Admission caps per k-bucket (§7.2).
//
// These bound identities per LOCATION, not per wallet. §7.7 is explicit that
// bonds are a price rather than a barrier and that a funded adversary buys
// their share f; the caps are what stop that share from being concentrated
// where it does the most damage.
//
// The FIGURES live in params, not here. They used to be literals in this file
// and identical literals existed in three other selection points; P14 composes
// them into one policy because four copies of a policy drift, and a cap that
// drifts at one point out of four is no cap at all -- the adversary uses that
// point. See sybil.CapsFor.
const (
	MaxPerPrefixPerBucket = params.MaxPerPrefixPerBucket
	MaxPerASNPerBucket    = params.MaxPerASNPerBucket
)

// Sibling-list caps (§7.5 diversity ladder). Tighter than the bucket caps
// because the sibling list is what decides replica-set membership, and a
// replica set admits at most one member per /24 and one per ASN.
//
// This is the term that converts eclipse from "buy identities" to "buy presence
// in eight independent autonomous systems, each with its own /24, and keep all
// eight bonded across every epoch you want the eclipse to persist". For a
// well-resourced adversary that is a purchase order, not a barrier -- a large
// cloud provider spans many ASNs, and ASN diversity is not operator diversity.
const (
	MaxPerPrefixInSiblings = params.MaxPerPrefixPerReplicaSet
	MaxPerASNInSiblings    = params.MaxPerASNPerReplicaSet
)

var (
	ErrPrefixCapReached = errors.New("axon/dht: per-prefix admission cap reached for this bucket")
	ErrASNCapReached    = errors.New("axon/dht: per-ASN admission cap reached for this bucket")
	ErrBucketFull       = errors.New("axon/dht: bucket is full")
	ErrUnverified       = errors.New("axon/dht: entry is unverified and may not be counted toward a replica set")
	// ErrContained is an admission refused because the operator contained this
	// peer. Distinct from every cap error on purpose: a cap refusal describes the
	// NETWORK and this one describes a DECISION somebody made, and an operator
	// debugging a thin table needs to tell those apart immediately.
	ErrContained = errors.New("axon/dht: peer is contained by operator decision")
)

// Contact is one routing-table entry: a peer's compact RelayDescriptor
// projection plus how we came to believe it.
type Contact struct {
	NodeIDPub [32]byte
	KadID     Key
	Addr      netip.Addr
	Prefix    NetworkPrefix
	ASN       uint32

	// Verified means the entry was learned over a LIVE CONNECTION whose observed
	// source prefix matched the KadID recomputation (§7.3 rule (c)).
	//
	// Entries learned indirectly -- returned in a FIND_NODE -- satisfy the
	// signature and KadID checks but not this one. THAT DISTINCTION IS THE WHOLE
	// VALUE OF THE SIGNATURE: an unverified entry may be used to make routing
	// progress but may NEVER be counted toward a replica set, because a peer
	// that can put itself in your replica set by being mentioned has not been
	// checked by anybody.
	Verified bool
}

// prefixKey is the string form used for cap accounting.
func (c Contact) prefixKey() string { return c.Prefix.String() }

// Table is a Kademlia routing table rooted at one node's KadID.
type Table struct {
	self Key

	mu      sync.RWMutex
	buckets map[int][]Contact
	// siblings is the s=16 nodes closest to self, under the tighter caps.
	siblings []Contact
	// contained is the operator's containment list, or nil.
	//
	// CONSULTED, NOT OWNED. The policy lives in internal/axon/contain because
	// the peerbook needs the same answer and two copies of a denial rule is one
	// copy too many -- a peer contained in one structure and admitted by the
	// other is contained nowhere. Nil denies nothing, so a table built without
	// one behaves exactly as it did before containment existed.
	contained Denier
}

// Denier answers whether a peer is contained. Satisfied by *contain.List.
//
// An interface rather than the concrete type so this package does not import
// the containment list, which imports nothing from here: the dependency runs
// one way and the test doubles stay trivial.
type Denier interface {
	Denied(id string) bool
}

// NewTable builds an empty table for a node at `self`.
func NewTable(self Key) *Table {
	return &Table{self: self, buckets: map[int][]Contact{}}
}

// SetContainment wires the operator's containment list in.
//
// Existing entries are NOT swept here. Contain does that, and separating them
// is deliberate: a responder containing one relay should not silently reshape
// the table according to a list they have not read. Call SweepContained
// explicitly after loading a list from disk at startup.
func (t *Table) SetContainment(d Denier) {
	t.mu.Lock()
	t.contained = d
	t.mu.Unlock()
}

// ContactID is how a contact is spelled in the containment list.
func ContactID(pub [32]byte) string { return hex.EncodeToString(pub[:]) }

// Eject removes a peer from every bucket and from the sibling list.
//
// Returns how many entries went. EJECTING WITHOUT DENYING IS THEATRE: Admit
// re-inserts the peer on the next FIND_NODE that mentions it, so a responder
// who called only this would watch the relay walk back in. Deny in the
// containment list first, or use it through SweepContained.
func (t *Table) Eject(pub [32]byte) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ejectLocked(pub)
}

func (t *Table) ejectLocked(pub [32]byte) int {
	removed := 0
	for idx, b := range t.buckets {
		kept := b[:0]
		for _, c := range b {
			if c.NodeIDPub == pub {
				removed++
				continue
			}
			kept = append(kept, c)
		}
		if len(kept) == 0 {
			delete(t.buckets, idx)
			continue
		}
		t.buckets[idx] = kept
	}
	kept := t.siblings[:0]
	for _, c := range t.siblings {
		if c.NodeIDPub == pub {
			removed++
			continue
		}
		kept = append(kept, c)
	}
	t.siblings = kept
	return removed
}

// SweepContained ejects every peer the containment list currently denies.
//
// This is what makes a denial retroactive. A list loaded from disk at startup
// describes peers an operator ejected in an earlier incident, and without this
// the table would happily re-learn all of them -- containment that lapses
// across the restart it was supposed to survive.
func (t *Table) SweepContained() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.contained == nil {
		return 0
	}
	seen := map[[32]byte]bool{}
	for _, b := range t.buckets {
		for _, c := range b {
			seen[c.NodeIDPub] = true
		}
	}
	for _, c := range t.siblings {
		seen[c.NodeIDPub] = true
	}
	removed := 0
	for pub := range seen {
		if t.contained.Denied(ContactID(pub)) {
			removed += t.ejectLocked(pub)
		}
	}
	return removed
}

// Self is the table's own KadID.
func (t *Table) Self() Key { return t.self }

// bucketIndex is the shared-prefix length with self.
func (t *Table) bucketIndex(k Key) int {
	i := CommonPrefixLen(t.self, k)
	if i >= 256 {
		i = 255
	}
	return i
}

// Admit inserts a contact, enforcing the §7.2 caps.
//
// The caps are checked BEFORE the bucket-full check so a diverse-but-full
// bucket and a concentrated one produce different errors: an operator reading
// "per-prefix cap reached" is looking at a possible eclipse attempt, and one
// reading "bucket full" is looking at a healthy table.
func (t *Table) Admit(c Contact) error {
	idx := t.bucketIndex(c.KadID)

	t.mu.Lock()
	defer t.mu.Unlock()

	// Containment is checked FIRST, before the caps and before the re-admission
	// upgrade below. A contained peer must not be able to refresh an existing
	// entry either, or a relay an operator ejected keeps its slot by being
	// mentioned once more.
	if t.contained != nil && t.contained.Denied(ContactID(c.NodeIDPub)) {
		return fmt.Errorf("%w: %s", ErrContained, ContactID(c.NodeIDPub)[:16])
	}

	// The sibling list is a SEPARATE structure with its own, tighter caps, and
	// it is maintained independently of bucket admission.
	//
	// Coupling them was a real defect: bucket 0 covers half the keyspace and
	// fills at k=20 in any network of moderate size, and a coupled
	// implementation would let a full routing bucket silently block replica-set
	// membership for a node that is genuinely among the s closest. S/Kademlia
	// keeps the sibling list separate precisely because "who is near me" and
	// "who do I route through" are different questions.
	defer t.updateSiblingsLocked(c)

	b := t.buckets[idx]
	for i, existing := range b {
		if existing.NodeIDPub == c.NodeIDPub {
			// Re-admission upgrades unverified to verified, never the reverse:
			// a peer cannot launder a verified entry back to unverified to
			// escape a cap, and a live connection is strictly better evidence
			// than a mention.
			if c.Verified {
				b[i] = c
			}
			return nil
		}
	}

	prefixes, asns := 0, 0
	for _, existing := range b {
		if existing.prefixKey() == c.prefixKey() {
			prefixes++
		}
		if c.ASN != 0 && existing.ASN == c.ASN {
			asns++
		}
	}
	if prefixes >= MaxPerPrefixPerBucket {
		return fmt.Errorf("%w: %s already holds %d of %d in bucket %d",
			ErrPrefixCapReached, c.prefixKey(), prefixes, MaxPerPrefixPerBucket, idx)
	}
	if c.ASN != 0 && asns >= MaxPerASNPerBucket {
		return fmt.Errorf("%w: AS%d already holds %d of %d in bucket %d",
			ErrASNCapReached, c.ASN, asns, MaxPerASNPerBucket, idx)
	}
	if len(b) >= BucketSize {
		return ErrBucketFull
	}

	t.buckets[idx] = append(b, c)
	return nil
}

// updateSiblingsLocked maintains the s=16 closest under the tighter caps.
func (t *Table) updateSiblingsLocked(c Contact) {
	// An unverified entry may make routing progress but may never enter the
	// sibling list, because the sibling list is what decides replica sets.
	if !c.Verified {
		return
	}
	for i, s := range t.siblings {
		if s.NodeIDPub == c.NodeIDPub {
			// Already a sibling: refresh it in place so a re-verification does
			// not silently keep a stale KadID.
			t.siblings[i] = c
			return
		}
	}
	prefixes, asns := 0, 0
	for _, s := range t.siblings {
		if s.prefixKey() == c.prefixKey() {
			prefixes++
		}
		if c.ASN != 0 && s.ASN == c.ASN {
			asns++
		}
	}
	if prefixes >= MaxPerPrefixInSiblings {
		return
	}
	if c.ASN != 0 && asns >= MaxPerASNInSiblings {
		return
	}

	t.siblings = append(t.siblings, c)
	self := t.self
	sort.Slice(t.siblings, func(i, j int) bool {
		return Distance(t.siblings[i].KadID, self).Less(Distance(t.siblings[j].KadID, self))
	})
	if len(t.siblings) > SiblingCount {
		t.siblings = t.siblings[:SiblingCount]
	}
}

// Siblings returns the s closest known nodes to self.
func (t *Table) Siblings() []Contact {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]Contact(nil), t.siblings...)
}

// Bucket returns a copy of one bucket, for tests and diagnostics.
func (t *Table) Bucket(idx int) []Contact {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]Contact(nil), t.buckets[idx]...)
}

// Len is the total number of contacts.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, b := range t.buckets {
		n += len(b)
	}
	return n
}

// Closest returns the n contacts closest to a key.
//
// verifiedOnly is not a convenience flag: a replica-set decision must pass
// true, and a routing-progress decision may pass false. Getting this wrong is
// how an unverified entry ends up counted toward a replica set.
func (t *Table) Closest(key Key, n int, verifiedOnly bool) []Contact {
	t.mu.RLock()
	all := make([]Contact, 0, t.lenLocked())
	for _, b := range t.buckets {
		for _, c := range b {
			if verifiedOnly && !c.Verified {
				continue
			}
			all = append(all, c)
		}
	}
	t.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool {
		return Distance(all[i].KadID, key).Less(Distance(all[j].KadID, key))
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func (t *Table) lenLocked() int {
	n := 0
	for _, b := range t.buckets {
		n += len(b)
	}
	return n
}

// Rebuild recomputes every contact's KadID under a new SRV and re-admits them.
//
// THE EPOCH BOUNDARY IS THE DANGEROUS MOMENT, and this is where it is handled.
// Every node's position moves at once, so a table that was not rebuilt would
// route toward positions nobody occupies any more -- and a lookup crossing the
// boundary would fail CONSISTENTLY rather than randomly, which looks like a
// broken network rather than a transient.
//
// Contacts whose KadID cannot be recomputed (no address on file) are dropped
// rather than carried over at a stale position: a contact at a position it does
// not occupy is worse than a missing contact, because it silently absorbs
// lookups.
func (t *Table) Rebuild(selfPub [32]byte, srv SRV, selfPrefix NetworkPrefix) (kept, dropped int, err error) {
	newSelf, err := DeriveKadID(selfPub, srv, selfPrefix)
	if err != nil {
		return 0, 0, err
	}

	t.mu.Lock()
	old := make([]Contact, 0, t.lenLocked())
	for _, b := range t.buckets {
		old = append(old, b...)
	}
	t.self = newSelf
	t.buckets = map[int][]Contact{}
	t.siblings = nil
	t.mu.Unlock()

	for _, c := range old {
		id, err := DeriveKadID(c.NodeIDPub, srv, c.Prefix)
		if err != nil {
			dropped++
			continue
		}
		c.KadID = id
		if err := t.Admit(c); err != nil {
			dropped++
			continue
		}
		kept++
	}
	return kept, dropped, nil
}
