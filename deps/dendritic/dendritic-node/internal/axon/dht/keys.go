// Package dht is AXON's L3: one Kademlia routing substrate carrying six
// domain-separated record classes across two keyspaces (R4d).
//
// The three things that make it different from the production
// go-libp2p-kad-dht already running in this binary:
//
//  1. A node cannot choose its position. KadID = H(NodeIdentity ‖ SRV_epoch ‖
//     network_prefix), so placement costs an identity, expires every epoch, and
//     is checkable against the address a peer is actually speaking from.
//  2. Lookups run d=3 node-disjoint paths, so censorship requires a presence on
//     every path rather than on one.
//  3. Every record class recomputes its own key from its own fields, so a write
//     for one class can never land on another class's record.
//
// WHAT IS DELIBERATELY ABSENT, per P4's "must NOT be built yet": client lookups
// over circuits (R4b needs them; circuits are P5, so lookups are direct and the
// code LOGS that as a known unsafe mode -- see UnsafeDirectLookup), storage
// contracts, and any reputation weighting of routing entries.
package dht

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// RecordClass is one of the six §7.1 classes. The string form is the ASCII
// label that goes into the key pre-image, and it is the entire reason two
// classes can never collide.
type RecordClass uint8

const (
	ClassRelay    RecordClass = iota + 1 // RelayDescriptor
	ClassDesc                            // ServiceDescriptor, blinded
	ClassDomain                          // DomainRecord
	ClassLocation                        // StorageLocation, multi-writer
	ClassSnapshot                        // RegistrySnapshot anchor
	ClassIntro                           // IntroPointRecord
	ClassReport                          // ContentReport (Part X §89, G4)
)

// label is the ASCII class label used in the key pre-image.
func (c RecordClass) label() string {
	switch c {
	case ClassRelay:
		return "relay"
	case ClassDesc:
		return "desc"
	case ClassDomain:
		return "domain"
	case ClassLocation:
		return "loc"
	case ClassSnapshot:
		return "snap"
	case ClassIntro:
		return "intro"
	case ClassReport:
		return "report"
	default:
		return ""
	}
}

func (c RecordClass) String() string {
	if l := c.label(); l != "" {
		return l
	}
	return "unknown"
}

// Keyspace separates descriptor-plane records from content-plane records.
//
// R4d asks for two keyspaces, NOT two overlays. §7.1 rejects the two-overlay
// reading explicitly: separate overlays halve the honest node count in each
// while leaving the attacker's identity budget whole, which LOWERS the Sybil bar
// in both. So this is a label on records over one routing table, not a second
// routing table.
type Keyspace uint8

const (
	KeyspaceDescriptor Keyspace = iota // relay, desc, domain, snap, intro
	KeyspaceContent                    // loc
)

// Keyspace reports which plane a class belongs to.
func (c RecordClass) Keyspace() Keyspace {
	if c == ClassLocation {
		return KeyspaceContent
	}
	return KeyspaceDescriptor
}

// Replicas is r, the replica count for a key. Uniform at 8 (Constitution §5).
const Replicas = 8

// DescriptorReplicaPositions is how many INDEPENDENT keyspace positions a
// ServiceDescriptor occupies.
//
// Descriptors alone get this: with replica_index in the pre-image the 8 replicas
// sit at 8 unrelated keyspace points, so eclipsing a descriptor means eclipsing
// eight unrelated regions. Publishing costs 8 lookups; fetching costs one,
// because the client picks an index at random. StorageLocation is excluded --
// 8x publish cost per CID is unaffordable at content scale, and its replica set
// is already governed by the §7.5 diversity ladder.
const DescriptorReplicaPositions = 8

// Key is a 256-bit DHT key.
type Key [32]byte

func (k Key) String() string { return fmt.Sprintf("%x", k[:]) }

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// ErrUnknownClass is returned for a class outside the six.
var ErrUnknownClass = errors.New("axon/dht: unknown record class")

// DeriveKey computes key(class, input) = SHA-256("axon:" ‖ class ‖ ":v1" ‖ 0x00 ‖ input).
//
// The 0x00 separator is what makes the label unambiguous: without it, class
// "relay" with input "x" and a hypothetical class "relayx" with empty input
// would hash the same bytes. The labels here happen not to be prefixes of one
// another, but relying on that is relying on a property nobody will re-check
// when a seventh class is added.
func DeriveKey(class RecordClass, input []byte) (Key, error) {
	label := class.label()
	if label == "" {
		return Key{}, ErrUnknownClass
	}
	h := sha256.New()
	h.Write([]byte("axon:"))
	h.Write([]byte(label))
	h.Write([]byte(":v1"))
	h.Write([]byte{0x00})
	h.Write(input)
	var k Key
	copy(k[:], h.Sum(nil))
	return k, nil
}

// MustDeriveKey is DeriveKey for a class known at compile time.
func MustDeriveKey(class RecordClass, input []byte) Key {
	k, err := DeriveKey(class, input)
	if err != nil {
		panic(err)
	}
	return k
}

// Distance is the Kademlia XOR metric.
func Distance(a, b Key) Key {
	var d Key
	for i := range a {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// Less orders two distances. Kademlia's metric is a big-endian unsigned
// comparison of the XOR.
func (k Key) Less(other Key) bool {
	for i := range k {
		if k[i] != other[i] {
			return k[i] < other[i]
		}
	}
	return false
}

// CommonPrefixLen is the number of leading bits two keys share, which is the
// bucket index for Kademlia routing.
func CommonPrefixLen(a, b Key) int {
	for i := range a {
		if x := a[i] ^ b[i]; x != 0 {
			n := 0
			for bit := byte(0x80); bit != 0 && x&bit == 0; bit >>= 1 {
				n++
			}
			return i*8 + n
		}
	}
	return len(a) * 8
}
