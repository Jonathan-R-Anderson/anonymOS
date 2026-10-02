package dht

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// The six §7.1 record classes, their canonical encoding, and their validators.
//
// The rule that makes six classes safe over one routing table: THE STORING NODE
// RECOMPUTES THE KEY FROM THE RECORD'S OWN FIELDS AND REJECTS A MISMATCH. A
// write for class X can never overwrite a record of class Y even if an attacker
// finds an input producing the same digest, because the digest is not what
// authorises the write -- the recomputation is. This generalises the rule
// internal/dcs/dht.go already enforces for worker records.

// Size bounds from §7.1, in bytes.
const (
	MaxRelayDescriptor   = 2 << 10  // 2 KiB
	MaxServiceDescriptor = 8 << 10  // 8 KiB
	MaxDomainRecord      = 16 << 10 // 16 KiB
	MaxStorageLocation   = 8 << 10  // 8 KiB
	MaxRegistrySnapshot  = 4 << 10  // 4 KiB
	MaxIntroPoint        = 512      // 512 B
)

// TTLs from §7.1.
const (
	TTLRelayDescriptor   = 3 * time.Hour
	TTLServiceDescriptor = 3 * time.Hour
	TTLDomainRecord      = 6 * time.Hour
	TTLStorageEntry      = 2 * time.Hour
	TTLRegistrySnapshot  = 48 * time.Hour
	TTLIntroPoint        = 30 * time.Minute
)

// MaxTTL is the longest lifetime any class may claim. The seq_floor retention
// window is 2x this (§7.6).
const MaxTTL = TTLRegistrySnapshot

// MaxStorageEntries is the StorageLocation entry cap (§7.1).
const MaxStorageEntries = 64

// encMode is RFC 8949 Core Deterministic Encoding.
//
// Determinism is load-bearing, not tidiness: §7.6's tiebreak rule is "lower
// SHA-256(canonical_encoding(record)) wins", and two honest replicas that
// encode the same record differently would compute different digests, break the
// tie differently, and oscillate forever with every client seeing a coin flip.
var encMode = func() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// decMode rejects anything the deterministic encoder would not have produced,
// so a record cannot carry a non-canonical encoding that hashes differently
// from its own re-encoding.
var decMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

var (
	ErrOversize        = errors.New("axon/dht: record exceeds its class size bound")
	ErrWrongKey        = errors.New("axon/dht: record stored under the wrong key")
	ErrBadSignature    = errors.New("axon/dht: signature does not verify")
	ErrExpired         = errors.New("axon/dht: record has expired")
	ErrOverLongTTL     = errors.New("axon/dht: record lifetime exceeds its class bound")
	ErrReplayedSeq     = errors.New("axon/dht: sequence number is not above the floor")
	ErrBadEncoding     = errors.New("axon/dht: record encoding is not canonical")
	ErrTooManyEntries  = errors.New("axon/dht: too many entries")
	ErrWrongRecordType = errors.New("axon/dht: record type does not match its class")
)

// Record is what every class implements.
type Record interface {
	// Class is the record's class.
	Class() RecordClass
	// DerivedKey recomputes the key from the record's OWN fields. A validator
	// compares this against the key the record arrived under.
	DerivedKey() (Key, error)
	// Seq is the monotonic sequence number. Multi-writer classes return 0.
	Seq() uint64
	// Expiry is when the record stops being valid.
	Expiry() time.Time
}

// -----------------------------------------------------------------------------
// RelayDescriptor
// -----------------------------------------------------------------------------

// RelayDescriptor is class `relay`, keyed on NodeIdentity_pub ‖ SRV_epoch.
//
// The NodeIdentity signs the descriptor, and the descriptor certifies the
// epoch's RoutingIdentity inside its own value -- so the long-lived bonded key
// vouches for the short-lived routing key without ever appearing in a circuit.
type RelayDescriptor struct {
	Ver          uint8    `cbor:"1,keyasint"`
	NodeIDPub    []byte   `cbor:"2,keyasint"`
	RoutingEd    []byte   `cbor:"3,keyasint"`
	RoutingX     []byte   `cbor:"4,keyasint"`
	Addrs        []string `cbor:"5,keyasint"`
	Caps         uint32   `cbor:"6,keyasint"`
	ClaimedBW    uint64   `cbor:"7,keyasint"`
	PrefixFamily uint8    `cbor:"8,keyasint"`
	PrefixBytes  []byte   `cbor:"9,keyasint"`
	ASN          uint32   `cbor:"10,keyasint"`
	BondRef      []byte   `cbor:"11,keyasint"`
	Epoch        uint64   `cbor:"12,keyasint"`
	SRVEpoch     []byte   `cbor:"13,keyasint"`
	Sequence     uint64   `cbor:"14,keyasint"`
	IssuedAt     int64    `cbor:"15,keyasint"`
	ExpiresAt    int64    `cbor:"16,keyasint"`
	Sig          []byte   `cbor:"17,keyasint"`
}

func (r *RelayDescriptor) Class() RecordClass { return ClassRelay }
func (r *RelayDescriptor) Seq() uint64        { return r.Sequence }
func (r *RelayDescriptor) Expiry() time.Time  { return time.Unix(r.ExpiresAt, 0) }

func (r *RelayDescriptor) DerivedKey() (Key, error) {
	if len(r.NodeIDPub) != 32 || len(r.SRVEpoch) != 32 {
		return Key{}, ErrWrongKey
	}
	return DeriveKey(ClassRelay, append(append([]byte{}, r.NodeIDPub...), r.SRVEpoch...))
}

// KadID is the descriptor's own keyspace position, recomputed from its fields.
func (r *RelayDescriptor) KadID() (Key, error) {
	if len(r.NodeIDPub) != 32 || len(r.SRVEpoch) != 32 {
		return Key{}, ErrBadPrefix
	}
	var pub [32]byte
	copy(pub[:], r.NodeIDPub)
	var srv SRV
	copy(srv[:], r.SRVEpoch)
	return DeriveKadID(pub, srv, NetworkPrefix{Family: r.PrefixFamily, Bytes: r.PrefixBytes})
}

// signingBytes is everything but the signature.
func (r *RelayDescriptor) signingBytes() ([]byte, error) {
	c := *r
	c.Sig = nil
	return encMode.Marshal(&c)
}

// Sign signs the descriptor under the NodeIdentity.
func (r *RelayDescriptor) Sign(priv ed25519.PrivateKey) error {
	msg, err := r.signingBytes()
	if err != nil {
		return err
	}
	r.Sig = ed25519.Sign(priv, msg)
	return nil
}

// -----------------------------------------------------------------------------
// ServiceDescriptor (blinded)
// -----------------------------------------------------------------------------

// ServiceDescriptor is class `desc`, keyed on BlindedPub ‖ time_period ‖
// replica_index.
//
// THE PRIVACY PROPERTY, precisely. The storing node verifies the signature
// against the pubkey extracted from its OWN key pre-image, so it authorises the
// write without learning who wrote it. The inner layer is encrypted to a
// subcredential derived from the UNBLINDED identity, so the holder cannot read
// the intro-point set either. This is Tor's rend-spec-v3 design reimplemented,
// not improved on.
//
// What blinding does NOT buy, per §7.7: for an on-chain-registered .axon domain
// the adversary in our model already knows the DomainIdentity, computes
// BlindedPub for each period, and probes. Blinding does real work only for
// ServiceIdentity values never registered on-chain.
type ServiceDescriptor struct {
	Ver          uint8  `cbor:"1,keyasint"`
	BlindedPub   []byte `cbor:"2,keyasint"`
	TimePeriod   uint64 `cbor:"3,keyasint"`
	ReplicaIndex uint8  `cbor:"4,keyasint"`
	// DescSigningCert certifies the descriptor-signing key under the blinded
	// key, exactly as Tor does.
	DescSigningCert []byte `cbor:"5,keyasint"`
	Revision        uint64 `cbor:"6,keyasint"`
	IssuedAt        int64  `cbor:"7,keyasint"`
	ExpiresAt       int64  `cbor:"8,keyasint"`
	// Inner is the ENCRYPTED inner layer. Nothing here or in any other field
	// names the service, the domain, or its intro points.
	Inner []byte `cbor:"9,keyasint"`
	Sig   []byte `cbor:"10,keyasint"`
}

func (d *ServiceDescriptor) Class() RecordClass { return ClassDesc }
func (d *ServiceDescriptor) Seq() uint64        { return d.Revision }
func (d *ServiceDescriptor) Expiry() time.Time  { return time.Unix(d.ExpiresAt, 0) }

func (d *ServiceDescriptor) DerivedKey() (Key, error) {
	if len(d.BlindedPub) != 32 {
		return Key{}, ErrWrongKey
	}
	if d.ReplicaIndex >= DescriptorReplicaPositions {
		return Key{}, fmt.Errorf("%w: replica index %d", ErrWrongKey, d.ReplicaIndex)
	}
	in := make([]byte, 0, 32+8+1)
	in = append(in, d.BlindedPub...)
	in = appendU64(in, d.TimePeriod)
	in = append(in, d.ReplicaIndex)
	return DeriveKey(ClassDesc, in)
}

func (d *ServiceDescriptor) signingBytes() ([]byte, error) {
	c := *d
	c.Sig = nil
	return encMode.Marshal(&c)
}

// Sign signs under the BLINDED private key.
func (d *ServiceDescriptor) Sign(blinded ed25519.PrivateKey) error {
	msg, err := d.signingBytes()
	if err != nil {
		return err
	}
	d.Sig = ed25519.Sign(blinded, msg)
	return nil
}

// -----------------------------------------------------------------------------
// DomainRecord
// -----------------------------------------------------------------------------

// DomainRecord is class `domain`, keyed on SHA-256(name_normalised) ‖ SRV_epoch.
type DomainRecord struct {
	Ver            uint8  `cbor:"1,keyasint"`
	NameHash       []byte `cbor:"2,keyasint"`
	DomainIDPub    []byte `cbor:"3,keyasint"`
	Records        []byte `cbor:"4,keyasint"`
	SnapshotRoot   []byte `cbor:"5,keyasint"`
	InclusionProof []byte `cbor:"6,keyasint"`
	SRVEpoch       []byte `cbor:"7,keyasint"`
	Sequence       uint64 `cbor:"8,keyasint"`
	IssuedAt       int64  `cbor:"9,keyasint"`
	ExpiresAt      int64  `cbor:"10,keyasint"`
	Sig            []byte `cbor:"11,keyasint"`
}

func (d *DomainRecord) Class() RecordClass { return ClassDomain }
func (d *DomainRecord) Seq() uint64        { return d.Sequence }
func (d *DomainRecord) Expiry() time.Time  { return time.Unix(d.ExpiresAt, 0) }

func (d *DomainRecord) DerivedKey() (Key, error) {
	if len(d.NameHash) != 32 || len(d.SRVEpoch) != 32 {
		return Key{}, ErrWrongKey
	}
	return DeriveKey(ClassDomain, append(append([]byte{}, d.NameHash...), d.SRVEpoch...))
}

func (d *DomainRecord) signingBytes() ([]byte, error) {
	c := *d
	c.Sig = nil
	return encMode.Marshal(&c)
}

func (d *DomainRecord) Sign(priv ed25519.PrivateKey) error {
	msg, err := d.signingBytes()
	if err != nil {
		return err
	}
	d.Sig = ed25519.Sign(priv, msg)
	return nil
}

// -----------------------------------------------------------------------------
// StorageLocation (multi-writer)
// -----------------------------------------------------------------------------

// StorageEntry is one holder's claim to hold a CID.
type StorageEntry struct {
	HolderNodeID []byte `cbor:"1,keyasint"`
	BondRef      []byte `cbor:"2,keyasint"`
	// Bond is the bonded amount backing this entry, used for the §7.6
	// bond-ordered eviction that makes displacing an honest holder cost more
	// than the honest holder posted.
	Bond      uint64 `cbor:"3,keyasint"`
	ExpiresAt int64  `cbor:"4,keyasint"`
	CID       []byte `cbor:"5,keyasint"`
	Sig       []byte `cbor:"6,keyasint"`
}

func (e *StorageEntry) signingBytes() ([]byte, error) {
	c := *e
	c.Sig = nil
	return encMode.Marshal(&c)
}

// Sign signs the entry under the holder's key.
func (e *StorageEntry) Sign(priv ed25519.PrivateKey) error {
	msg, err := e.signingBytes()
	if err != nil {
		return err
	}
	e.Sig = ed25519.Sign(priv, msg)
	return nil
}

// Verify checks the entry's own signature under its declared holder id.
func (e *StorageEntry) Verify() error {
	if len(e.HolderNodeID) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	msg, err := e.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(e.HolderNodeID), msg, e.Sig) {
		return ErrBadSignature
	}
	return nil
}

// StorageLocation is class `loc`, keyed on the CID alone.
//
// The record as a whole is UNSIGNED. Each entry carries its own holder's
// signature, and the record is a set that merges rather than a value that is
// replaced -- see MergeStorageLocation. A single-writer rule here would mean the
// last holder to publish erased every other holder's claim.
type StorageLocation struct {
	Ver     uint8          `cbor:"1,keyasint"`
	CID     []byte         `cbor:"2,keyasint"`
	Entries []StorageEntry `cbor:"3,keyasint"`
}

func (l *StorageLocation) Class() RecordClass { return ClassLocation }
func (l *StorageLocation) Seq() uint64        { return 0 }

// Expiry is the latest entry expiry; an empty record is already expired.
func (l *StorageLocation) Expiry() time.Time {
	var latest int64
	for _, e := range l.Entries {
		if e.ExpiresAt > latest {
			latest = e.ExpiresAt
		}
	}
	return time.Unix(latest, 0)
}

func (l *StorageLocation) DerivedKey() (Key, error) {
	if len(l.CID) == 0 {
		return Key{}, ErrWrongKey
	}
	return DeriveKey(ClassLocation, l.CID)
}

// -----------------------------------------------------------------------------
// RegistrySnapshot anchor
// -----------------------------------------------------------------------------

// RegistrySnapshot is class `snap`, keyed on chain_id ‖ snapshot_epoch.
//
// It has NO authorised writer. The record proves itself against the chain
// through the light client, so restricting publication would only create a
// censorship point -- anyone may publish, and a wrong one fails verification and
// is dropped. The signature identifies the publisher; it is NOT the
// authorisation.
type RegistrySnapshot struct {
	Ver            uint8  `cbor:"1,keyasint"`
	ChainID        uint64 `cbor:"2,keyasint"`
	SnapshotEpoch  uint64 `cbor:"3,keyasint"`
	SnapshotRoot   []byte `cbor:"4,keyasint"`
	EthBlockNumber uint64 `cbor:"5,keyasint"`
	EthStateRoot   []byte `cbor:"6,keyasint"`
	AnchorTxProof  []byte `cbor:"7,keyasint"`
	BodyCID        []byte `cbor:"8,keyasint"`
	PublisherPub   []byte `cbor:"9,keyasint"`
	IssuedAt       int64  `cbor:"10,keyasint"`
	ExpiresAt      int64  `cbor:"11,keyasint"`
	Sig            []byte `cbor:"12,keyasint"`
}

func (s *RegistrySnapshot) Class() RecordClass { return ClassSnapshot }

// Seq is the snapshot epoch: the §7.1 merge rule is "highest snapshot_epoch
// whose chain proof verifies", which is exactly the single-writer BETTER rule
// with the epoch in the seq position.
func (s *RegistrySnapshot) Seq() uint64       { return s.SnapshotEpoch }
func (s *RegistrySnapshot) Expiry() time.Time { return time.Unix(s.ExpiresAt, 0) }

func (s *RegistrySnapshot) DerivedKey() (Key, error) {
	in := make([]byte, 0, 16)
	in = appendU64(in, s.ChainID)
	in = appendU64(in, s.SnapshotEpoch)
	return DeriveKey(ClassSnapshot, in)
}

func (s *RegistrySnapshot) signingBytes() ([]byte, error) {
	c := *s
	c.Sig = nil
	return encMode.Marshal(&c)
}

func (s *RegistrySnapshot) Sign(priv ed25519.PrivateKey) error {
	msg, err := s.signingBytes()
	if err != nil {
		return err
	}
	s.Sig = ed25519.Sign(priv, msg)
	return nil
}

// -----------------------------------------------------------------------------
// IntroPointRecord
// -----------------------------------------------------------------------------

// IntroPointRecord is class `intro`, keyed on IntroPoint_RoutingID ‖ SRV_epoch.
//
// It exists separately from the descriptor -- where Tor keeps intro points --
// because R10 requires them rate-limited by a PoW/token puzzle whose difficulty
// must move faster than a 3 h descriptor lifetime, or it is useless against a
// live flood. The cost is that intro-point RELAYS become enumerable; the service
// they front does not, because that binding lives only in the descriptor's
// encrypted inner layer.
type IntroPointRecord struct {
	Ver            uint8  `cbor:"1,keyasint"`
	RoutingID      []byte `cbor:"2,keyasint"`
	SRVEpoch       []byte `cbor:"3,keyasint"`
	PoWSeed        []byte `cbor:"4,keyasint"`
	PoWDifficulty  uint8  `cbor:"5,keyasint"`
	TokenIssuerPub []byte `cbor:"6,keyasint"`
	CapacityHint   uint32 `cbor:"7,keyasint"`
	Sequence       uint64 `cbor:"8,keyasint"`
	IssuedAt       int64  `cbor:"9,keyasint"`
	ExpiresAt      int64  `cbor:"10,keyasint"`
	Sig            []byte `cbor:"11,keyasint"`
}

func (i *IntroPointRecord) Class() RecordClass { return ClassIntro }
func (i *IntroPointRecord) Seq() uint64        { return i.Sequence }
func (i *IntroPointRecord) Expiry() time.Time  { return time.Unix(i.ExpiresAt, 0) }

func (i *IntroPointRecord) DerivedKey() (Key, error) {
	if len(i.RoutingID) != 32 || len(i.SRVEpoch) != 32 {
		return Key{}, ErrWrongKey
	}
	return DeriveKey(ClassIntro, append(append([]byte{}, i.RoutingID...), i.SRVEpoch...))
}

func (i *IntroPointRecord) signingBytes() ([]byte, error) {
	c := *i
	c.Sig = nil
	return encMode.Marshal(&c)
}

func (i *IntroPointRecord) Sign(priv ed25519.PrivateKey) error {
	msg, err := i.signingBytes()
	if err != nil {
		return err
	}
	i.Sig = ed25519.Sign(priv, msg)
	return nil
}

// -----------------------------------------------------------------------------
// Encoding helpers
// -----------------------------------------------------------------------------

func appendU64(b []byte, v uint64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Encode canonically encodes a record.
func Encode(r Record) ([]byte, error) { return encMode.Marshal(r) }

// CanonicalDigest is SHA-256 over the canonical encoding, used for §7.6's
// deterministic tiebreak.
func CanonicalDigest(b []byte) [32]byte { return sha256.Sum256(b) }

// IsCanonical reports whether a wire encoding round-trips to itself.
//
// A non-canonical encoding is refused rather than normalised: accepting it and
// re-encoding would mean the digest the sender computed and the digest the
// receiver computes differ, and §7.6's tiebreak would break the tie
// differently on different nodes.
func IsCanonical(class RecordClass, wire []byte) error {
	r, err := DecodeRecord(class, wire)
	if err != nil {
		return err
	}
	again, err := encMode.Marshal(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(wire, again) {
		return ErrBadEncoding
	}
	return nil
}

// DecodeRecord decodes a wire record of a known class.
func DecodeRecord(class RecordClass, wire []byte) (Record, error) {
	var r Record
	switch class {
	case ClassRelay:
		r = new(RelayDescriptor)
	case ClassDesc:
		r = new(ServiceDescriptor)
	case ClassDomain:
		r = new(DomainRecord)
	case ClassLocation:
		r = new(StorageLocation)
	case ClassSnapshot:
		r = new(RegistrySnapshot)
	case ClassIntro:
		r = new(IntroPointRecord)
	case ClassReport:
		r = new(ContentReport)
	default:
		return nil, ErrUnknownClass
	}
	if err := decMode.Unmarshal(wire, r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadEncoding, err)
	}
	return r, nil
}
