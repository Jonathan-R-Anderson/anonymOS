package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"golang.org/x/crypto/curve25519"
)

// SeedSize is the length of a master seed. All roots are 32 bytes of CSPRNG
// output; nothing in this package derives a root from a password or a name.
const SeedSize = 32

// ---------------------------------------------------------------------------
// The eight classes
// ---------------------------------------------------------------------------

// NodeSeed is the node master seed, stored as node.key. It roots the node-side
// tree only. Service and domain seeds are independent roots precisely so that
// compromising a node does not reach a service key hosted on the same machine.
type NodeSeed [SeedSize]byte

// NodeIdentity is the long-term Ed25519 identity a node presents to peers for
// transport authentication and for bonding. Public, and never anonymous.
type NodeIdentity struct {
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// RoutingIdentity is epoch-scoped. Circuits are extended to this, not to
// NodeIdentity, which is what lets a relay rotate its onion key without
// losing the reputation and bond attached to its node identity.
type RoutingIdentity struct {
	Epoch     uint64
	EdPublic  ed25519.PublicKey
	edPrivate ed25519.PrivateKey
	XPublic   [32]byte
	xPrivate  [32]byte
}

// KadID is a node's position in the DHT keyspace. It is NOT freely chosen: it
// is bound to the node identity, the epoch's shared random value and the node's
// network prefix, so an attacker who wants to sit next to a particular key must
// grind identities and must re-grind them every epoch.
type KadID [32]byte

// ServiceIdentity is the long-term key of an anonymous service. It is blinded
// per time period for descriptor publication and never appears in the clear on
// the wire.
type ServiceIdentity struct {
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// DomainIdentity is the authoritative signer for every record under a name. It
// is committed on-chain by the owner and used off-chain; it is deliberately a
// different key from the owner's wallet, so the overlay never sees the wallet.
type DomainIdentity struct {
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

// NewNodeSeed reads a fresh master seed from the OS CSPRNG.
func NewNodeSeed() (NodeSeed, error) {
	var s NodeSeed
	if _, err := io.ReadFull(rand.Reader, s[:]); err != nil {
		return s, fmt.Errorf("identity: read seed: %w", err)
	}
	return s, nil
}

// DeriveNodeIdentity produces the node's long-term Ed25519 identity from the
// master seed.
func DeriveNodeIdentity(seed NodeSeed) NodeIdentity {
	edSeed := derive(LabelNodeSeed, seed[:], nil, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(edSeed)
	return NodeIdentity{
		Public:  priv.Public().(ed25519.PublicKey),
		private: priv,
	}
}

// DeriveRoutingIdentity produces the epoch-scoped routing keypair. Both halves
// are derived from the same master seed but under different labels, so the
// Ed25519 signing key and the X25519 key-agreement key are independent even
// though one seed produced them.
func DeriveRoutingIdentity(seed NodeSeed, epoch uint64) RoutingIdentity {
	ctx := u64be(epoch)

	edSeed := derive(LabelRoutingEd, seed[:], ctx, ed25519.SeedSize)
	edPriv := ed25519.NewKeyFromSeed(edSeed)

	var xPriv [32]byte
	copy(xPriv[:], derive(LabelRoutingX, seed[:], ctx, 32))
	// Clamp per RFC 7748. curve25519.X25519 does not clamp for you when the
	// scalar is used with ScalarBaseMult on a raw array, so it is done here and
	// the clamped value is what is stored.
	xPriv[0] &= 248
	xPriv[31] &= 127
	xPriv[31] |= 64

	var xPub [32]byte
	curve25519.ScalarBaseMult(&xPub, &xPriv)

	return RoutingIdentity{
		Epoch:     epoch,
		EdPublic:  edPriv.Public().(ed25519.PublicKey),
		edPrivate: edPriv,
		XPublic:   xPub,
		xPrivate:  xPriv,
	}
}

// DeriveKadID computes the node's keyspace position for an epoch.
//
// prefix is the node's network prefix -- the /24 for IPv4 or /48 for IPv6 --
// not the full address. Including it caps how many distinct identities one
// network location can present; including srv forces the whole population to
// move every epoch, so a position ground for one epoch is worthless in the next.
func DeriveKadID(node ed25519.PublicKey, srv [32]byte, prefix []byte) KadID {
	return KadID(sha256Prefixed(LabelKadID, node, srv[:], prefix))
}

// Sign signs with the node's long-term identity, under a caller-supplied domain
// separator. There is deliberately no unlabelled Sign: a signature without a
// domain separator is reusable in another context.
func (n NodeIdentity) Sign(label string, message []byte) []byte {
	return signPrefixed(n.private, label, message)
}

// Sign signs with the epoch routing key.
func (r RoutingIdentity) Sign(label string, message []byte) []byte {
	return signPrefixed(r.edPrivate, label, message)
}

// Sign signs with the service identity.
func (s ServiceIdentity) Sign(label string, message []byte) []byte {
	return signPrefixed(s.private, label, message)
}

// Sign signs with the domain identity.
func (d DomainIdentity) Sign(label string, message []byte) []byte {
	return signPrefixed(d.private, label, message)
}

// Agree performs the X25519 exchange for circuit extension.
func (r RoutingIdentity) Agree(peerPublic [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(r.xPrivate[:], peerPublic[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("identity: x25519: %w", err)
	}
	var out [32]byte
	copy(out[:], shared)
	return out, nil
}

func signPrefixed(priv ed25519.PrivateKey, label string, message []byte) []byte {
	buf := make([]byte, 0, len(label)+1+len(message))
	buf = append(buf, label...)
	buf = append(buf, 0x00)
	buf = append(buf, message...)
	return ed25519.Sign(priv, buf)
}

// VerifyPrefixed checks a signature made by signPrefixed.
func VerifyPrefixed(pub ed25519.PublicKey, label string, message, sig []byte) bool {
	buf := make([]byte, 0, len(label)+1+len(message))
	buf = append(buf, label...)
	buf = append(buf, 0x00)
	buf = append(buf, message...)
	return ed25519.Verify(pub, buf, sig)
}

// ---------------------------------------------------------------------------
// Independent roots for service and domain identities
// ---------------------------------------------------------------------------

// NewServiceIdentity generates a service key from its own root. It is NOT
// derived from the node seed: a service must be movable between machines and
// must survive the compromise of the node that happens to host it today.
func NewServiceIdentity() (ServiceIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ServiceIdentity{}, fmt.Errorf("identity: service keygen: %w", err)
	}
	return ServiceIdentity{Public: pub, private: priv}, nil
}

// NewDomainIdentity generates a domain signing key from its own root.
func NewDomainIdentity() (DomainIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return DomainIdentity{}, fmt.Errorf("identity: domain keygen: %w", err)
	}
	return DomainIdentity{Public: pub, private: priv}, nil
}

// ---------------------------------------------------------------------------
// Self-certifying addresses (section 5.8 / 11.9)
// ---------------------------------------------------------------------------

// AddressVersion is the single version byte carried in an address.
const AddressVersion byte = 0x01

// addressEncoding is lowercase base32 without padding: 35 bytes becomes exactly
// 56 characters, which fits inside a 63-byte DNS label so the address is
// syntactically a name and string handling needs no second code path.
var addressEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Address renders a public key as its self-certifying address, without the
// namespace suffix.
func Address(pub ed25519.PublicKey) string {
	body := make([]byte, 0, 35)
	body = append(body, pub...)
	sum := sha256Prefixed(LabelAddressChecksum, pub, []byte{AddressVersion})
	body = append(body, sum[0], sum[1])
	body = append(body, AddressVersion)
	return addressEncoding.EncodeToString(body)
}

// FullAddress renders the complete Layer 1 name, e.g. <56 chars>.key.axon.
func FullAddress(pub ed25519.PublicKey) string {
	return Address(pub) + "." + params.AddressNamespace + "." + params.RootSuffix
}

// ErrBadAddress covers every rejection reason. The reasons are deliberately not
// distinguished in the error: a caller that reports "bad checksum" separately
// from "bad length" hands an attacker a grinding oracle.
var ErrBadAddress = errors.New("identity: malformed address")

// ParseAddress decodes and verifies an address, accepting either the bare
// 56-character form or the full <addr>.key.axon form.
func ParseAddress(s string) (ed25519.PublicKey, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	suffix := "." + params.AddressNamespace + "." + params.RootSuffix
	s = strings.TrimSuffix(s, suffix)

	if len(s) != 56 {
		return nil, ErrBadAddress
	}
	body, err := addressEncoding.DecodeString(s)
	if err != nil || len(body) != 35 {
		return nil, ErrBadAddress
	}
	pub := ed25519.PublicKey(body[:32])
	version := body[34]
	if version != AddressVersion {
		return nil, ErrBadAddress
	}
	want := sha256Prefixed(LabelAddressChecksum, pub, []byte{version})
	if body[32] != want[0] || body[33] != want[1] {
		return nil, ErrBadAddress
	}
	return pub, nil
}

// ---------------------------------------------------------------------------
// At-rest storage
// ---------------------------------------------------------------------------

// SaveSeed writes a master seed with 0600 permissions.
//
// Section 5.7's objection is unresolved and deliberately not papered over here:
// there is no password KDF, so the seed is protected by filesystem permissions
// alone. A caller that needs more must supply an encrypted filesystem or a
// hardware token, and this function does not pretend otherwise.
func SaveSeed(path string, seed NodeSeed) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("identity: mkdir: %w", err)
	}
	if err := os.WriteFile(path, seed[:], 0o600); err != nil {
		return fmt.Errorf("identity: write seed: %w", err)
	}
	return nil
}

// LoadSeed reads a master seed and refuses one whose permissions are wider than
// 0600, because a world-readable key file is a compromise that has already
// happened rather than a risk to warn about.
func LoadSeed(path string) (NodeSeed, error) {
	var s NodeSeed
	info, err := os.Stat(path)
	if err != nil {
		return s, fmt.Errorf("identity: stat seed: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return s, fmt.Errorf("identity: seed %s has permissions %04o, want 0600", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return s, fmt.Errorf("identity: read seed: %w", err)
	}
	if len(raw) != SeedSize {
		return s, fmt.Errorf("identity: seed %s is %d bytes, want %d", path, len(raw), SeedSize)
	}
	copy(s[:], raw)
	return s, nil
}

// LoadOrCreateSeed is the node startup path.
func LoadOrCreateSeed(path string) (NodeSeed, error) {
	s, err := LoadSeed(path)
	if err == nil {
		return s, nil
	}
	if !os.IsNotExist(errors.Unwrap(err)) && !os.IsNotExist(err) {
		return s, err
	}
	s, err = NewNodeSeed()
	if err != nil {
		return s, err
	}
	return s, SaveSeed(path, s)
}
