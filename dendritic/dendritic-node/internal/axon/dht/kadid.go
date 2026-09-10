package dht

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// KadID derivation and epoch rotation (§7.2).
//
//	KadID = SHA-256( "axon:kadid:v1" ‖ 0x00 ‖ NodeIdentity_pub[32]
//	                                 ‖ SRV_epoch[32]
//	                                 ‖ network_prefix )
//
//	network_prefix = 0x04 ‖ <IPv4 /24, 3 bytes>
//	               = 0x06 ‖ <IPv6 /48, 6 bytes>
//
// Each term does exactly one job:
//
//	NodeIdentity_pub  binds position to the identity carrying the bond, so a new
//	                  position costs a new bond.
//	SRV_epoch         makes the position PERISHABLE. A position ground for
//	                  today's SRV is uncorrelated with tomorrow's, and the SRV is
//	                  unknown until the epoch's sampling slot passes, so
//	                  pre-positioning against a future date is impossible.
//	network_prefix    makes the position SELF-CHECKABLE. Any peer with a live
//	                  connection recomputes KadID from the observed source prefix
//	                  and rejects a mismatch, so a ground position cannot be held
//	                  while rotating addresses through a proxy pool.
//
// What this does NOT do, stated because the arithmetic in §7.2 is easy to
// misread: it does not make eclipse impossible. At an attacker share f=0.5 no
// CHOSEN key is reliably eclipsed, but 1/256 of the whole namespace is eclipsed
// at any instant and it is a different 1/256 every epoch. Rotation converts a
// persistent targeted attack into a rotating untargeted one; the harm does not
// go away, it moves.

// kadIDLabel is the domain-separation label for KadID.
const kadIDLabel = "axon:kadid:v1"

// EpochDuration is the KadID rotation period.
const EpochDuration = 24 * time.Hour

// SRV is a verified beacon-chain RANDAO mix for one epoch.
type SRV [32]byte

// NetworkPrefix is the address-bound term of the derivation.
type NetworkPrefix struct {
	// Family is 0x04 or 0x06.
	Family byte
	// Bytes is 3 bytes of IPv4 /24, or 6 bytes of IPv6 /48.
	Bytes []byte
}

// Encode is the wire form used in the hash pre-image.
func (p NetworkPrefix) Encode() []byte {
	out := make([]byte, 0, 1+len(p.Bytes))
	return append(append(out, p.Family), p.Bytes...)
}

func (p NetworkPrefix) String() string {
	return fmt.Sprintf("%02x%x", p.Family, p.Bytes)
}

var (
	ErrBadPrefix      = errors.New("axon/dht: malformed network prefix")
	ErrPrefixMismatch = errors.New("axon/dht: KadID does not match the observed source prefix")
	ErrNoSRV          = errors.New("axon/dht: no verified SRV for the epoch")
)

// PrefixFor derives the network prefix term from an address.
func PrefixFor(addr netip.Addr) (NetworkPrefix, error) {
	if !addr.IsValid() {
		return NetworkPrefix{}, ErrBadPrefix
	}
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return NetworkPrefix{Family: 0x04, Bytes: b[:3]}, nil
	}
	b := addr.As16()
	return NetworkPrefix{Family: 0x06, Bytes: b[:6]}, nil
}

// DeriveKadID computes a node's keyspace position for one epoch.
func DeriveKadID(nodePub [32]byte, srv SRV, prefix NetworkPrefix) (Key, error) {
	switch {
	case prefix.Family == 0x04 && len(prefix.Bytes) == 3:
	case prefix.Family == 0x06 && len(prefix.Bytes) == 6:
	default:
		return Key{}, ErrBadPrefix
	}
	h := sha256.New()
	h.Write([]byte(kadIDLabel))
	h.Write([]byte{0x00})
	h.Write(nodePub[:])
	h.Write(srv[:])
	h.Write(prefix.Encode())
	var k Key
	copy(k[:], h.Sum(nil))
	return k, nil
}

// VerifyKadID recomputes a claimed KadID and checks it against the address the
// peer is actually speaking from.
//
// This is §7.3 admission rule (c), and it is the rule that turns the network
// prefix from decoration into a constraint: an entry learned over a live
// connection whose prefix does not match the connection's observed source is
// refused outright. Entries learned INDIRECTLY (returned in a FIND_NODE) cannot
// be checked this way, which is precisely why they are marked unverified and
// barred from replica sets.
func VerifyKadID(claimed Key, nodePub [32]byte, srv SRV, observed netip.Addr) error {
	prefix, err := PrefixFor(observed)
	if err != nil {
		return err
	}
	want, err := DeriveKadID(nodePub, srv, prefix)
	if err != nil {
		return err
	}
	if want != claimed {
		return fmt.Errorf("%w: claimed %s, recomputed %s from %s",
			ErrPrefixMismatch, claimed, want, prefix)
	}
	return nil
}

// SRVSource supplies verified RANDAO mixes. In production this is the existing
// mainnet-verified light client in internal/ethproof; the interface exists so
// the DHT never reaches for an unverified beacon value.
type SRVSource interface {
	// SRVForEpoch returns the VERIFIED mix for an epoch, or an error.
	SRVForEpoch(epoch uint64) (SRV, error)
}

// SRVStore holds the current and previous epoch's mixes and reports staleness.
//
// THE FALLBACK RULE, which is the whole reason this type exists. P4's failure
// modes name "beacon unavailability stalling rotation, where the fallback must
// be to continue on the last verified SRV with a declared staleness rather than
// invent one." Inventing an SRV -- deriving one from the previous, hashing the
// epoch number, anything -- would make the position predictable to whoever knows
// the rule, which is everyone, and that is exactly the pre-positioning the SRV
// term exists to prevent. So: continue on the last verified value, and make the
// staleness visible to every caller.
type SRVStore struct {
	src SRVSource

	mu       sync.RWMutex
	current  SRV
	epoch    uint64
	acquired time.Time
	// previous is kept because a lookup crossing the epoch boundary must be
	// able to check entries derived under either mix. The boundary is the
	// dangerous moment: every node's position moves at once, so a lookup that
	// only knew one mix would fail CONSISTENTLY rather than randomly.
	previous     SRV
	previousSet  bool
	previousEpch uint64
	lastErr      string
}

// NewSRVStore builds a store over a source.
func NewSRVStore(src SRVSource) *SRVStore {
	return &SRVStore{src: src}
}

// Refresh fetches the mix for an epoch, keeping the previous one.
func (s *SRVStore) Refresh(epoch uint64, now time.Time) error {
	srv, err := s.src.SRVForEpoch(epoch)
	if err != nil {
		s.mu.Lock()
		s.lastErr = err.Error()
		s.mu.Unlock()
		return fmt.Errorf("axon/dht: SRV for epoch %d: %w", epoch, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.acquired.IsZero() && epoch != s.epoch {
		s.previous, s.previousEpch, s.previousSet = s.current, s.epoch, true
	}
	s.current, s.epoch, s.acquired, s.lastErr = srv, epoch, now, ""
	return nil
}

// Current returns the live mix and its epoch.
func (s *SRVStore) Current() (SRV, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.acquired.IsZero() {
		return SRV{}, 0, ErrNoSRV
	}
	return s.current, s.epoch, nil
}

// Previous returns the prior epoch's mix, for verifying entries across the
// boundary.
func (s *SRVStore) Previous() (SRV, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.previous, s.previousEpch, s.previousSet
}

// Staleness reports how long the store has been running on the same mix, and
// whether that exceeds one epoch.
//
// A caller that sees Stale must degrade loudly. It must NOT synthesise a mix.
func (s *SRVStore) Staleness(now time.Time) (age time.Duration, stale bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.acquired.IsZero() {
		return 0, true, "no verified SRV has ever been obtained"
	}
	age = now.Sub(s.acquired)
	if age > EpochDuration {
		r := fmt.Sprintf("running on the epoch-%d mix for %s, past the %s rotation period",
			s.epoch, age.Truncate(time.Minute), EpochDuration)
		if s.lastErr != "" {
			r += "; last beacon error: " + s.lastErr
		}
		return age, true, r
	}
	return age, false, ""
}

// EpochAt is the epoch number for a wall-clock instant, counted from genesis.
func EpochAt(genesis, t time.Time) uint64 {
	if t.Before(genesis) {
		return 0
	}
	return uint64(t.Sub(genesis) / EpochDuration)
}
