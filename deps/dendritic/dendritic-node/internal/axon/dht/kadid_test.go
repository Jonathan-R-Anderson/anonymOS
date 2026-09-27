package dht

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func mkSRV(b byte) SRV {
	var s SRV
	for i := range s {
		s[i] = b
	}
	return s
}

func mkPub(n uint64) [32]byte {
	var p [32]byte
	binary.BigEndian.PutUint64(p[:8], n)
	return p
}

func TestKadIDBindsToObservedPrefix(t *testing.T) {
	pub := mkPub(1)
	srv := mkSRV(0x11)
	addr := netip.MustParseAddr("198.51.100.7")

	prefix, err := PrefixFor(addr)
	if err != nil {
		t.Fatal(err)
	}
	id, err := DeriveKadID(pub, srv, prefix)
	if err != nil {
		t.Fatal(err)
	}

	// The same /24 verifies: the prefix, not the host address, is the bound
	// term, so a node may change its last octet without moving.
	if err := VerifyKadID(id, pub, srv, netip.MustParseAddr("198.51.100.200")); err != nil {
		t.Fatalf("same /24 rejected: %v", err)
	}
	// A different /24 does not. This is what stops an attacker holding a ground
	// position while rotating addresses through a proxy pool.
	err = VerifyKadID(id, pub, srv, netip.MustParseAddr("203.0.113.7"))
	if !errors.Is(err, ErrPrefixMismatch) {
		t.Fatalf("err = %v, want ErrPrefixMismatch", err)
	}
}

func TestIPv6UsesSlash48(t *testing.T) {
	pub := mkPub(2)
	srv := mkSRV(0x22)
	p, err := PrefixFor(netip.MustParseAddr("2001:db8:1234:5678::1"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Family != 0x06 || len(p.Bytes) != 6 {
		t.Fatalf("prefix = %+v, want 0x06 with 6 bytes", p)
	}
	id, _ := DeriveKadID(pub, srv, p)
	// Same /48, different interface identifier and subnet: same position.
	if err := VerifyKadID(id, pub, srv, netip.MustParseAddr("2001:db8:1234:ffff::99")); err != nil {
		t.Fatalf("same /48 rejected: %v", err)
	}
	// Different /48: different position.
	if err := VerifyKadID(id, pub, srv, netip.MustParseAddr("2001:db8:9999::1")); err == nil {
		t.Fatal("a different /48 verified")
	}
}

// TestKadIDRotatesEveryEpoch is half of T4.2: every node's position changes at
// the epoch boundary.
func TestKadIDRotatesEveryEpoch(t *testing.T) {
	srvA, srvB := mkSRV(0xAA), mkSRV(0xBB)
	prefix, _ := PrefixFor(netip.MustParseAddr("198.51.100.7"))

	moved := 0
	const n = 1000
	for i := 0; i < n; i++ {
		pub := mkPub(uint64(i))
		a, _ := DeriveKadID(pub, srvA, prefix)
		b, _ := DeriveKadID(pub, srvB, prefix)
		if a != b {
			moved++
		}
	}
	if moved != n {
		t.Fatalf("%d of %d nodes kept their position across the epoch boundary", n-moved, n)
	}
}

// TestGrindCostToApproachAChosenKey is T4.1 and E4.2: MEASURE the grinding cost
// to place within 8, 16 and 24 bits of a target, and report it.
//
// THE MEASUREMENT'S POINT IS NOT THAT GRINDING IS HARD. §7.2 says the opposite
// in as many words: finding one identity inside the 8-nearest ball at N=10^4 is
// ~1,250 SHA-256 and is FREE, and finding eight is ~10^4 and is also free. What
// is not free is making those eight identities USABLE, which costs eight bonds
// in StakeVault, and keeping them usable next epoch, which costs eight MORE
// bonds because the ground positions are gone and the old capital is still
// locked through withdrawDelay.
//
// So this test measures the grind, reports it, and then asserts the property
// that actually does the work: a position ground under one SRV is worthless
// under the next.
func TestGrindCostToApproachAChosenKey(t *testing.T) {
	target := MustDeriveKey(ClassRelay, []byte("a key somebody wants censored"))
	srv := mkSRV(0x5A)
	prefix, _ := PrefixFor(netip.MustParseAddr("203.0.113.9"))

	widths := []int{8, 16}
	if !testing.Short() {
		widths = append(widths, 24)
	}

	for _, bits := range widths {
		var tries uint64
		var found [32]byte
		start := time.Now()
		for {
			tries++
			pub := mkPub(tries)
			id, err := DeriveKadID(pub, srv, prefix)
			if err != nil {
				t.Fatal(err)
			}
			if CommonPrefixLen(id, target) >= bits {
				found = pub
				break
			}
			if tries > 1<<28 {
				t.Fatalf("no identity within %d bits after 2^28 tries", bits)
			}
		}
		elapsed := time.Since(start)
		expected := uint64(1) << bits
		t.Logf("T4.1: %2d-bit placement took %10d derivations in %8s (expected ~2^%d = %d, %.0f H/s)",
			bits, tries, elapsed.Truncate(time.Millisecond), bits, expected,
			float64(tries)/elapsed.Seconds())

		// The ground position must be worthless under the next epoch's SRV.
		// This is the claim the whole mechanism rests on, and it is the one
		// worth asserting rather than the cost.
		next, err := DeriveKadID(found, mkSRV(0x5B), prefix)
		if err != nil {
			t.Fatal(err)
		}
		if cpl := CommonPrefixLen(next, target); cpl >= bits {
			t.Fatalf("a position ground for one SRV survived into the next (%d bits)", cpl)
		}
	}
}

// TestGrindCannotBeatTheDiversityCap records the structural bound: §7.2's
// arithmetic says a full eclipse is impossible below 8 distinct ASNs REGARDLESS
// of how many identities the attacker grinds, because the replica set admits at
// most one per ASN.
func TestGrindCannotBeatTheDiversityCap(t *testing.T) {
	self := MustDeriveKey(ClassRelay, []byte("victim"))
	table := NewTable(self)
	srv := mkSRV(0x77)

	// 500 ground identities, all in one AS across many /24s.
	admitted := 0
	for i := 0; i < 500; i++ {
		addr := netip.AddrFrom4([4]byte{203, 0, byte(i % 256), 9})
		prefix, _ := PrefixFor(addr)
		pub := mkPub(uint64(i))
		id, _ := DeriveKadID(pub, srv, prefix)
		if err := table.Admit(Contact{
			NodeIDPub: pub, KadID: id, Addr: addr, Prefix: prefix,
			ASN: 64500, Verified: true,
		}); err == nil {
			admitted++
		}
	}

	sibs := table.Siblings()
	if len(sibs) > MaxPerASNInSiblings {
		t.Fatalf("one AS holds %d sibling slots, cap is %d", len(sibs), MaxPerASNInSiblings)
	}
	t.Logf("500 ground identities in one AS: %d admitted to buckets, %d sibling slots (cap %d)",
		admitted, len(sibs), MaxPerASNInSiblings)
}

// -----------------------------------------------------------------------------
// SRV store
// -----------------------------------------------------------------------------

type fixedSRV struct {
	vals map[uint64]SRV
	err  error
}

func (f fixedSRV) SRVForEpoch(e uint64) (SRV, error) {
	if f.err != nil {
		return SRV{}, f.err
	}
	v, ok := f.vals[e]
	if !ok {
		return SRV{}, errors.New("no mix for that epoch")
	}
	return v, nil
}

// TestBeaconOutageContinuesOnLastVerifiedWithDeclaredStaleness is P4's stated
// fallback: continue on the last verified SRV with a DECLARED staleness rather
// than invent one.
func TestBeaconOutageContinuesOnLastVerifiedWithDeclaredStaleness(t *testing.T) {
	src := &fixedSRV{vals: map[uint64]SRV{10: mkSRV(0x10)}}
	s := NewSRVStore(src)

	base := time.Unix(1_700_000_000, 0)
	if err := s.Refresh(10, base); err != nil {
		t.Fatal(err)
	}

	// The beacon goes away.
	src.err = errors.New("beacon endpoint unreachable")
	if err := s.Refresh(11, base.Add(EpochDuration)); err == nil {
		t.Fatal("Refresh reported success with no beacon")
	}

	// The last VERIFIED value is still what the node uses. It must not have
	// been replaced by anything derived.
	got, epoch, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got != mkSRV(0x10) || epoch != 10 {
		t.Fatalf("SRV = %x epoch %d, want the last verified 0x10 at epoch 10", got[:4], epoch)
	}

	// And the staleness must be declared, with the beacon error in the reason.
	age, stale, reason := s.Staleness(base.Add(EpochDuration + time.Hour))
	if !stale {
		t.Fatal("running past the rotation period was not reported as stale")
	}
	if age < EpochDuration {
		t.Fatalf("age = %s, want at least one epoch", age)
	}
	if reason == "" {
		t.Fatal("no operator-facing reason for the staleness")
	}
	t.Logf("declared staleness: %s", reason)
}

// TestNoSRVMeansNoPosition: before any verified mix exists the node has no
// keyspace position at all, rather than a default one.
func TestNoSRVMeansNoPosition(t *testing.T) {
	s := NewSRVStore(&fixedSRV{vals: map[uint64]SRV{}})
	if _, _, err := s.Current(); !errors.Is(err, ErrNoSRV) {
		t.Fatalf("err = %v, want ErrNoSRV", err)
	}
	_, stale, reason := s.Staleness(time.Now())
	if !stale || reason == "" {
		t.Fatal("a store with no SRV did not report itself stale")
	}
}

// TestPreviousSRVKeptAcrossBoundary: a lookup crossing the epoch boundary needs
// both mixes, or it fails consistently rather than randomly.
func TestPreviousSRVKeptAcrossBoundary(t *testing.T) {
	s := NewSRVStore(&fixedSRV{vals: map[uint64]SRV{10: mkSRV(0x10), 11: mkSRV(0x11)}})
	base := time.Unix(1_700_000_000, 0)
	if err := s.Refresh(10, base); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Previous(); ok {
		t.Fatal("a first refresh reported a previous epoch")
	}
	if err := s.Refresh(11, base.Add(EpochDuration)); err != nil {
		t.Fatal(err)
	}
	prev, prevEpoch, ok := s.Previous()
	if !ok || prev != mkSRV(0x10) || prevEpoch != 10 {
		t.Fatalf("previous = %x/%d ok=%v, want 0x10/10", prev[:4], prevEpoch, ok)
	}
}

func TestEpochAt(t *testing.T) {
	genesis := time.Unix(1_600_000_000, 0)
	if got := EpochAt(genesis, genesis); got != 0 {
		t.Fatalf("epoch at genesis = %d, want 0", got)
	}
	if got := EpochAt(genesis, genesis.Add(EpochDuration*3+time.Hour)); got != 3 {
		t.Fatalf("epoch = %d, want 3", got)
	}
	if got := EpochAt(genesis, genesis.Add(-time.Hour)); got != 0 {
		t.Fatalf("pre-genesis epoch = %d, want 0", got)
	}
}

func TestRandomKadIDsAreUniform(t *testing.T) {
	// A crude uniformity check: over 4096 identities, the first byte should hit
	// most of its 256 possible values. A derivation that clustered would break
	// the §7.2 arithmetic, which assumes uniform landing.
	srv := mkSRV(0x33)
	prefix, _ := PrefixFor(netip.MustParseAddr("198.51.100.1"))
	seen := map[byte]int{}
	for i := 0; i < 4096; i++ {
		var pub [32]byte
		if _, err := rand.Read(pub[:]); err != nil {
			t.Fatal(err)
		}
		id, _ := DeriveKadID(pub, srv, prefix)
		seen[id[0]]++
	}
	if len(seen) < 200 {
		t.Fatalf("first byte took only %d of 256 values over 4096 derivations", len(seen))
	}
}
