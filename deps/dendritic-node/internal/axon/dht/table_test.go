package dht

import (
	"errors"
	"net/netip"
	"testing"
)

func contactAt(n uint64, addr string, asn uint32, srv SRV, verified bool) Contact {
	a := netip.MustParseAddr(addr)
	prefix, _ := PrefixFor(a)
	pub := mkPub(n)
	id, _ := DeriveKadID(pub, srv, prefix)
	return Contact{NodeIDPub: pub, KadID: id, Addr: a, Prefix: prefix, ASN: asn, Verified: verified}
}

// TestEclipseAttemptFrom100SiblingsInOnePrefix is T4.3.
//
// A NOTE ON THE TWO CAPS, because the roadmap states them at different
// tightnesses and this test asserts both rather than picking one. §7.2's
// ADMISSION block sets "<= 2 entries per /24 per k-bucket" and "<= 1 replica-set
// slot per /24". T4.3's phrasing ("at most one slot per bucket") matches the
// REPLICA-SET rule, which in this implementation is the sibling list -- the
// structure that decides replica-set membership. Both are checked here: buckets
// admit at most 2 from one /24, siblings at most 1.
func TestEclipseAttemptFrom100SiblingsInOnePrefix(t *testing.T) {
	srv := mkSRV(0x42)
	self := MustDeriveKey(ClassRelay, []byte("the victim node"))
	table := NewTable(self)

	admitted, refused := 0, 0
	for i := 0; i < 100; i++ {
		// 100 distinct identities, all in 203.0.113.0/24, all in one AS.
		c := contactAt(uint64(1000+i), netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}).String(), 64500, srv, true)
		if err := table.Admit(c); err != nil {
			refused++
			if !errors.Is(err, ErrPrefixCapReached) && !errors.Is(err, ErrASNCapReached) && !errors.Is(err, ErrBucketFull) {
				t.Fatalf("unexpected refusal: %v", err)
			}
			continue
		}
		admitted++
	}

	// Per-bucket: at most MaxPerPrefixPerBucket from the one /24.
	perBucket := map[int]int{}
	for idx := 0; idx < 256; idx++ {
		b := table.Bucket(idx)
		if len(b) == 0 {
			continue
		}
		n := 0
		for _, c := range b {
			if c.Prefix.String() == "04cb0071" { // 203.0.113
				n++
			}
		}
		perBucket[idx] = n
		if n > MaxPerPrefixPerBucket {
			t.Fatalf("bucket %d holds %d entries from one /24, cap is %d", idx, n, MaxPerPrefixPerBucket)
		}
	}

	// Replica-set slots: T4.3's "at most one slot".
	sibs := table.Siblings()
	if len(sibs) > MaxPerPrefixInSiblings {
		t.Fatalf("T4.3 violated: %d replica-set slots held by one /24, cap is %d",
			len(sibs), MaxPerPrefixInSiblings)
	}

	t.Logf("T4.3: 100 identities in one /24 -> %d admitted to buckets across %d buckets (<=%d each), %d replica-set slot(s)",
		admitted, len(perBucket), MaxPerPrefixPerBucket, len(sibs))
	if refused == 0 {
		t.Fatal("no admission was refused; the caps are not being enforced")
	}
}

// TestDiverseSetFillsSiblings is the control: the caps must not starve an
// honest, diverse network.
func TestDiverseSetFillsSiblings(t *testing.T) {
	srv := mkSRV(0x43)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))

	full := 0
	for i := 0; i < 64; i++ {
		addr := netip.AddrFrom4([4]byte{198, byte(i), byte(i * 3), 1}).String()
		err := table.Admit(contactAt(uint64(i), addr, uint32(64500+i), srv, true))
		switch {
		case err == nil:
		case errors.Is(err, ErrBucketFull):
			// Expected and correct: bucket 0 covers half the keyspace and fills
			// at k=20. It is not a diversity refusal.
			full++
		default:
			t.Fatalf("diverse contact %d refused on diversity grounds: %v", i, err)
		}
	}
	// A full routing bucket must NOT block replica-set membership.
	if got := len(table.Siblings()); got != SiblingCount {
		t.Fatalf("siblings = %d, want %d from a fully diverse set (%d bucket-full refusals)",
			got, SiblingCount, full)
	}
}

// TestUnverifiedEntriesNeverEnterSiblings is §7.3's load-bearing distinction: an
// unverified entry may make routing progress but may never be counted toward a
// replica set.
func TestUnverifiedEntriesNeverEnterSiblings(t *testing.T) {
	srv := mkSRV(0x44)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))

	for i := 0; i < 32; i++ {
		addr := netip.AddrFrom4([4]byte{198, byte(i), 7, 1}).String()
		if err := table.Admit(contactAt(uint64(i), addr, uint32(65000+i), srv, false)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(table.Siblings()); got != 0 {
		t.Fatalf("%d unverified entries entered the sibling list", got)
	}
	// They are still usable for routing progress.
	if got := len(table.Closest(Key{}, 10, false)); got == 0 {
		t.Fatal("unverified entries are unusable even for routing progress")
	}
	// And invisible to a replica-set query.
	if got := len(table.Closest(Key{}, 10, true)); got != 0 {
		t.Fatalf("%d unverified entries returned to a verified-only query", got)
	}
}

// TestVerificationUpgradesButNeverDowngrades: a peer must not be able to launder
// a verified entry back to unverified to escape a cap.
func TestVerificationUpgradesButNeverDowngrades(t *testing.T) {
	srv := mkSRV(0x45)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))

	c := contactAt(1, "198.51.100.1", 64500, srv, false)
	if err := table.Admit(c); err != nil {
		t.Fatal(err)
	}
	if len(table.Siblings()) != 0 {
		t.Fatal("unverified entry entered the sibling list")
	}

	c.Verified = true
	if err := table.Admit(c); err != nil {
		t.Fatal(err)
	}
	if len(table.Siblings()) != 1 {
		t.Fatal("re-admission with verification did not upgrade the entry")
	}

	c.Verified = false
	if err := table.Admit(c); err != nil {
		t.Fatal(err)
	}
	got := table.Closest(c.KadID, 1, true)
	if len(got) != 1 || !got[0].Verified {
		t.Fatal("a verified entry was downgraded by a later unverified mention")
	}
}

// TestRebuildConvergesAtTheEpochBoundary is the other half of T4.2: routing
// tables converge after rotation rather than pointing at positions nobody
// occupies.
func TestRebuildConvergesAtTheEpochBoundary(t *testing.T) {
	srvA, srvB := mkSRV(0xA1), mkSRV(0xB1)
	selfPub := mkPub(999)
	selfAddr := netip.MustParseAddr("192.0.2.1")
	selfPrefix, _ := PrefixFor(selfAddr)

	selfA, _ := DeriveKadID(selfPub, srvA, selfPrefix)
	table := NewTable(selfA)

	var contacts []Contact
	for i := 0; i < 40; i++ {
		addr := netip.AddrFrom4([4]byte{198, byte(i), byte(i * 7), 1}).String()
		c := contactAt(uint64(i), addr, uint32(64000+i), srvA, true)
		if err := table.Admit(c); err != nil && !errors.Is(err, ErrBucketFull) {
			t.Fatalf("contact %d refused: %v", i, err)
		} else if err == nil {
			contacts = append(contacts, c)
		}
	}
	before := table.Len()

	kept, dropped, err := table.Rebuild(selfPub, srvB, selfPrefix)
	if err != nil {
		t.Fatal(err)
	}
	// Drops here are bucket-capacity, not lost knowledge: positions moved, so a
	// bucket that was not full before may be full now. What must NOT happen is a
	// contact surviving at a stale position.
	t.Logf("T4.2: rebuild across the epoch boundary kept %d of %d, dropped %d to bucket capacity",
		kept, before, dropped)
	if kept == 0 {
		t.Fatal("the whole table was lost at the epoch boundary")
	}

	// Self moved.
	selfB, _ := DeriveKadID(selfPub, srvB, selfPrefix)
	if table.Self() != selfB {
		t.Fatal("the table's own position did not move at the boundary")
	}

	// EVERY surviving contact must sit at its NEW position. A contact carried
	// over at a stale position is worse than a missing one, because it silently
	// absorbs lookups aimed at a region it no longer occupies.
	survivors := 0
	for _, orig := range contacts {
		want, _ := DeriveKadID(orig.NodeIDPub, srvB, orig.Prefix)
		for _, c := range table.Closest(want, BucketSize, false) {
			if c.NodeIDPub != orig.NodeIDPub {
				continue
			}
			survivors++
			if c.KadID != want {
				t.Fatalf("contact %x kept a stale position across the boundary", orig.NodeIDPub[:4])
			}
			if c.KadID == orig.KadID {
				t.Fatalf("contact %x did not move at the boundary", orig.NodeIDPub[:4])
			}
		}
	}
	if survivors == 0 {
		t.Fatal("no contact survived the rebuild")
	}
	if len(table.Siblings()) == 0 {
		t.Fatal("the sibling list was not rebuilt")
	}
}

func TestCommonPrefixLenAndDistance(t *testing.T) {
	var a, b Key
	if got := CommonPrefixLen(a, b); got != 256 {
		t.Fatalf("identical keys share %d bits, want 256", got)
	}
	b[0] = 0x80
	if got := CommonPrefixLen(a, b); got != 0 {
		t.Fatalf("keys differing in the top bit share %d bits, want 0", got)
	}
	b[0] = 0x01
	if got := CommonPrefixLen(a, b); got != 7 {
		t.Fatalf("shared bits = %d, want 7", got)
	}

	var near, far Key
	near[31] = 1
	far[0] = 1
	if !Distance(a, near).Less(Distance(a, far)) {
		t.Fatal("XOR distance ordering is wrong")
	}
}
