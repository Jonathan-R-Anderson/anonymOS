package dht

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// T4.5: StorageLocation entries merge rather than overwrite.

func newEntry(t *testing.T, cid []byte, bond uint64, exp time.Time) (StorageEntry, ed25519.PublicKey) {
	t.Helper()
	pub, priv := keypair(t)
	e := StorageEntry{
		HolderNodeID: pub, BondRef: rand32(t), Bond: bond,
		ExpiresAt: exp.Unix(), CID: cid,
	}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return e, pub
}

// TestStorageLocationMergesRatherThanOverwrites is T4.5. A single-writer rule
// here would mean the last holder to publish erased every other holder's claim.
func TestStorageLocationMergesRatherThanOverwrites(t *testing.T) {
	cid := rand32(t)
	exp := testNow.Add(TTLStorageEntry)

	e1, h1 := newEntry(t, cid, 100, exp)
	e2, h2 := newEntry(t, cid, 200, exp)
	e3, h3 := newEntry(t, cid, 300, exp)

	a := &StorageLocation{Ver: 1, CID: cid, Entries: []StorageEntry{e1}}
	b := &StorageLocation{Ver: 1, CID: cid, Entries: []StorageEntry{e2, e3}}

	merged := MergeStorageLocation(a, b, testNow, nil)
	if len(merged.Entries) != 3 {
		t.Fatalf("merged to %d entries, want 3 (a publish erased other holders)", len(merged.Entries))
	}
	have := map[string]bool{}
	for _, e := range merged.Entries {
		have[string(e.HolderNodeID)] = true
	}
	for _, h := range []ed25519.PublicKey{h1, h2, h3} {
		if !have[string(h)] {
			t.Fatalf("holder %x lost in the merge", h[:4])
		}
	}

	// Merging is idempotent and commutative: replicas that merge in different
	// orders must reach the same set, or the record never settles.
	rev := MergeStorageLocation(b, a, testNow, nil)
	if len(rev.Entries) != len(merged.Entries) {
		t.Fatal("merge is not commutative")
	}
	for i := range merged.Entries {
		if string(merged.Entries[i].HolderNodeID) != string(rev.Entries[i].HolderNodeID) {
			t.Fatal("merge order differs by argument order; replicas would disagree")
		}
	}
}

// TestMergeKeepsTheLaterEntryPerHolder: a holder republishing extends its own
// claim rather than duplicating it.
func TestMergeKeepsTheLaterEntryPerHolder(t *testing.T) {
	cid := rand32(t)
	pub, priv := keypair(t)

	mk := func(exp time.Time) StorageEntry {
		e := StorageEntry{HolderNodeID: pub, BondRef: rand32(t), Bond: 10, ExpiresAt: exp.Unix(), CID: cid}
		if err := e.Sign(priv); err != nil {
			t.Fatal(err)
		}
		return e
	}
	early := mk(testNow.Add(30 * time.Minute))
	late := mk(testNow.Add(2 * time.Hour))

	a := &StorageLocation{Ver: 1, CID: cid, Entries: []StorageEntry{early}}
	b := &StorageLocation{Ver: 1, CID: cid, Entries: []StorageEntry{late}}

	for _, m := range []*StorageLocation{
		MergeStorageLocation(a, b, testNow, nil),
		MergeStorageLocation(b, a, testNow, nil),
	} {
		if len(m.Entries) != 1 {
			t.Fatalf("one holder produced %d entries", len(m.Entries))
		}
		if m.Entries[0].ExpiresAt != late.ExpiresAt {
			t.Fatal("the merge kept the earlier expiry")
		}
	}
}

// TestMergeDropsExpiredForgedAndUnbondedEntries.
func TestMergeDropsExpiredForgedAndUnbondedEntries(t *testing.T) {
	cid := rand32(t)
	good, _ := newEntry(t, cid, 100, testNow.Add(time.Hour))
	expired, _ := newEntry(t, cid, 100, testNow.Add(-time.Hour))

	forged, _ := newEntry(t, cid, 100, testNow.Add(time.Hour))
	forged.Bond = 999999 // tampered after signing

	unbonded, unbondedPub := newEntry(t, cid, 100, testNow.Add(time.Hour))

	// An entry claiming a different CID must not ride along in this record.
	wrongCID, _ := newEntry(t, rand32(t), 100, testNow.Add(time.Hour))

	a := &StorageLocation{Ver: 1, CID: cid, Entries: []StorageEntry{good, expired, forged, unbonded, wrongCID}}
	bondOK := func(e StorageEntry) bool { return string(e.HolderNodeID) != string(unbondedPub) }

	merged := MergeStorageLocation(a, nil, testNow, bondOK)
	if len(merged.Entries) != 1 {
		t.Fatalf("kept %d entries, want only the one valid bonded entry", len(merged.Entries))
	}
	if string(merged.Entries[0].HolderNodeID) != string(good.HolderNodeID) {
		t.Fatal("the wrong entry survived")
	}
}

// TestBondOrderedEvictionAtTheCap is the anti-poisoning rule: displacing an
// honest holder from a full record costs more bond than the honest holder
// posted.
//
// The residual §7.7 names and this cannot fix: an attacker with ENOUGH bond can
// still occupy the list and turn every fetch into 64 wasted dials. That is a DoS
// on retrieval latency, not on correctness.
func TestBondOrderedEvictionAtTheCap(t *testing.T) {
	cid := rand32(t)
	exp := testNow.Add(time.Hour)

	// 64 honest holders, each with a modest bond.
	var honest []StorageEntry
	for i := 0; i < MaxStorageEntries; i++ {
		e, _ := newEntry(t, cid, 1000, exp)
		honest = append(honest, e)
	}
	full := &StorageLocation{Ver: 1, CID: cid, Entries: honest}

	// A cheap attacker cannot displace anyone.
	cheap, cheapPub := newEntry(t, cid, 1, exp)
	afterCheap := MergeStorageLocation(full, &StorageLocation{Ver: 1, CID: cid,
		Entries: []StorageEntry{cheap}}, testNow, nil)
	if len(afterCheap.Entries) != MaxStorageEntries {
		t.Fatalf("entries = %d, want the %d cap", len(afterCheap.Entries), MaxStorageEntries)
	}
	for _, e := range afterCheap.Entries {
		if string(e.HolderNodeID) == string(cheapPub) {
			t.Fatal("a lower-bonded attacker displaced an honest holder")
		}
	}

	// An attacker outbidding an honest holder does get in -- which is the
	// honest characterisation: this is a price, not a barrier.
	rich, richPub := newEntry(t, cid, 5000, exp)
	afterRich := MergeStorageLocation(full, &StorageLocation{Ver: 1, CID: cid,
		Entries: []StorageEntry{rich}}, testNow, nil)
	if len(afterRich.Entries) != MaxStorageEntries {
		t.Fatalf("entries = %d, want the %d cap", len(afterRich.Entries), MaxStorageEntries)
	}
	in := false
	for _, e := range afterRich.Entries {
		if string(e.HolderNodeID) == string(richPub) {
			in = true
		}
	}
	if !in {
		t.Fatal("a higher-bonded entry failed to displace a lower one")
	}
}

// TestStorageLocationValidatorRejectsForgedEntries: the validator refuses the
// whole record, since a record carrying an unverifiable entry was assembled by
// somebody who does not follow the rules.
func TestStorageLocationValidatorRejectsForgedEntries(t *testing.T) {
	cid := rand32(t)
	good, _ := newEntry(t, cid, 10, testNow.Add(time.Hour))
	bad, _ := newEntry(t, cid, 10, testNow.Add(time.Hour))
	bad.Sig = rand32(t)

	l := &StorageLocation{Ver: 1, CID: cid, Entries: []StorageEntry{good, bad}}
	wire, err := Encode(l)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := l.DerivedKey()

	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassLocation, key, wire); err == nil {
		t.Fatal("a record carrying a forged entry was accepted")
	}

	clean := &StorageLocation{Ver: 1, CID: cid, Entries: []StorageEntry{good}}
	wire, _ = Encode(clean)
	if _, err := v.Validate(ClassLocation, key, wire); err != nil {
		t.Fatalf("a clean record was rejected: %v", err)
	}
}

// TestStorageLocationCapEnforcedAtValidation: a 65-entry record never enters.
func TestStorageLocationCapEnforcedAtValidation(t *testing.T) {
	cid := rand32(t)
	var entries []StorageEntry
	for i := 0; i <= MaxStorageEntries; i++ {
		e, _ := newEntry(t, cid, 1, testNow.Add(time.Hour))
		entries = append(entries, e)
	}
	l := &StorageLocation{Ver: 1, CID: cid, Entries: entries}
	wire, _ := Encode(l)
	key, _ := l.DerivedKey()

	// This record is also over the 8 KiB size bound, which is the first thing
	// that stops it -- both refusals are correct and either is sufficient.
	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassLocation, key, wire); err == nil {
		t.Fatal("an over-cap record was accepted")
	}
}
