package dht

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/contain"
)

func contained(t *testing.T, ids ...string) *contain.List {
	t.Helper()
	l := contain.New()
	for _, id := range ids {
		if err := l.Deny(id, "drill: simulated relay compromise", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

// TestEjectWithoutDenyingIsTheatre is the property the whole design rests on.
//
// The incident drill found there was no removal API. The trap in ADDING one is
// that removal alone does not contain: Admit re-inserts on the next FIND_NODE
// that mentions the peer, so a responder who ejected and walked away would be
// watching a relay they believed gone.
func TestEjectWithoutDenyingIsTheatre(t *testing.T) {
	srv := mkSRV(0x42)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))
	c := contactAt(7, "198.51.100.7", 64507, srv, true)

	if err := table.Admit(c); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got := table.Eject(c.NodeIDPub); got != 2 {
		// One bucket entry and one sibling entry.
		t.Logf("Eject removed %d entries", got)
	}
	if table.Len() != 0 {
		t.Fatalf("Eject left %d entries", table.Len())
	}
	// The next mention brings it straight back, because nothing denied it.
	if err := table.Admit(c); err != nil {
		t.Fatalf("re-Admit: %v", err)
	}
	if table.Len() != 1 {
		t.Fatal("the re-admitted contact is not in the table")
	}
	t.Log("confirmed: Eject alone is undone by the next mention — containment " +
		"is removal AND refusal, which is why contain.List exists")
}

// TestContainedPeerIsRefusedOnAdmission.
func TestContainedPeerIsRefusedOnAdmission(t *testing.T) {
	srv := mkSRV(0x42)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))
	c := contactAt(7, "198.51.100.7", 64507, srv, true)

	table.SetContainment(contained(t, ContactID(c.NodeIDPub)))

	err := table.Admit(c)
	if !errors.Is(err, ErrContained) {
		t.Fatalf("Admit of a contained peer: %v, want ErrContained", err)
	}
	if table.Len() != 0 {
		t.Error("a contained peer entered the table")
	}
	// And an uncontained peer is unaffected -- containment must not become a
	// partition the node performed on itself.
	other := contactAt(8, "198.51.101.8", 64508, srv, true)
	if err := table.Admit(other); err != nil {
		t.Errorf("an uncontained peer was refused: %v", err)
	}
}

// TestContainedPeerCannotRefreshAnExistingEntry.
//
// Admit's re-admission path upgrades an existing entry in place, BEFORE the
// caps are consulted. If containment were checked after it, a contained relay
// would keep its slot by being mentioned once more -- ejected, then quietly
// restored by its own presence.
func TestContainedPeerCannotRefreshAnExistingEntry(t *testing.T) {
	srv := mkSRV(0x42)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))
	c := contactAt(7, "198.51.100.7", 64507, srv, false) // unverified first
	if err := table.Admit(c); err != nil {
		t.Fatal(err)
	}
	table.SetContainment(contained(t, ContactID(c.NodeIDPub)))

	verified := c
	verified.Verified = true
	if err := table.Admit(verified); !errors.Is(err, ErrContained) {
		t.Fatalf("a contained peer refreshed its entry: %v", err)
	}
}

// TestSweepContainedMakesADenialRetroactive.
//
// A list loaded from disk names peers ejected in an earlier incident. Without a
// sweep the table keeps every one of them -- containment that lapses across
// exactly the restart it was built to survive.
func TestSweepContainedMakesADenialRetroactive(t *testing.T) {
	srv := mkSRV(0x42)
	table := NewTable(MustDeriveKey(ClassRelay, []byte("self")))

	var target Contact
	for i := 0; i < 6; i++ {
		addr := netip.AddrFrom4([4]byte{198, 51, byte(100 + i), byte(i + 1)})
		c := contactAt(uint64(i), addr.String(), uint32(64500+i), srv, true)
		if err := table.Admit(c); err != nil {
			t.Fatalf("Admit %d: %v", i, err)
		}
		if i == 3 {
			target = c
		}
	}
	before := table.Len()
	if before != 6 {
		t.Fatalf("table holds %d contacts, want 6", before)
	}

	// The list arrives AFTER the contacts are already in, which is the startup
	// order: load the table's peers, then load the list.
	table.SetContainment(contained(t, ContactID(target.NodeIDPub)))
	if table.Len() != before {
		t.Error("SetContainment swept on its own; it must not reshape a table " +
			"according to a list nobody has read")
	}
	removed := table.SweepContained()
	if removed == 0 {
		t.Fatal("SweepContained removed nothing")
	}
	if table.Len() != before-1 {
		t.Errorf("table holds %d after the sweep, want %d", table.Len(), before-1)
	}
	for _, c := range table.Siblings() {
		if c.NodeIDPub == target.NodeIDPub {
			t.Error("the contained peer is still in the sibling list, which is " +
				"what decides replica-set membership")
		}
	}
}

// TestContainmentSurvivesTheRestartItReplaces is the end-to-end property, and
// the reason the list is on disk.
//
// The incident procedure's containment step was "restart the node", because the
// table is in memory. An in-memory denial would be erased by the very act
// prescribed to enforce it.
func TestContainmentSurvivesTheRestartItReplaces(t *testing.T) {
	dir := t.TempDir()
	srv := mkSRV(0x42)
	c := contactAt(7, "198.51.100.7", 64507, srv, true)

	// Incident: the responder contains the relay and saves.
	list := contain.New()
	if err := list.Deny(ContactID(c.NodeIDPub), "host seized", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := list.Save(dir); err != nil {
		t.Fatal(err)
	}

	// Restart: a brand new table, and the list read back off disk.
	reloaded, err := contain.Load(dir)
	if err != nil {
		t.Fatalf("Load after restart: %v", err)
	}
	fresh := NewTable(MustDeriveKey(ClassRelay, []byte("self")))
	fresh.SetContainment(reloaded)

	if err := fresh.Admit(c); !errors.Is(err, ErrContained) {
		t.Fatalf("after a restart the contained relay was admitted: %v", err)
	}
}
