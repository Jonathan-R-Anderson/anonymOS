package contain_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/contain"
	"github.com/syndichan/maniwani/storage-client/internal/axon/dht"
	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
)

// TestContainmentIDsAgreeWithEveryStructureThatChecksThem.
//
// The trap this closes: a node has two identities derived from one key, and a
// containment list stores opaque strings, so denying one spelling contains the
// host in some structures and not others. The runbook told a responder to type
// both, which is not a mechanism -- it is read under pressure by somebody who
// has never done this before.
//
// This asserts the mapping rather than trusting the comment that says the hex
// here is the same hex dht.ContactID produces.
func TestContainmentIDsAgreeWithEveryStructureThatChecksThem(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := link.ContainmentIDs(pub)
	if err != nil {
		t.Fatalf("ContainmentIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d spellings, want 2", len(ids))
	}

	// The routing table and peerbook spell it as hex of the 32-byte key.
	var arr [32]byte
	copy(arr[:], pub)
	if ids[0] != dht.ContactID(arr) {
		t.Errorf("ContainmentIDs[0] = %q but dht.ContactID says %q — the two "+
			"spellings have drifted and a denial will land in one structure only",
			ids[0], dht.ContactID(arr))
	}

	// The bootstrap path and storage spell it as the libp2p peer id.
	p2p, err := link.NodeIDFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	if ids[1] != p2p.String() {
		t.Errorf("ContainmentIDs[1] = %q but NodeIDFromPublic says %q", ids[1], p2p.String())
	}
	if ids[0] == ids[1] {
		t.Error("the two spellings are identical, so this test proves nothing — " +
			"if the identities have genuinely collapsed (item 2.9), delete it")
	}
}

// TestDenyAllContainsEveryStructureFromOneCall is 4.10f.
func TestDenyAllContainsEveryStructureFromOneCall(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := link.ContainmentIDs(pub)
	if err != nil {
		t.Fatal(err)
	}

	list := contain.New()
	if err := list.DenyAll(ids, "drill: host seized", time.Now()); err != nil {
		t.Fatalf("DenyAll: %v", err)
	}
	for _, id := range ids {
		if !list.Denied(id) {
			t.Errorf("spelling %q is not contained after DenyAll", id)
		}
	}

	// The routing table refuses it.
	var arr [32]byte
	copy(arr[:], pub)
	table := dht.NewTable(dht.MustDeriveKey(dht.ClassRelay, []byte("self")))
	table.SetContainment(list)
	addr := netip.MustParseAddr("198.51.100.7")
	prefix, err := dht.PrefixFor(addr)
	if err != nil {
		t.Fatal(err)
	}
	kad, err := dht.DeriveKadID(arr, dht.SRV{}, prefix)
	if err != nil {
		t.Fatal(err)
	}
	err = table.Admit(dht.Contact{
		NodeIDPub: arr, KadID: kad, Addr: addr, Prefix: prefix,
		ASN: 64507, Verified: true,
	})
	if !errors.Is(err, dht.ErrContained) {
		t.Errorf("the routing table admitted a DenyAll'd node: %v", err)
	}

	// And the libp2p spelling, which is what the bootstrap path checks.
	p2p, err := link.NodeIDFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !list.Denied(p2p.String()) {
		t.Error("the libp2p spelling is not contained, so the host returns " +
			"through bootstrap")
	}
}

// TestDenyAllIsAllOrNothing.
//
// A partial containment is the worst outcome available: no error is reported,
// the responder believes the host is contained, and it keeps returning through
// whichever structure got the id that did not land.
func TestDenyAllIsAllOrNothing(t *testing.T) {
	list := contain.New()
	at := time.Now()
	// Fill to one short of the cap.
	for i := 0; i < contain.MaxEntries-1; i++ {
		if err := list.Deny(filler(i), "drill", at); err != nil {
			t.Fatalf("Deny %d: %v", i, err)
		}
	}
	// Two spellings will not fit in one slot.
	err := list.DenyAll([]string{"aaaa", "bbbb"}, "host seized", at)
	if !errors.Is(err, contain.ErrFull) {
		t.Fatalf("DenyAll past the cap: %v, want ErrFull", err)
	}
	if list.Denied("aaaa") || list.Denied("bbbb") {
		t.Error("DenyAll applied PART of the set before failing — a half-contained " +
			"host is worse than an uncontained one, because nobody is looking for it")
	}

	// Re-denying an already-contained node must not fail on the cap.
	list2 := contain.New()
	if err := list2.DenyAll([]string{"aaaa", "bbbb"}, "seized", at); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < contain.MaxEntries-2; i++ {
		if err := list2.Deny(filler(i), "drill", at); err != nil {
			t.Fatal(err)
		}
	}
	if err := list2.DenyAll([]string{"aaaa", "bbbb"}, "updated: confirmed", at); err != nil {
		t.Errorf("re-denying an already-contained node at the cap failed: %v", err)
	}
}

// TestAllowAllReleasesEverySpelling.
func TestAllowAllReleasesEverySpelling(t *testing.T) {
	list := contain.New()
	ids := []string{"aaaa", "bbbb"}
	if err := list.DenyAll(ids, "suspected, since disproved", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := list.AllowAll(ids); got != 2 {
		t.Errorf("AllowAll released %d, want 2", got)
	}
	for _, id := range ids {
		if list.Denied(id) {
			t.Errorf("%q is still contained", id)
		}
	}
}

func TestContainmentIDsRefusesAShortKey(t *testing.T) {
	if _, err := link.ContainmentIDs([]byte{1, 2, 3}); err == nil {
		t.Error("a short key produced containment ids")
	}
}

func filler(i int) string {
	const hexd = "0123456789abcdef"
	return "f" + string([]byte{hexd[(i/256)%16], hexd[(i/16)%16], hexd[i%16]})
}
