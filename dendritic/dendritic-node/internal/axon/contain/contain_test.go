package contain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDenyRequiresAReason(t *testing.T) {
	l := New()
	at := time.Now()
	// An entry nobody can explain later is an entry nobody can safely remove --
	// six months on, the only person who knows why a relay is contained is the
	// person who typed it.
	if err := l.Deny("abc", "", at); !errors.Is(err, ErrNoReason) {
		t.Errorf("Deny with no reason: %v, want ErrNoReason", err)
	}
	if err := l.Deny("abc", "   ", at); !errors.Is(err, ErrNoReason) {
		t.Errorf("Deny with a blank reason: %v, want ErrNoReason", err)
	}
	if err := l.Deny("", "operator says so", at); !errors.Is(err, ErrNoID) {
		t.Errorf("Deny with no id: %v, want ErrNoID", err)
	}
	if err := l.Deny("abc", "host seized, confirmed by the operator", at); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if !l.Denied("abc") {
		t.Error("the peer is not contained after Deny")
	}
}

func TestIDsAreCaseInsensitive(t *testing.T) {
	// dht.Table spells an id as hex of a public key and the peerbook uses its
	// own node id string. If the two disagree about case, a peer is contained
	// in one structure and admitted by the other, which is contained nowhere.
	l := New()
	if err := l.Deny("AABBCC", "seized", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !l.Denied("aabbcc") {
		t.Error("a lower-case spelling of the same id is not contained")
	}
	if !l.Denied("  AaBbCc  ") {
		t.Error("a padded spelling of the same id is not contained")
	}
}

func TestAllowIsReversible(t *testing.T) {
	l := New()
	if err := l.Deny("abc", "suspected, since disproved", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !l.Allow("abc") {
		t.Error("Allow says the peer was not contained")
	}
	if l.Denied("abc") {
		t.Error("the peer is still contained after Allow")
	}
	if l.Allow("never-contained") {
		t.Error("Allow claims to have released a peer that was never contained")
	}
}

func TestListIsBoundedByRefusalNotEviction(t *testing.T) {
	l := New()
	at := time.Now()
	for i := 0; i < MaxEntries; i++ {
		if err := l.Deny(idFor(i), "drill", at); err != nil {
			t.Fatalf("Deny %d: %v", i, err)
		}
	}
	// Silently dropping the OLDEST to admit a new one would quietly un-contain
	// the first relay somebody worried about, which is the one they are most
	// likely to still care about.
	if err := l.Deny("one-too-many", "drill", at); !errors.Is(err, ErrFull) {
		t.Errorf("Deny past the cap: %v, want ErrFull", err)
	}
	if !l.Denied(idFor(0)) {
		t.Error("the oldest entry was evicted to make room; it must be refused instead")
	}
	// Re-denying an EXISTING entry must still work at the cap: a responder
	// learning more mid-incident has to be able to write it down.
	if err := l.Deny(idFor(0), "updated: confirmed seizure", at); err != nil {
		t.Errorf("re-denying an existing entry at the cap failed: %v", err)
	}
}

func TestNilListDeniesNothing(t *testing.T) {
	// A structure with no containment wired in must behave exactly as it did
	// before this package existed.
	var l *List
	if l.Denied("anything") {
		t.Error("a nil list denied a peer")
	}
	if l.Len() != 0 || l.Entries() != nil {
		t.Error("a nil list is not empty")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	l := New()
	if err := l.Deny("aa", "host seized", at); err != nil {
		t.Fatal(err)
	}
	if err := l.Deny("bb", "operator hostile", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := l.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	back, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if back.Len() != 2 {
		t.Fatalf("loaded %d entries, want 2", back.Len())
	}
	if !back.Denied("aa") || !back.Denied("bb") {
		t.Error("a contained peer did not survive the round trip")
	}
	// The reason has to survive, or the list is unauditable on the far side of
	// exactly the restart it exists to survive.
	got := back.Entries()
	if got[0].Reason != "host seized" {
		t.Errorf("reason lost: %q", got[0].Reason)
	}
	if !got[0].At.Equal(at) {
		t.Errorf("timestamp lost: %v", got[0].At)
	}
	// Oldest first, so an operator reads the list in the order it was built.
	if got[0].ID != "aa" || got[1].ID != "bb" {
		t.Errorf("entries are not oldest-first: %v", got)
	}
}

func TestMissingFileIsAnEmptyListNotAnError(t *testing.T) {
	l, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("first run should not error: %v", err)
	}
	if l.Len() != 0 {
		t.Errorf("a fresh list holds %d entries", l.Len())
	}
}

func TestUnreadableFileIsAnErrorNotAnEmptyList(t *testing.T) {
	// The failure mode this prevents: a node that cannot read its containment
	// list proceeding as though nothing were contained, and re-admitting every
	// relay an operator ejected. Failing loudly is the only safe direction.
	dir := t.TempDir()
	if err := os.WriteFile(Path(dir), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("an unreadable containment list loaded as empty")
	}

	dir2 := t.TempDir()
	if err := os.WriteFile(Path(dir2), []byte(`{"format":99,"entries":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir2); err == nil {
		t.Fatal("an unknown format loaded as empty")
	}
}

func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	l := New()
	if err := l.Deny("aa", "seized", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := l.Save(dir); err != nil {
		t.Fatal(err)
	}
	if err := l.Save(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != FileName {
			t.Errorf("stray file left behind: %s", e.Name())
		}
	}
}

func TestReasonIsBounded(t *testing.T) {
	l := New()
	long := strings.Repeat("x", MaxReasonBytes*3)
	if err := l.Deny("aa", long, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := len(l.Entries()[0].Reason); got > MaxReasonBytes {
		t.Errorf("reason stored at %d bytes, cap is %d", got, MaxReasonBytes)
	}
}

func idFor(i int) string {
	const hexd = "0123456789abcdef"
	return string([]byte{
		hexd[(i/4096)%16], hexd[(i/256)%16], hexd[(i/16)%16], hexd[i%16],
	})
}

var _ = filepath.Join
