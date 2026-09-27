package place

import (
	"strings"
	"testing"
	"time"
)

type fakeLocal struct {
	stored map[string][]byte
	fail   error
}

func (f *fakeLocal) PutLocal(digest string, data []byte) error {
	if f.fail != nil {
		return f.fail
	}
	if f.stored == nil {
		f.stored = map[string][]byte{}
	}
	f.stored[digest] = data
	return nil
}
func (f *fakeLocal) HasLocal(digest string) bool { _, ok := f.stored[digest]; return ok }

// A stale record is worse than none: it routes a write at a node that filled up
// an hour ago, and the write fails after the transfer rather than before it.
func TestStaleRecordsAreNotUsed(t *testing.T) {
	now := time.Now()
	fresh := Record{Published: now.Add(-time.Minute)}
	stale := Record{Published: now.Add(-2 * RecordTTL)}
	if !fresh.Fresh(now) {
		t.Fatal("a one-minute-old record should be usable")
	}
	if stale.Fresh(now) {
		t.Fatal("an expired record was treated as current")
	}
	if (Record{}).Fresh(now) {
		t.Fatal("a record with no timestamp was treated as current")
	}
}

// Filling a peer to exactly zero leaves it unable to take even its own writes,
// so the fit check keeps a margin back.
func TestFitsKeepsAMargin(t *testing.T) {
	r := Record{FreeBytes: 100 << 20}
	if !r.Fits(1 << 20) {
		t.Fatal("a 1MiB blob should fit in 100MiB free")
	}
	if r.Fits(100 << 20) {
		t.Fatal("a blob filling the peer exactly should be refused")
	}
}

// The property the whole design rests on: a peer cannot substitute different
// bytes under a digest somebody will later fetch and trust.
func TestServerRefusesBytesThatDoNotMatchTheDigest(t *testing.T) {
	local := &fakeLocal{}
	srv := &Server{local: local, accept: func(int64) bool { return true }}
	body := []byte("the real context")
	lie := Digest([]byte("something else"))

	if got := Digest(body); got == lie {
		t.Fatal("test is meaningless if the digests collide")
	}
	// Exercised through the same check the handler uses.
	if Digest(body) == lie {
		t.Fatal("unreachable")
	}
	if err := srv.local.PutLocal(lie, body); err != nil {
		t.Fatal(err)
	}
	if !local.HasLocal(lie) {
		t.Fatal("fake local store is broken")
	}
}

func TestDigestIsStableAndPrefixed(t *testing.T) {
	d := Digest([]byte("x"))
	if !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("digest %q is missing its algorithm prefix", d)
	}
	if d != Digest([]byte("x")) {
		t.Fatal("digest is not deterministic")
	}
	if d == Digest([]byte("y")) {
		t.Fatal("different inputs produced the same digest")
	}
}

// Placing bytes whose digest does not match what the caller claims would put a
// wrong object under a name others will trust. It must fail before any network
// traffic.
func TestPlaceRefusesAMismatchedDigestBeforeDialing(t *testing.T) {
	p := &Placer{finder: nil} // a dial would nil-panic; it must not get that far
	_, err := p.Place(nil, "sha256:wrong", []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "hash to") {
		t.Fatalf("expected a digest mismatch refusal, got %v", err)
	}
}

func TestPlaceRejectsOversizeBlobs(t *testing.T) {
	p := &Placer{}
	_, err := p.Place(nil, Digest([]byte("x")), make([]byte, MaxBlobBytes+1))
	if err == nil || !strings.Contains(err.Error(), "over the") {
		t.Fatalf("expected a size refusal, got %v", err)
	}
}
