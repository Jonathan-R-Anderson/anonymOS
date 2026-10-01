package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func reporter(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func b32(b byte) []byte {
	out := make([]byte, 32)
	out[0] = b
	return out
}

func newReport(t *testing.T, priv ed25519.PrivateKey, subject, version byte) *ContentReport {
	t.Helper()
	r := &ContentReport{
		Ver: 1, NameHash: b32(subject), ManifestCID: b32(version),
		Category: 7, Reason: "serves a credential-harvesting page",
		Evidence:  [][]byte{b32(0xe1)},
		Sequence:  1,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour).Unix(),
	}
	if err := SignReport(r, priv); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestEG4ReportIsRetrievableByNodesThatNeverMetTheReporter is E-G4.
//
// "A report is retrievable from the DHT by three nodes that never contacted the
// reporter." The point of §89: a report is a PUBLICATION, and a third party can
// find and check it without asking anybody's permission or trusting a server.
func TestEG4ReportIsRetrievableByNodesThatNeverMetTheReporter(t *testing.T) {
	priv := reporter(t)
	r := newReport(t, priv, 0xaa, 0x01)

	key, err := r.DerivedKey()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}

	// Three independent nodes: each decodes the record from the wire, derives
	// the key from the RECORD'S OWN FIELDS, and checks it against the key it
	// arrived under. None of them has spoken to the reporter.
	for node := 0; node < 3; node++ {
		got, err := DecodeRecord(ClassReport, wire)
		if err != nil {
			t.Fatalf("node %d could not decode: %v", node, err)
		}
		rec, ok := got.(*ContentReport)
		if !ok {
			t.Fatalf("node %d decoded a %T", node, got)
		}
		derived, err := rec.DerivedKey()
		if err != nil {
			t.Fatalf("node %d: %v", node, err)
		}
		if derived != key {
			t.Fatalf("node %d derived a different key; the record could be filed "+
				"anywhere and nobody could tell", node)
		}
		if err := ValidateReport(rec); err != nil {
			t.Fatalf("node %d refused a valid report: %v", node, err)
		}
	}
}

// TestREG891EvidenceIsContentAddressedNotLinked is R-89.1.
//
// Evidence at a URL can be withdrawn after the vote, leaving a governance record
// that says a thing happened with nothing behind it.
func TestREG891EvidenceIsContentAddressedNotLinked(t *testing.T) {
	priv := reporter(t)
	for _, link := range []string{
		"https://example.invalid/evidence.png",
		"http://x/y",
		"ipfs://bafy",
		"//cdn/x",
	} {
		r := &ContentReport{
			Ver: 1, NameHash: b32(1), ManifestCID: b32(2), Category: 7,
			Evidence: [][]byte{[]byte(link)},
			IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}
		if err := SignReport(r, priv); !errors.Is(err, ErrReportURL) {
			t.Fatalf("evidence %q was accepted: %v", link, err)
		}
	}

	// And a non-CID-sized blob is refused too, so "evidence" cannot become a
	// payload smuggled inside a report.
	r := &ContentReport{
		Ver: 1, NameHash: b32(1), ManifestCID: b32(2), Category: 7,
		Evidence: [][]byte{make([]byte, 4096)},
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	if err := SignReport(r, priv); !errors.Is(err, ErrReportEvidence) {
		t.Fatalf("a 4 KiB evidence blob was accepted: %v", err)
	}
}

// TestOneReporterCannotFloodOneSubject is why the key includes the reporter.
func TestOneReporterCannotFloodOneSubject(t *testing.T) {
	priv := reporter(t)

	first := newReport(t, priv, 0xaa, 0x01)
	k1, _ := first.DerivedKey()

	// The same reporter files again about the same subject, different content
	// and a higher sequence. It is the SAME key -- a correction, not a second
	// voice.
	second := newReport(t, priv, 0xaa, 0x02)
	second.Sequence = 2
	if err := SignReport(second, priv); err != nil {
		t.Fatal(err)
	}
	k2, _ := second.DerivedKey()
	if k1 != k2 {
		t.Fatal("one reporter filing twice about one subject occupies two keys; " +
			"the neighbourhood can be filled by a single identity")
	}

	// A DIFFERENT reporter about the same subject is a different key, or two
	// people could not both be heard.
	other := newReport(t, reporter(t), 0xaa, 0x01)
	k3, _ := other.DerivedKey()
	if k1 == k3 {
		t.Fatal("two reporters collide on one key; the second would overwrite the first")
	}
}

// TestSignatureBindsEvidenceOrderAndContents is the tamper surface.
func TestSignatureBindsEvidenceOrderAndContents(t *testing.T) {
	priv := reporter(t)
	r := &ContentReport{
		Ver: 1, NameHash: b32(1), ManifestCID: b32(2), Category: 7,
		Evidence: [][]byte{b32(0xe1), b32(0xe2)},
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	if err := SignReport(r, priv); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReport(r); err != nil {
		t.Fatal(err)
	}

	// Reordered: refused. Otherwise "the first piece of evidence" means nothing.
	reordered := *r
	reordered.Evidence = [][]byte{b32(0xe2), b32(0xe1)}
	if err := ValidateReport(&reordered); !errors.Is(err, ErrReportSig) {
		t.Fatalf("evidence was reordered with the signature intact: %v", err)
	}

	// Trimmed: refused. Dropping the inconvenient half of the evidence would
	// otherwise leave a valid-looking report.
	trimmed := *r
	trimmed.Evidence = [][]byte{b32(0xe1)}
	if err := ValidateReport(&trimmed); !errors.Is(err, ErrReportSig) {
		t.Fatalf("evidence was trimmed with the signature intact: %v", err)
	}

	// Re-subjected: refused.
	moved := *r
	moved.NameHash = b32(9)
	if err := ValidateReport(&moved); !errors.Is(err, ErrReportSig) {
		t.Fatalf("a report was moved to another subject: %v", err)
	}

	// Recategorised: refused.
	recat := *r
	recat.Category = 2
	if err := ValidateReport(&recat); !errors.Is(err, ErrReportSig) {
		t.Fatalf("a report's category was rewritten: %v", err)
	}
}

// TestReasonIsBounded keeps the record from becoming a payload channel.
func TestReasonIsBounded(t *testing.T) {
	priv := reporter(t)
	r := &ContentReport{
		Ver: 1, NameHash: b32(1), ManifestCID: b32(2), Category: 7,
		Reason:   string(make([]byte, MaxReportReason+1)),
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	if err := SignReport(r, priv); !errors.Is(err, ErrReportReasonLong) {
		t.Fatalf("an oversized reason was accepted: %v", err)
	}
}

// TestValidatorDoesNotMakeModerationDecisions is a deliberate non-property.
//
// A validator that dropped reports it disagreed with -- unknown category,
// unregistered name -- would be moderating at the STORAGE layer, where nobody
// can see it happen and no vote is involved. §90 weighs; §93 decides.
func TestValidatorDoesNotMakeModerationDecisions(t *testing.T) {
	priv := reporter(t)
	r := newReport(t, priv, 0xaa, 0x01)
	r.Category = 200 // not a category §86 defines
	if err := SignReport(r, priv); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReport(r); err != nil {
		t.Fatalf("the storage validator refused a well-formed report on the merits "+
			"of its category: %v", err)
	}
}
