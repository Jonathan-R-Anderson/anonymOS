package content

import (
	"errors"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

func mustName(t *testing.T, s string) name.Name {
	t.Helper()
	n, err := name.Normalise(s)
	if err != nil {
		t.Fatalf("normalise %q: %v", s, err)
	}
	return n
}

func cid(b byte) CID {
	var c CID
	c[0] = b
	return c
}

func owner(b byte) Address {
	var a Address
	a[0] = b
	return a
}

// TestEG1ReportSurvivesARepublish is E-G1.
//
// "A report survives a content republish and still names the version it was made
// against — falsified by a report voided by a seq bump."
//
// This is the whole point of §85. If reports keyed on the content, publishing
// one new byte would clear a name's entire record, and moderation would be a
// suggestion.
func TestEG1ReportSurvivesARepublish(t *testing.T) {
	n := mustName(t, "acmeworks.lab.axon")

	// Observed, reported, then republished with different content.
	before, err := For(n, cid(1), owner(0xaa), ServiceSite, 100)
	if err != nil {
		t.Fatal(err)
	}
	after, err := For(n, cid(2), owner(0xaa), ServiceSite, 200)
	if err != nil {
		t.Fatal(err)
	}

	if !SameSubject(before, after) {
		t.Fatal("E-G1 violated: a republish produced a different subject, so the " +
			"report against the old content counts against nothing")
	}
	if before.Subject() != after.Subject() {
		t.Fatal("the accumulation key changed with the content")
	}
	// And the report still names what it was made against.
	if SameVersion(before, after) {
		t.Fatal("two different manifests compared as the same version; an appeal " +
			"could not point at the difference")
	}
	if before.ManifestCID != cid(1) {
		t.Fatal("the reported version was overwritten by the republish")
	}
}

// TestTheAppealDefenceIsComputable covers R-85.1's second half.
func TestTheAppealDefenceIsComputable(t *testing.T) {
	n := mustName(t, "acmeworks.lab.axon")
	reported, err := For(n, cid(1), owner(0xaa), ServiceSite, 100)
	if err != nil {
		t.Fatal(err)
	}

	if !reported.Superseded(cid(2)) {
		t.Fatal("a name now serving different content did not make the defence available")
	}
	if reported.Superseded(cid(1)) {
		t.Fatal("unchanged content reported as superseded")
	}
	// An unknown current version is not a defence. Absence of evidence must not
	// read as evidence of change, or "we could not check" clears a report.
	if reported.Superseded(CID{}) {
		t.Fatal("an unknown current CID was treated as a supersession")
	}
}

// TestOneNameHasOneIdentityWhateverItsSpelling is why For takes a name.Name.
//
// §11.3.2's normalisation is total and idempotent. If two spellings produced
// two identities, a publisher could shed a name's entire report history by
// changing the case of a letter.
func TestOneNameHasOneIdentityWhateverItsSpelling(t *testing.T) {
	for _, spelling := range []string{
		"ACMEWORKS.LAB.AXON",
		"AcmeWorks.Lab.Axon",
		"acmeworks.lab.axon",
	} {
		n, err := name.Normalise(spelling)
		if err != nil {
			t.Fatalf("%q: %v", spelling, err)
		}
		id, err := For(n, cid(1), owner(0xaa), ServiceSite, 100)
		if err != nil {
			t.Fatal(err)
		}
		base, _ := For(mustName(t, "acmeworks.lab.axon"), cid(1), owner(0xaa), ServiceSite, 100)
		if id.Subject() != base.Subject() {
			t.Fatalf("%q produced a different subject; a publisher could shed its "+
				"report history by changing case", spelling)
		}
	}
}

// TestAnIdentityCannotOmitEitherKey is the shape R-85.1 forbids.
func TestAnIdentityCannotOmitEitherKey(t *testing.T) {
	full, err := For(mustName(t, "acmeworks.lab.axon"), cid(1), owner(0xaa), ServiceSite, 100)
	if err != nil {
		t.Fatal(err)
	}

	noVersion := full
	noVersion.ManifestCID = CID{}
	if err := noVersion.Validate(); !errors.Is(err, ErrNoVersion) {
		t.Fatalf("an identity with no version validated: %v", err)
	}

	noName := full
	noName.NameHash = [32]byte{}
	if err := noName.Validate(); !errors.Is(err, ErrNoName) {
		t.Fatalf("an identity with no name validated: %v", err)
	}

	noHeight := full
	noHeight.ObservedAt = 0
	if err := noHeight.Validate(); !errors.Is(err, ErrNoHeight) {
		t.Fatalf("an unanchored observation validated: %v", err)
	}
}

// TestOwnerIsRecordedNotResolvedLater is R-93.3's requirement seen from here.
//
// A seizure stays in the name's history so a NEW owner is judged on their own
// content. An identity that resolved the owner at read time would silently
// re-attribute every old report to whoever holds the name now.
func TestOwnerIsRecordedNotResolvedLater(t *testing.T) {
	n := mustName(t, "acmeworks.lab.axon")
	first, err := For(n, cid(1), owner(0xaa), ServiceSite, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Same name, later, new owner after a recycle.
	second, err := For(n, cid(9), owner(0xbb), ServiceSite, 900)
	if err != nil {
		t.Fatal(err)
	}

	if first.Owner == second.Owner {
		t.Fatal("the owner is not carried per observation")
	}
	if first.Owner != owner(0xaa) {
		t.Fatal("an earlier observation's owner changed")
	}
	// They still share a subject: the NAME is what accumulates. Distinguishing
	// the two tenancies is §93's history, not this type's job.
	if !SameSubject(first, second) {
		t.Fatal("a change of owner split the subject")
	}
}

// TestSubordinatesAccumulateAgainstTheirRegistrableParent is the ruling in For.
//
// §11 gives an on-chain namehash only to a registrable name, so a subordinate
// has no hash of its own and §85's "reports accumulate against the name hash"
// has to mean something for it. It means the PARENT: the chain is what §93 can
// act on, and a namespace where anyone sheds their report history by publishing
// under a fresh subdomain would make reporting pointless.
func TestSubordinatesAccumulateAgainstTheirRegistrableParent(t *testing.T) {
	parent, err := For(mustName(t, "acmeworks.lab.axon"), cid(1), owner(1), ServiceSite, 10)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := For(mustName(t, "sub.acmeworks.lab.axon"), cid(1), owner(1), ServiceSite, 10)
	if err != nil {
		t.Fatalf("a subordinate could not be given an identity at all: %v", err)
	}

	if !SameSubject(parent, sub) {
		t.Fatal("a subordinate does not accumulate against its registrable parent, " +
			"so a publisher sheds their history by moving to a subdomain")
	}
	// But they remain distinguishable, or a report could not say WHICH page.
	if parent.ZoneID == sub.ZoneID {
		t.Fatal("parent and subordinate share a zone id; a report could not say " +
			"which of them it was about")
	}

	// Two DIFFERENT registrable names must not merge.
	other, err := For(mustName(t, "widgetco.lab.axon"), cid(1), owner(1), ServiceSite, 10)
	if err != nil {
		t.Fatal(err)
	}
	if SameSubject(parent, other) {
		t.Fatal("two unrelated registrable names share a subject")
	}
}
