package content

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func signer(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func subject(t *testing.T, n string, c byte) ContentIdentity {
	t.Helper()
	id, err := For(mustName(t, n), cid(c), owner(1), ServiceSite, 100)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestEG2NoLabelExistsWithoutAnIssuerAndSignature is E-G2, behaviourally.
func TestEG2NoLabelExistsWithoutAnIssuerAndSignature(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)

	good, err := Sign(subj, CategoryMalware, 0.9, 100, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := good.Verify(); err != nil {
		t.Fatalf("a signed label did not verify: %v", err)
	}

	// Unattributed: refused. This is R-86.1 — whoever can write an
	// unattributed label can suppress content with nobody answerable for it.
	orphan := good
	orphan.Claimant = ClaimantID{}
	if err := orphan.Verify(); !errors.Is(err, ErrUnattributed) {
		t.Fatalf("an unattributed label verified: %v", err)
	}

	// Unsigned: refused.
	unsigned := good
	unsigned.Signature = nil
	if err := unsigned.Verify(); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("an unsigned label verified: %v", err)
	}

	// Signed by somebody else, claimant relabelled to a party who did not say it.
	_, other := signer(t)
	forged, err := Sign(subj, CategoryMalware, 0.9, 100, other)
	if err != nil {
		t.Fatal(err)
	}
	forged.Claimant = good.Claimant
	if err := forged.Verify(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a label attributed to a party who did not sign it verified: %v", err)
	}
}

// TestEG2SchemaHasNoUnattributedLabel is E-G2's schema half.
//
// "No label exists anywhere without an issuer and a signature, BY SCHEMA
// AUDIT." A behavioural test proves the constructor is careful; this proves the
// TYPE cannot express the thing at all.
func TestEG2SchemaHasNoUnattributedLabel(t *testing.T) {
	src, err := os.ReadFile("label.go")
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "label.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	var fields []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Label" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			for _, name := range fld.Names {
				fields = append(fields, name.Name)
			}
		}
		return false
	})
	if len(fields) == 0 {
		t.Fatal("Label struct not found; the audit is reading the wrong file")
	}
	for _, required := range []string{"Claimant", "Signature", "Subject", "Category"} {
		found := false
		for _, f := range fields {
			if f == required {
				found = true
			}
		}
		if !found {
			t.Errorf("E-G2 violated: Label has no %s field, so a label can exist "+
				"without saying who claims it", required)
		}
	}
	// And no constructor that returns a Label WITHOUT signing it.
	//
	// A count of `func Sign(` missed this: `func SignSkipped(` does not contain
	// that substring, so a second constructor sailed past. Found by adding one
	// and watching the audit stay green. Every top-level function returning a
	// Label is now checked for an ed25519.Sign in its body.
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Type.Results == nil {
			continue
		}
		returnsLabel := false
		for _, res := range fn.Type.Results.List {
			if id, ok := res.Type.(*ast.Ident); ok && id.Name == "Label" {
				returnsLabel = true
			}
		}
		if !returnsLabel {
			continue
		}
		body := string(src[fn.Pos()-1 : fn.End()-1])
		if !strings.Contains(body, "ed25519.Sign(") {
			t.Errorf("E-G2 violated: %s returns a Label without signing it, so a "+
				"label can be created that no claimant stands behind", fn.Name.Name)
		}
	}
}

// TestUnknownIsNotAClaimableCategory is §86's distinction.
//
// `unknown` is the ABSENCE of a claim. Signing one would assert that content IS
// unclassified, which is a different and unfalsifiable thing — and it would give
// §87's policy engine a label to match on where it should be seeing nothing.
func TestUnknownIsNotAClaimableCategory(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)

	if _, err := Sign(subj, CategoryUnknown, 1.0, 100, priv); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("`unknown` was signable: %v", err)
	}
	if CategoryUnknown.Valid() {
		t.Fatal("`unknown` reports itself as claimable")
	}
	// It is still the zero value, so an uninitialised Category is never a claim.
	var zero Category
	if zero != CategoryUnknown {
		t.Fatal("the zero Category is not `unknown`; an uninitialised label would " +
			"assert a real category")
	}
	if _, err := ParseCategory("unknown"); err == nil {
		t.Fatal("`unknown` can be parsed into a claimable category")
	}
	if _, err := ParseCategory("nonsense"); !errors.Is(err, ErrUnknownCategory) {
		t.Fatal("an undefined category string was accepted")
	}
}

// TestJurisdictionalCategoriesAreNotPruneEligible is §94's rule in code.
func TestJurisdictionalCategoriesAreNotPruneEligible(t *testing.T) {
	for _, c := range []Category{CategoryIllegal, CategoryExtremist, CategoryCopyright} {
		if !c.Jurisdictional() {
			t.Errorf("%s is not marked jurisdictional", c)
		}
		if c.PruneEligible() {
			t.Errorf("§94 violated: %s is prune-eligible. The network spans legal "+
				"systems that disagree and a majority vote does not resolve a "+
				"conflict of laws, it exports one jurisdiction's answer", c)
		}
	}
	// Only two are, and they are attacks on the network's own users.
	for _, c := range []Category{CategoryMalware, CategoryPhishing} {
		if !c.PruneEligible() {
			t.Errorf("%s should be prune-eligible", c)
		}
		if c.Jurisdictional() {
			t.Errorf("%s marked jurisdictional; it is not a matter of opinion", c)
		}
	}
	// Taste is not prune-eligible either.
	for _, c := range []Category{CategoryAdult, CategoryGambling, CategoryPolitical, CategorySocial} {
		if c.PruneEligible() {
			t.Errorf("§94 violated: %s is prune-eligible", c)
		}
	}
}

// TestASignatureBindsTheSubject is why SigningBytes covers both keys.
func TestASignatureBindsTheSubject(t *testing.T) {
	_, priv := signer(t)
	a := subject(t, "acmeworks.lab.axon", 1)
	b := subject(t, "widgetco.lab.axon", 1)

	l, err := Sign(a, CategoryMalware, 0.9, 100, priv)
	if err != nil {
		t.Fatal(err)
	}
	moved := l
	moved.Subject = b
	if err := moved.Verify(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a label was moved to another name with its signature intact: %v", err)
	}

	// And to the VERSION, so a claim about one manifest cannot be re-pointed.
	reversioned := l
	reversioned.Subject = subject(t, "acmeworks.lab.axon", 2)
	if err := reversioned.Verify(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a label was moved to another version: %v", err)
	}

	// Category and confidence too.
	recategorised := l
	recategorised.Category = CategoryTechnology
	if err := recategorised.Verify(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a label's category was rewritten: %v", err)
	}
}

// TestLabelSetKeepsClaimantsDistinct is what §90's sublinear corroboration needs.
func TestLabelSetKeepsClaimantsDistinct(t *testing.T) {
	subj := subject(t, "acmeworks.lab.axon", 1)
	set := NewLabelSet(subj.Subject())

	// One claimant, ten claims.
	_, priv := signer(t)
	for i := 0; i < 10; i++ {
		l, err := Sign(subj, CategoryMalware, 0.9, uint64(100+i), priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.Add(l); err != nil {
			t.Fatal(err)
		}
	}
	if set.Len() != 10 {
		t.Fatalf("held %d labels", set.Len())
	}
	if got := len(set.Claimants()); got != 1 {
		t.Fatalf("ten claims from one claimant reported as %d claimants; §90's "+
			"corroboration factor would be defeated before the weighting ran", got)
	}

	// A label about a different subject is refused, not re-filed.
	other := subject(t, "widgetco.lab.axon", 1)
	l, err := Sign(other, CategoryMalware, 0.9, 100, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Add(l); err == nil {
		t.Fatal("a label about another subject was admitted")
	}
}

// TestConfidenceIsBounded keeps §91's estimate an estimate.
func TestConfidenceIsBounded(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)
	for _, bad := range []float32{-0.1, 1.1, 2} {
		if _, err := Sign(subj, CategoryMalware, bad, 100, priv); !errors.Is(err, ErrConfidence) {
			t.Fatalf("confidence %v was accepted", bad)
		}
	}
}
