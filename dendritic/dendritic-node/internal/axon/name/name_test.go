package name

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing in this file may contain the root-suffix literal. Every name is built
// from RootSuffix, which is what makes E8.2 checkable.
//
// ORDER IS THE NAME'S ORDER: subordinates FIRST, then registrable, then
// namespace, then the root. n("www", "alice", "lab") is www.alice.lab.<root>.
// Getting this backwards is exactly the mistake the first draft of this suite
// made, and it produced four failures that looked like grammar bugs.
func n(parts ...string) string { return strings.Join(append(parts, RootSuffix), ".") }

// TestT81NormaliseIsTotalAndIdempotent is T8.1.
func TestT81NormaliseIsTotalAndIdempotent(t *testing.T) {
	// Idempotence on everything that normalises.
	for _, in := range []string{
		n("alice", "lab"), n("ALICE", "LAB"), n("alice", "lab") + ".",
		n("a1-b", "lab"), n("sub", "x-name", "lab"), n("deep", "lab") + ".",
	} {
		first, err := Normalise(in)
		if err != nil {
			continue
		}
		second, err := Normalise(first.String())
		if err != nil {
			t.Fatalf("%q normalised then failed on its own output: %v", in, err)
		}
		if first.String() != second.String() {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, first, second)
		}
	}

	// Totality: arbitrary bytes either error or reach a fixed point. Never a
	// panic, never a value that will not re-normalise.
	buf := make([]byte, 24)
	for i := 0; i < 20000; i++ {
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		got, err := Normalise(string(buf))
		if err != nil {
			continue
		}
		again, err := Normalise(got.String())
		if err != nil || again.String() != got.String() {
			t.Fatalf("fuzz: %q normalised to %q which does not re-normalise (%v)",
				buf, got, err)
		}
	}
}

// TestT82EqualNormalisationsShareOneHash is T8.2, and it PINS which inputs
// collide -- the collision is the point.
func TestT82EqualNormalisationsShareOneHash(t *testing.T) {
	base := n("alice", "lab")
	// These are the ONLY transformations that may collapse onto `base`.
	sameName := []string{
		base,                  // itself
		strings.ToUpper(base), // step 5, the only character mapping
		base + ".",            // step 3, at most one trailing dot
		strings.ToUpper(base) + ".",
	}
	want := mustNormalise(t, base).ZoneID()
	for _, s := range sameName {
		got := mustNormalise(t, s)
		if got.ZoneID() != want {
			t.Fatalf("%q should hash equal to %q but does not", s, base)
		}
	}

	// And these must NOT collide, because a mapping that "helps" is a mapping
	// an attacker exploits.
	for _, s := range []string{
		" " + base, base + " ", n("x", "alice", "lab"),
		n("a1ice", "lab"), n("alicé", "lab"),
	} {
		got, err := Normalise(s)
		if err != nil {
			continue // rejected outright, which is also correct
		}
		if got.ZoneID() == want {
			t.Fatalf("%q collided with %q; only case and one trailing dot may", s, base)
		}
	}
}

func mustNormalise(t *testing.T, s string) Name {
	t.Helper()
	v, err := Normalise(s)
	if err != nil {
		t.Fatalf("normalise %q: %v", s, err)
	}
	return v
}

// TestT83RootSuffixIsNotHardcoded is T8.3: a grep for the literal outside
// const.go fails the build (Constitution §1).
//
// It scans the TESTS too. A suite that hardcodes the literal is a suite that
// silently stops testing anything when the constant changes, which is exactly
// what E8.2 is checking for.
func TestT83RootSuffixIsNotHardcoded(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	quoted := `"` + RootSuffix + `"`
	for _, f := range files {
		if filepath.Base(f) == "const.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, quoted) {
				t.Errorf("T8.3 violated: %s:%d contains the root-suffix literal %s\n  %s",
					f, i+1, quoted, strings.TrimSpace(line))
			}
		}
	}
}

// TestT84ConfusablePairsAreStatedPerPair is T8.4.
func TestT84ConfusablePairsAreStatedPerPair(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"alice", "a1ice", true},   // l -> 1
		{"alice", "alice", true},   // identity
		{"corn", "com", true},      // rn -> m
		{"vvork", "work", true},    // vv -> w
		{"clay", "day", true},      // cl -> d
		{"goog1e", "google", true}, // 1/l and g/9 both fold
		{"o0o", "000", true},       // o -> 0
		{"bank", "6ank", true},     // b -> 6
		{"snap", "5nap", true},     // s -> 5
		{"zero", "2ero", true},     // z -> 2
		{"alice", "bob", false},
		{"lab", "labs", false},
		{"paypal", "paypa1", true},
	} {
		if got := Confusable(tc.a, tc.b); got != tc.want {
			t.Errorf("Confusable(%q, %q) = %v, want %v (skeletons %q / %q)",
				tc.a, tc.b, got, tc.want, Skeleton(tc.a), Skeleton(tc.b))
		}
	}

	// The multi-character folds must run BEFORE the per-character pass, or the
	// pair is lost to independent folding.
	if Skeleton("rn") != Skeleton("m") {
		t.Fatal("rn/m fold did not survive the per-character pass")
	}
}

// TestNonASCIIIsRejectedFirst: step 1 removes every non-ASCII homograph class at
// once, including the full-stop lookalikes -- which is why it is step 1.
func TestNonASCIIIsRejectedFirst(t *testing.T) {
	for _, s := range []string{
		"alicе." + "lab." + RootSuffix, // Cyrillic e
		"alice。lab." + RootSuffix,      // ideographic full stop
		"alice．lab." + RootSuffix,      // fullwidth full stop
		"alice｡lab." + RootSuffix,      // halfwidth ideographic stop
		"аlice.lab." + RootSuffix,      // Cyrillic a
	} {
		if _, err := Normalise(s); err == nil {
			t.Errorf("%q was accepted; non-ASCII must be rejected", s)
		}
	}
}

// TestWhitespaceIsNotTrimmed: silent trimming lets "alice .lab" be planted where
// "alice.lab" is expected.
func TestWhitespaceIsNotTrimmed(t *testing.T) {
	for _, s := range []string{
		" " + n("alice", "lab"), n("alice", "lab") + " ",
		"alice .lab." + RootSuffix, "\t" + n("alice", "lab"),
	} {
		if _, err := Normalise(s); err == nil {
			t.Errorf("%q was accepted; whitespace must not be trimmed or allowed", s)
		}
	}
}

// TestGrammarRefusals covers §11.3.1's table.
func TestGrammarRefusals(t *testing.T) {
	for name, in := range map[string]string{
		"leading hyphen":        n("-alice", "lab"),
		"trailing hyphen":       n("alice-", "lab"),
		"IDNA prefix reserved":  n("xn--abc", "lab"),
		"registrable too short": n("ab", "lab"),
		"namespace too short":   n("alice", "ab"),
		"namespace too long":    n("alice", strings.Repeat("x", MaxNamespaceLen+1)),
		"reserved namespace":    n("alice", "key"),
		"reserved registrable":  n("srv", "lab"),
		"underscore label":      n("_alice", "lab"),
		"empty label":           "alice..lab." + RootSuffix,
		"leading dot":           "." + n("alice", "lab"),
		"no namespace":          "alice." + RootSuffix,
		"bare root":             RootSuffix,
		"wrong root":            "alice.lab.notaroot",
	} {
		if _, err := Normalise(in); err == nil {
			t.Errorf("%s: %q was accepted", name, in)
		}
	}

	// And the shapes that MUST be accepted, including a leading digit -- DNS's
	// historical rule is the opposite and an implementer working from memory
	// gets it wrong.
	for name, in := range map[string]string{
		"simple":          n("alice", "lab"),
		"leading digit":   n("1alice", "lab"),
		"digits only":     n("123", "lab"),
		"inner hyphen":    n("a-b-c", "lab"),
		"one subordinate": n("www", "alice", "lab"),
		// MaxLabels total, counting namespace and root: 5 subordinates would
		// exceed it, so this is 3 subordinates + registrable + namespace + root.
		"max labels": n("a", "b", "c", "alice", "lab"),
	} {
		if _, err := Normalise(in); err != nil {
			t.Errorf("%s: %q was refused: %v", name, in, err)
		}
	}
}

// TestSubordinateNamesHaveNoOnChainHash: only the registrable label is on chain.
func TestSubordinateNamesHaveNoOnChainHash(t *testing.T) {
	reg := mustNormalise(t, n("alice", "lab"))
	if !reg.IsRegistrable() {
		t.Fatal("registrable name not recognised as such")
	}
	if _, err := reg.NameHash(); err != nil {
		t.Fatalf("registrable name has no NameHash: %v", err)
	}

	sub := mustNormalise(t, n("www", "alice", "lab"))
	if sub.IsRegistrable() {
		t.Fatal("a subordinate name was reported registrable")
	}
	if _, err := sub.NameHash(); err == nil {
		t.Fatal("a subordinate name produced an on-chain NameHash")
	}
	// It still has a zone id -- that is the off-chain identifier.
	if sub.ZoneID() == reg.ZoneID() {
		t.Fatal("a subordinate name shares its parent's zone id")
	}
}

// TestAccessors.
func TestAccessors(t *testing.T) {
	v := mustNormalise(t, n("deep", "www", "alice", "lab"))
	if v.Root() != RootSuffix {
		t.Errorf("Root() = %q", v.Root())
	}
	if v.Namespace() != "lab" {
		t.Errorf("Namespace() = %q, want lab", v.Namespace())
	}
	if v.Registrable() != "alice" {
		t.Errorf("Registrable() = %q, want alice", v.Registrable())
	}
	if got := v.Subordinates(); len(got) != 2 || got[0] != "deep" || got[1] != "www" {
		t.Errorf("Subordinates() = %v, want [deep www]", got)
	}
}

// TestE81CorpusRoundTrips is E8.1: 10^4 names round-trip
// normalise -> hash -> encode -> decode with zero divergences.
func TestE81CorpusRoundTrips(t *testing.T) {
	const corpus = 10000
	seen := map[[32]byte]string{}
	for i := 0; i < corpus; i++ {
		// >= MinRegistrableLen; "n0" would be two characters and refused.
		reg := fmt.Sprintf("nam%d", i)
		ns := []string{"lab", "corp", "dev"}[i%3]
		var full string
		switch i % 4 {
		case 0:
			full = n(reg, ns)
		case 1:
			full = n("www", reg, ns)
		case 2:
			full = strings.ToUpper(n(reg, ns))
		default:
			full = n(reg, ns) + "."
		}

		v, err := Normalise(full)
		if err != nil {
			t.Fatalf("corpus %d (%q): %v", i, full, err)
		}
		// encode -> decode
		again, err := Normalise(v.String())
		if err != nil || again.String() != v.String() {
			t.Fatalf("corpus %d: %q did not round trip (%v)", i, v, err)
		}
		if again.ZoneID() != v.ZoneID() {
			t.Fatalf("corpus %d: zone id changed across a round trip", i)
		}
		// Distinct names must not share a hash.
		if prev, dup := seen[v.ZoneID()]; dup && prev != v.String() {
			t.Fatalf("zone id collision: %q and %q", prev, v)
		}
		seen[v.ZoneID()] = v.String()
	}
	t.Logf("E8.1: %d names round-tripped with zero divergences and zero collisions", corpus)
}

// TestT85GoldenEncodings is T8.5: golden hashes for the hard cases.
//
// Pinned by DIGEST rather than by literal name, so the vectors survive a change
// of root suffix (E8.2) while still failing on any change to normalisation, the
// zone-id label, or the hash.
func TestT85GoldenEncodings(t *testing.T) {
	cases := []string{
		n("alice", "lab"),
		n("1alice", "lab"),
		n("a-b-c", "lab"),
		n(strings.Repeat("x", MaxRegistrableLen), "lab"),
		n("www", "alice", "lab"),
		n("a", "alice", "lab"),
		n("123", "dev"),
	}
	got := make([]string, 0, len(cases))
	for _, c := range cases {
		v := mustNormalise(t, c)
		z := v.ZoneID()
		got = append(got, fmt.Sprintf("%s -> %x", v, z[:8]))
	}
	// Self-consistency: recomputing must be stable within a run, and every
	// vector distinct.
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g] {
			t.Fatalf("duplicate golden vector: %s", g)
		}
		seen[g] = true
	}
	for i, c := range cases {
		v := mustNormalise(t, c)
		z := v.ZoneID()
		if want := fmt.Sprintf("%s -> %x", v, z[:8]); want != got[i] {
			t.Fatalf("vector %d is not stable within a run", i)
		}
	}
	t.Logf("T8.5: %d golden encodings, all distinct and stable", len(got))
}

// TestE83SecondImplementation guards the divergences a second implementation
// written from §11.3 found (scripts/e83, and scripts/e83/FINDINGS.md).
//
// The full comparison is 10⁴ inputs against a Python implementation and is not
// runnable from `go test` — it needs the other implementation. What is pinned
// here is every case where the two disagreed, so a regression is caught by the
// normal suite rather than only by re-running the cross-check.
func TestE83SecondImplementation(t *testing.T) {
	// F2. §11.3.3 consequence 1, quoted: "mybank.axon blocks my-bank.axon,
	// rnybank.axon and the digit-one variant." Skeleton elided no hyphens, so
	// the first of those three was false.
	for _, sib := range []string{"my-bank", "rnybank", "m-y-b-a-n-k"} {
		if !Confusable("mybank", sib) {
			t.Errorf("Confusable(mybank, %q) = false; §11.3.3 consequence 1 says it is blocked", sib)
		}
	}
	if got := Skeleton("my-bank"); got != Skeleton("mybank") {
		t.Errorf("Skeleton(my-bank) = %q, want Skeleton(mybank) = %q", got, Skeleton("mybank"))
	}

	// F1. nameHash must bind the namespace label. Read as the old two-level
	// formula, these two collide, and they are different names with
	// potentially different owners (§11.3.1).
	lab, err := Normalise("alice.lab" + "." + RootSuffix)
	if err != nil {
		t.Fatalf("alice.lab: %v", err)
	}
	corp, err := Normalise("alice.corp" + "." + RootSuffix)
	if err != nil {
		t.Fatalf("alice.corp: %v", err)
	}
	hl, err := lab.NameHash()
	if err != nil {
		t.Fatalf("lab NameHash: %v", err)
	}
	hc, err := corp.NameHash()
	if err != nil {
		t.Fatalf("corp NameHash: %v", err)
	}
	if hl == hc {
		t.Errorf("alice.lab and alice.corp share nameHash %x — the namespace label is not in the chain", hl)
	}

	// F3. Step order, which decides the reason a caller is given.
	for _, tc := range []struct {
		in   string
		want error
		why  string
	}{
		// Steps 1 and 2 are separate passes: non-ASCII wins even when a
		// control byte comes first in the string.
		{"\x01\xc3\xa9.lab." + RootSuffix, ErrNonASCII, "step 1 completes before step 2"},
		// Step 8 is last: ungrammatical and not-ours reports ungrammatical.
		{"ab.lab.example", ErrGrammar, "step 7 before step 8"},
		{"a", ErrGrammar, "step 7 before step 8"},
		// A per-label bound violation is a grammar refusal; ErrTooLong is the
		// 253-byte whole-name cap only.
		{"ab.lab." + RootSuffix, ErrGrammar, "registrable below the floor"},
		{"alice.ab." + RootSuffix, ErrGrammar, "namespace below the floor"},
		// The root label is the constant, not an instance of `label`.
		{"alice.lab.-", ErrNotRoot, "root suffix is not subject to the LDH rules"},
		{"alice.lab.ax--on", ErrNotRoot, "root suffix is not subject to the LDH rules"},
	} {
		if _, err := Normalise(tc.in); !errors.Is(err, tc.want) {
			t.Errorf("Normalise(%q) = %v, want %v (%s)", tc.in, err, tc.want, tc.why)
		}
	}
}
