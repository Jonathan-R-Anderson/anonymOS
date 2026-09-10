package reputation

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func issuer(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func attest(t *testing.T, priv ed25519.PrivateKey, subject string, d Dimension, v float64, at time.Time) Attestation {
	t.Helper()
	a := Attestation{
		Subject: subject, Dimension: d, Value: v,
		Basis: "observed over the stated window", Window: time.Hour, At: at,
	}
	if err := a.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return a
}

// ownView is a FirstHandSource standing in for whatever measured the subject.
type ownView struct{ m map[string]float64 }

func (o ownView) FirstHand(subject string, d Dimension) (float64, time.Time, bool) {
	v, ok := o.m[subject+"/"+d.String()]
	return v, time.Unix(1_700_000_000, 0), ok
}

var testNow = time.Unix(1_700_000_000, 0).UTC()

// TestEG6FirstHandOutranksAnyNumberOfIssuers is E-G6.
//
//	"A node's own first-hand observation outranks a contradicting attestation
//	from any issuer — falsified by an attestation overriding measurement."
//
// Deliberately overwhelming: twenty trusted issuers all say the opposite of what
// this node measured. A weighted average would let them outvote the measurement,
// which is the falsifier — so the measurement is returned AS IS.
func TestEG6FirstHandOutranksAnyNumberOfIssuers(t *testing.T) {
	own := ownView{m: map[string]float64{"relay-a/routing": -0.8}}
	r := NewReducer()
	r.FirstHand = own
	r.Now = func() time.Time { return testNow }

	for i := 0; i < 20; i++ {
		pub, priv := issuer(t)
		r.Trust(IssuerID(pub))
		if err := r.Accept(attest(t, priv, "relay-a", DimRouting, 1.0, testNow)); err != nil {
			t.Fatalf("Accept: %v", err)
		}
	}

	v := r.Reduce("relay-a", DimRouting)
	if v.Confidence != FirstHand {
		t.Fatalf("confidence is %v, want first-hand", v.Confidence)
	}
	if v.Value != -0.8 {
		t.Fatalf("E-G6 FALSIFIED: 20 issuers moved the value to %v; this node "+
			"measured -0.8 and what you saw yourself cannot be overridden by "+
			"what you were told", v.Value)
	}
	// The attestations are still read, because §88 makes them evidence about
	// the ISSUER as much as the subject.
	if v.Contradicted != 20 {
		t.Errorf("Contradicted = %d, want 20 — the disagreement is the signal", v.Contradicted)
	}
}

// TestEG6HoldsForEveryDimension: a single score would force the network to
// choose which of "excellent reporter, poor governance participant" to be wrong
// about, so the ordering has to hold per dimension.
func TestEG6HoldsForEveryDimension(t *testing.T) {
	pub, priv := issuer(t)
	for d := Dimension(0); d.Valid(); d++ {
		own := ownView{m: map[string]float64{"relay-a/" + d.String(): 0.9}}
		r := NewReducer(IssuerID(pub))
		r.FirstHand = own
		r.Now = func() time.Time { return testNow }
		if err := r.Accept(attest(t, priv, "relay-a", d, -1.0, testNow)); err != nil {
			t.Fatal(err)
		}
		if v := r.Reduce("relay-a", d); v.Value != 0.9 {
			t.Errorf("dimension %s: attestation overrode measurement (%v)", d, v.Value)
		}
	}
}

// TestEG7DisjointIssuerSetsDiverge is E-G7's first half.
//
//	"Two nodes with disjoint trusted_issuers reach different conclusions about
//	the same subject and both keep routing — this is the pluralism test, and a
//	network that converges here has built a consensus document (R14)."
//
// Neither node has measured the subject, so each is left with what it was told,
// and they were told opposite things by issuers the other does not trust.
func TestEG7DisjointIssuerSetsDiverge(t *testing.T) {
	pubX, privX := issuer(t)
	pubY, privY := issuer(t)

	good := attest(t, privX, "relay-a", DimHosting, 0.9, testNow)
	bad := attest(t, privY, "relay-a", DimHosting, -0.9, testNow)

	// Alice trusts X only; Bob trusts Y only. Both HOLD both attestations --
	// trust is applied when reducing, not at ingest.
	alice := NewReducer(IssuerID(pubX))
	bob := NewReducer(IssuerID(pubY))
	for _, r := range []*Reducer{alice, bob} {
		r.Now = func() time.Time { return testNow }
		if err := r.Accept(good); err != nil {
			t.Fatal(err)
		}
		if err := r.Accept(bad); err != nil {
			t.Fatal(err)
		}
	}

	av := alice.Reduce("relay-a", DimHosting)
	bv := bob.Reduce("relay-a", DimHosting)

	if av.Confidence != FromAttestations || bv.Confidence != FromAttestations {
		t.Fatalf("confidences: alice=%v bob=%v", av.Confidence, bv.Confidence)
	}
	if av.Value == bv.Value {
		t.Fatalf("E-G7 FALSIFIED: both nodes concluded %v. Convergence here is a "+
			"consensus document, which R14 forbids", av.Value)
	}
	if av.Value <= 0 {
		t.Errorf("alice trusts the positive issuer and concluded %v", av.Value)
	}
	if bv.Value >= 0 {
		t.Errorf("bob trusts the negative issuer and concluded %v", bv.Value)
	}
	// Each counted only its own issuer, so neither is reading the other's.
	if av.Issuers != 1 || bv.Issuers != 1 {
		t.Errorf("issuer counts: alice=%d bob=%d, want 1 each", av.Issuers, bv.Issuers)
	}
}

// TestEG7BothKeepRouting is the half of E-G7 that is easy to skip.
//
// Divergence is only pluralism if BOTH nodes still function. A design where the
// node holding the negative view refuses to route has not built pluralism, it
// has built exclusion with extra steps -- and by R-87.1 an UNKNOWN or poorly
// rated peer stays workable.
func TestEG7BothKeepRouting(t *testing.T) {
	pubX, privX := issuer(t)
	pubY, privY := issuer(t)

	alice := NewReducer(IssuerID(pubX))
	bob := NewReducer(IssuerID(pubY))
	for _, r := range []*Reducer{alice, bob} {
		r.Now = func() time.Time { return testNow }
		if err := r.Accept(attest(t, privX, "relay-a", DimRouting, 0.9, testNow)); err != nil {
			t.Fatal(err)
		}
		if err := r.Accept(attest(t, privY, "relay-a", DimRouting, -0.9, testNow)); err != nil {
			t.Fatal(err)
		}
	}

	// The package offers NO predicate that answers "may I route through this",
	// and that absence is the point: a reducer that returned a boolean would be
	// making the exclusion decision on the caller's behalf, network-wide by
	// convention if not by protocol. It returns a value and a confidence; what
	// to do about a negative view is the caller's policy, and R-87.1 says
	// UNKNOWN must stay workable.
	av := alice.Reduce("relay-a", DimRouting)
	bv := bob.Reduce("relay-a", DimRouting)
	if av.Confidence == Unknown || bv.Confidence == Unknown {
		t.Fatal("setup: both nodes should have a view")
	}
	// Bob's view is negative and he is not thereby prevented from anything --
	// there is nothing here to prevent him with.
	if bv.Value >= 0 {
		t.Fatalf("bob's view is %v, expected negative", bv.Value)
	}
}

// TestNoBootstrapByDeclaration: §88 says a new node has no attestations and is
// UNKNOWN, and R-87.1 makes UNKNOWN workable rather than excluded.
func TestNoBootstrapByDeclaration(t *testing.T) {
	r := NewReducer()
	r.Now = func() time.Time { return testNow }
	v := r.Reduce("brand-new-node", DimRouting)
	if v.Confidence != Unknown {
		t.Errorf("a node nobody has attested to is %v, want unknown", v.Confidence)
	}
	if v.Value != 0 {
		t.Errorf("an unknown subject reported a value of %v; a consumer must "+
			"branch on Confidence rather than reading this as neutral", v.Value)
	}

	// And it may not attest to itself into existence.
	pub, priv := issuer(t)
	self := Attestation{
		Subject: IssuerID(pub), Dimension: DimRouting, Value: 1,
		Basis: "I am excellent", Window: time.Hour, At: testNow,
	}
	if err := self.Sign(priv); !errors.Is(err, ErrSelfAttested) {
		t.Errorf("a self-attestation signed: %v", err)
	}
}

// TestUntrustedIssuersAreHeldButNotCounted.
//
// Trust is applied at REDUCE time, so granting it later makes what an issuer
// already said count without it having to say everything again. Refusing at
// ingest would make the trusted set a filter on history rather than on belief.
func TestUntrustedIssuersAreHeldButNotCounted(t *testing.T) {
	pub, priv := issuer(t)
	r := NewReducer()
	r.Now = func() time.Time { return testNow }
	if err := r.Accept(attest(t, priv, "relay-a", DimUptime, 0.5, testNow)); err != nil {
		t.Fatalf("an untrusted issuer's attestation was refused at ingest: %v", err)
	}
	if v := r.Reduce("relay-a", DimUptime); v.Confidence != Unknown {
		t.Errorf("an untrusted issuer counted: %+v", v)
	}
	r.Trust(IssuerID(pub))
	if v := r.Reduce("relay-a", DimUptime); v.Value != 0.5 {
		t.Errorf("after trusting, the held attestation did not count: %+v", v)
	}
	// And revoking trust stops it counting immediately, without the operator
	// having to remember what they accepted while it was granted.
	r.Distrust(IssuerID(pub))
	if v := r.Reduce("relay-a", DimUptime); v.Confidence != Unknown {
		t.Errorf("after distrusting, it still counted: %+v", v)
	}
}

// TestDecayIsAppliedOnRead is T12a.5's reasoning, extended.
//
// THIS TEST CAUGHT A REAL DEFECT and is worth reading for it. The reducer first
// returned a NORMALISED weighted mean, and a normalised mean never decays:
// scaling every weight by the same factor cancels, so a single attestation from
// a year ago yields exactly the conclusion it did when fresh. That is precisely
// what T12a.5 forbids -- "a score that only decays on write freezes when
// observation stops, and asserts a stale figure with undiminished confidence" --
// and the value looked perfectly healthy while doing it.
//
// The fix is the analogue of ProfileMinSamples: a floor on the DECAYED weight,
// below which the view returns to UNKNOWN. Value alone cannot express staleness;
// Confidence has to.
func TestDecayIsAppliedOnRead(t *testing.T) {
	pub, priv := issuer(t)
	r := NewReducer(IssuerID(pub))
	r.HalfLife = time.Hour
	now := testNow
	r.Now = func() time.Time { return now }
	if err := r.Accept(attest(t, priv, "relay-a", DimUptime, 1.0, testNow)); err != nil {
		t.Fatal(err)
	}

	fresh := r.Reduce("relay-a", DimUptime)
	if fresh.Confidence != FromAttestations || fresh.Value != 1.0 {
		t.Fatalf("fresh view: %+v", fresh)
	}

	// The weight falls as the clock advances, without any write.
	now = testNow.Add(time.Hour)
	oneHalfLife := r.Reduce("relay-a", DimUptime)
	if oneHalfLife.Weight >= fresh.Weight {
		t.Errorf("weight did not fall with time: %v then %v",
			fresh.Weight, oneHalfLife.Weight)
	}
	if oneHalfLife.Confidence != FromAttestations {
		t.Errorf("one half-life aged the view out already: %+v", oneHalfLife)
	}

	// Past the floor, a lone stale voice no longer supports a conclusion.
	now = testNow.Add(3 * time.Hour)
	stale := r.Reduce("relay-a", DimUptime)
	if stale.Confidence != Unknown {
		t.Errorf("a lone attestation three half-lives old still asserts a "+
			"conclusion: %+v", stale)
	}
	// But the caller can still tell "aged out" from "nobody ever spoke", which
	// is the difference between going to look for a fresher issuer and not.
	if stale.Issuers == 0 || stale.Weight == 0 {
		t.Errorf("an aged-out view is indistinguishable from silence: %+v", stale)
	}
	never := r.Reduce("relay-never-mentioned", DimUptime)
	if never.Issuers != 0 || never.Weight != 0 {
		t.Errorf("a subject nobody attested to reports evidence: %+v", never)
	}
}

// TestRelativeAgeStillDecidesTheBalance: the floor is about staleness, and
// between two live attestations the older one must still weigh less.
func TestRelativeAgeStillDecidesTheBalance(t *testing.T) {
	pubA, privA := issuer(t)
	pubB, privB := issuer(t)
	r := NewReducer(IssuerID(pubA), IssuerID(pubB))
	r.HalfLife = time.Hour
	r.Now = func() time.Time { return testNow }

	if err := r.Accept(attest(t, privA, "relay-a", DimUptime, 1.0, testNow)); err != nil {
		t.Fatal(err)
	}
	if err := r.Accept(attest(t, privB, "relay-a", DimUptime, -1.0, testNow.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	v := r.Reduce("relay-a", DimUptime)
	if v.Value <= 0 {
		t.Errorf("a two-half-life-old contradiction outweighed a fresh "+
			"attestation: %v", v.Value)
	}
}

// TestAnAttestationFromTheFutureIsNotAmplified: exp2(-negative/half) > 1 would
// give a clock that moved MORE weight than a fresh attestation.
func TestAnAttestationFromTheFutureIsNotAmplified(t *testing.T) {
	pubA, privA := issuer(t)
	pubB, privB := issuer(t)
	r := NewReducer(IssuerID(pubA), IssuerID(pubB))
	r.HalfLife = time.Hour
	r.Now = func() time.Time { return testNow }

	if err := r.Accept(attest(t, privA, "relay-a", DimUptime, 1.0, testNow)); err != nil {
		t.Fatal(err)
	}
	// Ten half-lives into the future.
	if err := r.Accept(attest(t, privB, "relay-a", DimUptime, -1.0, testNow.Add(10*time.Hour))); err != nil {
		t.Fatal(err)
	}
	v := r.Reduce("relay-a", DimUptime)
	if v.Value < -0.001 {
		t.Errorf("a future-dated attestation outweighed a current one (%v); a "+
			"clock that moved is not fresher evidence", v.Value)
	}
}

// TestOneIssuerCorrectsRatherThanRepeats.
//
// Keyed by issuer LAST, so a second attestation from one issuer about one
// subject and dimension replaces the first. Otherwise an issuer votes as many
// times as it speaks.
func TestOneIssuerCorrectsRatherThanRepeats(t *testing.T) {
	pub, priv := issuer(t)
	r := NewReducer(IssuerID(pub))
	r.Now = func() time.Time { return testNow }
	for i := 0; i < 10; i++ {
		if err := r.Accept(attest(t, priv, "relay-a", DimUptime, 1.0, testNow)); err != nil {
			t.Fatal(err)
		}
	}
	v := r.Reduce("relay-a", DimUptime)
	if v.Issuers != 1 {
		t.Errorf("one issuer speaking ten times counted as %d issuers", v.Issuers)
	}

	// A correction lands; a STALE one does not overwrite it.
	if err := r.Accept(attest(t, priv, "relay-a", DimUptime, -1.0, testNow.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if v := r.Reduce("relay-a", DimUptime); v.Value != -1.0 {
		t.Errorf("the correction did not land: %v", v.Value)
	}
	if err := r.Accept(attest(t, priv, "relay-a", DimUptime, 1.0, testNow.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if v := r.Reduce("relay-a", DimUptime); v.Value != -1.0 {
		t.Errorf("a stale attestation overwrote a fresher one: %v", v.Value)
	}
}

// TestAuditIssuerIsLocalAndAdvisory.
//
// §88: an issuer that disagrees with a node's own observations "loses weight
// WITH THAT NODE, locally, without any global consequence". Reported rather
// than acted on -- a reducer that quietly re-weighted its inputs would make the
// resulting view unauditable.
func TestAuditIssuerIsLocalAndAdvisory(t *testing.T) {
	pub, priv := issuer(t)
	own := ownView{m: map[string]float64{
		"relay-a/routing": -0.9,
		"relay-b/routing": 0.9,
	}}
	r := NewReducer(IssuerID(pub))
	r.FirstHand = own
	r.Now = func() time.Time { return testNow }

	if err := r.Accept(attest(t, priv, "relay-a", DimRouting, 0.9, testNow)); err != nil {
		t.Fatal(err)
	}
	if err := r.Accept(attest(t, priv, "relay-b", DimRouting, 0.9, testNow)); err != nil {
		t.Fatal(err)
	}
	if err := r.Accept(attest(t, priv, "relay-c", DimRouting, 0.9, testNow)); err != nil {
		t.Fatal(err)
	}

	ag := r.AuditIssuer(IssuerID(pub))
	if ag.Comparable != 2 {
		t.Errorf("Comparable = %d, want 2 (relay-c was never measured)", ag.Comparable)
	}
	if ag.Disagreed != 1 || ag.Agreed != 1 {
		t.Errorf("agreement: %+v", ag)
	}
	// The issuer is still trusted: the audit informs an operator, it does not
	// act.
	if len(r.TrustedIssuers()) != 1 {
		t.Error("AuditIssuer silently dropped the issuer")
	}
}

// TestValidationRefusesTheObviousAbuses.
func TestValidationRefusesTheObviousAbuses(t *testing.T) {
	_, priv := issuer(t)
	base := func() Attestation {
		return Attestation{
			Subject: "relay-a", Dimension: DimUptime, Value: 0.5,
			Basis: "observed", Window: time.Hour, At: testNow,
		}
	}
	for name, mutate := range map[string]func(*Attestation){
		"no subject":     func(a *Attestation) { a.Subject = "" },
		"bad dimension":  func(a *Attestation) { a.Dimension = Dimension(99) },
		"value above 1":  func(a *Attestation) { a.Value = 1.5 },
		"value below -1": func(a *Attestation) { a.Value = -1.5 },
		"no basis":       func(a *Attestation) { a.Basis = "" },
		"no window":      func(a *Attestation) { a.Window = 0 },
		"basis too long": func(a *Attestation) { a.Basis = strings.Repeat("x", MaxBasisBytes+1) },
	} {
		a := base()
		mutate(&a)
		if err := a.Sign(priv); err == nil {
			t.Errorf("%s: signed anyway", name)
		}
	}
}

// TestSignatureBindsEveryField, including the basis, and a basis carrying a
// newline cannot forge the fields above it.
func TestSignatureBindsEveryField(t *testing.T) {
	_, priv := issuer(t)
	a := attest(t, priv, "relay-a", DimUptime, 0.5, testNow)
	if err := a.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for name, mutate := range map[string]func(*Attestation){
		"subject":   func(x *Attestation) { x.Subject = "relay-b" },
		"dimension": func(x *Attestation) { x.Dimension = DimHosting },
		"value":     func(x *Attestation) { x.Value = -0.5 },
		"window":    func(x *Attestation) { x.Window = 2 * time.Hour },
		"at":        func(x *Attestation) { x.At = testNow.Add(time.Hour) },
		"basis":     func(x *Attestation) { x.Basis = "something else entirely" },
	} {
		tampered := a
		mutate(&tampered)
		if err := tampered.Verify(); !errors.Is(err, ErrBadSignature) {
			t.Errorf("tampering with %s survived verification: %v", name, err)
		}
	}

	// A basis that tries to forge a value line above it. Length-prefixed and
	// last, so it cannot.
	forge := Attestation{
		Subject: "relay-a", Dimension: DimUptime, Value: -1,
		Basis: "x\nvalue: 1.000000", Window: time.Hour, At: testNow,
	}
	if err := forge.Sign(priv); err != nil {
		t.Fatal(err)
	}
	other := forge
	other.Value = 1
	if err := other.Verify(); !errors.Is(err, ErrBadSignature) {
		t.Error("a basis containing a value line forged the value")
	}
}

// TestNothingHerePublishes is R-97.1's deployment constraint, as a test.
//
// "A reading that treats reaching G6/G7 as permission to publish attestations is
// the privacy regression §96 exists to prevent." At nine nodes (PAR-15), a
// node's attestation history identifies its operator completely, which is
// exactly the scale §96 names.
//
// A comment saying so does not fail. This does.
func TestNothingHerePublishes(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	// Anything that would put an attestation on a wire or in the DHT.
	banned := []string{
		"net/http", "internal/axon/dht", "internal/axon/link",
		"internal/axon/circuit", "internal/axon/tunnel", "libp2p",
		"encoding/gob", "net\"",
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		src := string(body)
		for _, b := range banned {
			if strings.Contains(src, b) {
				t.Errorf("%s references %q. G6/G7 are IMPLEMENTED AND TESTED, "+
					"not published: at nine nodes an attestation history "+
					"identifies its operator completely (§96), and R-97.1 makes "+
					"G6 deployable only after G17. If this is deliberate, G17 "+
					"has to land first and this test has to be the thing that "+
					"changes.", e.Name(), b)
			}
		}
	}
}
