package content

import (
	"crypto/ed25519"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// labelled builds a set with one label from `priv` about `subj`.
func labelled(t *testing.T, subj ContentIdentity, cat Category, conf float32, priv ed25519.PrivateKey) *LabelSet {
	t.Helper()
	set := NewLabelSet(subj.Subject())
	l, err := Sign(subj, cat, conf, 100, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Add(l); err != nil {
		t.Fatal(err)
	}
	return set
}

func claimantOf(priv ed25519.PrivateKey) ClaimantID {
	var id ClaimantID
	copy(id[:], priv.Public().(ed25519.PublicKey))
	return id
}

// TestEG3BlocksHostingAndNeverTouchesRelaying is E-G3.
//
// "A node with host_block: malware refuses to store a labelled object and still
// relays normally for every category — falsified by any relay-position
// filtering (R-84.1)."
func TestEG3BlocksHostingAndNeverTouchesRelaying(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)
	pol := NodePolicy{
		HostBlock:      []Category{CategoryMalware},
		TrustedIssuers: []ClaimantID{claimantOf(priv)},
	}

	// Hosting: refused, and the reason names the category.
	d, err := pol.Decide(PositionHost, labelled(t, subj, CategoryMalware, 0.9, priv))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Fatal("a blocked category was accepted for hosting")
	}
	if d.Category != CategoryMalware {
		t.Fatalf("refusal blamed %s", d.Category)
	}

	// Relaying: THERE IS NO DECISION TO MAKE. Asking is an error, not an allow.
	if _, err := pol.DecideRelay(labelled(t, subj, CategoryMalware, 0.9, priv)); !errors.Is(err, ErrRelayPositionHasNoPolicy) {
		t.Fatalf("a relay-position content decision was answered: %v", err)
	}
	// And the position enum has no relay member to pass.
	for pos := Position(0); pos < 10; pos++ {
		if pos.String() == "relay" {
			t.Fatal("R-84.1 violated: a relay Position exists, so relay-position " +
				"filtering is expressible")
		}
	}

	// Every other category still hosts fine -- the block is one category, not a
	// posture.
	for _, c := range []Category{CategoryTechnology, CategoryPolitical, CategoryAdult} {
		d, err := pol.Decide(PositionHost, labelled(t, subj, c, 0.9, priv))
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allow {
			t.Fatalf("%s was refused by a malware-only block", c)
		}
	}
}

// TestR871UnknownIsHostedByDefault is R-87.1.
func TestR871UnknownIsHostedByDefault(t *testing.T) {
	var fresh NodePolicy // the zero value: what a new node runs
	if fresh.Unknown != UnknownHost {
		t.Fatal("R-87.1 violated: the zero-value policy refuses unknown content, so " +
			"a fresh node on a mostly-unlabelled network stores nothing")
	}
	d, err := fresh.Decide(PositionHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Fatalf("unlabelled content was refused by default: %s", d.Reason)
	}
	if d.Category != CategoryUnknown {
		t.Fatal("an unlabelled decision claimed a category")
	}

	// The strict reading is available, explicitly.
	strict := NodePolicy{Unknown: UnknownRefuse}
	d, err = strict.Decide(PositionHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Fatal("UnknownRefuse still hosted unlabelled content")
	}
}

// TestOnlyTrustedIssuersCount is R-88.1's local reducer, one layer down.
//
// A label from somebody this node does not trust is not FALSE — it is simply not
// this node's evidence. If any signed label could drive a refusal, anyone could
// make any node drop any content by signing a claim about it.
func TestOnlyTrustedIssuersCount(t *testing.T) {
	_, trusted := signer(t)
	_, stranger := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)

	pol := NodePolicy{
		HostBlock:      []Category{CategoryMalware},
		TrustedIssuers: []ClaimantID{claimantOf(trusted)},
	}

	// A stranger's malware claim: valid, signed, and not this node's evidence.
	d, err := pol.Decide(PositionHost, labelled(t, subj, CategoryMalware, 1.0, stranger))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Fatal("an untrusted claimant caused a refusal; anyone could make any node " +
			"drop any content by signing a claim about it")
	}

	// The same claim from the trusted issuer does refuse.
	d, _ = pol.Decide(PositionHost, labelled(t, subj, CategoryMalware, 1.0, trusted))
	if d.Allow {
		t.Fatal("a trusted claimant's block was ignored")
	}
}

// TestConfidenceFloorIsApplied stops the least confident claim being a veto.
func TestConfidenceFloorIsApplied(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)
	pol := NodePolicy{
		HostBlock:      []Category{CategoryMalware},
		MinConfidence:  0.5,
		TrustedIssuers: []ClaimantID{claimantOf(priv)},
	}

	d, _ := pol.Decide(PositionHost, labelled(t, subj, CategoryMalware, 0.05, priv))
	if !d.Allow {
		t.Fatal("a 0.05-confidence claim drove a refusal; the least confident " +
			"claimant anybody trusts becomes a veto")
	}
	d, _ = pol.Decide(PositionHost, labelled(t, subj, CategoryMalware, 0.6, priv))
	if d.Allow {
		t.Fatal("a claim above the floor was ignored")
	}
}

// TestBlockBeatsAllow resolves the contradictory-config case one way.
func TestBlockBeatsAllow(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)
	pol := NodePolicy{
		HostAllow:      []Category{CategoryMalware, CategoryTechnology},
		HostBlock:      []Category{CategoryMalware},
		TrustedIssuers: []ClaimantID{claimantOf(priv)},
	}
	d, _ := pol.Decide(PositionHost, labelled(t, subj, CategoryMalware, 0.9, priv))
	if d.Allow {
		t.Fatal("a category in BOTH lists was allowed; an operator who wrote it in " +
			"the block list meant to refuse it")
	}
}

// TestAllowListIsAWhitelist checks the non-empty-allow semantics.
func TestAllowListIsAWhitelist(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)
	pol := NodePolicy{
		HostAllow:      []Category{CategoryTechnology},
		TrustedIssuers: []ClaimantID{claimantOf(priv)},
	}
	if d, _ := pol.Decide(PositionHost, labelled(t, subj, CategoryTechnology, 0.9, priv)); !d.Allow {
		t.Fatal("an allowed category was refused")
	}
	if d, _ := pol.Decide(PositionHost, labelled(t, subj, CategoryPolitical, 0.9, priv)); d.Allow {
		t.Fatal("a category outside a non-empty allow-list was hosted")
	}
	// Unlabelled content still follows the Unknown rule, not the allow-list:
	// an allow-list is about CLAIMS, and there is no claim here.
	if d, _ := pol.Decide(PositionHost, nil); !d.Allow {
		t.Fatal("an allow-list turned the unknown default into a refusal")
	}
}

// TestExitPolicyIsSeparateFromHost keeps the two positions from bleeding.
func TestExitPolicyIsSeparateFromHost(t *testing.T) {
	_, priv := signer(t)
	subj := subject(t, "acmeworks.lab.axon", 1)
	pol := NodePolicy{
		HostBlock:      []Category{CategoryMalware},
		ExitBlock:      []Category{CategoryGambling},
		TrustedIssuers: []ClaimantID{claimantOf(priv)},
	}
	if d, _ := pol.Decide(PositionExit, labelled(t, subj, CategoryMalware, 0.9, priv)); !d.Allow {
		t.Fatal("a HOST block was applied at the EXIT position")
	}
	if d, _ := pol.Decide(PositionExit, labelled(t, subj, CategoryGambling, 0.9, priv)); d.Allow {
		t.Fatal("an EXIT block was not applied at the exit position")
	}
	if d, _ := pol.Decide(PositionHost, labelled(t, subj, CategoryGambling, 0.9, priv)); !d.Allow {
		t.Fatal("an EXIT block was applied at the HOST position")
	}
}

// TestPolicyIsNeverSerialised is §87's "local and never published".
//
// A node that advertised what it refuses would be advertising what it holds,
// which is a search index for anyone looking for a host to seize.
func TestPolicyIsNeverSerialised(t *testing.T) {
	src, err := os.ReadFile("policy.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if tag := regexp.MustCompile(`(?:json|cbor|xml|yaml):"`).FindString(body); tag != "" {
		t.Errorf("§87 violated: policy.go carries a %s serialisation tag; a published "+
			"policy is a search index for whoever wants to seize a host", tag)
	}
	// METHODS, not substrings. The first version searched for "Publish" and
	// matched `PositionPublish` -- a legitimate policy position, since PUBLISH
	// is one of R-84.1's three. An audit that cannot tell a method from an
	// identifier fails on correct code and gets deleted.
	method := regexp.MustCompile(`func \([^)]*NodePolicy\) (Marshal\w*|Encode\w*|Publish\w*|Advertise\w*|WriteTo)\(`)
	if m := method.FindString(body); m != "" {
		t.Errorf("§87 violated: policy.go exposes %s; a published policy is a search "+
			"index for whoever wants to seize a host", strings.TrimSpace(m))
	}
}
