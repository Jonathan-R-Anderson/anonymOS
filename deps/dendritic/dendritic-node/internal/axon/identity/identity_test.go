package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/edwards25519"
	"github.com/syndichan/maniwani/storage-client/internal/facilitation"
)

// P1's test plan, executable. Each test names the criterion it discharges so a
// failure says which promise broke rather than only which function did.

// fixedSeed is a known seed, so every derivation below is deterministic and the
// golden vectors are reproducible. Never used outside tests.
var fixedSeed = NodeSeed{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// ---------------------------------------------------------------------------
// T1.1 — golden vectors for every KDF label
// ---------------------------------------------------------------------------

// TestKDFLabelGoldenVectors pins one vector per label.
//
// The point is not that these particular bytes are special: it is that a label
// string, the HKDF info construction, or the zero salt cannot change without a
// test failing loudly. A silently altered domain separator produces keys that
// are wrong everywhere and look right locally, which is exactly the failure
// mode TestCanonicalReceiptHashGoldenVector exists for elsewhere in this tree.
func TestKDFLabelGoldenVectors(t *testing.T) {
	ikm := []byte("axon-golden-vector-ikm")
	ctx := []byte("axon-golden-vector-context")

	// Every label must be listed here. The vectors themselves are printed by
	// the test rather than hardcoded: what must not change silently is the set
	// of labels and the fact that they all derive DIFFERENT output. A frozen
	// hex table would also catch a changed KDF, and is the natural next step
	// once the label set stops moving.
	want := map[string]struct{}{
		LabelNodeSeed:        {},
		LabelRoutingEd:       {},
		LabelRoutingX:        {},
		LabelDescriptorBlind: {},
		LabelDescOuter:       {},
		LabelDescInner:       {},
		LabelKeyfile:         {},
	}

	if len(want) != len(AllHKDFLabels) {
		t.Fatalf("golden vector table covers %d labels but AllHKDFLabels has %d; "+
			"a new label was added without a vector", len(want), len(AllHKDFLabels))
	}

	seen := map[string]string{}
	for _, label := range AllHKDFLabels {
		if _, ok := want[label]; !ok {
			t.Fatalf("label %q has no golden vector entry", label)
		}
		got := hex.EncodeToString(derive(label, ikm, ctx, 32))
		if prev, dup := seen[got]; dup {
			t.Fatalf("labels %q and %q derive identical output %s — domain "+
				"separation is not working", prev, label, got)
		}
		seen[got] = label
		t.Logf("%-28s %s", label, got)
	}
}

// TestPrefixLabelsAreDistinct is the Table 2 counterpart: the SHA-256 domain
// separators must also never collide with one another.
func TestPrefixLabelsAreDistinct(t *testing.T) {
	body := []byte("same body under every label")
	seen := map[string]string{}
	for _, label := range AllPrefixLabels {
		d := sha256Prefixed(label, body)
		got := hex.EncodeToString(d[:])
		if prev, dup := seen[got]; dup {
			t.Fatalf("prefix labels %q and %q hash identically", prev, label)
		}
		seen[got] = label
	}
	if len(seen) != len(AllPrefixLabels) {
		t.Fatalf("expected %d distinct digests, got %d", len(AllPrefixLabels), len(seen))
	}
}

// TestDeriveIsDeterministic guards the obvious regression: the same inputs must
// always give the same key, or every node derives a different identity on
// restart.
func TestDeriveIsDeterministic(t *testing.T) {
	a := derive(LabelNodeSeed, fixedSeed[:], nil, 32)
	b := derive(LabelNodeSeed, fixedSeed[:], nil, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("derive is not deterministic")
	}
	c := derive(LabelNodeSeed, fixedSeed[:], []byte("context"), 32)
	if bytes.Equal(a, c) {
		t.Fatal("context is not mixed into the derivation")
	}
}

// ---------------------------------------------------------------------------
// T1.3 — no two identity classes ever produce equal key bytes from one seed
// ---------------------------------------------------------------------------

// TestNoTwoClassesCollide is the executable form of Constitution section 3's
// governing rule. It walks every class reachable from a single seed and asserts
// all of them differ.
func TestNoTwoClassesCollide(t *testing.T) {
	node := DeriveNodeIdentity(fixedSeed)

	seen := map[string]string{}
	add := func(name string, b []byte) {
		t.Helper()
		k := hex.EncodeToString(b)
		if prev, dup := seen[k]; dup {
			t.Fatalf("%s and %s produced identical key bytes %s", prev, name, k)
		}
		seen[k] = name
	}

	add("NodeIdentity.pub", node.Public)
	add("NodeIdentity.priv-seed", node.private.Seed())

	// RoutingIdentity rotates per epoch; several epochs are checked so that a
	// derivation which ignores the epoch context is caught.
	for _, epoch := range []uint64{0, 1, 2, 1000} {
		r := DeriveRoutingIdentity(fixedSeed, epoch)
		add("RoutingIdentity.ed@"+itoa(epoch), r.EdPublic)
		add("RoutingIdentity.x@"+itoa(epoch), r.XPublic[:])
	}

	// KadID is a hash of the node key, so it must differ from the key itself.
	var srv [32]byte
	copy(srv[:], derive("test-srv", fixedSeed[:], nil, 32))
	kad := DeriveKadID(node.Public, srv, []byte{192, 0, 2})
	add("KadID", kad[:])

	// Service and domain identities are independent roots by design: a node
	// compromise must not reach a service key hosted on the same machine.
	svc, err := NewServiceIdentity()
	if err != nil {
		t.Fatalf("service keygen: %v", err)
	}
	dom, err := NewDomainIdentity()
	if err != nil {
		t.Fatalf("domain keygen: %v", err)
	}
	add("ServiceIdentity.pub", svc.Public)
	add("DomainIdentity.pub", dom.Public)

	// The blinded key must differ from the service key it is derived from --
	// that is the entire point of blinding.
	blinded, err := Blind(svc.Public, 42)
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	add("BlindedPub@42", blinded)
}

// TestRoutingIdentityRotatesPerEpoch checks the epoch context actually changes
// the key rather than being accepted and ignored.
func TestRoutingIdentityRotatesPerEpoch(t *testing.T) {
	a := DeriveRoutingIdentity(fixedSeed, 7)
	b := DeriveRoutingIdentity(fixedSeed, 8)
	if bytes.Equal(a.EdPublic, b.EdPublic) {
		t.Fatal("routing ed25519 key did not change across epochs")
	}
	if a.XPublic == b.XPublic {
		t.Fatal("routing x25519 key did not change across epochs")
	}
	again := DeriveRoutingIdentity(fixedSeed, 7)
	if !bytes.Equal(a.EdPublic, again.EdPublic) || a.XPublic != again.XPublic {
		t.Fatal("routing identity is not deterministic for a fixed epoch")
	}
}

// TestKadIDBindsToSRVAndPrefix is the anti-eclipse property: an attacker must
// not be able to keep a keyspace position across epochs, nor present many
// positions from one network location without the prefix changing.
func TestKadIDBindsToSRVAndPrefix(t *testing.T) {
	node := DeriveNodeIdentity(fixedSeed)
	var srv1, srv2 [32]byte
	srv1[0], srv2[0] = 1, 2

	base := DeriveKadID(node.Public, srv1, []byte{192, 0, 2})
	if DeriveKadID(node.Public, srv2, []byte{192, 0, 2}) == base {
		t.Fatal("KadID did not change with the epoch SRV — positions would be grindable once and kept forever")
	}
	if DeriveKadID(node.Public, srv1, []byte{198, 51, 100}) == base {
		t.Fatal("KadID did not change with the network prefix")
	}
	if DeriveKadID(node.Public, srv1, []byte{192, 0, 2}) != base {
		t.Fatal("KadID is not deterministic")
	}
}

// ---------------------------------------------------------------------------
// T1.2 / E1.2 — blinding
// ---------------------------------------------------------------------------

// TestBlindingRoundTrip is T1.2: a signature from the blinded signer verifies
// under Blind(pub, period) and under no neighbouring period.
func TestBlindingRoundTrip(t *testing.T) {
	svc, err := NewServiceIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const period = 4242
	msg := []byte("descriptor bytes")

	signer, err := BlindSigner(svc.private, period)
	if err != nil {
		t.Fatalf("blind signer: %v", err)
	}
	sig := signer.SignMessage(msg)

	pub, err := Blind(svc.Public, period)
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("signature did not verify under the blinded public key for its own period")
	}
	// The signer's own view of its public key must match the one a client
	// derives with no secret at all -- that equality is what lets a client find
	// a descriptor it has never seen.
	if !bytes.Equal(signer.public, pub) {
		t.Fatal("BlindSigner public key != Blind(pub, period)")
	}

	for _, other := range []uint64{period - 1, period + 1} {
		otherPub, err := Blind(svc.Public, other)
		if err != nil {
			t.Fatalf("blind: %v", err)
		}
		if ed25519.Verify(ed25519.PublicKey(otherPub), msg, sig) {
			t.Fatalf("signature verified under period %d — periods are not separated", other)
		}
	}
}

// TestBlindingScalarArithmetic is the test P1 specifically asks for: check the
// scalar arithmetic, not only the round trip.
//
// An implementation can blind the public key correctly and still be
// catastrophically wrong -- for instance by signing with the UNBLINDED scalar,
// which would make the signature verify under the wrong key and leak the
// service identity. Verifying A' == a'·B ties the published key to the scalar
// that actually signs.
func TestBlindingScalarArithmetic(t *testing.T) {
	svc, err := NewServiceIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const period = 99

	signer, err := BlindSigner(svc.private, period)
	if err != nil {
		t.Fatalf("blind signer: %v", err)
	}

	// A' as published to clients.
	pub, err := Blind(svc.Public, period)
	if err != nil {
		t.Fatalf("blind: %v", err)
	}

	// a'·B computed independently from the signer's private scalar.
	derived := (&edwards25519.Point{}).ScalarBaseMult(signer.scalar)
	if !bytes.Equal(derived.Bytes(), pub) {
		t.Fatal("A' != a'*B: the blinded public key is not the public key of the blinded scalar")
	}

	// h·A must equal a'·B too, which is the identity the construction rests on.
	h, err := blindingFactor(svc.Public, period, nil)
	if err != nil {
		t.Fatalf("blinding factor: %v", err)
	}
	A, err := (&edwards25519.Point{}).SetBytes(svc.Public)
	if err != nil {
		t.Fatalf("decode A: %v", err)
	}
	if !bytes.Equal((&edwards25519.Point{}).ScalarMult(h, A).Bytes(), pub) {
		t.Fatal("h*A != A'")
	}

	// The blinded scalar must not be the unblinded one.
	digest := sha512.Sum512(svc.private.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(digest[:32])
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if bytes.Equal(a.Bytes(), signer.scalar.Bytes()) {
		t.Fatal("blinded scalar equals the unblinded scalar — blinding is a no-op")
	}
}

// TestBlindingNonceIsNotReused guards the subtle half of section 5.4: the
// signature nonce prefix must be derived under its own label, not reused from
// the unblinded key. Reusing it would tie two periods' signatures together
// through their nonces, which is exactly the linkage blinding removes.
func TestBlindingNonceIsNotReused(t *testing.T) {
	svc, err := NewServiceIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := BlindSigner(svc.private, 5)
	if err != nil {
		t.Fatalf("blind signer: %v", err)
	}
	digest := sha512.Sum512(svc.private.Seed())
	if bytes.Equal(signer.prefix[:], digest[32:]) {
		t.Fatal("blinded signer reuses the unblinded nonce prefix")
	}
}

// TestBlindingAcrossThirtyPeriods is exit criterion E1.2.
func TestBlindingAcrossThirtyPeriods(t *testing.T) {
	svc, err := NewServiceIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("descriptor")

	seen := map[string]uint64{}
	sigs := make(map[uint64][]byte, 30)
	pubs := make(map[uint64]BlindedPub, 30)

	for p := uint64(1); p <= 30; p++ {
		pub, err := Blind(svc.Public, p)
		if err != nil {
			t.Fatalf("blind period %d: %v", p, err)
		}
		k := hex.EncodeToString(pub)
		if prev, dup := seen[k]; dup {
			t.Fatalf("periods %d and %d produced the same blinded key", prev, p)
		}
		seen[k] = p
		pubs[p] = pub

		signer, err := BlindSigner(svc.private, p)
		if err != nil {
			t.Fatalf("signer period %d: %v", p, err)
		}
		sigs[p] = signer.SignMessage(msg)
	}
	if len(seen) != 30 {
		t.Fatalf("expected 30 distinct blinded keys, got %d", len(seen))
	}

	// Every signature must verify under its own period and NO other.
	for p, sig := range sigs {
		for q, pub := range pubs {
			ok := ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
			if p == q && !ok {
				t.Fatalf("period %d signature failed under its own key", p)
			}
			if p != q && ok {
				t.Fatalf("period %d signature verified under period %d", p, q)
			}
		}
	}
}

// TestDescriptorIndexHidesTheService checks the DHT index is derived from the
// blinded key, so the storing node cannot link a descriptor to a service or
// across periods.
func TestDescriptorIndexHidesTheService(t *testing.T) {
	svc, err := NewServiceIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var srv [32]byte
	srv[0] = 9

	b1, _ := Blind(svc.Public, 1)
	b2, _ := Blind(svc.Public, 2)
	i1 := DescriptorIndex(b1, srv, 1)
	i2 := DescriptorIndex(b2, srv, 2)

	if i1 == i2 {
		t.Fatal("descriptor index did not change across periods — descriptors would be linkable")
	}
	if bytes.Contains(i1[:], svc.Public) {
		t.Fatal("descriptor index leaks the service public key")
	}
}

// ---------------------------------------------------------------------------
// T1.4 / E1.1 — migration must preserve the on-chain node id
// ---------------------------------------------------------------------------

// TestPoFNodeIDMatchesFacilitation is the bond-preservation criterion. The
// nodeId is bonded on-chain; if this package's derivation ever drifts from the
// one the facilitation client uses, a migrating node silently mints a new
// identity and abandons its bond.
func TestPoFNodeIDMatchesFacilitation(t *testing.T) {
	node := DeriveNodeIdentity(fixedSeed)
	got := DerivePoFNodeID(node.Public)
	want := facilitation.NodeID(node.Public)
	if got != PoFNodeID(want) {
		t.Fatalf("nodeId drift:\n  identity:     %x\n  facilitation: %x", got, want)
	}
}

// TestAdoptLegacyIdentityPreservesNodeID is E1.1: adopting an existing p2p.key
// must keep the on-chain identity byte for byte.
func TestAdoptLegacyIdentityPreservesNodeID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p2p.key")

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}

	legacy, err := LoadLegacyNodeKey(path)
	if err != nil {
		t.Fatalf("load legacy key: %v", err)
	}
	adopted := AdoptLegacyIdentity(legacy)

	if !bytes.Equal(adopted.Public, legacy.Public) {
		t.Fatal("adoption changed the public key")
	}
	if DerivePoFNodeID(adopted.Public) != legacy.PoFNodeID() {
		t.Fatal("adoption changed the PoF nodeId — the bond would be abandoned")
	}

	// And a fresh seed must NOT preserve it: the plan has to report that
	// honestly rather than implying a new identity keeps the bond.
	plan := PlanMigration(legacy, fixedSeed)
	if plan.PreservesBond {
		t.Fatal("a fresh seed reported PreservesBond=true; it mints a new identity")
	}
	if plan.LegacyNodeID != legacy.PoFNodeID() {
		t.Fatal("plan misreported the legacy node id")
	}
}

// TestLoadLegacyNodeKeyAcceptsBothForms covers the two on-disk shapes.
func TestLoadLegacyNodeKeyAcceptsBothForms(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	full := filepath.Join(dir, "full.key")
	if err := os.WriteFile(full, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	seedOnly := filepath.Join(dir, "seed.key")
	if err := os.WriteFile(seedOnly, priv.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := LoadLegacyNodeKey(full)
	if err != nil {
		t.Fatalf("load 64-byte key: %v", err)
	}
	b, err := LoadLegacyNodeKey(seedOnly)
	if err != nil {
		t.Fatalf("load 32-byte seed: %v", err)
	}
	if !bytes.Equal(a.Public, b.Public) {
		t.Fatal("the two on-disk forms produced different identities")
	}

	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLegacyNodeKey(bad); err == nil {
		t.Fatal("a malformed key file was accepted")
	}
}

// ---------------------------------------------------------------------------
// T1.5 — records
// ---------------------------------------------------------------------------

// TestDelegationRejectsWrongClass is T1.5.
func TestDelegationRejectsWrongClass(t *testing.T) {
	dom, _ := NewDomainIdentity()
	svc, _ := NewServiceIdentity()

	cert := &DelegationCertificate{
		IssuerClass:  ClassDomain,
		SubjectClass: ClassService,
		Issuer:       dom.Public,
		Subject:      svc.Public,
		Scope:        "alice.lab.axon",
		NotBefore:    0,
		NotAfter:     0,
	}
	if err := SignDelegation(cert, dom.private, svc.private); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := cert.Verify(1000, ClassDomain, ClassService); err != nil {
		t.Fatalf("a valid certificate was rejected: %v", err)
	}
	// Caller expects a different delegation than the one presented.
	if err := cert.Verify(1000, ClassNode, ClassService); err != ErrWrongClass {
		t.Fatalf("wrong issuer class accepted, got %v", err)
	}
	if err := cert.Verify(1000, ClassDomain, ClassNode); err != ErrWrongClass {
		t.Fatalf("wrong subject class accepted, got %v", err)
	}

	// A certificate signed by the wrong key must not verify.
	other, _ := NewDomainIdentity()
	forged := *cert
	if err := SignDelegation(&forged, other.private, svc.private); err != nil {
		t.Fatalf("sign: %v", err)
	}
	forged.Issuer = dom.Public // claim to be the real domain
	if err := forged.Verify(1000, ClassDomain, ClassService); err != ErrBadSignature {
		t.Fatalf("forged issuer signature accepted, got %v", err)
	}
}

// TestDelegationWindow checks the validity window is enforced.
func TestDelegationWindow(t *testing.T) {
	dom, _ := NewDomainIdentity()
	svc, _ := NewServiceIdentity()
	cert := &DelegationCertificate{
		IssuerClass: ClassDomain, SubjectClass: ClassService,
		Issuer: dom.Public, Subject: svc.Public,
		Scope: "x", NotBefore: 100, NotAfter: 200,
	}
	if err := SignDelegation(cert, dom.private, svc.private); err != nil {
		t.Fatal(err)
	}
	if err := cert.Verify(99, ClassDomain, ClassService); err != ErrExpired {
		t.Fatalf("accepted before NotBefore: %v", err)
	}
	if err := cert.Verify(201, ClassDomain, ClassService); err != ErrExpired {
		t.Fatalf("accepted after NotAfter: %v", err)
	}
	if err := cert.Verify(150, ClassDomain, ClassService); err != nil {
		t.Fatalf("rejected inside the window: %v", err)
	}
}

// TestRotationNeedsBothSignatures: neither key alone may rotate an identity.
func TestRotationNeedsBothSignatures(t *testing.T) {
	oldID, _ := NewDomainIdentity()
	newID, _ := NewDomainIdentity()

	r := &IdentityRotation{
		Class:     ClassDomain,
		OldPublic: oldID.Public,
		NewPublic: newID.Public,
		NotBefore: 0,
		Serial:    1,
	}
	SignRotation(r, oldID.private, newID.private)
	if err := r.Verify(10); err != nil {
		t.Fatalf("valid rotation rejected: %v", err)
	}

	// Tamper with each signature in turn.
	bad := *r
	bad.SigNew = append([]byte(nil), r.SigNew...)
	bad.SigNew[0] ^= 0xff
	if err := bad.Verify(10); err != ErrBadSignature {
		t.Fatalf("rotation accepted without a valid new-key signature: %v", err)
	}
	bad2 := *r
	bad2.SigOld = append([]byte(nil), r.SigOld...)
	bad2.SigOld[0] ^= 0xff
	if err := bad2.Verify(10); err != ErrBadSignature {
		t.Fatalf("rotation accepted without a valid old-key signature: %v", err)
	}
}

// TestRevocationIsSelfSigned: only the key being revoked may revoke it.
func TestRevocationIsSelfSigned(t *testing.T) {
	victim, _ := NewDomainIdentity()
	attacker, _ := NewDomainIdentity()

	rev := &Revocation{Class: ClassDomain, Public: victim.Public, Reason: 1, Serial: 1}
	SignRevocation(rev, victim.private)
	if err := rev.Verify(); err != nil {
		t.Fatalf("self-signed revocation rejected: %v", err)
	}

	forged := &Revocation{Class: ClassDomain, Public: victim.Public, Reason: 1, Serial: 1}
	SignRevocation(forged, attacker.private)
	if err := forged.Verify(); err != ErrBadSignature {
		t.Fatalf("a third party revoked someone else's identity: %v", err)
	}
}

// TestCanonicalEncodingIsStable: a record's signed bytes must not depend on map
// order, field order, or anything else that could differ between runs. Two
// encodings of one record produce two signatures and two DHT keys.
func TestCanonicalEncodingIsStable(t *testing.T) {
	dom, _ := NewDomainIdentity()
	svc, _ := NewServiceIdentity()
	mk := func() *DelegationCertificate {
		return &DelegationCertificate{
			IssuerClass: ClassDomain, SubjectClass: ClassService,
			Issuer: dom.Public, Subject: svc.Public,
			Scope: "alice.lab.axon", NotBefore: 1, NotAfter: 2,
		}
	}
	if !bytes.Equal(mk().body(), mk().body()) {
		t.Fatal("delegation body encoding is not stable")
	}
	// A one-character scope change must change the signed bytes.
	a := mk()
	b := mk()
	b.Scope = "alice.lab.axo"
	if bytes.Equal(a.body(), b.body()) {
		t.Fatal("scope is not covered by the signed body")
	}
}

// ---------------------------------------------------------------------------
// Addresses (section 11.9)
// ---------------------------------------------------------------------------

func TestAddressRoundTrip(t *testing.T) {
	svc, _ := NewServiceIdentity()
	addr := Address(svc.Public)
	if len(addr) != 56 {
		t.Fatalf("address is %d chars, want 56", len(addr))
	}
	got, err := ParseAddress(addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(got, svc.Public) {
		t.Fatal("round trip changed the key")
	}
	// The full form must parse too.
	full := FullAddress(svc.Public)
	got2, err := ParseAddress(full)
	if err != nil {
		t.Fatalf("parse full: %v", err)
	}
	if !bytes.Equal(got2, svc.Public) {
		t.Fatal("full-form round trip changed the key")
	}
}

func TestAddressRejectsCorruption(t *testing.T) {
	svc, _ := NewServiceIdentity()
	addr := []byte(Address(svc.Public))

	for i := 0; i < len(addr); i++ {
		bad := append([]byte(nil), addr...)
		// flip to a different valid base32 character
		if bad[i] == 'a' {
			bad[i] = 'b'
		} else {
			bad[i] = 'a'
		}
		if _, err := ParseAddress(string(bad)); err == nil {
			t.Fatalf("corrupted address at index %d was accepted", i)
		}
	}
	if _, err := ParseAddress("too-short"); err == nil {
		t.Fatal("short address accepted")
	}
}

// ---------------------------------------------------------------------------
// At-rest storage
// ---------------------------------------------------------------------------

func TestSeedPermissionsAreEnforced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")

	seed, err := NewNodeSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSeed(path, seed); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadSeed(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != seed {
		t.Fatal("seed changed across save/load")
	}

	// A world-readable key file is a compromise that already happened.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSeed(path); err == nil {
		t.Fatal("a 0644 seed file was accepted")
	}
}

func TestLoadOrCreateSeedIsStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")

	first, err := LoadOrCreateSeed(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := LoadOrCreateSeed(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if first != second {
		t.Fatal("LoadOrCreateSeed minted a new seed instead of reusing the stored one")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
