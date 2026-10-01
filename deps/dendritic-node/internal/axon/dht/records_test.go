package dht

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// T4.4: each record class rejects wrong signer, expired, replayed lower seq,
// oversized, and wrong key derivation.

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func rand32(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

var testNow = time.Unix(1_700_000_000, 0)

func fixedNow() time.Time { return testNow }

// newRelay builds a valid, signed RelayDescriptor.
func newRelay(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, srv []byte) *RelayDescriptor {
	t.Helper()
	r := &RelayDescriptor{
		Ver: 1, NodeIDPub: pub, RoutingEd: rand32(t), RoutingX: rand32(t),
		Addrs: []string{"198.51.100.4:4001"}, Caps: 0b111, ClaimedBW: 1 << 20,
		PrefixFamily: 0x04, PrefixBytes: []byte{198, 51, 100}, ASN: 64500,
		BondRef: rand32(t), Epoch: 42, SRVEpoch: srv, Sequence: 7,
		IssuedAt: testNow.Unix(), ExpiresAt: testNow.Add(TTLRelayDescriptor).Unix(),
	}
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRelayDescriptorValidates(t *testing.T) {
	pub, priv := keypair(t)
	srv := rand32(t)
	r := newRelay(t, priv, pub, srv)

	wire, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	key, err := r.DerivedKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassRelay, key, wire); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
}

// TestRelayRejectsWrongSigner: the key pre-image names the NodeIdentity, so
// only that identity may write.
func TestRelayRejectsWrongSigner(t *testing.T) {
	pub, _ := keypair(t)
	_, otherPriv := keypair(t)
	srv := rand32(t)

	r := newRelay(t, otherPriv, pub, srv) // signed by somebody else
	wire, _ := Encode(r)
	key, _ := r.DerivedKey()

	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassRelay, key, wire); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// TestRelayRejectsWrongKeyDerivation is the rule that makes six classes safe on
// one table: a record must derive to the key it arrived under.
func TestRelayRejectsWrongKeyDerivation(t *testing.T) {
	pub, priv := keypair(t)
	r := newRelay(t, priv, pub, rand32(t))
	wire, _ := Encode(r)

	// Some other, entirely valid key.
	wrong := MustDeriveKey(ClassRelay, []byte("somebody else"))

	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassRelay, wrong, wire); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("err = %v, want ErrWrongKey", err)
	}
}

// TestCrossClassWriteIsRefused: a relay record presented as a domain record
// cannot land, even though both are valid encodings.
func TestCrossClassWriteIsRefused(t *testing.T) {
	pub, priv := keypair(t)
	r := newRelay(t, priv, pub, rand32(t))
	wire, _ := Encode(r)
	key, _ := r.DerivedKey()

	v := &Validator{Now: fixedNow, DomainAuthorised: func(_, _, _, _ []byte) error { return nil }}
	if _, err := v.Validate(ClassDomain, key, wire); err == nil {
		t.Fatal("a relay record was accepted into the domain keyspace")
	}
}

func TestRelayRejectsExpiredAndOverLongTTL(t *testing.T) {
	pub, priv := keypair(t)
	v := &Validator{Now: fixedNow}

	expired := newRelay(t, priv, pub, rand32(t))
	expired.IssuedAt = testNow.Add(-4 * time.Hour).Unix()
	expired.ExpiresAt = testNow.Add(-time.Hour).Unix()
	if err := expired.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wire, _ := Encode(expired)
	key, _ := expired.DerivedKey()
	if _, err := v.Validate(ClassRelay, key, wire); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}

	// A descriptor claiming a lifetime longer than its class permits would
	// otherwise pin a stale relay in the table past the point the network can
	// notice it left.
	long := newRelay(t, priv, pub, rand32(t))
	long.ExpiresAt = testNow.Add(TTLRelayDescriptor + time.Hour).Unix()
	if err := long.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wire, _ = Encode(long)
	key, _ = long.DerivedKey()
	if _, err := v.Validate(ClassRelay, key, wire); !errors.Is(err, ErrOverLongTTL) {
		t.Fatalf("err = %v, want ErrOverLongTTL", err)
	}
}

func TestOversizeRejectedBeforeDecoding(t *testing.T) {
	v := &Validator{Now: fixedNow}
	huge := bytes.Repeat([]byte{0x00}, MaxIntroPoint+1)
	if _, err := v.Validate(ClassIntro, Key{}, huge); !errors.Is(err, ErrOversize) {
		t.Fatalf("err = %v, want ErrOversize", err)
	}
}

// TestSeqFloorRejectsReplayedLowerSeq is §7.6's rollback guard.
func TestSeqFloorRejectsReplayedLowerSeq(t *testing.T) {
	pub, priv := keypair(t)
	srv := rand32(t)

	newSeq := newRelay(t, priv, pub, srv)
	newSeq.Sequence = 9
	if err := newSeq.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wireNew, _ := Encode(newSeq)
	key, _ := newSeq.DerivedKey()

	floor := NewSeqFloor(fixedNow)
	v := &Validator{Now: fixedNow, Floor: floor}

	if _, err := v.Validate(ClassRelay, key, wireNew); err != nil {
		t.Fatal(err)
	}
	floor.Record(key, newSeq.Sequence, newSeq.Expiry())

	old := newRelay(t, priv, pub, srv)
	old.Sequence = 3
	if err := old.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wireOld, _ := Encode(old)
	if _, err := v.Validate(ClassRelay, key, wireOld); !errors.Is(err, ErrReplayedSeq) {
		t.Fatalf("err = %v, want ErrReplayedSeq", err)
	}
}

// TestNoFloorMeansNoProtection documents the residual §7.6 names rather than
// hiding it: a node that has never seen the key accepts the rollback.
func TestNoFloorMeansNoProtection(t *testing.T) {
	pub, priv := keypair(t)
	srv := rand32(t)
	old := newRelay(t, priv, pub, srv)
	old.Sequence = 1
	if err := old.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wire, _ := Encode(old)
	key, _ := old.DerivedKey()

	fresh := &Validator{Now: fixedNow, Floor: NewSeqFloor(fixedNow)}
	if _, err := fresh.Validate(ClassRelay, key, wire); err != nil {
		t.Fatalf("a fresh node rejected a record it has no floor for: %v", err)
	}
}

// TestBetterIsDeterministicOnTies is §7.6 rule 3. Two honest replicas must
// converge WITHOUT talking to each other.
func TestBetterIsDeterministicOnTies(t *testing.T) {
	a := []byte("record-a")
	b := []byte("record-b")

	ab := Better(5, a, 5, b)
	ba := Better(5, b, 5, a)
	if ab == ba {
		t.Fatal("the tiebreak is not antisymmetric; replicas would oscillate")
	}
	// And it must not depend on argument order across calls.
	for i := 0; i < 100; i++ {
		if Better(5, a, 5, b) != ab {
			t.Fatal("the tiebreak is not deterministic across calls")
		}
	}
	// Higher seq always wins regardless of digest.
	if !Better(6, b, 5, a) {
		t.Fatal("higher seq did not win")
	}
}

// TestServiceDescriptorAuthorisesWithoutIdentity is T4.6/E4.4 in its unit form:
// the storing node verifies against the pubkey from its OWN key pre-image.
func TestServiceDescriptorAuthorisesWithoutIdentity(t *testing.T) {
	blindedPub, blindedPriv := keypair(t)

	d := &ServiceDescriptor{
		Ver: 1, BlindedPub: blindedPub, TimePeriod: 900, ReplicaIndex: 3,
		DescSigningCert: rand32(t), Revision: 4,
		IssuedAt:  testNow.Unix(),
		ExpiresAt: testNow.Add(TTLServiceDescriptor).Unix(),
		Inner:     bytes.Repeat([]byte{0xAB}, 256),
	}
	if err := d.Sign(blindedPriv); err != nil {
		t.Fatal(err)
	}
	wire, _ := Encode(d)
	key, _ := d.DerivedKey()

	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassDesc, key, wire); err != nil {
		t.Fatalf("blinded descriptor rejected: %v", err)
	}

	// A replica index outside 0..7 must not derive a key at all.
	d.ReplicaIndex = DescriptorReplicaPositions
	if _, err := d.DerivedKey(); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("out-of-range replica index derived a key: %v", err)
	}
}

// TestEightReplicaPositionsAreUnrelated: eclipsing a descriptor means eclipsing
// eight unrelated keyspace regions.
func TestEightReplicaPositionsAreUnrelated(t *testing.T) {
	blindedPub, _ := keypair(t)
	seen := map[Key]struct{}{}
	var keys []Key
	for i := uint8(0); i < DescriptorReplicaPositions; i++ {
		d := &ServiceDescriptor{BlindedPub: blindedPub, TimePeriod: 900, ReplicaIndex: i}
		k, err := d.DerivedKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[k]; dup {
			t.Fatalf("replica %d collided with an earlier position", i)
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	// "Unrelated" is testable as: no two positions share an implausibly long
	// prefix. Eight random 256-bit points sharing >32 bits would be a derivation
	// bug, not luck.
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if cpl := CommonPrefixLen(keys[i], keys[j]); cpl > 32 {
				t.Fatalf("replicas %d and %d share %d leading bits", i, j, cpl)
			}
		}
	}
}

// TestSnapshotNeedsChainNotSignature: the signature identifies the publisher and
// is explicitly not the authorisation.
func TestSnapshotNeedsChainNotSignature(t *testing.T) {
	pub, priv := keypair(t)
	s := &RegistrySnapshot{
		Ver: 1, ChainID: 1, SnapshotEpoch: 12, SnapshotRoot: rand32(t),
		EthBlockNumber: 21_000_000, EthStateRoot: rand32(t),
		AnchorTxProof: rand32(t), BodyCID: rand32(t), PublisherPub: pub,
		IssuedAt:  testNow.Unix(),
		ExpiresAt: testNow.Add(TTLRegistrySnapshot).Unix(),
	}
	if err := s.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wire, _ := Encode(s)
	key, _ := s.DerivedKey()

	// A node with no chain verifier must REFUSE, not accept. Otherwise "anyone
	// may publish" becomes "anyone may publish anything".
	noChain := &Validator{Now: fixedNow}
	if _, err := noChain.Validate(ClassSnapshot, key, wire); err == nil {
		t.Fatal("a snapshot was accepted with no chain verification")
	}

	withChain := &Validator{Now: fixedNow, Chain: okChain{}}
	if _, err := withChain.Validate(ClassSnapshot, key, wire); err != nil {
		t.Fatalf("a chain-verified snapshot was rejected: %v", err)
	}

	// A verifier that rejects must be decisive even with a perfect signature.
	badChain := &Validator{Now: fixedNow, Chain: failChain{}}
	if _, err := badChain.Validate(ClassSnapshot, key, wire); err == nil {
		t.Fatal("a snapshot failing chain verification was accepted on its signature")
	}
}

type okChain struct{}

func (okChain) VerifySnapshot(*RegistrySnapshot) error { return nil }

type failChain struct{}

func (failChain) VerifySnapshot(*RegistrySnapshot) error {
	return errors.New("chain proof does not verify")
}

// TestDomainRecordNeedsRegistryBinding: a valid signature over a name claim is
// not authorisation, because any keypair can sign any claim.
func TestDomainRecordNeedsRegistryBinding(t *testing.T) {
	pub, priv := keypair(t)
	d := &DomainRecord{
		Ver: 1, NameHash: rand32(t), DomainIDPub: pub,
		Records: []byte("delegations"), SnapshotRoot: rand32(t),
		InclusionProof: rand32(t), SRVEpoch: rand32(t), Sequence: 2,
		IssuedAt:  testNow.Unix(),
		ExpiresAt: testNow.Add(TTLDomainRecord).Unix(),
	}
	if err := d.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wire, _ := Encode(d)
	key, _ := d.DerivedKey()

	if _, err := (&Validator{Now: fixedNow}).Validate(ClassDomain, key, wire); err == nil {
		t.Fatal("a self-signed name claim was accepted with no registry binding")
	}

	refuse := &Validator{Now: fixedNow, DomainAuthorised: func(_, _, _, _ []byte) error {
		return errors.New("not bound in the snapshot")
	}}
	if _, err := refuse.Validate(ClassDomain, key, wire); err == nil {
		t.Fatal("a name claim the registry rejects was accepted")
	}

	accept := &Validator{Now: fixedNow, DomainAuthorised: func(_, _, _, _ []byte) error { return nil }}
	if _, err := accept.Validate(ClassDomain, key, wire); err != nil {
		t.Fatalf("a registry-bound name claim was rejected: %v", err)
	}
}

// TestNonCanonicalEncodingRefused: accepting it would mean sender and receiver
// compute different digests and break §7.6's tie differently.
func TestNonCanonicalEncodingRefused(t *testing.T) {
	pub, priv := keypair(t)
	i := &IntroPointRecord{
		Ver: 1, RoutingID: pub, SRVEpoch: rand32(t), PoWSeed: rand32(t),
		PoWDifficulty: 18, TokenIssuerPub: rand32(t), CapacityHint: 100,
		Sequence:  1,
		IssuedAt:  testNow.Unix(),
		ExpiresAt: testNow.Add(TTLIntroPoint).Unix(),
	}
	if err := i.Sign(priv); err != nil {
		t.Fatal(err)
	}
	wire, _ := Encode(i)
	key, _ := i.DerivedKey()

	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassIntro, key, wire); err != nil {
		t.Fatalf("valid intro record rejected: %v", err)
	}

	// Append trailing bytes: no longer the canonical encoding of itself.
	tampered := append(append([]byte(nil), wire...), 0x00)
	if _, err := v.Validate(ClassIntro, key, tampered); err == nil {
		t.Fatal("a non-canonical encoding was accepted")
	}
}
