package dht

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/identity"
)

// T4.6 / E4.4: an audit of everything a storing node holds for a
// ServiceDescriptor cannot recover the domain or the service.
//
// This test uses the REAL blinding from internal/axon/identity (P1), not a
// stand-in, because the claim is about that construction. It seizes everything
// the storing node has -- the DHT key, the full wire record, every field, and
// the node's own derivation code -- and then asks whether the service identity
// or the domain name can be recovered.
//
// AND IT ASSERTS THE LIMIT TOO. §7.7 is explicit: for an on-chain-registered
// .axon domain the adversary in our model already knows the DomainIdentity,
// computes BlindedPub for each period, and confirms. The last sub-test below
// demonstrates exactly that confirmation oracle working, because a test that
// only showed the good half would be claiming a privacy property the design
// does not have.

// storedRecord is everything a storing node holds for one descriptor.
type storedRecord struct {
	Key  Key
	Wire []byte
}

// publishDescriptor builds what a service actually publishes for one replica.
func publishDescriptor(t *testing.T, svc identity.ServiceIdentity, svcPriv ed25519.PrivateKey, domain string, period uint64, replica uint8) storedRecord {
	t.Helper()

	blindedPub, err := identity.Blind(svc.Public, period)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := identity.BlindSigner(svcPriv, period)
	if err != nil {
		t.Fatal(err)
	}

	// The inner layer names the domain and the intro points. It is encrypted to
	// a subcredential derived from the UNBLINDED identity, so the storing node
	// -- which only ever sees the blinded key -- cannot derive the decryption
	// key even though it can verify the signature.
	sub := identity.Subcredential(svc.Public, blindedPub)
	inner := encryptInner(t, sub, []byte("domain="+domain+";intro=RP1,RP2,RP3"))

	d := &ServiceDescriptor{
		Ver: 1, BlindedPub: blindedPub, TimePeriod: period, ReplicaIndex: replica,
		DescSigningCert: make([]byte, 32), Revision: 1,
		IssuedAt:  testNow.Unix(),
		ExpiresAt: testNow.Add(TTLServiceDescriptor).Unix(),
		Inner:     inner,
	}
	msg, err := d.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.Sig = sig

	wire, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	key, err := d.DerivedKey()
	if err != nil {
		t.Fatal(err)
	}
	return storedRecord{Key: key, Wire: wire}
}

func encryptInner(t *testing.T, sub [32]byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(sub[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)
}

// TestStoringNodeAuditRecoversNothing is T4.6 and E4.4.
func TestStoringNodeAuditRecoversNothing(t *testing.T) {
	// identity.NewServiceIdentity keeps its private key unexported, so the pair
	// is generated directly here; the blinding under test is identical either
	// way.
	svcPub, svcPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := identity.ServiceIdentity{Public: svcPub}

	const domain = "alice.lab.axon"
	const period = uint64(19_500)

	rec := publishDescriptor(t, svc, svcPriv, domain, period, 3)

	// The storing node accepts the write -- it can authorise without knowing
	// who wrote it.
	v := &Validator{Now: fixedNow}
	if _, err := v.Validate(ClassDesc, rec.Key, rec.Wire); err != nil {
		t.Fatalf("the storing node could not authorise a legitimate write: %v", err)
	}

	// THE AUDIT. Seize everything the node holds.
	held := append(append([]byte(nil), rec.Key[:]...), rec.Wire...)

	// 1. The service's own public key must appear nowhere.
	if bytes.Contains(held, svcPub) {
		t.Fatal("E4.4 falsified: the unblinded ServiceIdentity is present in what the node holds")
	}
	// 2. Neither must the domain name, in any form the node could read.
	if bytes.Contains(held, []byte(domain)) {
		t.Fatal("E4.4 falsified: the domain name is present in cleartext")
	}
	if h := sha256.Sum256([]byte(domain)); bytes.Contains(held, h[:]) {
		t.Fatal("E4.4 falsified: the domain name hash is present")
	}
	// 3. Nor the intro points named in the inner layer.
	if bytes.Contains(held, []byte("intro=")) {
		t.Fatal("E4.4 falsified: the inner layer is not encrypted")
	}

	// 4. The blinded key IS present -- it has to be, the node verifies against
	//    it -- and it must not equal the identity it was derived from.
	decoded, err := DecodeRecord(ClassDesc, rec.Wire)
	if err != nil {
		t.Fatal(err)
	}
	d := decoded.(*ServiceDescriptor)
	if bytes.Equal(d.BlindedPub, svcPub) {
		t.Fatal("E4.4 falsified: the blinded key equals the service identity")
	}

	// 5. The node holding the record cannot derive the subcredential, because
	//    that needs the UNBLINDED public key it does not have.
	nodeGuess := identity.Subcredential(ed25519.PublicKey(d.BlindedPub), identity.BlindedPub(d.BlindedPub))
	real := identity.Subcredential(svcPub, identity.BlindedPub(d.BlindedPub))
	if nodeGuess == real {
		t.Fatal("E4.4 falsified: the subcredential is derivable from the blinded key alone")
	}

	t.Logf("T4.6: audit of %d bytes held (key + record) recovered neither the service identity nor the domain",
		len(held))
}

// TestBlindedKeyRotatesPerPeriod: a key harvested in one period is useless in
// the next, so an enumerating adversary must re-harvest continuously.
func TestBlindedKeyRotatesPerPeriod(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := identity.ServiceIdentity{Public: pub}

	a := publishDescriptor(t, svc, priv, "alice.lab.axon", 19_500, 0)
	b := publishDescriptor(t, svc, priv, "alice.lab.axon", 19_501, 0)
	if a.Key == b.Key {
		t.Fatal("the descriptor key did not change across time periods")
	}

	da, _ := DecodeRecord(ClassDesc, a.Wire)
	db, _ := DecodeRecord(ClassDesc, b.Wire)
	if bytes.Equal(da.(*ServiceDescriptor).BlindedPub, db.(*ServiceDescriptor).BlindedPub) {
		t.Fatal("the blinded key did not rotate across time periods")
	}
}

// TestKnownIdentityIsAConfirmationOracle is the LIMIT, tested rather than
// omitted.
//
// §7.7: "descriptor blinding buys privacy against parties who do not already
// know the service identity, and for an on-chain-registered .axon domain the
// adversary in our model always knows it." An adversary holding the identity
// computes the blinded key for the period, derives the DHT key, and confirms the
// service is live -- without any secret at all. This is the same property Tor
// has: knowing the address lets you compute the HSDir key.
func TestKnownIdentityIsAConfirmationOracle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := identity.ServiceIdentity{Public: pub}
	const period = uint64(19_500)

	rec := publishDescriptor(t, svc, priv, "alice.lab.axon", period, 5)

	// The adversary knows only the public identity -- from the chain -- and the
	// period. It needs nothing else.
	blinded, err := identity.Blind(pub, period)
	if err != nil {
		t.Fatal(err)
	}
	probe := &ServiceDescriptor{BlindedPub: blinded, TimePeriod: period, ReplicaIndex: 5}
	guessed, err := probe.DerivedKey()
	if err != nil {
		t.Fatal(err)
	}
	if guessed != rec.Key {
		t.Fatal("a chain observer holding the identity could NOT compute the descriptor key -- " +
			"this would contradict the documented limit, so the derivation has changed")
	}
	t.Log("T4.6 limit confirmed: an adversary holding the service's public identity computes " +
		"its descriptor key for any period and probes for liveness. Blinding does real work " +
		"only for identities never registered on-chain.")
}

// TestEightReplicasAreIndependentlyEclipsable documents what the 8 positions do:
// eclipsing a descriptor means eclipsing eight unrelated regions, and a fetcher
// picks one at random so it only needs one to survive.
func TestEightReplicasAreIndependentlyEclipsable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := identity.ServiceIdentity{Public: pub}

	keys := map[Key]struct{}{}
	for i := uint8(0); i < DescriptorReplicaPositions; i++ {
		rec := publishDescriptor(t, svc, priv, "alice.lab.axon", 19_500, i)
		if _, dup := keys[rec.Key]; dup {
			t.Fatalf("replica %d landed on an earlier position", i)
		}
		keys[rec.Key] = struct{}{}
	}
	if len(keys) != DescriptorReplicaPositions {
		t.Fatalf("%d distinct positions, want %d", len(keys), DescriptorReplicaPositions)
	}
}

func TestDescriptorLifetimeIsBounded(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := identity.ServiceIdentity{Public: pub}
	rec := publishDescriptor(t, svc, priv, "alice.lab.axon", 19_500, 0)

	// Past its lifetime it must be refused, which bounds revocation latency to
	// the descriptor lifetime -- 3 h worst case, as the threat model states.
	late := &Validator{Now: func() time.Time { return testNow.Add(TTLServiceDescriptor + time.Minute) }}
	if _, err := late.Validate(ClassDesc, rec.Key, rec.Wire); err == nil {
		t.Fatal("an expired descriptor was still accepted")
	}
}
