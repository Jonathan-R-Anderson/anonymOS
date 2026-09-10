package gateway

import (
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type testSigner struct {
	key crypto.PrivKey
	id  peer.ID
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{key: key, id: id}
}

func (s *testSigner) ID() string                        { return s.id.String() }
func (s *testSigner) Sign(value []byte) ([]byte, error) { return s.key.Sign(value) }
func (s *testSigner) PublicKey() ([]byte, error)        { return crypto.MarshalPublicKey(s.key.GetPublic()) }
func (s *testSigner) DHTReady() bool                    { return true }

func publicKeyString(t *testing.T, signer *testSigner) string {
	t.Helper()
	doc, err := NewIdentity(signer, "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return doc.PublicKey
}

func TestPublicAddressPolicy(t *testing.T) {
	rejected := []string{
		"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1",
		"192.0.2.1", "198.51.100.2", "203.0.113.3", "::1", "fc00::1",
		"fe80::1", "2001:db8::1", "2001::1",
	}
	for _, value := range rejected {
		if PublicAddress(netip.MustParseAddr(value)) {
			t.Errorf("restricted address %s accepted", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !PublicAddress(netip.MustParseAddr(value)) {
			t.Errorf("public address %s rejected", value)
		}
	}
}

func TestSignedQuorumRequiresDistinctAdmittedProbes(t *testing.T) {
	now := time.Now().UTC()
	candidate := newTestSigner(t)
	probes := []*testSigner{newTestSigner(t), newTestSigner(t), newTestSigner(t)}
	trusted := map[string]string{}
	var results []ProbeResult
	for index, probe := range probes {
		trusted[probe.ID()] = publicKeyString(t, probe)
		result := ProbeResult{
			RequestID: "request", CandidateNodeID: candidate.ID(),
			ProbeNodeID: probe.ID(), ProbeNetwork: []string{"as-one", "as-one", "as-two"}[index],
			TestedAddress: "8.8.8.8", TestedPort: 443,
			TCPReachable: true, TLSValid: true, IdentityValid: true,
			ChallengeValid: true, ProtocolValid: true,
			ObservedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		}
		result.Signature, _ = signJSON(probe, result)
		results = append(results, result)
	}
	if err := EvaluateQuorum(results, trusted, now, 3, 2); err != nil {
		t.Fatal(err)
	}
	duplicates := append(results, results[0])
	if err := EvaluateQuorum(duplicates[:3], trusted, now, 3, 3); err == nil {
		t.Fatal("same-network probes satisfied network diversity")
	}
	results[0].CandidateNodeID = results[0].ProbeNodeID
	if err := EvaluateQuorum(results, trusted, now, 3, 2); err == nil {
		t.Fatal("self-verification was counted")
	}
}

func TestAddressFamiliesMustMeetQuorumIndependently(t *testing.T) {
	now := time.Now().UTC()
	candidate := newTestSigner(t)
	probes := []*testSigner{newTestSigner(t), newTestSigner(t), newTestSigner(t)}
	trusted := map[string]string{}
	var results []ProbeResult
	for index, probe := range probes {
		trusted[probe.ID()] = publicKeyString(t, probe)
		for _, address := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
			if address[0] == '2' && index == 2 {
				continue // IPv6 has only two probes and must not be advertised.
			}
			result := ProbeResult{
				RequestID: "request", CandidateNodeID: candidate.ID(),
				ProbeNodeID: probe.ID(), ProbeNetwork: []string{"a", "b", "c"}[index],
				TestedAddress: address, TestedPort: 443,
				TCPReachable: true, TLSValid: true, IdentityValid: true,
				ChallengeValid: true, ProtocolValid: true,
				ObservedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
			}
			result.Signature, _ = signJSON(probe, result)
			results = append(results, result)
		}
	}
	addresses, accepted := VerifiedAddressResults(
		[]Address{
			{Address: "8.8.8.8", Port: 443},
			{Address: "2606:4700:4700::1111", Port: 443},
		},
		results, trusted, now, 3, 2,
	)
	if len(addresses) != 1 || addresses[0].Address != "8.8.8.8" {
		t.Fatalf("verified addresses = %#v", addresses)
	}
	for _, result := range accepted {
		if result.TestedAddress != "8.8.8.8" {
			t.Fatal("unverified IPv6 result entered registration")
		}
	}
	if _, err := NewRegistration(
		candidate,
		[]Address{
			{Address: "8.8.8.8", Port: 443},
			{Address: "2606:4700:4700::1111", Port: 443},
		},
		results, trusted, now, time.Minute, 1, "test", 3, 2,
	); err == nil {
		t.Fatal("registration admitted an address which did not meet quorum")
	}
}

func TestHealthTransitionsDrainBeforeRemoval(t *testing.T) {
	now := time.Now()
	state := HealthMachine{State: StateHealthy}
	state = state.Observe(false, now, 2, 2, time.Minute)
	if state.State != StateSuspect {
		t.Fatalf("first failure state = %s", state.State)
	}
	state = state.Observe(false, now.Add(time.Second), 2, 2, time.Minute)
	if state.State != StateDraining {
		t.Fatalf("threshold state = %s", state.State)
	}
	state = state.Observe(false, now.Add(62*time.Second), 2, 2, time.Minute)
	if state.State != StateRemoved {
		t.Fatalf("post-drain state = %s", state.State)
	}
	state = state.Observe(true, now.Add(63*time.Second), 2, 2, time.Minute)
	if state.State != StateRemoved {
		t.Fatalf("single recovery check restored removed node: %s", state.State)
	}
	state = state.Observe(true, now.Add(64*time.Second), 2, 2, time.Minute)
	if state.State != StateHealthy {
		t.Fatalf("recovery threshold did not restore node: %s", state.State)
	}
}

func TestDHTValidatorRejectsWrongKeyAndSelectsNewestSequence(t *testing.T) {
	now := time.Now().UTC()
	candidate := newTestSigner(t)
	probes := []*testSigner{newTestSigner(t), newTestSigner(t), newTestSigner(t)}
	trusted := map[string]string{}
	var results []ProbeResult
	for index, probe := range probes {
		trusted[probe.ID()] = publicKeyString(t, probe)
		result := ProbeResult{
			RequestID: "request", CandidateNodeID: candidate.ID(),
			ProbeNodeID: probe.ID(), ProbeNetwork: []string{"a", "b", "c"}[index],
			TestedAddress: "8.8.8.8", TestedPort: 443, TCPReachable: true,
			TLSValid: true, IdentityValid: true, ChallengeValid: true, ProtocolValid: true,
			ObservedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		}
		result.Signature, _ = signJSON(probe, result)
		results = append(results, result)
	}
	first, err := NewRegistration(candidate,
		[]Address{{Address: "8.8.8.8", Port: 443}}, results, trusted,
		now, time.Minute, 1, "test", 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Sequence = 2
	second.Signature = ""
	second.Signature, _ = signJSON(candidate, second)
	firstRaw, _ := json.Marshal(first)
	secondRaw, _ := json.Marshal(second)
	validator := DHTValidator{
		TrustedProbes: trusted, MinimumProbes: 3, MinimumNetworks: 2,
		Now: func() time.Time { return now },
	}
	if err := validator.Validate(DHTKey("another-node"), firstRaw); err == nil {
		t.Fatal("registration was accepted under another node's DHT key")
	}
	selected, err := validator.Select(DHTKey(candidate.ID()), [][]byte{firstRaw, secondRaw})
	if err != nil || selected != 1 {
		t.Fatalf("selected=%d err=%v", selected, err)
	}
}
