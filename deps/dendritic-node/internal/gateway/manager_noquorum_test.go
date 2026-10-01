package gateway

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type recordingPublisher struct {
	mu       sync.Mutex
	received []Registration
	err      error
}

func (p *recordingPublisher) PublishGatewayRegistration(_ context.Context, r Registration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.received = append(p.received, r)
	return nil
}

func (p *recordingPublisher) last(t *testing.T) Registration {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.received) == 0 {
		t.Fatal("no registration was published")
	}
	return p.received[len(p.received)-1]
}

func noQuorumManagerConfig(t *testing.T) ManagerConfig {
	t.Helper()
	return ManagerConfig{
		Addresses:            []Address{{Address: "8.8.8.8", Port: 443}},
		PublicHostname:       "gw-node.example.com",
		RegistrationValidity: 5 * time.Minute,
		Interval:             time.Minute,
		StatePath:            filepath.Join(t.TempDir(), "gateway-registration.json"),
		SoftwareVersion:      "1.0.0",
		MinimumProbes:        3,
		MinimumNetworks:      2,
		RequireProbeQuorum:   false,
	}
}

// A first gateway has no peer probe fleet to point at. It must still be able
// to start and register; the controller performs its own reachability check.
func TestManagerWithoutQuorumNeedsNoProbeURLs(t *testing.T) {
	publisher := &recordingPublisher{}
	manager, err := NewManager(newTestSigner(t), publisher, noQuorumManagerConfig(t), nil, nil)
	if err != nil {
		t.Fatalf("a gateway with no probe URLs was rejected: %v", err)
	}
	manager.verify(context.Background())

	registration := publisher.last(t)
	if registration.NodeID == "" || len(registration.Addresses) != 1 {
		t.Fatalf("unexpected registration: %+v", registration)
	}
	if registration.Addresses[0].Address != "8.8.8.8" {
		t.Fatalf("registered address is %q", registration.Addresses[0].Address)
	}
	if registration.HealthState != StateHealthy {
		t.Fatalf("registration health is %q, want %q", registration.HealthState, StateHealthy)
	}
	if registration.Signature == "" {
		t.Fatal("registration was published unsigned")
	}
}

// The quorum requirement is still enforced when it is switched on.
func TestManagerWithQuorumStillRequiresProbeURLs(t *testing.T) {
	config := noQuorumManagerConfig(t)
	config.RequireProbeQuorum = true
	if _, err := NewManager(newTestSigner(t), &recordingPublisher{}, config, nil, nil); err == nil {
		t.Fatal("quorum mode accepted a gateway with no probe URLs")
	}
}

// A registration built without a probe quorum must never pass as verified.
func TestControllerRegistrationIsNotPeerVerified(t *testing.T) {
	publisher := &recordingPublisher{}
	var reported []bool
	var mu sync.Mutex
	manager, err := NewManager(newTestSigner(t), publisher, noQuorumManagerConfig(t), nil,
		func(verified bool) {
			mu.Lock()
			defer mu.Unlock()
			reported = append(reported, verified)
		})
	if err != nil {
		t.Fatal(err)
	}
	manager.verify(context.Background())

	mu.Lock()
	defer mu.Unlock()
	for _, verified := range reported {
		if verified {
			t.Fatal("a gateway with no probe quorum reported itself as verified")
		}
	}
	registration := publisher.last(t)
	if registration.SuccessfulProbes != 0 || registration.DistinctNetworks != 0 {
		t.Fatalf("registration claims %d probes across %d networks",
			registration.SuccessfulProbes, registration.DistinctNetworks)
	}
	if len(registration.ProbeResults) != 0 {
		t.Fatal("registration carries probe results it never collected")
	}
	// The DHT validator must still refuse it: quorum records and
	// controller-only records are not interchangeable.
	if err := registration.Validate(map[string]string{}, time.Now(), 3, 2); err == nil {
		t.Fatal("a controller-only registration satisfied the quorum validator")
	}
}

// Sequence numbers must keep increasing so the controller's rollback check
// accepts successive registrations.
func TestControllerRegistrationSequenceIncreases(t *testing.T) {
	publisher := &recordingPublisher{}
	manager, err := NewManager(newTestSigner(t), publisher, noQuorumManagerConfig(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.verify(context.Background())
	manager.verify(context.Background())

	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if len(publisher.received) != 2 {
		t.Fatalf("published %d registrations, want 2", len(publisher.received))
	}
	if publisher.received[1].Sequence <= publisher.received[0].Sequence {
		t.Fatalf("sequence did not increase: %d then %d",
			publisher.received[0].Sequence, publisher.received[1].Sequence)
	}
}

// A private or non-443 address must be refused on this path too; skipping the
// probe quorum must not skip address eligibility.
func TestControllerRegistrationRejectsIneligibleAddresses(t *testing.T) {
	signer := newTestSigner(t)
	for _, address := range []Address{
		{Address: "10.0.0.5", Port: 443},
		{Address: "127.0.0.1", Port: 443},
		{Address: "8.8.8.8", Port: 8443},
	} {
		_, err := NewControllerRegistration(
			signer, []Address{address}, time.Now(), time.Minute, 1, "1.0.0",
		)
		if err == nil {
			t.Fatalf("ineligible address %v was accepted", address)
		}
	}
	if _, err := NewControllerRegistration(
		signer, nil, time.Now(), time.Minute, 1, "1.0.0",
	); err == nil {
		t.Fatal("a registration with no addresses was accepted")
	}
}

// A registration goes to the controller and to the DHT through one publisher
// that returns on the first error. A gateway without a peer probe quorum
// always fails the DHT step -- so the controller would accept and store
// sequence N while the node kept N-1, then offer N again after a restart and
// be refused with 409 forever.
//
// The sequence must therefore advance on the ATTEMPT. This is a regression
// test for a failure that is silent, permanent, and indistinguishable from a
// gateway that simply stopped working.
func TestSequenceAdvancesEvenWhenPublishingFails(t *testing.T) {
	config := noQuorumManagerConfig(t)
	failing := &recordingPublisher{err: context.DeadlineExceeded}
	manager, err := NewManager(newTestSigner(t), failing, config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.verify(context.Background())
	first := manager.Current()
	if first == nil {
		t.Fatal("a failed publish left no registration; the sequence it spent is lost")
	}

	manager.verify(context.Background())
	second := manager.Current()
	if second.Sequence <= first.Sequence {
		t.Fatalf("sequence did not advance after a failed publish: %d then %d; "+
			"the controller would refuse the retry as a replay",
			first.Sequence, second.Sequence)
	}

	// And it must survive a restart, or the next boot reuses a spent number.
	restarted, err := NewManager(newTestSigner(t), failing, config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	recovered := restarted.Current()
	if recovered == nil || recovered.Sequence < second.Sequence {
		t.Fatalf("restart did not recover the spent sequence: got %v, want >= %d",
			recovered, second.Sequence)
	}
}
