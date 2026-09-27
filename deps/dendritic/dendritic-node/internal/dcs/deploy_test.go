package dcs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// testIdentity is a real Ed25519 libp2p identity, so envelope signing and
// verification exercise the actual crypto path, not a stub.
type testIdentity struct {
	key crypto.PrivKey
	id  peer.ID
}

func newIdentity(t *testing.T) *testIdentity {
	t.Helper()
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdentity{key: key, id: id}
}

func (i *testIdentity) ID() string                    { return i.id.String() }
func (i *testIdentity) Sign(m []byte) ([]byte, error) { return i.key.Sign(m) }
func (i *testIdentity) PublicKey() ([]byte, error)    { return crypto.MarshalPublicKey(i.key.GetPublic()) }

// fakeRuntime records what the agent asked Docker to do.
type fakeRuntime struct {
	created   []ContainerSpec
	started   []string
	removed   []string
	failStart bool
}

func (r *fakeRuntime) Create(_ context.Context, spec ContainerSpec) (string, error) {
	r.created = append(r.created, spec)
	return "ctr-" + spec.Name, nil
}
func (r *fakeRuntime) Start(_ context.Context, id string) error {
	if r.failStart {
		return errors.New("boom")
	}
	r.started = append(r.started, id)
	return nil
}
func (r *fakeRuntime) Remove(_ context.Context, id string, _ bool) error {
	r.removed = append(r.removed, id)
	return nil
}

type memAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *memAudit) Record(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
}

// loopback transport: verifies the envelope as the worker would, runs the
// agent, and returns the reply. This is the whole deploy path minus the I2P
// stream, which is exactly what a unit test should cover.
type loopback struct {
	agent      *Agent
	workerNode string
	replay     ReplayGuard
	now        time.Time
	verifyErr  error
}

func (l *loopback) RoundTrip(ctx context.Context, _ WorkerRecord, env Envelope) ([]byte, error) {
	if err := env.Verify(l.workerNode, l.now, l.replay); err != nil {
		l.verifyErr = err
		return nil, err
	}
	if env.Method != MethodLaunch {
		return nil, errors.New("unexpected method")
	}
	reply, err := l.agent.HandleLaunch(ctx, env)
	if err != nil {
		return nil, err
	}
	return json.Marshal(reply)
}

func workerRecord(t *testing.T, id *testIdentity, caps ...string) WorkerRecord {
	t.Helper()
	key, _ := id.PublicKey()
	return WorkerRecord{
		RecordType: "dcs_worker", NodeID: id.ID(),
		PublicKey: b64(key), Destination: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p",
		ProtocolVer: 1, Arch: "linux/amd64",
		Capabilities: caps, CPUCores: 4, RAMBytes: 8 << 30, Slots: 4,
		Sequence: 1, IssuedAt: 0, ExpiresAt: 1 << 40,
	}
}

func b64(b []byte) string {
	// base64.RawStdEncoding, matching the record format.
	return string(mustB64(b))
}

// THE HEADLINE PATH: deploy a lab instance to a random peer and get its private
// I2P destination back -- the address the researcher points a port scanner at.
func TestDeployLabToRandomPeerReturnsPrivateAddress(t *testing.T) {
	researcher := newIdentity(t)
	worker := newIdentity(t)

	rt := &fakeRuntime{}
	audit := &memAudit{}
	alloc := NewAddressAllocator(&fakeOpener{}, t.TempDir())
	agent := NewAgent(AgentConfig{
		AcceptsLab: true, LabMaxRuntime: DefaultLabMaxRuntime, NodeID: worker.ID(),
	}, rt, alloc, audit)
	agent.now = func() time.Time { return time.Unix(1700000000, 0) }

	now := time.Unix(1700000000, 0)
	transport := &loopback{agent: agent, workerNode: worker.ID(), replay: newMemReplay(), now: now}

	mgr := NewManager(researcher, transport)
	mgr.now = func() time.Time { return now }
	mgr.rand = func() uint64 { return 0 } // deterministic pick

	// The DHT view the caller would have read.
	records := []WorkerRecord{
		workerRecord(t, newIdentity(t), "worker"), // not a lab worker
		workerRecord(t, worker, "worker", "lab"),  // the one that qualifies
	}

	reply, chosen, err := mgr.DeployToRandom(context.Background(), records, DeployRequest{
		DeploymentID: "scan-target-1",
		Image:        "sha256:deadbeef",
		Lab:          true,
		RuntimeSecs:  3600,
	}, nil)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	// It landed on the lab-capable worker, never the plain one.
	if chosen.NodeID != worker.ID() {
		t.Fatalf("lab workload placed on a non-lab worker %s", chosen.NodeID)
	}
	// The address came back and is a real-looking I2P destination.
	if !base32Address.MatchString(reply.Destination) {
		t.Fatalf("returned destination is not an I2P address: %q", reply.Destination)
	}
	if !reply.Private {
		t.Fatal("a lab container's address was not marked private")
	}
	// Requested 1h, which is within the 4h ceiling, so it stays 1h. (Clamping
	// of an over-ceiling request is covered by TestLabRuntimeCeilingBinds.)
	if reply.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Fatalf("expiry %d is not now+1h", reply.ExpiresAt)
	}

	// The container actually ran, addressed before it started.
	if len(rt.created) != 1 || len(rt.started) != 1 {
		t.Fatalf("expected one create+start, got %d/%d", len(rt.created), len(rt.started))
	}
	if !rt.created[0].Lab {
		t.Fatal("container was not created with the lab profile")
	}

	// The private address is NOT in the publishable set -- nobody but the
	// researcher can learn it.
	if pub := alloc.PublishableAddresses(); len(pub) != 0 {
		t.Fatalf("a private lab address became publishable: %v", pub)
	}
	// And the audit log shows exactly one disclosure, to the researcher.
	entry, ok := alloc.Lookup(reply.ContainerID)
	if !ok {
		t.Fatal("container address not tracked")
	}
	if to := entry.DisclosedTo(); len(to) != 1 || to[0] != researcher.ID() {
		t.Fatalf("address disclosed to %v, want only the researcher", to)
	}
}

// A lab workload must never be placed on a worker that did not opt into lab
// hosting -- even if it is the only worker available.
func TestLabDeployRefusedWithNoLabWorker(t *testing.T) {
	researcher := newIdentity(t)
	records := []WorkerRecord{workerRecord(t, newIdentity(t), "worker")} // no "lab"
	mgr := NewManager(researcher, &loopback{})
	mgr.rand = func() uint64 { return 0 }
	_, _, err := mgr.DeployToRandom(context.Background(), records, DeployRequest{
		DeploymentID: "x", Image: "sha256:a", Lab: true,
	}, nil)
	if !errors.Is(err, ErrNoWorkerMatched) {
		t.Fatalf("lab workload matched a non-lab worker: %v", err)
	}
}

// A researcher who asks for egress on a vulnerable box is refused, out loud.
func TestLabDeployWithEgressIsRefused(t *testing.T) {
	researcher := newIdentity(t)
	worker := newIdentity(t)
	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()},
		&fakeRuntime{}, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = func() time.Time { return time.Unix(1700000000, 0) }
	now := time.Unix(1700000000, 0)
	transport := &loopback{agent: agent, workerNode: worker.ID(), replay: newMemReplay(), now: now}
	mgr := NewManager(researcher, transport)
	mgr.now, mgr.rand = func() time.Time { return now }, func() uint64 { return 0 }

	_, _, err := mgr.DeployToRandom(context.Background(),
		[]WorkerRecord{workerRecord(t, worker, "worker", "lab")},
		DeployRequest{DeploymentID: "x", Image: "sha256:a", Lab: true, RequestEgress: true}, nil)
	if !errors.Is(err, ErrLabEgressRefused) {
		t.Fatalf("egress on a lab box was not refused: %v", err)
	}
}

// A replayed envelope is rejected: capturing the launch request off the wire
// cannot re-run it.
func TestEnvelopeReplayRejected(t *testing.T) {
	sender := newIdentity(t)
	worker := newIdentity(t)
	now := time.Unix(1700000000, 0)
	env, err := NewEnvelope(sender, worker.ID(), MethodPing, map[string]string{"hi": "there"}, now)
	if err != nil {
		t.Fatal(err)
	}
	replay := newMemReplay()
	if err := env.Verify(worker.ID(), now, replay); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if err := env.Verify(worker.ID(), now, replay); !errors.Is(err, ErrEnvelopeReplay) {
		t.Fatalf("replayed envelope accepted: %v", err)
	}
}

// An envelope addressed to a different worker is never executed, even if the
// signature is perfectly valid.
func TestEnvelopeWrongAudienceRejected(t *testing.T) {
	sender := newIdentity(t)
	intended := newIdentity(t)
	other := newIdentity(t)
	now := time.Unix(1700000000, 0)
	env, _ := NewEnvelope(sender, intended.ID(), MethodPing, struct{}{}, now)
	if err := env.Verify(other.ID(), now, newMemReplay()); !errors.Is(err, ErrEnvelopeAudience) {
		t.Fatalf("envelope for another node was accepted: %v", err)
	}
}

// A forged key -- valid signature by the wrong identity -- is rejected.
func TestEnvelopeForgedIdentityRejected(t *testing.T) {
	real := newIdentity(t)
	attacker := newIdentity(t)
	worker := newIdentity(t)
	now := time.Unix(1700000000, 0)

	env, _ := NewEnvelope(attacker, worker.ID(), MethodPing, struct{}{}, now)
	// Claim to be `real` while carrying attacker's key/signature.
	env.FromNode = real.ID()
	if err := env.Verify(worker.ID(), now, newMemReplay()); err == nil {
		t.Fatal("an envelope claiming another identity was accepted")
	}
}

// The failed-start path cleans up: no dangling container, no leaked address.
func TestFailedStartCleansUp(t *testing.T) {
	researcher := newIdentity(t)
	worker := newIdentity(t)
	rt := &fakeRuntime{failStart: true}
	alloc := NewAddressAllocator(&fakeOpener{}, t.TempDir())
	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()}, rt, alloc, &memAudit{})
	agent.now = func() time.Time { return time.Unix(1700000000, 0) }

	env, _ := NewEnvelope(researcher, worker.ID(), MethodLaunch,
		DeployRequest{DeploymentID: "x", Image: "sha256:a", Lab: true, RuntimeSecs: 60},
		time.Unix(1700000000, 0))
	if _, err := agent.HandleLaunch(context.Background(), env); err == nil {
		t.Fatal("HandleLaunch reported success despite a failed start")
	}
	if len(rt.removed) != 1 {
		t.Fatal("the container was not removed after start failed")
	}
	if pub := alloc.PublishableAddresses(); len(pub) != 0 {
		t.Fatal("an address leaked after a failed start")
	}
}
