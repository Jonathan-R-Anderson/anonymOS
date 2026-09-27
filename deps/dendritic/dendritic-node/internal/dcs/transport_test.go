package dcs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// hostIdentity adapts a libp2p host's private key to EnvelopeSigner, so the
// deployer signs with the SAME key its host authenticates with -- which is
// what makes the stream-peer == envelope-sender check pass.
type hostIdentity struct {
	h   host.Host
	key crypto.PrivKey
}

func (i *hostIdentity) ID() string                    { return i.h.ID().String() }
func (i *hostIdentity) Sign(m []byte) ([]byte, error) { return i.key.Sign(m) }
func (i *hostIdentity) PublicKey() ([]byte, error)    { return crypto.MarshalPublicKey(i.key.GetPublic()) }

func newHost(t *testing.T) (host.Host, crypto.PrivKey) {
	t.Helper()
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	// A real libp2p host on TCP loopback: a genuine Noise handshake, stream
	// muxer and peer authentication. This is the DCS transport running for
	// real, minus only the I2P tunnel underneath (which libp2p treats as just
	// another transport, so the DCS-layer behaviour is identical).
	h, err := libp2p.New(
		libp2p.Identity(key),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, key
}

// THE INTEGRATION: a real deployer host opens a real DCS stream to a real
// worker host, the worker admits the lab deployment, and the private I2P
// destination comes back across the wire.
func TestStreamDeployReturnsAddressAcrossRealHosts(t *testing.T) {
	workerHost, workerKey := newHost(t)
	deployHost, deployKey := newHost(t)
	connect(t, deployHost, workerHost)

	// Worker side: agent + stream server on the worker's host.
	rt := &fakeRuntime{}
	alloc := NewAddressAllocator(&fakeOpener{}, t.TempDir())
	agent := NewAgent(AgentConfig{
		AcceptsLab: true, LabMaxRuntime: DefaultLabMaxRuntime,
		NodeID: workerHost.ID().String(),
	}, rt, alloc, &memAudit{})
	server := NewStreamServer(workerHost, agent, workerHost.ID().String())
	server.Start()

	// Deployer side: manager over the real stream transport.
	deployer := &hostIdentity{h: deployHost, key: deployKey}
	transport := NewStreamTransport(deployHost)
	mgr := NewManager(deployer, transport)
	mgr.rand = func() uint64 { return 0 }

	record := WorkerRecord{
		RecordType: "dcs_worker", NodeID: workerHost.ID().String(),
		// The transport needs a parseable destination to build a garlic
		// multiaddr for the peerstore; the actual dial goes over the memory
		// transport via the already-open connection, so any valid b32 works.
		Destination:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p",
		Capabilities: []string{"worker", "lab"}, Slots: 4,
		RAMBytes: 8 << 30, Arch: "linux/amd64", ExpiresAt: 1 << 40,
	}

	reply, worker, err := mgr.DeployToRandom(context.Background(),
		[]WorkerRecord{record},
		DeployRequest{DeploymentID: "scan-1", Image: "sha256:vuln", Lab: true, RuntimeSecs: 3600}, nil)
	if err != nil {
		t.Fatalf("stream deploy failed: %v", err)
	}
	if worker.NodeID != workerHost.ID().String() {
		t.Fatal("deployed to the wrong worker")
	}
	if !base32Address.MatchString(reply.Destination) {
		t.Fatalf("no I2P destination came back: %q", reply.Destination)
	}
	if !reply.Private {
		t.Fatal("lab address not marked private")
	}
	if len(rt.started) != 1 {
		t.Fatal("worker did not actually start the container")
	}
	_ = workerKey
}

// A validly-signed envelope relayed by a DIFFERENT peer is refused: the
// connection must be the envelope's author for a mutating op.
func TestStreamRefusesRelayedEnvelope(t *testing.T) {
	workerHost, _ := newHost(t)
	realDeployer, realKey := newHost(t)
	relay, _ := newHost(t)
	connect(t, relay, workerHost)

	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: workerHost.ID().String()},
		&fakeRuntime{}, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	NewStreamServer(workerHost, agent, workerHost.ID().String()).Start()

	// Envelope signed by realDeployer, addressed to the worker...
	env, err := NewEnvelope(&hostIdentity{h: realDeployer, key: realKey},
		workerHost.ID().String(), MethodLaunch,
		DeployRequest{DeploymentID: "x", Image: "sha256:a", Lab: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// ...but sent over the RELAY's connection.
	raw, err := (&StreamTransport{host: relay, timeout: 30 * time.Second}).RoundTrip(
		context.Background(),
		WorkerRecord{NodeID: workerHost.ID().String(),
			Destination: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p"},
		env)
	if err == nil {
		t.Fatalf("a relayed envelope was accepted; reply=%s", raw)
	}
}

func connect(t *testing.T, a, b host.Host) {
	t.Helper()
	a.Peerstore().AddAddrs(b.ID(), b.Addrs(), time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

// Confirm the reply frame round-trips.
func TestReplyFrameRoundTrip(t *testing.T) {
	reply := DeployReply{DeploymentID: "d", ContainerID: "c",
		Destination: "abc.b32.i2p", Private: true}
	raw, _ := json.Marshal(reply)
	var back DeployReply
	if err := json.Unmarshal(raw, &back); err != nil || back.ContainerID != "c" {
		t.Fatalf("reply frame did not round-trip: %v", err)
	}
}
