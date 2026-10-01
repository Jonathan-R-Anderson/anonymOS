package dcs

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func labDeployment() Deployment {
	return Deployment{
		ID: "dcs-lab-1", Owner: "12D3KooWResearcher", Image: "sha256:abcd",
		Lab: true, RequestedRuntime: time.Hour,
	}
}

// The worker's operator decides, and nothing a deployer sends can create that
// consent.
func TestLabRefusedUnlessWorkerOptedIn(t *testing.T) {
	if _, err := AdmitLab(labDeployment(), false, DefaultLabMaxRuntime); !errors.Is(err, ErrLabNotEnabled) {
		t.Fatalf("a worker that never opted in accepted a vulnerable workload: %v", err)
	}
	if _, err := AdmitLab(labDeployment(), true, DefaultLabMaxRuntime); err != nil {
		t.Fatalf("an opted-in worker refused a well-formed lab deployment: %v", err)
	}
}

// Publishing, egress and gateway exposure are refused OUT LOUD rather than
// silently downgraded, so a researcher who asked for the wrong thing is told.
func TestLabRefusesExposureRequests(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Deployment)
		want   error
	}{
		{"publish", func(d *Deployment) { d.RequestPublish = true }, ErrLabPublishRefused},
		{"egress", func(d *Deployment) { d.RequestEgress = true }, ErrLabEgressRefused},
		{"gateway", func(d *Deployment) { d.RequestGateway = true }, ErrLabGatewayRefused},
		{"privileged", func(d *Deployment) { d.Privileged = true }, ErrPrivilegedRefused},
	} {
		t.Run(test.name, func(t *testing.T) {
			dep := labDeployment()
			test.mutate(&dep)
			if _, err := AdmitLab(dep, true, DefaultLabMaxRuntime); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestLabRequiresExactlyOneOwner(t *testing.T) {
	dep := labDeployment()
	dep.Owner = "   "
	if _, err := AdmitLab(dep, true, DefaultLabMaxRuntime); !errors.Is(err, ErrLabNoOwner) {
		t.Fatalf("a lab deployment with no owner was admitted: %v", err)
	}
}

// The containment struct must never come back permissive, whatever it is asked
// for. This is the test that fails if someone later adds a "trusted lab" path.
func TestLabContainmentIsAlwaysRefusing(t *testing.T) {
	for _, d := range []time.Duration{-1, 0, time.Minute, 500 * time.Hour} {
		c := LabContainmentFor(d)
		if c.PublishDestination || c.AllowClearnetEgress ||
			c.AllowGatewayPublish || c.AllowInboundFromNetwork {
			t.Fatalf("containment for %v is permissive: %+v", d, c)
		}
		if c.MaxRuntime <= 0 || c.MaxRuntime > DefaultLabMaxRuntime {
			t.Fatalf("runtime ceiling escaped: %v", c.MaxRuntime)
		}
	}
}

// A forgotten vulnerable container is the failure mode. The ceiling binds even
// when the deployer asks for longer.
func TestLabRuntimeCeilingBinds(t *testing.T) {
	dep := labDeployment()
	dep.RequestedRuntime = 30 * 24 * time.Hour
	c, err := AdmitLab(dep, true, DefaultLabMaxRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxRuntime != DefaultLabMaxRuntime {
		t.Fatalf("a month-long lab deployment was granted %v", c.MaxRuntime)
	}
	start := time.Unix(1700000000, 0)
	if got := c.ExpiresAt(start); !got.Equal(start.Add(DefaultLabMaxRuntime)) {
		t.Fatalf("expiry %v is not start+ceiling", got)
	}
	// A worker may be stricter than the default, never laxer.
	strict, err := AdmitLab(dep, true, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if strict.MaxRuntime != 15*time.Minute {
		t.Fatalf("worker's stricter ceiling ignored: %v", strict.MaxRuntime)
	}
}

// "Only one other person knows about it" -- the audience for a lab container's
// address is exactly its owner.
func TestLabAudienceIsExactlyTheOwner(t *testing.T) {
	dep := labDeployment()
	audience := AudienceFor(dep)
	if len(audience) != 1 || audience[0] != dep.Owner {
		t.Fatalf("lab audience is %v, want exactly [%s]", audience, dep.Owner)
	}
}

// ---------------------------------------------------------------------------
// Address allocation
// ---------------------------------------------------------------------------

type fakeSession struct {
	addr   string
	closed bool
}

func (f *fakeSession) Base32() string { return f.addr }
func (f *fakeSession) Close() error   { f.closed = true; return nil }
func (f *fakeSession) AcceptStreamPort() (net.Conn, int, error) {
	return nil, 0, errors.New("fake session does not accept streams")
}

type fakeOpener struct {
	n     int
	made  []string
	paths []string
}

func (f *fakeOpener) Open(_ context.Context, keyPath string) (Session, error) {
	f.n++
	// 52 chars of base32, distinct per call.
	body := strings.Repeat("abcdefgh", 7)[:51] + string(rune('a'+f.n%26))
	addr := body + ".b32.i2p"
	f.made = append(f.made, addr)
	f.paths = append(f.paths, keyPath)
	return &fakeSession{addr: addr}, nil
}

func TestEachContainerGetsItsOwnDestination(t *testing.T) {
	opener := &fakeOpener{}
	alloc := NewAddressAllocator(opener, t.TempDir())
	ctx := context.Background()

	a, err := alloc.Allocate(ctx, "container-a", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := alloc.Allocate(ctx, "container-b", true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Destination == b.Destination {
		t.Fatal("two containers share one I2P destination; co-location is observable")
	}
	// Separate key files, so one container's key cannot impersonate another.
	if opener.paths[0] == opener.paths[1] {
		t.Fatalf("both containers used the same key file: %s", opener.paths[0])
	}
	for _, p := range opener.paths {
		if filepath.Base(p) != "i2p.destination" {
			t.Fatalf("unexpected key path %s", p)
		}
	}
	// Stable across a restart: re-allocating returns the same entry.
	again, err := alloc.Allocate(ctx, "container-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if again.Destination != a.Destination {
		t.Fatal("a container's address changed under it")
	}
}

// The publication path must source addresses from one place that already
// filters private ones, rather than relying on every call site to remember.
func TestPrivateAddressesAreNeverPublishable(t *testing.T) {
	alloc := NewAddressAllocator(&fakeOpener{}, t.TempDir())
	ctx := context.Background()
	if _, err := alloc.Allocate(ctx, "public-1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := alloc.Allocate(ctx, "lab-1", true); err != nil {
		t.Fatal(err)
	}
	if _, err := alloc.Allocate(ctx, "lab-2", true); err != nil {
		t.Fatal(err)
	}

	pub := alloc.PublishableAddresses()
	if len(pub) != 1 {
		t.Fatalf("publishable set has %d entries, want 1", len(pub))
	}
	if pub[0].ContainerID != "public-1" {
		t.Fatalf("a private lab address reached the publishable set: %s", pub[0].ContainerID)
	}
	for _, entry := range pub {
		if entry.Private {
			t.Fatal("a private address is in the publishable set")
		}
	}
}

// Disclosure is the audit trail that makes "only one person knows" checkable.
func TestDisclosureIsRecorded(t *testing.T) {
	alloc := NewAddressAllocator(&fakeOpener{}, t.TempDir())
	entry, err := alloc.Allocate(context.Background(), "lab-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.Disclosures()) != 0 {
		t.Fatal("a freshly allocated address already has disclosures")
	}
	addr, err := entry.Disclose("12D3KooWResearcher", "launch result", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if addr != entry.Destination {
		t.Fatal("Disclose returned a different address")
	}
	// Repeated disclosure to the same party is still one person.
	if _, err := entry.Disclose("12D3KooWResearcher", "status", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := entry.DisclosedTo(); len(got) != 1 || got[0] != "12D3KooWResearcher" {
		t.Fatalf("disclosed audience is %v, want exactly the owner", got)
	}
	if len(entry.Disclosures()) != 2 {
		t.Fatal("the audit trail lost an entry")
	}
}

func TestImplausibleAddressIsRejected(t *testing.T) {
	bad := &badOpener{}
	alloc := NewAddressAllocator(bad, t.TempDir())
	if _, err := alloc.Allocate(context.Background(), "c", true); err == nil {
		t.Fatal("a malformed I2P address was accepted as a container identity")
	}
	if !bad.closed {
		t.Fatal("the rejected session was leaked instead of closed")
	}
}

type badOpener struct{ closed bool }

func (b *badOpener) Open(context.Context, string) (Session, error) {
	return &closerSession{onClose: func() { b.closed = true }}, nil
}

type closerSession struct{ onClose func() }

func (c *closerSession) Base32() string { return "192.0.2.1" } // not an I2P address
func (c *closerSession) Close() error   { c.onClose(); return nil }
func (c *closerSession) AcceptStreamPort() (net.Conn, int, error) {
	return nil, 0, errors.New("fake session does not accept streams")
}

// ---------------------------------------------------------------------------
// Docker profile
// ---------------------------------------------------------------------------

// The hardened profile is the only place a container is configured, so these
// assertions cover every container the agent can create.
func TestHardenedProfileRefusesDangerousOptions(t *testing.T) {
	body := hardened(ContainerSpec{Image: "sha256:abcd", Lab: true})
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	if body.HostConfig.Privileged {
		t.Fatal("privileged is set")
	}
	if body.HostConfig.NetworkMode != "none" || !body.NetworkDisabled {
		t.Fatal("docker networking is not disabled; the container could reach the host LAN")
	}
	if !body.HostConfig.ReadonlyRootfs {
		t.Fatal("root filesystem is writable")
	}
	if len(body.HostConfig.CapDrop) != 1 || body.HostConfig.CapDrop[0] != "ALL" {
		t.Fatalf("capabilities not fully dropped: %v", body.HostConfig.CapDrop)
	}
	if body.HostConfig.PidsLimit == nil || *body.HostConfig.PidsLimit <= 0 {
		t.Fatal("no pids limit; a fork bomb is unbounded")
	}
	var sawNoNewPrivs bool
	for _, opt := range body.HostConfig.SecurityOpt {
		if opt == "no-new-privileges:true" {
			sawNoNewPrivs = true
		}
	}
	if !sawNoNewPrivs {
		t.Fatal("no-new-privileges is not set")
	}
	// Nothing in the emitted body may bind the docker socket or a host path.
	for _, forbidden := range []string{"docker.sock", "\"Binds\"", "\"PidMode\"", "\"IpcMode\":\"host\""} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("create body contains %s: %s", forbidden, text)
		}
	}
	// A lab container must not resurrect itself past its ceiling.
	if body.HostConfig.RestartPolicy.Name != "no" {
		t.Fatalf("lab restart policy is %q", body.HostConfig.RestartPolicy.Name)
	}
}

func TestSpecHasNoFieldForDangerousOptions(t *testing.T) {
	// If someone adds a Privileged or Binds field to ContainerSpec, a deployer
	// gains a way to ask for it. Catch that at review time.
	raw, _ := json.Marshal(ContainerSpec{})
	for _, forbidden := range []string{"Privileged", "Binds", "Devices", "CapAdd", "NetworkMode", "PidMode"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("ContainerSpec exposes %s to deployers", forbidden)
		}
	}
}

func TestCreateRefusesEmptyImage(t *testing.T) {
	client, err := NewDockerClient("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(context.Background(), ContainerSpec{}); !errors.Is(err, ErrEmptyImage) {
		t.Fatalf("empty image accepted: %v", err)
	}
}

func TestOnlyUnixDockerEndpoints(t *testing.T) {
	for _, endpoint := range []string{"tcp://10.0.0.5:2375", "http://docker:2375", ""} {
		if _, err := NewDockerClient(endpoint); err == nil {
			t.Fatalf("accepted a remote docker endpoint %q; that is an unauthenticated root API", endpoint)
		}
	}
}
