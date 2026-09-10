package peer

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMapper is a Mapper whose behaviour the test drives.
type fakeMapper struct {
	proto    MappingProtocol
	calls    atomic.Int32
	unmapped atomic.Int32
	// failAfter makes Map fail once this many calls have succeeded.
	failAfter int32
	// port is the external port handed back; movePortAfter changes it to
	// simulate a router silently relocating the mapping.
	port           uint16
	movePortAfter  int32
	grantedLease   time.Duration
	requestedLease time.Duration
}

func (f *fakeMapper) Protocol() MappingProtocol { return f.proto }

func (f *fakeMapper) Map(_ context.Context, internal uint16, lease time.Duration) (Mapping, error) {
	n := f.calls.Add(1)
	f.requestedLease = lease
	if f.failAfter > 0 && n > f.failAfter {
		return Mapping{}, errors.New("router said no")
	}
	port := f.port
	if port == 0 {
		port = internal
	}
	if f.movePortAfter > 0 && n > f.movePortAfter {
		port++
	}
	l := f.grantedLease
	if l == 0 {
		l = lease
	}
	return Mapping{
		Protocol: f.proto, InternalPort: internal, ExternalPort: port,
		External: netip.MustParseAddr("198.51.100.77"), Lease: l,
	}, nil
}

func (f *fakeMapper) Unmap(context.Context, Mapping) error {
	f.unmapped.Add(1)
	return nil
}

// TestMappingIsOffByDefault is §6.5's opt-in rule: the zero config maps
// nothing, and nothing touches the operator's router.
func TestMappingIsOffByDefault(t *testing.T) {
	f := &fakeMapper{proto: MappingUPnP}
	m := NewMappingManager(MappingConfig{}, nil, f)

	if _, err := m.Acquire(context.Background()); !errors.Is(err, ErrMappingDisabled) {
		t.Fatalf("Acquire on a zero config = %v, want ErrMappingDisabled", err)
	}
	if err := m.Run(context.Background()); !errors.Is(err, ErrMappingDisabled) {
		t.Fatalf("Run on a zero config = %v, want ErrMappingDisabled", err)
	}
	if n := f.calls.Load(); n != 0 {
		t.Fatalf("the router was contacted %d times without opt-in", n)
	}
}

// TestUPnPTriedBeforeNATPMP is the §6.5 order of decreasing awfulness.
func TestUPnPTriedBeforeNATPMP(t *testing.T) {
	upnp := &fakeMapper{proto: MappingUPnP}
	pmp := &fakeMapper{proto: MappingNATPMP}
	m := NewMappingManager(MappingConfig{Enabled: true, InternalPort: 4001}, nil, upnp, pmp)

	got, err := m.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != MappingUPnP {
		t.Fatalf("protocol = %s, want upnp first", got.Protocol)
	}
	if pmp.calls.Load() != 0 {
		t.Fatal("NAT-PMP was contacted even though UPnP succeeded")
	}
}

// TestFallsBackToNATPMP: UPnP failing must not end the attempt.
func TestFallsBackToNATPMP(t *testing.T) {
	failing := &failingMapper{proto: MappingUPnP}
	pmp := &fakeMapper{proto: MappingNATPMP}

	m := NewMappingManager(MappingConfig{Enabled: true, InternalPort: 4001}, nil, failing, pmp)
	got, err := m.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != MappingNATPMP {
		t.Fatalf("protocol = %s, want nat-pmp after UPnP failed", got.Protocol)
	}
}

type failingMapper struct{ proto MappingProtocol }

func (f *failingMapper) Protocol() MappingProtocol { return f.proto }
func (f *failingMapper) Map(context.Context, uint16, time.Duration) (Mapping, error) {
	return Mapping{}, errors.New("no IGD")
}
func (f *failingMapper) Unmap(context.Context, Mapping) error { return nil }

// TestRefreshFailureDemotesImmediately is the §6.5 rule with no grace period: a
// lapsed lease turns a relay into a black hole for every circuit through it.
func TestRefreshFailureDemotesImmediately(t *testing.T) {
	self := NewSelfReachability()
	// Put the node in MAPPED/REACHABLE first, so the test proves a demotion
	// rather than an absence of promotion.
	var round []ProbeObservation
	for i, n := range []string{"n1", "n2", "n3"} {
		o := obs(ProberID(n), n, "198.51.100.77", uint16(3000+i))
		o.DialBackOK, o.Mapped = true, true
		round = append(round, o)
	}
	if c := self.Apply(round, time.Now()); c.Class != ClassMapped {
		t.Fatalf("setup: class = %s, want MAPPED", c.Class)
	}
	if !self.MayRelay() {
		t.Fatal("setup: MAPPED node cannot relay")
	}

	f := &fakeMapper{proto: MappingUPnP, failAfter: 1}
	m := NewMappingManager(MappingConfig{Enabled: true, InternalPort: 4001}, self, f)
	if _, err := m.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded on a mapper set to fail")
	}
	if _, ok := m.Current(); ok {
		t.Fatal("a mapping survived a failed refresh")
	}
	if self.State() != ReachUnreachable {
		t.Fatalf("state = %s after a failed refresh, want unreachable immediately", self.State())
	}
	if self.MayRelay() {
		t.Fatal("a node whose mapping refresh failed still advertises relay")
	}
	if m.LastError() == "" {
		t.Error("no operator-facing reason recorded for the demotion")
	}
}

// TestMovedExternalPortDemotes: a router that renews on a different port has
// invalidated every descriptor advertising the old one.
func TestMovedExternalPortDemotes(t *testing.T) {
	self := NewSelfReachability()
	var round []ProbeObservation
	for i, n := range []string{"n1", "n2", "n3"} {
		o := obs(ProberID(n), n, "198.51.100.77", uint16(3000+i))
		o.DialBackOK, o.Mapped = true, true
		round = append(round, o)
	}
	self.Apply(round, time.Now())

	f := &fakeMapper{proto: MappingUPnP, movePortAfter: 1}
	m := NewMappingManager(MappingConfig{Enabled: true, InternalPort: 4001}, self, f)
	if _, err := m.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("a silently relocated mapping was accepted as a renewal")
	}
	if self.State() != ReachUnreachable {
		t.Fatalf("state = %s, want unreachable after the mapping moved", self.State())
	}
}

// TestRefreshAtHalfTheLease is the §6.5 schedule, and uses the GRANTED lease
// rather than the requested one -- a gateway that grants less than asked must
// still be refreshed inside the window it actually promised.
func TestRefreshAtHalfTheLease(t *testing.T) {
	f := &fakeMapper{proto: MappingNATPMP, grantedLease: 4 * time.Minute}
	m := NewMappingManager(MappingConfig{
		Enabled: true, InternalPort: 4001, Lease: time.Hour,
	}, nil, f)

	base := time.Unix(2_000_000, 0)
	m.now = func() time.Time { return base }

	got, err := m.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Lease != 4*time.Minute {
		t.Fatalf("lease = %v, want the granted 4m not the requested 1h", got.Lease)
	}
	if want := base.Add(2 * time.Minute); !got.RefreshAt().Equal(want) {
		t.Fatalf("RefreshAt = %v, want %v (half the granted lease)", got.RefreshAt(), want)
	}
	if !got.Expiry().Equal(base.Add(4 * time.Minute)) {
		t.Fatalf("Expiry = %v, want %v", got.Expiry(), base.Add(4*time.Minute))
	}
}

// TestReleaseUnmapsAndDemotes: a mapping left behind outlives the process that
// asked for it, which is the surprise the opt-in default exists to prevent.
func TestReleaseUnmapsAndDemotes(t *testing.T) {
	self := NewSelfReachability()
	var round []ProbeObservation
	for i, n := range []string{"n1", "n2", "n3"} {
		o := obs(ProberID(n), n, "198.51.100.77", uint16(3000+i))
		o.DialBackOK, o.Mapped = true, true
		round = append(round, o)
	}
	self.Apply(round, time.Now())

	f := &fakeMapper{proto: MappingUPnP}
	m := NewMappingManager(MappingConfig{Enabled: true, InternalPort: 4001}, self, f)
	if _, err := m.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Release(context.Background())

	if f.unmapped.Load() != 1 {
		t.Fatalf("Unmap called %d times, want 1", f.unmapped.Load())
	}
	if _, ok := m.Current(); ok {
		t.Fatal("a mapping survived Release")
	}
	if self.MayRelay() {
		t.Fatal("a node still advertises relay after releasing its mapping")
	}
}

// TestRunRefreshesUntilCancelled exercises the loop end to end on a short
// lease.
func TestRunRefreshesUntilCancelled(t *testing.T) {
	f := &fakeMapper{proto: MappingNATPMP, grantedLease: 2 * time.Second}
	m := NewMappingManager(MappingConfig{Enabled: true, InternalPort: 4001}, nil, f)

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	if err := m.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v, want DeadlineExceeded", err)
	}
	// Acquire plus at least one refresh at the 1s floor.
	if n := f.calls.Load(); n < 2 {
		t.Fatalf("Map called %d times, want at least one refresh", n)
	}
	if f.unmapped.Load() != 1 {
		t.Fatal("Run did not release the mapping on exit")
	}
}
