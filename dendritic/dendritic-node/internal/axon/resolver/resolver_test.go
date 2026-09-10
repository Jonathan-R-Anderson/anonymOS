package resolver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

func nm(t *testing.T, s string) name.Name {
	t.Helper()
	v, err := name.Normalise(s + "." + name.RootSuffix)
	if err != nil {
		t.Fatalf("normalise %q: %v", s, err)
	}
	return v
}

func id(b byte) [32]byte { var x [32]byte; x[0] = b; return x }

// --- fakes ------------------------------------------------------------------

type fakeSnap struct {
	snap    Snapshot
	have    bool
	present map[[32]byte][32]byte
	err     error
}

func (f *fakeSnap) Current() (Snapshot, bool) { return f.snap, f.have }
func (f *fakeSnap) Prove(z [32]byte) ([32]byte, []byte, bool, error) {
	if f.err != nil {
		return [32]byte{}, nil, false, f.err
	}
	v, ok := f.present[z]
	if !ok {
		return [32]byte{}, nil, false, nil
	}
	return v, []byte("records"), true, nil
}

type fakeDHT struct {
	rec map[[32]byte][32]byte
	err error
}

func (f *fakeDHT) Fetch(_ context.Context, z [32]byte) ([32]byte, []byte, error) {
	if f.err != nil {
		return [32]byte{}, nil, f.err
	}
	v, ok := f.rec[z]
	if !ok {
		return [32]byte{}, nil, errors.New("miss")
	}
	return v, []byte("dht-records"), nil
}

type fakeChain struct {
	auth bool
	rec  map[[32]byte][32]byte
	err  error
}

func (f *fakeChain) Authenticated() bool { return f.auth }
func (f *fakeChain) Resolve(_ context.Context, nh [32]byte) ([32]byte, []byte, error) {
	if f.err != nil {
		return [32]byte{}, nil, f.err
	}
	v, ok := f.rec[nh]
	if !ok {
		return [32]byte{}, nil, errors.New("absent")
	}
	return v, []byte("chain-records"), nil
}

type fakeRevoke struct{ set map[[32]byte]bool }

func (f *fakeRevoke) Revoked(x [32]byte) bool { return f.set[x] }

// --- tests ------------------------------------------------------------------

// TestT101ResolvesWithEveryRPCBlackholed is T10.1 and E10.1: with no chain
// reachable, resolution succeeds from the snapshot AND reports a non-zero
// staleness. Success without a staleness figure is a failure (S6).
func TestT101ResolvesWithEveryRPCBlackholed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	verified := now.Add(-3 * time.Hour)
	n := nm(t, "alice.lab")

	r := &Resolver{
		Now: func() time.Time { return now },
		Snapshots: &fakeSnap{
			have:    true,
			snap:    Snapshot{Root: id(9), VerifiedAt: verified, BlockNumber: 100},
			present: map[[32]byte][32]byte{n.ZoneID(): id(1)},
		},
		// No chain at all: not merely erroring, ABSENT.
		Chain: nil,
	}
	a, err := r.Resolve(context.Background(), n)
	if err != nil {
		t.Fatalf("T10.1 falsified: resolution failed with no chain: %v", err)
	}
	if a.DomainIdentity != id(1) {
		t.Fatal("wrong identity")
	}
	if a.Mode != ModeSnapshotWarm {
		t.Fatalf("mode = %s, want SNAPSHOT-WARM", a.Mode)
	}
	s := a.StalenessSeconds()
	if s <= 0 {
		t.Fatalf("T10.1/S6 falsified: staleness = %d, want > 0", s)
	}
	if s != int64(3*time.Hour/time.Second) {
		t.Fatalf("staleness = %d s, want %d", s, int64(3*time.Hour/time.Second))
	}
	t.Logf("E10.1: resolved with the chain absent, mode %s, staleness %d s", a.Mode, s)
}

// TestT102UnauthenticatedChainIsRefused is T10.2. An RPC that answers is not
// the same as a chain that verifies.
func TestT102UnauthenticatedChainIsRefused(t *testing.T) {
	n := nm(t, "alice.lab")
	nh, _ := n.NameHash()
	r := &Resolver{
		Now:   time.Now,
		Chain: &fakeChain{auth: false, rec: map[[32]byte][32]byte{nh: id(7)}},
	}
	if _, err := r.Resolve(context.Background(), n); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("err = %v, want ErrNotAuthenticated", err)
	}
	// E10.2: a hostile RPC serving a fabricated chain gets no answer at all.
	if a, _ := r.Resolve(context.Background(), n); a != nil {
		t.Fatal("E10.2 falsified: an unauthenticated source produced an answer")
	}
}

// TestT103RevokedIdentityIsRefusedAndPurged is T10.3.
func TestT103RevokedIdentityIsRefusedAndPurged(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	n := nm(t, "alice.lab")
	rev := &fakeRevoke{set: map[[32]byte]bool{}}
	r := &Resolver{
		Now: func() time.Time { return now },
		Snapshots: &fakeSnap{
			have: true, snap: Snapshot{VerifiedAt: now.Add(-time.Hour)},
			present: map[[32]byte][32]byte{n.ZoneID(): id(1)},
		},
		Revocation: rev,
	}
	if _, err := r.Resolve(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if r.CacheLen() != 1 {
		t.Fatal("the answer was not cached, so the purge test proves nothing")
	}

	// Revoke AFTER caching: the cached copy must not be served.
	rev.set[id(1)] = true
	_, err := r.Resolve(context.Background(), n)
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
	if r.CacheLen() != 0 {
		t.Fatalf("T10.3 falsified: %d cached artefacts survived revocation", r.CacheLen())
	}
}

// TestT104And105NegativeAnswersAreAuthenticatedAndFlagged is T10.4 and T10.5.
func TestT104And105NegativeAnswersAreAuthenticatedAndFlagged(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	n := nm(t, "notyet.lab")
	r := &Resolver{
		Now: func() time.Time { return now },
		Snapshots: &fakeSnap{
			have:    true,
			snap:    Snapshot{VerifiedAt: now.Add(-time.Hour), BlockNumber: 100},
			present: map[[32]byte][32]byte{}, // proven absent
		},
	}
	a, err := r.Resolve(context.Background(), n)
	if err != nil {
		t.Fatalf("a negative answer errored instead of answering: %v", err)
	}
	// T10.5: absence is an ANSWER carrying a proof, not a missing record.
	if !a.Negative() {
		t.Fatal("T10.5 falsified: absence was not reported as a negative answer")
	}
	// T10.4: and it may be wrong if the name is newer than the evidence.
	if !a.PendingPossible() {
		t.Fatal("T10.4 falsified: a negative answer claimed certainty it does not have")
	}
	if a.StalenessSeconds() <= 0 {
		t.Fatal("a negative answer carried no staleness")
	}
}

// TestSnapshotWarmAndColdAreNeverConflated: §13.3 says conflating them would be
// dishonest, because COLD trusts a publisher and WARM trusts an observation the
// client made itself.
func TestSnapshotWarmAndColdAreNeverConflated(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	n := nm(t, "alice.lab")

	warm := Snapshot{VerifiedAt: now.Add(-time.Hour)}
	cold := Snapshot{PublishedAt: now.Add(-time.Hour)} // never chain-verified

	if warm.Mode() == cold.Mode() {
		t.Fatal("warm and cold report the same mode")
	}
	if !warm.Mode().TrustsChainObservation() {
		t.Fatal("WARM does not claim a chain observation")
	}
	if cold.Mode().TrustsChainObservation() {
		t.Fatal("COLD claims a chain observation it never made")
	}
	if !strings.Contains(cold.Mode().String(), "COLD") {
		t.Fatalf("cold mode prints as %q, which hides the distinction", cold.Mode())
	}

	// A COLD answer reports staleness -1 rather than a comforting number: there
	// is no moment at which this client knew the root was good.
	r := &Resolver{
		Now: func() time.Time { return now },
		Snapshots: &fakeSnap{have: true, snap: cold,
			present: map[[32]byte][32]byte{n.ZoneID(): id(1)}},
	}
	a, err := r.Resolve(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode != ModeSnapshotCold {
		t.Fatalf("mode = %s, want SNAPSHOT-COLD", a.Mode)
	}
	if a.StalenessSeconds() != -1 {
		t.Fatalf("a COLD answer reported staleness %d; it has no verified moment "+
			"to measure from", a.StalenessSeconds())
	}
}

// TestStaleSnapshotIsRefused: the freshness bound is a refusal, not a warning.
func TestStaleSnapshotIsRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	n := nm(t, "alice.lab")
	r := &Resolver{
		Now: func() time.Time { return now },
		Snapshots: &fakeSnap{
			have:    true,
			snap:    Snapshot{VerifiedAt: now.Add(-MaxFreshness - time.Hour)},
			present: map[[32]byte][32]byte{n.ZoneID(): id(1)},
		},
	}
	if _, err := r.Resolve(context.Background(), n); !errors.Is(err, ErrTooStale) {
		t.Fatalf("err = %v, want ErrTooStale", err)
	}
}

// TestT106EveryPathWithSourcesDown is T10.6: chain unreachable, DHT
// unreachable, and both.
func TestT106EveryPathWithSourcesDown(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	n := nm(t, "alice.lab")
	good := map[[32]byte][32]byte{n.ZoneID(): id(1)}
	snapOK := func() *fakeSnap {
		return &fakeSnap{have: true,
			snap:    Snapshot{VerifiedAt: now.Add(-time.Hour)},
			present: good}
	}
	down := errors.New("unreachable")

	t.Run("chain down, DHT and snapshot up", func(t *testing.T) {
		r := &Resolver{Now: func() time.Time { return now },
			Snapshots: snapOK(),
			DHT:       &fakeDHT{rec: good},
			Chain:     &fakeChain{auth: true, err: down}}
		if _, err := r.Resolve(context.Background(), n); err != nil {
			t.Fatalf("failed with only the chain down: %v", err)
		}
	})
	t.Run("DHT down, snapshot up", func(t *testing.T) {
		r := &Resolver{Now: func() time.Time { return now },
			Snapshots: snapOK(),
			DHT:       &fakeDHT{err: down}}
		a, err := r.Resolve(context.Background(), n)
		if err != nil {
			t.Fatalf("failed with the DHT down: %v", err)
		}
		if a.Mode != ModeSnapshotWarm {
			t.Fatalf("mode = %s", a.Mode)
		}
	})
	t.Run("chain and DHT both down", func(t *testing.T) {
		r := &Resolver{Now: func() time.Time { return now },
			Snapshots: snapOK(),
			DHT:       &fakeDHT{err: down},
			Chain:     &fakeChain{auth: true, err: down}}
		a, err := r.Resolve(context.Background(), n)
		if err != nil {
			t.Fatalf("failed with chain and DHT down: %v", err)
		}
		if a.StalenessSeconds() <= 0 {
			t.Fatal("answered without a staleness figure")
		}
	})
	t.Run("everything down", func(t *testing.T) {
		r := &Resolver{Now: func() time.Time { return now },
			Snapshots: &fakeSnap{have: false},
			DHT:       &fakeDHT{err: down},
			Chain:     &fakeChain{auth: true, err: down}}
		if _, err := r.Resolve(context.Background(), n); err == nil {
			t.Fatal("answered with every source down")
		}
	})
}

// TestE103NoAddressInTheResolutionPath is E10.3, by struct audit.
func TestE103NoAddressInTheResolutionPath(t *testing.T) {
	banned := []string{"netip", "net.IP", "net.Addr", "multiaddr", "ip4", "ip6"}
	bannedField := []string{"Addr", "Address", "Host", "Port", "IP", "Endpoint"}

	var walk func(reflect.Type, string, map[reflect.Type]bool)
	walk = func(ty reflect.Type, path string, seen map[reflect.Type]bool) {
		if seen[ty] {
			return
		}
		seen[ty] = true
		full := ty.PkgPath() + "." + ty.Name()
		for _, b := range banned {
			if strings.Contains(full, b) {
				t.Errorf("E10.3 violated: %s is address-bearing (%s)", path, full)
			}
		}
		switch ty.Kind() {
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				for _, b := range bannedField {
					if strings.EqualFold(f.Name, b) {
						t.Errorf("E10.3 violated: %s.%s looks like an address", path, f.Name)
					}
				}
				walk(f.Type, path+"."+f.Name, seen)
			}
		case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
			walk(ty.Elem(), path+"[]", seen)
		}
	}
	seen := map[reflect.Type]bool{}
	for n, ty := range map[string]reflect.Type{
		"Answer":   reflect.TypeOf(Answer{}),
		"Snapshot": reflect.TypeOf(Snapshot{}),
		"Resolver": reflect.TypeOf(Resolver{}),
	} {
		walk(ty, n, seen)
	}
}

// TestNoDNSFallbackExists: §13 calls a fallback "a downgrade attack with a
// friendly name". Asserted against the source, because the way this gets added
// is somebody helpfully wiring it in when the overlay is flaky.
func TestNoDNSFallbackExists(t *testing.T) {
	src := sourceOf(t, "resolver.go")
	for _, bad := range []string{"net.Resolver", "LookupHost", "LookupIP", "net.Dial", "dns."} {
		if strings.Contains(src, bad) {
			t.Errorf("a DNS path (%s) appeared in the resolver", bad)
		}
	}
	if !strings.Contains(src, "NO DNS FALLBACK") {
		t.Error("the no-fallback rule is no longer stated in the source")
	}
}

// TestCacheDoesNotOutliveTheFreshnessBound.
func TestCacheDoesNotOutliveTheFreshnessBound(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	n := nm(t, "alice.lab")
	r := &Resolver{
		Now: func() time.Time { return now },
		Snapshots: &fakeSnap{have: true,
			snap:    Snapshot{VerifiedAt: now.Add(-time.Hour)},
			present: map[[32]byte][32]byte{n.ZoneID(): id(1)}},
		Freshness: 2 * time.Hour,
	}
	if _, err := r.Resolve(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if r.CacheLen() != 1 {
		t.Fatal("not cached")
	}
	// Past the bound, the cached answer must not be served.
	now = now.Add(3 * time.Hour)
	if a := r.cached(n.ZoneID(), now); a != nil {
		t.Fatal("a cached answer outlived the freshness bound")
	}
}
