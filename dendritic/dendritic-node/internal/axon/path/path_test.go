package path

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
	"github.com/syndichan/maniwani/storage-client/internal/axon/profile"
)

// relayAt places a relay at 10.b1.b2.b3 with an explicit ASN.
//
// The three bytes are separate arguments because the path constraint is /16 and
// the replication constraint is /24, so a fixture has to be able to vary them
// INDEPENDENTLY -- two relays in distinct /24s inside one /16 is exactly the
// case the coarser path width exists to refuse, and a helper that derives both
// from one index cannot express it.
func relayAt(t *testing.T, id string, b1, b2, b3 int, asn uint32) Relay {
	t.Helper()
	addr := netip.AddrFrom4([4]byte{10, byte(b1), byte(b2), byte(b3)})
	ann, err := peer.Annotate(addr)
	if err != nil {
		t.Fatalf("annotate %s: %v", addr, err)
	}
	ann.ASN = asn
	if asn != peer.ASNUnknown {
		ann.ASNSource = peer.ASNSourceOperator
	}
	return Relay{NodeID: id, Ann: ann}
}

// relay is the common case: `a` selects a distinct /16 (and therefore a
// distinct /24), `b` is the host.
func relay(t *testing.T, id string, a, b int, asn uint32) Relay {
	t.Helper()
	return relayAt(t, id, a, 0, b, asn)
}

// population builds n relays, each in its own /16, spread over `asns` ASes.
func population(t *testing.T, n, asns int) []Relay {
	t.Helper()
	out := make([]Relay, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, relay(t, fmt.Sprintf("r%03d", i), i, 1, uint32(1+i%asns)))
	}
	return out
}

// TestPathPrefixIsCoarserThanReplication is the §8.7 vs §7.5 finding, as a test.
//
// Two relays in 10.5.1.0/24 and 10.5.2.0/24 are distinct at the REPLICATION
// width and identical at the PATH width. Before these were separated, the path
// selector used /24 and would have put both in one circuit -- two hops inside
// one provider's /16, which is one vantage point.
func TestPathPrefixIsCoarserThanReplication(t *testing.T) {
	a := relayAt(t, "a", 5, 1, 1, 100)
	b := relayAt(t, "b", 5, 2, 1, 200)

	if peer.SameDomain(a.Ann, b.Ann, peer.DomainPrefix) {
		t.Fatal("setup: the two relays are not distinct at the /24 replication width")
	}
	if !samePathDomain(a.Ann, b.Ann, peer.DomainPrefix, UnknownOperatorsDistinct) {
		t.Fatal("§8.7 violated: two relays in one /16 are distinct at the path width")
	}

	// And a 2-hop path across them must therefore be refused.
	s := selector([]Relay{a, b}, seeded(1))
	if _, _, err := s.SelectPath(context.Background(), 2, Default(), WeightPolicy{}); err != ErrNoPath {
		t.Fatalf("a path was built across one /16: %v", err)
	}
}

func selector(cands []Relay, rnd func() float64) *Selector {
	return &Selector{Candidates: func() []Relay { return cands }, Rand: rnd}
}

// seeded is a reproducible uniform stream. Used ONLY where a test needs to
// compare a distribution against an exact model; see Selector.Rand.
func seeded(seed int64) func() float64 {
	r := rand.New(rand.NewSource(seed))
	return r.Float64
}

// TestT121NoTwoHopsShareADomain is T12.1 over many draws.
//
// The interesting half is the ASN case: 60 relays each in a distinct /24 but
// spread over only 4 ASes. A prefix-only constraint is satisfied by every
// possible path, so a selector that quietly ignores DomainASN passes a
// /24-only test and fails this one.
func TestT121NoTwoHopsShareADomain(t *testing.T) {
	cands := population(t, 60, 4)
	s := selector(cands, seeded(1))
	ctx := context.Background()

	for i := 0; i < 10000; i++ {
		p, rep, err := s.SelectPath(ctx, 3, Default(), WeightPolicy{})
		if err != nil {
			t.Fatalf("selection %d failed: %v (report %+v)", i, err, rep)
		}
		if len(p) != 3 {
			t.Fatalf("selection %d returned %d hops", i, len(p))
		}
		if rep.Relaxed() {
			t.Fatalf("E12.2 violated: relaxed with alternatives available: %+v", rep.Relaxations)
		}
		for a := 0; a < len(p); a++ {
			for b := a + 1; b < len(p); b++ {
				if p[a].NodeID == p[b].NodeID {
					t.Fatalf("selection %d repeated %s", i, p[a].NodeID)
				}
				if peer.SameDomain(p[a].Ann, p[b].Ann, peer.DomainPrefix) {
					t.Fatalf("S12: hops %d,%d share prefix %s", a, b, p[a].Ann.Prefix)
				}
				if peer.SameDomain(p[a].Ann, p[b].Ann, peer.DomainASN) {
					t.Fatalf("S12: hops %d,%d share ASN %d", a, b, p[a].Ann.ASN)
				}
			}
		}
	}
}

// TestE121NoViolationsWhereAlternativesExisted is E12.1.
//
// 60 nodes, 10^4 selections, synthetic address diversity, zero violations.
// Falsified by one.
func TestE121NoViolationsWhereAlternativesExisted(t *testing.T) {
	cands := population(t, 60, 20)
	s := selector(cands, seeded(7))
	ctx := context.Background()

	violations := 0
	for i := 0; i < 10000; i++ {
		p, _, err := s.SelectPath(ctx, params.DefaultHops, Default(), WeightPolicy{})
		if err != nil {
			t.Fatalf("selection %d: %v", i, err)
		}
		for a := range p {
			for b := a + 1; b < len(p); b++ {
				if conflicts(p[a], []Relay{p[b]}, Default()) {
					violations++
				}
			}
		}
	}
	if violations != 0 {
		t.Fatalf("E12.1 violated: %d constraint violations over 10^4 selections", violations)
	}
}

// TestE122RelaxationIsCountedAndNeverSilent is E12.2.
//
// Three assertions, and the middle one is the one that catches the real bug:
// with relaxation DISABLED the selector must fail rather than return a path,
// because a caller that receives 3 hops has no way to ask whether they were the
// 3 hops it constrained for.
func TestE122RelaxationIsCountedAndNeverSilent(t *testing.T) {
	// 20 relays in distinct /24s but only TWO ASes. A 3-hop path under
	// distinct-ASN is impossible; a 2-hop one is not.
	cands := population(t, 20, 2)
	s := selector(cands, seeded(3))
	ctx := context.Background()

	// (1) No relaxation: the request fails, and it fails with a report that
	// says what the pool looked like.
	p, rep, err := s.SelectPath(ctx, 3, Default(), WeightPolicy{})
	if err != ErrNoPath {
		t.Fatalf("impossible constraint returned %v with path %v", err, p)
	}
	if rep.Relaxed() {
		t.Fatal("a failed selection recorded a relaxation")
	}
	if rep.DistinctASNs != 2 {
		t.Fatalf("report says %d distinct ASNs, want 2", rep.DistinctASNs)
	}

	// (2) With relaxation: a path exists, and the relaxation is recorded with
	// the hop at which the full constraint set ran out.
	p, rep, err = s.SelectPath(ctx, 3, Default(), WeightPolicy{AllowRelaxation: true})
	if err != nil {
		t.Fatalf("relaxed selection failed: %v", err)
	}
	if !rep.Relaxed() {
		t.Fatal("E12.2 violated: relaxed silently")
	}
	if rep.Relaxations[0].Dropped != peer.DomainASN {
		t.Fatalf("dropped %v, want the ASN constraint", rep.Relaxations[0].Dropped)
	}
	if rep.Relaxations[0].Hop != 2 {
		t.Fatalf("relaxation recorded at hop %d, want 2 (two ASes admit two hops)",
			rep.Relaxations[0].Hop)
	}
	// The relaxation gave up ASN and kept the prefix. A relaxation that gave up
	// both would be indistinguishable from no constraint at all.
	for a := range p {
		for b := a + 1; b < len(p); b++ {
			if peer.SameDomain(p[a].Ann, p[b].Ann, peer.DomainPrefix) {
				t.Fatal("relaxation dropped the prefix constraint as well as the ASN one")
			}
		}
	}

	// (3) When alternatives DO exist, the counter stays at zero even with
	// relaxation enabled -- otherwise it would measure nothing.
	wide := selector(population(t, 60, 20), seeded(4))
	for i := 0; i < 500; i++ {
		_, rep, err := wide.SelectPath(ctx, 3, Default(), WeightPolicy{AllowRelaxation: true})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Relaxed() {
			t.Fatalf("E12.2 violated: relaxed on a pool with alternatives: %+v", rep)
		}
	}
}

// TestT123BondCapsTheClaim is T12.3.
func TestT123BondCapsTheClaim(t *testing.T) {
	tenGigabit := 10e9 / 8 // bytes per second

	minimal := Weight{Claimed: tenGigabit, BondCap: BondCapFor(1), ReceiptObserved: 1}
	if got := minimal.Value(); got != BondCapFor(1) {
		t.Fatalf("T12.3 violated: claim of %.0f B/s on a 1-token bond is worth %.0f, want the cap %.0f",
			tenGigabit, got, BondCapFor(1))
	}

	// An honest relay that claims less than its bond allows is worth its CLAIM.
	// The bond is a ceiling, never a floor: a floor would pay stake for
	// capacity nobody ever offered.
	honest := Weight{Claimed: 1 << 20, BondCap: BondCapFor(1000), ReceiptObserved: 1}
	if got := honest.Value(); got != 1<<20 {
		t.Fatalf("bond raised an honest claim: %.0f, want %d", got, 1<<20)
	}

	// No bond, any claim: worth nothing.
	if got := (Weight{Claimed: tenGigabit, ReceiptObserved: 1}).Value(); got != 0 {
		t.Fatalf("unbonded claim is worth %v, want 0", got)
	}
}

// TestT124ReceiptsOnlyLower is T12.4.
func TestT124ReceiptsOnlyLower(t *testing.T) {
	base := Weight{Claimed: 1000, BondCap: 1e9}
	full := Weight{Claimed: 1000, BondCap: 1e9, ReceiptObserved: 1}
	if full.Value() != 1000 {
		t.Fatalf("perfect receipts give %v, want the claim 1000", full.Value())
	}
	for _, r := range []float64{0, 0.1, 0.5, 0.9, 1} {
		w := base
		w.ReceiptObserved = r
		if v := w.Value(); v > 1000 {
			t.Fatalf("T12.4 violated: receipts %v raised the weight to %v above the claim", r, v)
		}
	}
	// Over-delivery is not evidence of extra capacity.
	over := base
	over.ReceiptObserved = 5
	if v := over.Value(); v > 1000 {
		t.Fatalf("T12.4 violated: a receipt fraction of 5 gave %v", v)
	}
	// And a NaN receipt must not produce a NaN weight, which would poison every
	// comparison in the sampler and select nothing at all.
	nan := base
	nan.ReceiptObserved = math.NaN()
	if v := nan.Value(); math.IsNaN(v) {
		t.Fatal("a NaN receipt produced a NaN weight")
	}
}

// TestT125CrudePartitionIsWarned is T12.5.
//
// Two clients are handed disjoint descriptor sets carved out of one network.
// Both must warn. The test also checks the negative: the undivided network does
// NOT warn, or the warning would be constant and therefore useless.
func TestT125CrudePartitionIsWarned(t *testing.T) {
	whole := population(t, 60, 20)
	ctx := context.Background()

	_, rep, err := selector(whole, seeded(1)).SelectPath(ctx, 3, Default(), WeightPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.PartitionWarning {
		t.Fatalf("the undivided network warned: %s", rep.PartitionReason)
	}

	// The adversary splits it into two small, concentrated halves.
	left := []Relay{}
	right := []Relay{}
	for i, r := range whole {
		if i%2 == 0 && len(left) < 6 {
			left = append(left, r)
		} else if len(right) < 6 {
			right = append(right, r)
		}
	}
	for name, half := range map[string][]Relay{"left": left, "right": right} {
		_, rep, err := selector(half, seeded(2)).SelectPath(ctx, 3, Default(), WeightPolicy{})
		if err != nil {
			t.Fatalf("%s half: %v", name, err)
		}
		if !rep.PartitionWarning {
			t.Fatalf("T12.5 violated: %s half of a partition did not warn (%d candidates, %d prefixes)",
				name, rep.Candidates, rep.DistinctPrefixes)
		}
	}

	// The concentration floor, independent of size: 40 relays all in one /24.
	// A count-only check passes this and it is not a network.
	conc := make([]Relay, 0, 40)
	for i := 0; i < 40; i++ {
		conc = append(conc, relayAt(t, fmt.Sprintf("c%02d", i), 7, 0, i, uint32(1+i)))
	}
	_, rep, err = selector(conc, seeded(3)).SelectPath(ctx, 3, Default(), WeightPolicy{})
	if err == nil {
		t.Fatal("40 relays in one /24 produced a distinct-prefix path")
	}
	if !rep.PartitionWarning {
		t.Fatal("T12.5 violated: a large pool in one failure domain did not warn")
	}
}

// TestT126SelectionIsNotDeterministic is T12.6.
//
// It uses the PRODUCTION source of randomness, not an injected one. A test that
// seeds the selector and then asserts non-determinism proves nothing about what
// ships.
func TestT126SelectionIsNotDeterministic(t *testing.T) {
	cands := population(t, 60, 20)
	s := &Selector{Candidates: func() []Relay { return cands }} // nil Rand => crypto/rand
	ctx := context.Background()

	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		p, _, err := s.SelectPath(ctx, 3, Default(), WeightPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		seen[fmt.Sprintf("%s|%s|%s", p[0].NodeID, p[1].NodeID, p[2].NodeID)]++
	}
	if len(seen) < 100 {
		t.Fatalf("T12.6 violated: 200 selections produced only %d distinct paths", len(seen))
	}
}

// TestE12a2TieringDoesNotReduceDiversity is E12a.2's statistical half, which
// belongs here because this is where the draw happens.
//
// The setup is adversarial toward the property: the fast tier is deliberately
// concentrated in ONE AS, so if tier weights could reach past the constraint,
// paths would collapse into that AS and measured diversity would fall.
func TestE12a2TieringDoesNotReduceDiversity(t *testing.T) {
	cands := population(t, 60, 20)
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	profs := profile.New(func() time.Time { return now })

	// Everything in AS 1 is observed as excellent; everything else is mediocre.
	at := now.Add(-time.Minute)
	for _, r := range cands {
		v := 0.3
		if r.Ann.ASN == 1 {
			v = 1.0
		}
		for j := 0; j < 15; j++ {
			if err := profs.Observe(r.NodeID, profile.ObsBuildAccepted, v, at); err != nil {
				t.Fatal(err)
			}
			at = at.Add(time.Millisecond)
		}
	}
	pol := WeightPolicy{UseProfile: true, Profiles: profs}
	ctx := context.Background()

	measure := func(p WeightPolicy, seed int64) (asnDiversity float64, src WeightSource) {
		s := selector(cands, seeded(seed))
		distinct := 0
		for i := 0; i < 5000; i++ {
			path, rep, err := s.SelectPath(ctx, 3, Default(), p)
			if err != nil {
				t.Fatal(err)
			}
			src = rep.Source
			seen := map[uint32]bool{}
			for _, h := range path {
				seen[h.Ann.ASN] = true
			}
			distinct += len(seen)
		}
		return float64(distinct) / 5000, src
	}

	uniformDiv, uniformSrc := measure(WeightPolicy{}, 11)
	tieredDiv, tieredSrc := measure(pol, 11)

	if uniformSrc != SourceUniform {
		t.Fatalf("control run reported source %v", uniformSrc)
	}
	if tieredSrc != SourceProfile {
		t.Fatalf("tiered run reported source %v -- the profile was not consulted", tieredSrc)
	}
	if tieredDiv < uniformDiv {
		t.Fatalf("E12a.2 violated: tiering reduced mean ASN diversity from %.4f to %.4f",
			uniformDiv, tieredDiv)
	}
	if uniformDiv != 3 || tieredDiv != 3 {
		t.Fatalf("distinct-ASN constraint did not hold: uniform %.4f, tiered %.4f", uniformDiv, tieredDiv)
	}
}

// TestFailingRelaysAreExcludedFromThePool checks that P12a's failing tier
// removes a relay from the CANDIDATE COUNT and not merely from the draw.
//
// The distinction is the whole reason exclusion happens in admissible() rather
// than through a zero weight: a report that counts unpickable relays makes a
// depleted pool look healthy, and the partition warning is computed from that
// count.
func TestFailingRelaysAreExcludedFromThePool(t *testing.T) {
	cands := population(t, 20, 20)
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	profs := profile.New(func() time.Time { return now })
	// Recent, deliberately: exclusion for failure is TEMPORARY, so observations
	// older than ProfileRepromoteInterval would have been re-admitted by the
	// time this reads them, and the test would be measuring re-promotion.
	at := now.Add(-time.Minute)
	for i, r := range cands {
		v := 1.0
		if i < 14 {
			v = 0 // failing
		}
		for j := 0; j < 15; j++ {
			if err := profs.Observe(r.NodeID, profile.ObsBuildAccepted, v, at); err != nil {
				t.Fatal(err)
			}
			at = at.Add(time.Millisecond)
		}
	}
	s := selector(cands, seeded(5))
	_, rep, err := s.SelectPath(context.Background(), 3, Default(),
		WeightPolicy{UseProfile: true, Profiles: profs})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Candidates != 6 {
		t.Fatalf("pool counts %d candidates, want 6 -- failing relays are still counted", rep.Candidates)
	}
	if !rep.PartitionWarning {
		t.Fatal("a pool depleted to 6 by exclusions did not warn")
	}
}

// TestBadRequests covers the argument contract.
func TestBadRequests(t *testing.T) {
	s := selector(population(t, 60, 20), seeded(1))
	ctx := context.Background()
	for _, n := range []int{0, -1, params.MaxHops + 1} {
		if _, _, err := s.SelectPath(ctx, n, Default(), WeightPolicy{}); err != ErrBadRequest {
			t.Fatalf("n=%d gave %v, want ErrBadRequest", n, err)
		}
	}
	// A profile policy without a store fails loudly rather than degrading to
	// uniform, which would make the misconfiguration invisible.
	if _, _, err := s.SelectPath(ctx, 3, Default(), WeightPolicy{UseProfile: true}); err != ErrNoProfiles {
		t.Fatalf("missing profile store gave %v", err)
	}
	// A cancelled context is not a path.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.SelectPath(cancelled, 3, Default(), WeightPolicy{}); err == nil {
		t.Fatal("a cancelled context still produced a path")
	}
}

// TestExcludeKeepsRelaysOutOfTheSecondLeg checks the exclusion set, which is
// what keeps a rendezvous circuit's two legs from sharing a relay.
func TestExcludeKeepsRelaysOutOfTheSecondLeg(t *testing.T) {
	cands := population(t, 60, 20)
	s := selector(cands, seeded(9))
	ctx := context.Background()

	first, _, err := s.SelectPath(ctx, 3, Default(), WeightPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	c := Default()
	c.Exclude = map[string]bool{}
	for _, r := range first {
		c.Exclude[r.NodeID] = true
	}
	for i := 0; i < 1000; i++ {
		second, rep, err := s.SelectPath(ctx, 3, c, WeightPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Candidates != 57 {
			t.Fatalf("exclusions not reflected in the pool: %d candidates", rep.Candidates)
		}
		for _, r := range second {
			if c.Exclude[r.NodeID] {
				t.Fatalf("excluded relay %s appeared in the second leg", r.NodeID)
			}
		}
	}
}
