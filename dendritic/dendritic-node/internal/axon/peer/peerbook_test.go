package peer

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// P3's peerbook criteria, executable.

func goodEvidence(reachable bool) Evidence {
	return Evidence{
		Probers:   []ProberID{"prober-a", "prober-b"},
		Networks:  []string{"net-1", "net-2"},
		At:        time.Unix(1_700_000_000, 0),
		Reachable: reachable,
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

// ---------------------------------------------------------------------------
// T3.1 — prefix and ASN annotation
// ---------------------------------------------------------------------------

func TestAnnotatePrefixes(t *testing.T) {
	cases := []struct {
		addr   string
		prefix string
	}{
		{"192.0.2.1", "192.0.2.0/24"},
		{"192.0.2.254", "192.0.2.0/24"},
		{"198.51.100.7", "198.51.100.0/24"},
		{"203.0.113.99", "203.0.113.0/24"},
		{"10.1.2.3", "10.1.2.0/24"},
		{"2001:db8:abcd:1234::1", "2001:db8:abcd::/48"},
		{"2001:db8:abcd:ffff::9", "2001:db8:abcd::/48"},
		{"2606:4700:4700::1111", "2606:4700:4700::/48"},
	}
	for _, tc := range cases {
		ann, err := Annotate(mustAddr(t, tc.addr))
		if err != nil {
			t.Fatalf("%s: %v", tc.addr, err)
		}
		if ann.Prefix.String() != tc.prefix {
			t.Fatalf("%s: prefix = %s, want %s", tc.addr, ann.Prefix, tc.prefix)
		}
	}
}

// TestAnnotateReportsIPv4ASNGap pins the limitation rather than letting a
// caller discover it. If an IPv4 ASN dataset is ever added this test should
// fail, which is the correct signal to update the diversity claims that depend
// on it.
func TestAnnotateReportsIPv4ASNGap(t *testing.T) {
	ann, err := Annotate(mustAddr(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if ann.ASN != ASNUnknown || ann.ASNSource != ASNSourceNone {
		t.Fatalf("IPv4 ASN is now resolvable (asn=%d src=%s) — update the diversity "+
			"claims that currently degrade to prefix-only for IPv4", ann.ASN, ann.ASNSource)
	}
}

// TestOperatorTableFillsTheIPv4Gap: the supported way to get IPv4 ASN
// diversity is an operator-supplied table, and longest match must win.
func TestOperatorTableFillsTheIPv4Gap(t *testing.T) {
	a := &Annotator{ASNv4: []PrefixASN{
		{Prefix: netip.MustParsePrefix("192.0.0.0/8"), ASN: 100},
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), ASN: 200}, // more specific
	}}
	ann, err := a.Annotate(mustAddr(t, "192.0.2.5"))
	if err != nil {
		t.Fatal(err)
	}
	if ann.ASN != 200 {
		t.Fatalf("ASN = %d, want 200 (longest match)", ann.ASN)
	}
	if ann.ASNSource != ASNSourceOperator {
		t.Fatalf("source = %s, want operator", ann.ASNSource)
	}
}

// TestUnknownASNsAreNotTheSame is the conservative direction: two peers whose
// ASN could not be determined are not known to share one, and collapsing them
// would under-count diversity in the flattering direction.
func TestUnknownASNsAreNotTheSame(t *testing.T) {
	a, _ := Annotate(mustAddr(t, "192.0.2.1"))
	b, _ := Annotate(mustAddr(t, "198.51.100.1"))
	if a.ASN != ASNUnknown || b.ASN != ASNUnknown {
		t.Skip("IPv4 ASN became resolvable")
	}
	if SameDomain(a, b, DomainASN) {
		t.Fatal("two unknown ASNs were treated as the same AS")
	}
}

// ---------------------------------------------------------------------------
// E3.3 — no entry may exist below the quorum floor
// ---------------------------------------------------------------------------

func TestObserveEnforcesQuorum(t *testing.T) {
	pb := NewPeerbook(nil, 1)
	addrs := []netip.Addr{mustAddr(t, "192.0.2.1")}

	t.Run("single prober refused", func(t *testing.T) {
		ev := Evidence{Probers: []ProberID{"only-one"}, Networks: []string{"net-1"}, Reachable: true}
		if err := pb.Observe("peer-1", addrs, ev); !errors.Is(err, ErrQuorumTooSmall) {
			t.Fatalf("single-prober observation accepted: %v", err)
		}
	})

	t.Run("duplicate probers do not make a quorum", func(t *testing.T) {
		ev := Evidence{
			Probers:  []ProberID{"same", "same", "same"},
			Networks: []string{"net-1", "net-1", "net-1"},
		}
		if err := pb.Observe("peer-1", addrs, ev); !errors.Is(err, ErrQuorumTooSmall) {
			t.Fatalf("duplicate probers counted as a quorum: %v", err)
		}
	})

	// T3.4: a coalition sharing one network is one vantage point.
	t.Run("three probers on one network refused", func(t *testing.T) {
		ev := Evidence{
			Probers:   []ProberID{"a", "b", "c"},
			Networks:  []string{"net-1", "net-1", "net-1"},
			Reachable: true,
		}
		if err := pb.Observe("peer-1", addrs, ev); !errors.Is(err, ErrNetworksTooFew) {
			t.Fatalf("a single-network coalition produced a reachability mark: %v", err)
		}
	})

	t.Run("diverse quorum accepted", func(t *testing.T) {
		if err := pb.Observe("peer-1", addrs, goodEvidence(true)); err != nil {
			t.Fatalf("valid observation refused: %v", err)
		}
	})

	// The invariant itself, over everything in the book.
	if pb.Len() != 1 {
		t.Fatalf("peerbook holds %d entries, want 1", pb.Len())
	}
	e, ok := pb.Get("peer-1")
	if !ok {
		t.Fatal("entry missing")
	}
	if e.ProbeQuorum < MinProbeQuorum {
		t.Fatalf("E3.3 violated: entry has quorum %d", e.ProbeQuorum)
	}
	if e.ProbeNetworks < MinProbeNetworks {
		t.Fatalf("entry has %d prober networks, want >= %d", e.ProbeNetworks, MinProbeNetworks)
	}
}

func TestObserveRejectsMalformed(t *testing.T) {
	pb := NewPeerbook(nil, 1)
	if err := pb.Observe("", []netip.Addr{mustAddr(t, "192.0.2.1")}, goodEvidence(true)); !errors.Is(err, ErrUnknownNodeID) {
		t.Fatalf("empty node id accepted: %v", err)
	}
	if err := pb.Observe("p", nil, goodEvidence(true)); !errors.Is(err, ErrNoAddresses) {
		t.Fatalf("address-less observation accepted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// T3.3 / E3.1 — diversity-constrained sampling
// ---------------------------------------------------------------------------

// fill populates a peerbook with peers spread over the given number of /24s,
// putting `perPrefix` peers in each so the sampler has to choose.
func fill(t *testing.T, pb *Peerbook, prefixes, perPrefix int) {
	t.Helper()
	for p := 0; p < prefixes; p++ {
		for i := 0; i < perPrefix; i++ {
			addr := mustAddr(t, fmt.Sprintf("10.%d.%d.%d", p/256, p%256, i+1))
			id := fmt.Sprintf("peer-%d-%d", p, i)
			if err := pb.Observe(id, []netip.Addr{addr}, goodEvidence(true)); err != nil {
				t.Fatalf("observe %s: %v", id, err)
			}
		}
	}
}

// TestSampleNeverReturnsTwoPeersInOnePrefix is T3.3.
func TestSampleNeverReturnsTwoPeersInOnePrefix(t *testing.T) {
	pb := NewPeerbook(nil, 42)
	fill(t, pb, 30, 5) // 30 distinct /24s, 5 peers each

	got := pb.Sample(20, DiversityConstraint{Domains: []Domain{DomainPrefix}, ReachableOnly: true})
	if len(got) != 20 {
		t.Fatalf("sampled %d peers, want 20 (30 prefixes were available)", len(got))
	}
	seen := map[netip.Prefix]string{}
	for _, e := range got {
		ann, _ := e.Primary()
		if prev, dup := seen[ann.Prefix]; dup {
			t.Fatalf("prefix %s returned twice: %s and %s", ann.Prefix, prev, e.NodeID)
		}
		seen[ann.Prefix] = e.NodeID
	}
}

// TestSampleReturnsShortRatherThanRelaxing is section 46.1's rule: a short set
// is information, a full but correlated set is a lie.
func TestSampleReturnsShortRatherThanRelaxing(t *testing.T) {
	pb := NewPeerbook(nil, 7)
	fill(t, pb, 3, 10) // only 3 distinct /24s, 30 peers

	got := pb.Sample(20, DiversityConstraint{Domains: []Domain{DomainPrefix}, ReachableOnly: true})
	if len(got) != 3 {
		t.Fatalf("sampled %d peers, want 3 — the sampler relaxed the constraint to fill the quota", len(got))
	}
}

// TestSampleExcludesUnreachableWhenAsked: R3 gates the relay role on
// reachability, so a sampler drawing relays must not return unreachable peers.
func TestSampleExcludesUnreachable(t *testing.T) {
	pb := NewPeerbook(nil, 3)
	for i := 0; i < 10; i++ {
		addr := mustAddr(t, fmt.Sprintf("10.9.%d.1", i))
		if err := pb.Observe(fmt.Sprintf("down-%d", i), []netip.Addr{addr}, goodEvidence(false)); err != nil {
			t.Fatal(err)
		}
	}
	if got := pb.Sample(5, DiversityConstraint{Domains: []Domain{DomainPrefix}, ReachableOnly: true}); len(got) != 0 {
		t.Fatalf("sampled %d unreachable peers", len(got))
	}
	if got := pb.Sample(5, DiversityConstraint{Domains: []Domain{DomainPrefix}}); len(got) != 5 {
		t.Fatalf("without ReachableOnly, sampled %d, want 5", len(got))
	}
}

// TestSampleDiversityOver10kDraws is E3.1.
func TestSampleDiversityOver10kDraws(t *testing.T) {
	pb := NewPeerbook(nil, 2026)
	// 40 distinct /24s with several peers each: alternatives always exist for a
	// draw of 20, so any violation is the sampler's fault and not scarcity.
	fill(t, pb, 40, 4)

	c := DiversityConstraint{Domains: []Domain{DomainPrefix, DomainASN}, ReachableOnly: true}
	const draws = 10_000
	violations := 0
	short := 0
	for d := 0; d < draws; d++ {
		got := pb.Sample(20, c)
		if len(got) < 20 {
			short++
		}
		seen := map[netip.Prefix]struct{}{}
		for _, e := range got {
			ann, _ := e.Primary()
			if _, dup := seen[ann.Prefix]; dup {
				violations++
			}
			seen[ann.Prefix] = struct{}{}
		}
	}
	if violations != 0 {
		t.Fatalf("E3.1 violated: %d prefix collisions across %d draws", violations, draws)
	}
	if short != 0 {
		t.Fatalf("%d/%d draws returned fewer than 20 despite 40 prefixes being available", short, draws)
	}
}

// TestSampleWithReportSurfacesUnenforceableASN: the caller must be able to
// learn that the ASN constraint could not be applied, not assume it held.
func TestSampleWithReportSurfacesUnenforceableASN(t *testing.T) {
	pb := NewPeerbook(nil, 11)
	fill(t, pb, 10, 1) // all IPv4 => all ASNUnknown

	got, rep := pb.SampleWithReport(5, DiversityConstraint{
		Domains: []Domain{DomainPrefix, DomainASN}, ReachableOnly: true,
	})
	if len(got) != 5 {
		t.Fatalf("sampled %d, want 5", len(got))
	}
	if rep.ASNUnavailable != 5 {
		t.Fatalf("report claims %d peers lacked an ASN, want 5 — the ASN constraint "+
			"was unenforceable and the report must say so", rep.ASNUnavailable)
	}
}

// TestSampleIsReproducible: a fixed seed must give a fixed draw, or E3.1's
// 10^4-draw result is not something anyone can re-check.
func TestSampleIsReproducible(t *testing.T) {
	ids := func(seed int64) []string {
		pb := NewPeerbook(nil, seed)
		fill(t, pb, 20, 2)
		out := []string{}
		for _, e := range pb.Sample(10, DiversityConstraint{Domains: []Domain{DomainPrefix}}) {
			out = append(out, e.NodeID)
		}
		return out
	}
	a, b := ids(99), ids(99)
	if len(a) != len(b) {
		t.Fatal("draw lengths differ for one seed")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("draw is not reproducible at %d: %s vs %s", i, a[i], b[i])
		}
	}
}
