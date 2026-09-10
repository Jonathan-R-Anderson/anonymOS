package p2p

import (
	"fmt"
	"net/netip"
	"testing"

	ma "github.com/multiformats/go-multiaddr"

	axonpeer "github.com/syndichan/maniwani/storage-client/internal/axon/peer"
	"github.com/syndichan/maniwani/storage-client/internal/placement"
)

// T12.2 — the planner has refused to co-locate two shards of a chunk in one
// failure domain since P12b, and nothing supplied it any domains, so what it
// actually delivered was distinct-PEER. These cover the supplier.

func mustAddr(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	m, err := ma.NewMultiaddr(s)
	if err != nil {
		t.Fatalf("multiaddr %q: %v", s, err)
	}
	return m
}

func TestIPIsTakenFromTheObservedAddress(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"/ip4/203.0.113.7/tcp/4001", "203.0.113.7"},
		{"/ip4/198.51.100.9/udp/4001/quic-v1", "198.51.100.9"},
		{"/ip6/2001:db8::1/tcp/4001", "2001:db8::1"},
	}
	for _, tc := range cases {
		got, ok := ipFromMultiaddr(mustAddr(t, tc.addr))
		if !ok || got.String() != tc.want {
			t.Fatalf("%s -> %v/%v, want %s", tc.addr, got, ok, tc.want)
		}
	}
}

// TestLoopbackYieldsNoDomain is the case that would have broken every dev fleet.
//
// On a single host every peer is 127.0.0.1. Annotating those puts every
// candidate in one /24, and the planner -- correctly, by its own rule -- refuses
// to place more than one shard of a chunk. A diversity mechanism would become an
// outage on exactly the setup people develop against, and it would look like a
// storage bug rather than an address bug.
func TestLoopbackYieldsNoDomain(t *testing.T) {
	for _, addr := range []string{
		"/ip4/127.0.0.1/tcp/4001",
		"/ip6/::1/tcp/4001",
		"/ip4/0.0.0.0/tcp/4001",
	} {
		if _, ok := ipFromMultiaddr(mustAddr(t, addr)); ok {
			t.Fatalf("%s was annotated; on a single-host fleet that collapses every "+
				"candidate into one failure domain and stops dispersal", addr)
		}
	}
}

// TestNonIPTransportsYieldNoDomain is §1.4's finding, as a test.
//
// An I2P destination is a public key, deliberately unrelated to where the
// machine is. There is no failure domain to be had from it, and inventing one
// would be worse than having none.
func TestNonIPTransportsYieldNoDomain(t *testing.T) {
	for _, addr := range []string{
		"/dns4/example.invalid/tcp/4001",
		"/unix/tmp/sock",
	} {
		m, err := ma.NewMultiaddr(addr)
		if err != nil {
			continue // not all builds register every protocol
		}
		if _, ok := ipFromMultiaddr(m); ok {
			t.Fatalf("%s produced an IP", addr)
		}
	}
	if _, ok := ipFromMultiaddr(nil); ok {
		t.Fatal("a nil multiaddr produced an IP")
	}
}

// TestPlannerActuallySeparatesOnSuppliedDomains is the end-to-end point.
//
// The two halves are useless apart: domains that reach no planner change
// nothing, and a planner with no domains guarantees distinct-peer. This runs
// real domain keys through the real planner.
func TestPlannerActuallySeparatesOnSuppliedDomains(t *testing.T) {
	// Nine peers, nine distinct identities, THREE /24s -- varied in the THIRD
	// octet, not the fourth. The first version of this fixture used
	// 203.0.113.{1,2,3}, which is one /24 wearing three addresses, and the
	// planner correctly placed a single shard. The fixture was wrong and the
	// mechanism was right, which is the more useful way round.
	var cands []placement.Candidate
	for i := 0; i < 9; i++ {
		addr, ok := ipFromMultiaddr(mustAddr(t, fmt.Sprintf("/ip4/203.0.%d.10/tcp/4001", i%3+1)))
		if !ok {
			t.Fatal("fixture address was refused")
		}
		ann, err := annotateForTest(addr)
		if err != nil {
			t.Fatal(err)
		}
		cands = append(cands, placement.Candidate{
			PeerID: fmt.Sprintf("peer-%d", i), FreeBytes: 1 << 30, Domains: ann,
		})
	}

	var shards []placement.Shard
	for i := 0; i < 9; i++ {
		shards = append(shards, placement.Shard{
			ID: fmt.Sprintf("s%d", i), Index: i, Size: 1 << 20,
		})
	}

	got := placement.Plan(shards, cands, 1)
	if len(got) != 3 {
		t.Fatalf("placed %d shards across 3 failure domains, want 3 -- the domains "+
			"are not reaching the planner", len(got))
	}
	if n := placement.DomainsUnavailable(cands); n != 0 {
		t.Fatalf("%d candidates reported no domains", n)
	}

	// And the control: strip the domains and all nine place, which is the
	// distinct-PEER guarantee this change exists to improve on.
	for i := range cands {
		cands[i].Domains = nil
	}
	if got := placement.Plan(shards, cands, 1); len(got) != 9 {
		t.Fatalf("without domains %d of 9 shards placed; the planner should fall "+
			"back to distinct-peer, not refuse", len(got))
	}
}

// annotateForTest mirrors what domainKeysFor does with a live connection's
// address, without needing a live connection.
func annotateForTest(addr netipAddr) ([]string, error) {
	ann, err := axonpeer.Annotate(addr)
	if err != nil {
		return nil, err
	}
	return axonpeer.DomainKeys(ann), nil
}

type netipAddr = netip.Addr
