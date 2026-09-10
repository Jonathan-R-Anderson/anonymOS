package peer

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// E3.2, the §6.5 classification table, and the role gate.

func obs(id ProberID, net string, ext string, port uint16) ProbeObservation {
	o := ProbeObservation{Prober: id, Network: net, ExternalPort: port, QUICOK: true, TCPOK: true}
	if ext != "" {
		o.External = netip.MustParseAddr(ext)
	}
	return o
}

// TestBlockedNodeClassifiesUnreachableAndRefusesRelay is E3.2: a node whose
// inbound UDP is blocked must classify itself unreachable and decline the relay
// role.
func TestBlockedNodeClassifiesUnreachableAndRefusesRelay(t *testing.T) {
	s := NewSelfReachability()

	// Inbound UDP blocked: no prober completed a QUIC handshake. TCP still
	// works, which is what separates UDP_BLOCKED from OFFLINE.
	var round []ProbeObservation
	for i, n := range []string{"n1", "n2", "n3"} {
		o := obs(ProberID(n), n, "203.0.113.7", uint16(4000+i))
		o.QUICOK = false
		round = append(round, o)
	}

	start := time.Now()
	c := s.Apply(round, start)

	if c.Class != ClassUDPBlocked {
		t.Fatalf("class = %s, want UDP_BLOCKED (%s)", c.Class, c.Reason)
	}
	if got := s.State(); got != ReachUnreachable {
		t.Fatalf("state = %s, want unreachable", got)
	}
	if s.MayRelay() {
		t.Fatal("E3.2 violated: a UDP-blocked node may relay")
	}

	// The verdict must land inside the deadline. Apply is synchronous, so the
	// only thing left to assert is that the elapsed time is inside E3.2's bound
	// and that Classify agrees without waiting.
	if elapsed := time.Since(start); elapsed >= ClassifyDeadline {
		t.Fatalf("classification took %v, over E3.2's %v", elapsed, ClassifyDeadline)
	}
	if got := s.Classify(context.Background(), time.Millisecond, time.Now); got != ReachUnreachable {
		t.Fatalf("Classify = %s, want unreachable", got)
	}

	// A UDP-blocked node retains the TCP roles; it must not retain rendezvous.
	roles := s.Roles([]Role{RoleClient, RoleGuard, RoleMiddleRelay, RoleRendezvousPoint, RoleStorageTunnel})
	if _, ok := roles[RoleRendezvousPoint]; ok {
		t.Error("rendezvous permitted to a UDP-blocked node; R12 forbids it")
	}
	if p := roles[RoleMiddleRelay]; p != PermTCPOnly {
		t.Errorf("middle relay permission = %v, want PermTCPOnly", p)
	}
	if p := roles[RoleGuard]; p != PermDeprioritised {
		t.Errorf("guard permission = %v, want PermDeprioritised", p)
	}
}

// TestOfflineNodeAdvertisesNothing: OFFLINE permits no role at all.
func TestOfflineNodeAdvertisesNothing(t *testing.T) {
	s := NewSelfReachability()
	var round []ProbeObservation
	for _, n := range []string{"n1", "n2", "n3"} {
		o := obs(ProberID(n), n, "", 0)
		o.QUICOK, o.TCPOK = false, false
		round = append(round, o)
	}
	c := s.Apply(round, time.Now())
	if c.Class != ClassOffline {
		t.Fatalf("class = %s, want OFFLINE", c.Class)
	}
	roles := s.Roles([]Role{RoleClient, RoleGuard, RoleAnonService, RoleStorageTunnel})
	if len(roles) != 0 {
		t.Fatalf("offline node advertised %v", roles)
	}
}

// TestSilenceFailsClosedAtTheDeadline: if probes never arrive, the verdict is
// unreachable, not optimism.
func TestSilenceFailsClosedAtTheDeadline(t *testing.T) {
	s := NewSelfReachability()

	base := time.Unix(1_000_000, 0)
	var advanced atomic.Bool
	clock := func() time.Time {
		if advanced.Load() {
			return base.Add(ClassifyDeadline + time.Second)
		}
		return base
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		advanced.Store(true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if got := s.Classify(ctx, 5*time.Millisecond, clock); got != ReachUnreachable {
		t.Fatalf("silent classification = %s, want unreachable (fail closed)", got)
	}
	if s.MayRelay() {
		t.Fatal("a node that learned nothing about itself advertised relay")
	}
}

// TestPublicNodeMayRelay is the positive case: a diverse quorum agreed on an
// address and a dial-back arrived.
func TestPublicNodeMayRelay(t *testing.T) {
	s := NewSelfReachability()
	var round []ProbeObservation
	for i, n := range []string{"n1", "n2", "n3"} {
		o := obs(ProberID(n), n, "198.51.100.9", uint16(5000+i))
		o.DialBackOK = true
		round = append(round, o)
	}
	c := s.Apply(round, time.Now())
	if c.Class != ClassPublic {
		t.Fatalf("class = %s, want PUBLIC (%s)", c.Class, c.Reason)
	}
	if !s.MayRelay() {
		t.Fatal("a public, dial-back-verified node may not relay")
	}
	if got := s.Snapshot().External; got.String() != "198.51.100.9" {
		t.Fatalf("external = %s, want 198.51.100.9", got)
	}
	roles := s.Roles([]Role{RoleGuard, RoleRendezvousPoint, RoleDHTServer})
	if len(roles) != 3 {
		t.Fatalf("public node roles = %v, want all three", roles)
	}
}

// TestAddressQuorumRefusesTwoPeers is §6.5 step REFUSE: below the address
// quorum nothing is advertised, because a node that believes one peer can be
// induced to advertise an address that is not its own.
func TestAddressQuorumRefusesTwoPeers(t *testing.T) {
	// Two probers in two networks: enough for MinProbeQuorum, short of
	// AddressQuorum.
	round := []ProbeObservation{
		obs("a", "n1", "192.0.2.5", 1234),
		obs("b", "n2", "192.0.2.5", 1234),
	}
	c := ClassifyObservations(round)
	if c.External.IsValid() {
		t.Fatalf("advertised %s on a quorum of 2, below AddressQuorum=%d", c.External, AddressQuorum)
	}
	if c.Class != ClassUnknown {
		t.Fatalf("class = %s, want UNKNOWN with an unconfirmed address", c.Class)
	}
}

// TestSingleNetworkCoalitionCannotConfirmAddress is T3.4 for the address path:
// three probers behind one network are one vantage point, and must not be able
// to talk this node into advertising an address.
func TestSingleNetworkCoalitionCannotConfirmAddress(t *testing.T) {
	round := []ProbeObservation{
		obs("a", "n1", "192.0.2.66", 1234),
		obs("b", "n1", "192.0.2.66", 1234),
		obs("c", "n1", "192.0.2.66", 1234),
	}
	c := ClassifyObservations(round)
	if c.External.IsValid() {
		t.Fatalf("a single-network coalition confirmed %s", c.External)
	}

	s := NewSelfReachability()
	s.Apply(round, time.Now())
	if s.MayRelay() {
		t.Fatal("a single-network prober coalition granted the relay role")
	}
	if got := s.State(); got != ReachProbing {
		t.Fatalf("state = %s, want probing (network diversity not met)", got)
	}
}

// TestSingleProberCannotGrantRelay: one prober is one prober's word.
func TestSingleProberCannotGrantRelay(t *testing.T) {
	s := NewSelfReachability()
	o := obs("only-one", "n1", "198.51.100.1", 1)
	o.DialBackOK = true
	s.Apply([]ProbeObservation{o}, time.Now())
	if s.MayRelay() {
		t.Fatal("a single prober granted the relay role")
	}
}

// TestCGNATSeparatedFromEDM: §6.5 keeps them apart because the operator advice
// differs, so the classifier must too.
func TestCGNATSeparatedFromEDM(t *testing.T) {
	var round []ProbeObservation
	for i, n := range []string{"n1", "n2", "n3"} {
		round = append(round, obs(ProberID(n), n, "100.100.5.5", uint16(7000+i)))
	}
	c := ClassifyObservations(round)
	if c.Class != ClassCGNAT {
		t.Fatalf("class = %s, want CGNAT for 100.64.0.0/10", c.Class)
	}
	if Permit(ClassCGNAT, RoleMiddleRelay).Allowed() {
		t.Error("CGNAT node permitted a middle relay role")
	}
	if !Permit(ClassCGNAT, RoleStorageTunnel).Allowed() {
		t.Error("CGNAT node denied storage-via-own-tunnel, which needs no inbound")
	}
}

// TestEIMvsEDMByPortObservation: same external port across distinct networks is
// endpoint-independent; different ports are endpoint-dependent.
func TestEIMvsEDMByPortObservation(t *testing.T) {
	same := []ProbeObservation{
		obs("a", "n1", "198.51.100.20", 4444),
		obs("b", "n2", "198.51.100.20", 4444),
		obs("c", "n3", "198.51.100.20", 4444),
	}
	if c := ClassifyObservations(same); c.Class != ClassEIM {
		t.Fatalf("same-port class = %s, want EIM (%s)", c.Class, c.Reason)
	}
	diff := []ProbeObservation{
		obs("a", "n1", "198.51.100.20", 4444),
		obs("b", "n2", "198.51.100.20", 5555),
		obs("c", "n3", "198.51.100.20", 6666),
	}
	if c := ClassifyObservations(diff); c.Class != ClassEDM {
		t.Fatalf("differing-port class = %s, want EDM (%s)", c.Class, c.Reason)
	}
	if Permit(ClassEDM, RoleStorageDirect).Allowed() {
		t.Error("EDM permitted direct storage dialing")
	}
	if Permit(ClassEIM, RoleStorageDirect) != PermOpportunistic {
		t.Error("EIM storage-direct should be opportunistic (BULK only)")
	}
}

// TestDemotionNeedsConsecutiveFailuresButLeaseLossIsImmediate.
func TestDemotionNeedsConsecutiveFailuresButLeaseLossIsImmediate(t *testing.T) {
	s := NewSelfReachability()
	var round []ProbeObservation
	for i, n := range []string{"n1", "n2", "n3"} {
		o := obs(ProberID(n), n, "198.51.100.44", uint16(9000+i))
		o.DialBackOK, o.Mapped = true, true
		round = append(round, o)
	}
	if c := s.Apply(round, time.Now()); c.Class != ClassMapped {
		t.Fatalf("class = %s, want MAPPED", c.Class)
	}

	now := time.Now()
	for i := 1; i < DemotionFailures; i++ {
		if st := s.Fail("dial-back timeout", now); st != ReachReachable {
			t.Fatalf("demoted after %d failures, want %d", i, DemotionFailures)
		}
	}
	if st := s.Fail("dial-back timeout", now); st != ReachUnreachable {
		t.Fatalf("state after %d failures = %s, want unreachable", DemotionFailures, st)
	}

	// Lease loss has no grace period.
	s2 := NewSelfReachability()
	s2.Apply(round, time.Now())
	s2.LeaseLost(time.Now())
	if s2.State() != ReachUnreachable {
		t.Fatal("a lost mapping lease did not demote immediately")
	}
	if s2.MayRelay() {
		t.Fatal("a node whose mapping lease lapsed still advertises relay")
	}
}

// TestUnknownStateAdvertisesNothing is the UNKNOWN box in §6.5's diagram:
// "advertise nothing, take no public role".
func TestUnknownStateAdvertisesNothing(t *testing.T) {
	s := NewSelfReachability()
	roles := s.Roles([]Role{RoleClient, RoleGuard, RoleAnonService})
	if len(roles) != 0 {
		t.Fatalf("a never-probed node advertised %v", roles)
	}
}
