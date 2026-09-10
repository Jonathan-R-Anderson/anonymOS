package dht

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/identity"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// network is a toy DHT: a routing table wide enough to hold r=8 verified
// contacts near any key, and a map standing in for what the holders stored.
type network struct {
	table  *Table
	stored map[string]map[[32]byte][]byte // key -> holder -> record
	fail   map[[32]byte]bool              // holders that refuse
}

func newNetwork(t *testing.T, size int) *network {
	t.Helper()
	srv := mkSRV(0x42)
	self := MustDeriveKey(ClassRelay, []byte("the publishing service"))
	n := &network{
		table:  NewTable(self),
		stored: map[string]map[[32]byte][]byte{},
		fail:   map[[32]byte]bool{},
	}
	// Spread across /24s and ASNs so the diversity caps do not refuse them --
	// the caps are §7.2's and this test is not about them.
	admitted := 0
	for i := 0; i < size; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i / 250), byte(i % 250), 1})
		c := contactAt(uint64(50000+i), addr.String(), uint32(64000+i), srv, true)
		if err := n.table.Admit(c); err == nil {
			admitted++
		}
	}
	if admitted < params.ReplicationFactor {
		t.Fatalf("routing table holds %d contacts, need at least r=%d",
			admitted, params.ReplicationFactor)
	}
	return n
}

func (n *network) store() StoreRPC {
	return func(_ context.Context, to Contact, key Key, record []byte) error {
		if n.fail[to.NodeIDPub] {
			return errors.New("holder refused")
		}
		if n.stored[key.String()] == nil {
			n.stored[key.String()] = map[[32]byte][]byte{}
		}
		n.stored[key.String()][to.NodeIDPub] = record
		return nil
	}
}

// fetch is what a client gets from one position: the record, or nothing.
func (n *network) fetch(k Key) ([]byte, bool) {
	holders := n.stored[k.String()]
	for _, rec := range holders {
		return rec, true
	}
	return nil, false
}

// blinder returns a period -> K_blind function over one service identity, which
// is what a real publisher holds.
func blinder(t *testing.T) (func(uint64) ([]byte, error), ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return func(period uint64) ([]byte, error) {
		bp, err := identity.Blind(pub, period)
		if err != nil {
			return nil, err
		}
		return []byte(bp), nil
	}, pub
}

// TestT75PublicationReachesAllEightPositions is the first half of T7.5.
func TestT75PublicationReachesAllEightPositions(t *testing.T) {
	net := newNetwork(t, 400)
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	record := []byte("a service descriptor")

	// Mid-period, so exactly one period is live and the count is unambiguous.
	now := PeriodStart(20000).Add(params.PeriodOverlap + time.Hour)

	p := &Publisher{Table: net.table, Store: net.store()}
	report, err := p.PublishOnce(context.Background(), kBlindFor, srv, record, now)
	if err != nil {
		t.Fatalf("PublishOnce: %v", err)
	}
	if len(report.Positions) != DescriptorReplicaPositions {
		t.Fatalf("published to %d positions, want %d",
			len(report.Positions), DescriptorReplicaPositions)
	}
	if !report.ReachedAll() {
		t.Fatalf("T7.5: publication did not reach all %d positions; missing %v",
			DescriptorReplicaPositions, report.Missing())
	}
	// The eight positions must be EIGHT DISTINCT keyspace points -- that is
	// what "eclipsing eight unrelated regions" buys, and a derivation that
	// dropped the replica index would still pass ReachedAll.
	seen := map[string]bool{}
	for _, pos := range report.Positions {
		if seen[pos.Target.Key.String()] {
			t.Errorf("two replica positions share key %s", pos.Target.Key)
		}
		seen[pos.Target.Key.String()] = true
		if pos.Accepted < params.ReplicationFactor {
			t.Errorf("position %d reached %d holders, want r=%d",
				pos.Target.Position, pos.Accepted, params.ReplicationFactor)
		}
	}
}

// TestT75ClientFetchingAnyOneOfEightSucceeds is the second half.
func TestT75ClientFetchingAnyOneOfEightSucceeds(t *testing.T) {
	net := newNetwork(t, 400)
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	record := []byte("a service descriptor")
	now := PeriodStart(20000).Add(params.PeriodOverlap + time.Hour)

	p := &Publisher{Table: net.table, Store: net.store()}
	if _, err := p.PublishOnce(context.Background(), kBlindFor, srv, record, now); err != nil {
		t.Fatalf("PublishOnce: %v", err)
	}

	period := periodNumber(now)
	kBlind, err := kBlindFor(period)
	if err != nil {
		t.Fatal(err)
	}
	// EVERY index, individually. "Any 1 of 8" is falsified by one that fails,
	// so trying a random one would test the property one eighth of the time.
	for j := 0; j < DescriptorReplicaPositions; j++ {
		k, err := HSDirIndex(kBlind, uint8(j), period, srv)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := net.fetch(k)
		if !ok {
			t.Errorf("T7.5: a client fetching position %d found nothing", j)
			continue
		}
		if string(got) != string(record) {
			t.Errorf("position %d served a different record", j)
		}
	}
}

// TestE73ServiceStaysReachableAcrossAPeriodRollover is E7.3.
//
//	"A service stays reachable across a full descriptor-period rollover
//	including the 12 h overlap — falsified by any unreachable window."
//
// Time is swept across a whole period and through the boundary, and at every
// step a client resolves with ITS OWN clock -- which is the thing that actually
// changes at a rollover. The publisher republishes on its own hourly cadence,
// exactly as it would in the field, rather than being nudged at the boundary.
func TestE73ServiceStaysReachableAcrossAPeriodRollover(t *testing.T) {
	net := newNetwork(t, 400)
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	record := []byte("a service descriptor")

	p := &Publisher{Table: net.table, Store: net.store()}
	rng := mrand.New(mrand.NewSource(7))

	start := PeriodStart(20000)
	end := start.Add(params.PeriodLength + 6*time.Hour)
	nextPublish := start

	step := 17 * time.Minute // deliberately not an hour divisor
	unreachable := 0
	var firstBad time.Time

	for now := start; now.Before(end); now = now.Add(step) {
		if !now.Before(nextPublish) {
			if _, err := p.PublishOnce(context.Background(), kBlindFor, srv, record, now); err != nil {
				t.Fatalf("PublishOnce at %s: %v", now, err)
			}
			nextPublish = NextRepublish(now)
		}
		// The client resolves. Its clock is `now`; it tries the periods
		// FetchPeriods names and one position at a time.
		found := false
		for _, period := range FetchPeriods(now) {
			kBlind, err := kBlindFor(period)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := FetchPositions(kBlind, period, srv, rng)
			if err != nil {
				t.Fatal(err)
			}
			// "Fetching any 1 of 8": take the first of the shuffled order.
			if _, ok := net.fetch(keys[0]); ok {
				found = true
				break
			}
		}
		if !found {
			if unreachable == 0 {
				firstBad = now
			}
			unreachable++
		}
	}
	if unreachable > 0 {
		t.Errorf("E7.3: %d unreachable sample(s) across the rollover, first at %s "+
			"(%s into period %d)", unreachable, firstBad,
			firstBad.Sub(PeriodStart(periodNumber(firstBad))), periodNumber(firstBad))
	}
}

// TestE73StaleClientResolvesThroughTheOverlap is what the overlap is FOR.
//
// The client's clock is behind, so after a boundary it still derives the
// PREVIOUS period's blinded key and looks at that period's eight positions. If
// the publisher stopped writing the old period at the boundary, this client
// finds nothing -- and §9.4's "two periods valid at once" exists precisely to
// stop that.
func TestE73StaleClientResolvesThroughTheOverlap(t *testing.T) {
	net := newNetwork(t, 400)
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	record := []byte("a service descriptor")
	p := &Publisher{Table: net.table, Store: net.store()}

	boundary := PeriodStart(20001)
	for _, skew := range []time.Duration{time.Minute, time.Hour, 6 * time.Hour, params.PeriodOverlap - time.Minute} {
		net.stored = map[string]map[[32]byte][]byte{}
		// The publisher's clock is right and it is just past the boundary.
		publisherNow := boundary.Add(skew)
		if _, err := p.PublishOnce(context.Background(), kBlindFor, srv, record, publisherNow); err != nil {
			t.Fatalf("PublishOnce: %v", err)
		}
		// The client is `skew` behind, so it is still in the old period.
		clientNow := publisherNow.Add(-skew - time.Second)
		clientPeriod := periodNumber(clientNow)
		if clientPeriod != 20000 {
			t.Fatalf("test setup: client period is %d, expected the previous one", clientPeriod)
		}
		kBlind, err := kBlindFor(clientPeriod)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := HSDirPositions(kBlind, clientPeriod, srv)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := net.fetch(keys[0]); !ok {
			t.Errorf("a client %v behind the boundary found nothing; the overlap "+
				"is not being published", skew)
		}
	}
}

// TestPublishPlanPublishesTwoPeriodsOnlyInsideTheOverlap pins §9.4's count.
func TestPublishPlanPublishesTwoPeriodsOnlyInsideTheOverlap(t *testing.T) {
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	start := PeriodStart(20001)

	for _, tc := range []struct {
		at    time.Time
		want  int
		label string
	}{
		{start, 2 * DescriptorReplicaPositions, "the instant the period begins"},
		{start.Add(params.PeriodOverlap - time.Second), 2 * DescriptorReplicaPositions, "just inside the overlap"},
		{start.Add(params.PeriodOverlap), DescriptorReplicaPositions, "the instant the overlap ends"},
		{start.Add(params.PeriodLength - time.Second), DescriptorReplicaPositions, "just before the next boundary"},
	} {
		got, err := PublishPlan(kBlindFor, srv, tc.at)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if len(got) != tc.want {
			t.Errorf("%s: %d targets, want %d", tc.label, len(got), tc.want)
		}
	}

	// Current period first, so an interrupted publisher has written the
	// positions everyone uses before the ones only a stale client does.
	plan, err := PublishPlan(kBlindFor, srv, start)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < DescriptorReplicaPositions; i++ {
		if !plan[i].Current {
			t.Fatalf("target %d is not the current period; the plan is misordered", i)
		}
	}
	for i := DescriptorReplicaPositions; i < len(plan); i++ {
		if plan[i].Current {
			t.Fatalf("target %d claims to be current but is the outgoing period", i)
		}
	}
}

// TestPublishPlanDoesNotUnderflowAtPeriodZero: period 0 has no predecessor, and
// current-1 on a uint64 is 2^64-1 -- a blinded key for a period that cannot
// exist, asked for at the one moment nothing else would notice.
func TestPublishPlanDoesNotUnderflowAtPeriodZero(t *testing.T) {
	kBlindFor, _ := blinder(t)
	plan, err := PublishPlan(kBlindFor, []byte("srv"), time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("PublishPlan at period 0: %v", err)
	}
	if len(plan) != DescriptorReplicaPositions {
		t.Fatalf("period 0 planned %d targets, want %d (no predecessor exists)",
			len(plan), DescriptorReplicaPositions)
	}
}

// TestPartialPublicationIsReportedNotSwallowed.
//
// A publisher that stopped at the first failure would leave later positions
// holding the PREVIOUS descriptor, so a client fetching one of those succeeds
// and gets stale intro points -- a service that is up and broken, which is
// harder to diagnose than one that is down.
func TestPartialPublicationIsReportedNotSwallowed(t *testing.T) {
	net := newNetwork(t, 400)
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	now := PeriodStart(20000).Add(params.PeriodOverlap + time.Hour)

	// Refuse every holder near the first position.
	plan, err := PublishPlan(kBlindFor, srv, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range net.table.Closest(plan[0].Key, params.ReplicationFactor, true) {
		net.fail[h.NodeIDPub] = true
	}

	p := &Publisher{Table: net.table, Store: net.store()}
	report, err := p.PublishOnce(context.Background(), kBlindFor, srv, []byte("desc"), now)
	if err != nil {
		t.Fatalf("PublishOnce returned an error rather than a report: %v", err)
	}
	if report.ReachedAll() {
		t.Fatal("a position reached no holder and the report says everything is fine")
	}
	if len(report.Missing()) == 0 {
		t.Error("Missing() is empty though a position failed")
	}
	// Every OTHER position must still have been attempted.
	attempted := 0
	for _, pos := range report.Positions {
		if pos.Offered > 0 {
			attempted++
		}
	}
	if attempted != len(plan) {
		t.Errorf("%d of %d positions were attempted; the loop stopped early",
			attempted, len(plan))
	}
}

// TestPositionsRotateEveryPeriod. Without the period in the pre-image a
// service's holders would be a stable, enumerable set -- the standing eclipse
// target the rotation denies.
func TestPositionsRotateEveryPeriod(t *testing.T) {
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	seen := map[string]uint64{}
	for _, period := range []uint64{20000, 20001, 20002} {
		kBlind, err := kBlindFor(period)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := HSDirPositions(kBlind, period, srv)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if prev, dup := seen[k.String()]; dup {
				t.Errorf("period %d reuses a position from period %d", period, prev)
			}
			seen[k.String()] = period
		}
	}
}

// TestPeriodNumberMatchesIdentity guards the one duplicated computation.
func TestPeriodNumberMatchesIdentity(t *testing.T) {
	for _, ts := range []int64{0, 1, 86399, 86400, 86401, 1<<31 - 1, 1782000000} {
		at := time.Unix(ts, 0).UTC()
		if got, want := periodNumber(at), identity.PeriodNumber(at); got != want {
			t.Errorf("periodNumber(%s) = %d, identity says %d", at, got, want)
		}
	}
	// And a negative instant, where both must refuse to wrap.
	before := time.Unix(-1, 0).UTC()
	if got, want := periodNumber(before), identity.PeriodNumber(before); got != want {
		t.Errorf("periodNumber(%s) = %d, identity says %d", before, got, want)
	}
}

// TestFetchPositionsPicksNoFixedFavourite.
//
// A client that always tried position 0 would make position 0's holders the
// only ones that matter -- the standing target eight positions exist to deny --
// and would leave the other seven unobservably broken.
func TestFetchPositionsPicksNoFixedFavourite(t *testing.T) {
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	kBlind, err := kBlindFor(20000)
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := HSDirPositions(kBlind, 20000, srv)
	if err != nil {
		t.Fatal(err)
	}
	index := map[string]int{}
	for i, k := range ordered {
		index[k.String()] = i
	}

	rng := mrand.New(mrand.NewSource(1))
	firsts := map[int]int{}
	const rounds = 2000
	for i := 0; i < rounds; i++ {
		keys, err := FetchPositions(kBlind, 20000, srv, rng)
		if err != nil {
			t.Fatal(err)
		}
		firsts[index[keys[0].String()]]++
	}
	if len(firsts) != DescriptorReplicaPositions {
		t.Errorf("only %d of %d positions were ever tried first",
			len(firsts), DescriptorReplicaPositions)
	}
	// Loose bound: this is a smoke test for "not fixed", not a uniformity proof.
	expected := rounds / DescriptorReplicaPositions
	for pos, n := range firsts {
		if n < expected/3 || n > expected*3 {
			t.Errorf("position %d chosen first %d times of %d, expected around %d",
				pos, n, rounds, expected)
		}
	}
}

// TestFastClockFindsNothingJustBeforeABoundary pins a KNOWN GAP.
//
// §9.4's overlap is one-directional: "two periods valid at once" means the
// current one and the PREVIOUS one, which covers a client whose clock is
// BEHIND. A client whose clock is AHEAD, in the moments before a boundary,
// derives period P+1 -- and nobody publishes P+1, so it finds nothing.
//
// This test asserts the gap rather than the fix, deliberately. Publishing P+1
// would make three periods live and cost another 64 holders, and it is not what
// the specification says; inventing it here would put the implementation ahead
// of the document with nothing recording why. If someone later decides the
// third period is worth it, THIS TEST FAILS, which is the point -- the decision
// has to be made in the specification and then here, not silently in one of
// them.
//
// The exposure is bounded by clock skew, not by the overlap: a client δ ahead
// has no descriptor for the δ before each boundary.
func TestFastClockFindsNothingJustBeforeABoundary(t *testing.T) {
	net := newNetwork(t, 400)
	kBlindFor, _ := blinder(t)
	srv := []byte("shared random value")
	p := &Publisher{Table: net.table, Store: net.store()}

	boundary := PeriodStart(20001)
	// The publisher's clock is right and it is just before the boundary.
	publisherNow := boundary.Add(-time.Minute)
	if _, err := p.PublishOnce(context.Background(), kBlindFor, srv, []byte("desc"), publisherNow); err != nil {
		t.Fatalf("PublishOnce: %v", err)
	}
	// A client two minutes fast has already rolled over.
	clientPeriod := periodNumber(publisherNow.Add(2 * time.Minute))
	if clientPeriod != 20001 {
		t.Fatalf("test setup: client period is %d, expected the next one", clientPeriod)
	}
	kBlind, err := kBlindFor(clientPeriod)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := HSDirPositions(kBlind, clientPeriod, srv)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if _, ok := net.fetch(k); ok {
			t.Fatal("the next period IS being published. That is a change to " +
				"§9.4's 'two periods valid at once' — update the specification " +
				"and this test together, or revert it.")
		}
	}
	t.Log("known gap confirmed: a client whose clock is ahead has no descriptor " +
		"for the skew before each boundary (§9.4's overlap covers only a stale clock)")
}
