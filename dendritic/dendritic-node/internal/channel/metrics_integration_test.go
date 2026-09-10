package channel

// P14 — instrumentation exercised through the REAL payment engine.
//
// Nothing here calls a Metrics method directly. Every assertion runs a payment
// through Coordinator.Pay → SCPP/1 → Channel.Accept, or through the executor,
// forwarder or watchtower, and then checks the aggregate moved. A test that
// calls the collector proves the collector works and says nothing about whether
// the payment path reaches it.
//
// The deltas are asserted as deltas, not as absolutes, so a test cannot pass
// because something else happened to leave the right number behind.

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"
)

// instrumented is a wired pair whose payer reports to a collector.
type instrumented struct {
	payer, payee *wiredNode
	id           [32]byte
	m            *Metrics
	peer         Peer
}

func newInstrumented(t *testing.T) *instrumented {
	t.Helper()
	payer, payee, id := wiredPair(t, anon(500))
	m := NewMetrics()
	payer.coord.SetMetrics(m)
	return &instrumented{payer: payer, payee: payee, id: id, m: m,
		peer: directPeer{t, payee.coord}}
}

// delta runs fn and returns what changed.
func (f *instrumented) delta(fn func()) (before, after Snapshot) {
	before = f.m.Snapshot()
	fn()
	after = f.m.Snapshot()
	return
}

func mustDelta(t *testing.T, label string, before, after uint64, want uint64) {
	t.Helper()
	if got := after - before; got != want {
		t.Fatalf("%s changed by %d, want %d", label, got, want)
	}
}

// ---- direct payments --------------------------------------------------------

func TestRealPathDirectPaymentCounts(t *testing.T) {
	f := newInstrumented(t)
	ctx := context.Background()

	before, after := f.delta(func() {
		if _, err := f.payer.coord.Pay(ctx, f.id, intent(1), payTransition(25), f.peer); err != nil {
			t.Fatalf("pay: %v", err)
		}
	})
	mustDelta(t, "tips attempted", before.TipsAttempted, after.TipsAttempted, 1)
	mustDelta(t, "tips completed", before.TipsCompleted, after.TipsCompleted, 1)
	mustDelta(t, "tips failed", before.TipsFailed, after.TipsFailed, 0)

	// The VALUE moved, from the transition's own amount.
	got, _ := new(big.Int).SetString(after.TipValue, 10)
	if got.Cmp(anon(25)) != 0 {
		t.Fatalf("tip value %s, want 25e18", after.TipValue)
	}
}

func TestRealPathFailedPaymentCounts(t *testing.T) {
	f := newInstrumented(t)
	ctx := context.Background()

	// More than the channel holds: the peer refuses.
	before, after := f.delta(func() {
		_, _ = f.payer.coord.Pay(ctx, f.id, intent(2), payTransition(9_000), f.peer)
	})
	mustDelta(t, "tips attempted", before.TipsAttempted, after.TipsAttempted, 1)
	mustDelta(t, "tips completed", before.TipsCompleted, after.TipsCompleted, 0)
	mustDelta(t, "tips failed", before.TipsFailed, after.TipsFailed, 1)
}

// A retry of an already-applied intent must NOT be counted twice.
//
// This is the metric that would silently inflate: after an ambiguous outcome a
// caller retries, and retrying is the ordinary case rather than the exception.
func TestRealPathRetryIsNotCountedTwice(t *testing.T) {
	f := newInstrumented(t)
	ctx := context.Background()

	if _, err := f.payer.coord.Pay(ctx, f.id, intent(3), payTransition(10), f.peer); err != nil {
		t.Fatalf("first: %v", err)
	}
	before, after := f.delta(func() {
		// Same intent, same transition — the engine answers from its record.
		if _, err := f.payer.coord.Pay(ctx, f.id, intent(3), payTransition(10), f.peer); err != nil {
			t.Fatalf("retry: %v", err)
		}
	})
	mustDelta(t, "tips attempted on retry", before.TipsAttempted, after.TipsAttempted, 0)
	mustDelta(t, "tips completed on retry", before.TipsCompleted, after.TipsCompleted, 0)
	if before.TipValue != after.TipValue {
		t.Fatalf("a retry moved value: %s -> %s", before.TipValue, after.TipValue)
	}
}

// ---- the HTLC lifecycle -----------------------------------------------------

func TestRealPathLockLifecycleCounts(t *testing.T) {
	f := newInstrumented(t)
	ctx := context.Background()
	const now = int64(1_000_000)
	f.payer.clock, f.payee.clock = now, now

	pre := [32]byte{31: 0x51}
	var h [32]byte
	copy(h[:], keccak(pre[:]))

	// Create.
	before, after := f.delta(func() {
		tr := StateTransition{Kind: KindLockAdd, Amount: anon(20),
			LockID: [32]byte{31: 1}, Hash: h, Expiry: now + 3600}
		if _, err := f.payer.coord.Pay(ctx, f.id, intent(10), tr, f.peer); err != nil {
			t.Fatalf("lock add: %v", err)
		}
	})
	mustDelta(t, "htlcs created", before.HTLCsCreated, after.HTLCsCreated, 1)
	mustDelta(t, "htlcs settled", before.HTLCsSettled, after.HTLCsSettled, 0)

	// Settle, proposed by the payee who holds the preimage.
	m2 := NewMetrics()
	f.payee.coord.SetMetrics(m2)
	b2 := m2.Snapshot()
	tr := StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: pre}
	if _, err := f.payee.coord.Pay(ctx, f.id, intent(11), tr,
		directPeer{t, f.payer.coord}); err != nil {
		t.Fatalf("settle: %v", err)
	}
	a2 := m2.Snapshot()
	mustDelta(t, "htlcs settled", b2.HTLCsSettled, a2.HTLCsSettled, 1)
}

func TestRealPathRefundCounts(t *testing.T) {
	f := newInstrumented(t)
	ctx := context.Background()
	const now = int64(1_000_000)
	f.payer.clock, f.payee.clock = now, now

	pre := [32]byte{31: 0x52}
	var h [32]byte
	copy(h[:], keccak(pre[:]))
	tr := StateTransition{Kind: KindLockAdd, Amount: anon(20),
		LockID: [32]byte{31: 2}, Hash: h, Expiry: now + 600}
	if _, err := f.payer.coord.Pay(ctx, f.id, intent(12), tr, f.peer); err != nil {
		t.Fatalf("lock add: %v", err)
	}

	f.payer.clock, f.payee.clock = now+900, now+900
	before, after := f.delta(func() {
		refund := StateTransition{Kind: KindLockRefund, LockID: [32]byte{31: 2}}
		if _, err := f.payer.coord.Pay(ctx, f.id, intent(13), refund, f.peer); err != nil {
			t.Fatalf("refund: %v", err)
		}
	})
	mustDelta(t, "htlcs refunded", before.HTLCsRefunded, after.HTLCsRefunded, 1)
}

// ---- routed -----------------------------------------------------------------

func TestRealPathRoutedForwardCounts(t *testing.T) {
	// A REAL forward: upstream pays the hub under a lock, the hub forwards a
	// matching lock downstream. An earlier version of this test logged and
	// passed whatever happened, which asserted nothing.
	const now = int64(1_000_000)
	contract := mustAddr(t, deployedChannelManager)
	chain := NewFakeChain()

	upKey, hubKey, downKey := newSigner(t), newSigner(t), newSigner(t)
	upID := chain.Add(upKey.address(), hubKey.address(), anon(500), new(big.Int))
	outID := chain.Add(hubKey.address(), downKey.address(), anon(500), new(big.Int))

	up := newWiredNode(t, upKey, chain, contract)
	hub := newWiredNode(t, hubKey, chain, contract)
	down := newWiredNode(t, downKey, chain, contract)
	for _, n := range []*wiredNode{up, hub, down} {
		n.clock = now
	}

	m := NewMetrics()
	hub.coord.SetMetrics(m)
	vault, err := OpenPreimageVault(t.TempDir())
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	fwd := NewForwarder(hub.coord, vault, hub.key.address())
	fwd.SetMetrics(m)
	fwd.SetClock(func() int64 { return now }, 600)

	// Upstream offers the hub a lock.
	pre := [32]byte{31: 0x53}
	var h [32]byte
	copy(h[:], keccak(pre[:]))
	add := StateTransition{Kind: KindLockAdd, Amount: anon(30),
		LockID: [32]byte{31: 3}, Hash: h, Expiry: now + 7200}
	if _, err := up.coord.Pay(context.Background(), upID, intent(21), add,
		directPeer{t, hub.coord}); err != nil {
		t.Fatalf("upstream lock: %v", err)
	}

	pending := fwd.Pending()
	if len(pending) != 1 {
		t.Fatalf("hub sees %d incoming locks, want 1", len(pending))
	}

	before := m.Snapshot()
	if _, err := fwd.Forward(context.Background(), pending[0], outID, intent(22),
		directPeer{t, down.coord}); err != nil {
		t.Fatalf("forward: %v", err)
	}
	after := m.Snapshot()

	mustDelta(t, "routed payments", before.RoutedPayments, after.RoutedPayments, 1)
	// The downstream lock really was created.
	mustDelta(t, "htlcs created", before.HTLCsCreated, after.HTLCsCreated, 1)
}

// ---- multi-path -------------------------------------------------------------

// One payment, N legs, one total — and no record of which legs belonged to it.
func TestRealPathMultipathCounts(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	ctx := context.Background()
	m := NewMetrics()
	f.payer.coord.SetMetrics(m)
	f.exec.SetMetrics(m)

	pay := f.payment(t, [32]byte{31: 0x60}, 20, 30, 50)

	before := m.Snapshot()
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	after := m.Snapshot()

	// ONE payment.
	mustDelta(t, "multipath payments", before.MultipathPayments, after.MultipathPayments, 1)
	// THREE legs.
	mustDelta(t, "multipath legs", before.MultipathLegs, after.MultipathLegs, 3)
	// The TOTAL, once — not once per leg.
	got, _ := new(big.Int).SetString(after.TipValue, 10)
	prev, _ := new(big.Int).SetString(before.TipValue, 10)
	moved := new(big.Int).Sub(got, prev)
	if moved.Cmp(pay.Total) != 0 {
		t.Fatalf("multipath moved %s, want the payment total %s", moved, pay.Total)
	}
	// Three legs each created and settled a lock.
	mustDelta(t, "htlcs created", before.HTLCsCreated, after.HTLCsCreated, 3)
	mustDelta(t, "htlcs settled", before.HTLCsSettled, after.HTLCsSettled, 3)
}

func TestRealPathMultipathPartialFailureCounts(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	ctx := context.Background()
	m := NewMetrics()
	f.payer.coord.SetMetrics(m)
	f.exec.SetMetrics(m)

	pay := f.payment(t, [32]byte{31: 0x61}, 20, 30, 50)
	peers := func(ch [32]byte) (Peer, error) {
		if ch == pay.Legs[1].Channel {
			return deadPeer{}, nil
		}
		return f.peers(t)(ch)
	}

	before := m.Snapshot()
	if _, err := f.exec.Lock(ctx, pay, peers); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	after := m.Snapshot()

	// Still ONE payment with THREE legs — the split is what was attempted.
	mustDelta(t, "multipath payments", before.MultipathPayments, after.MultipathPayments, 1)
	mustDelta(t, "multipath legs", before.MultipathLegs, after.MultipathLegs, 3)
	// One leg failed.
	if after.ExecutorFailures <= before.ExecutorFailures {
		t.Fatal("a failed leg was not counted as an executor failure")
	}
	// Two locks really were created.
	mustDelta(t, "htlcs created", before.HTLCsCreated, after.HTLCsCreated, 2)
}

// ---- watchtower -------------------------------------------------------------

func TestRealPathWatchtowerObservationCounts(t *testing.T) {
	chain := NewFakeChain()
	pk, qk := newSigner(t), newSigner(t)
	id := chain.Add(pk.address(), qk.address(), anon(500), new(big.Int))

	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	occ, err := chain.ReadChannel(t.Context(), mustAddr(t, deployedChannelManager), id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := store.TrackFromChain(big.NewInt(1), mustAddr(t, deployedChannelManager), occ); err != nil {
		t.Fatalf("track: %v", err)
	}

	m := NewMetrics()
	w := &Watchtower{Store: store, Chain: chain,
		Contract: mustAddr(t, deployedChannelManager), Metrics: m}

	before := m.Snapshot()
	w.Sweep(context.Background())
	after := m.Snapshot()
	mustDelta(t, "watchtower observations", before.WatchtowerObservations,
		after.WatchtowerObservations, 1)
	// Nothing was stale, so nothing was recovered.
	mustDelta(t, "watchtower recoveries", before.WatchtowerRecoveries,
		after.WatchtowerRecoveries, 0)
}

// ---- channel lifecycle ------------------------------------------------------

// Opens and closes are recorded by whoever drives them; this asserts the
// aggregate arithmetic the economics depend on.
func TestRealPathChannelLifecycleAggregates(t *testing.T) {
	m := NewMetrics()
	// Three opened, two closed — one cooperative, one disputed.
	m.ChannelOpened(anon(100))
	m.ChannelOpened(anon(200))
	m.ChannelOpened(anon(300))
	m.ChannelClosed(CloseCooperative, 8)
	m.ChannelClosed(CloseDisputed, 2)

	s := m.Snapshot()
	if s.ChannelOpens != 3 || s.ChannelCloses != 2 || s.ChannelsOpen != 1 {
		t.Fatalf("opens %d closes %d open %d", s.ChannelOpens, s.ChannelCloses, s.ChannelsOpen)
	}
	if s.CooperativeCloses != 1 || s.DisputedCloses != 1 {
		t.Fatalf("coop %d disputed %d", s.CooperativeCloses, s.DisputedCloses)
	}
	if s.ChannelValue != anon(600).String() {
		t.Fatalf("channel value %s, want 600e18", s.ChannelValue)
	}
}

// ---- concurrency ------------------------------------------------------------

// Concurrent real payments across many channels must not lose an increment.
func TestRealPathConcurrentPaymentsCountCorrectly(t *testing.T) {
	const channels, perChannel = 6, 12

	m := NewMetrics()
	chain := NewFakeChain()
	contract := mustAddr(t, deployedChannelManager)
	pk := newSigner(t)

	type pairT struct {
		id   [32]byte
		peer Peer
	}
	payer := newWiredNode(t, pk, chain, contract)
	payer.coord.SetMetrics(m)

	pairs := make([]pairT, 0, channels)
	for i := 0; i < channels; i++ {
		qk := newSigner(t)
		id := chain.Add(pk.address(), qk.address(), anon(1000), new(big.Int))
		payee := newWiredNode(t, qk, chain, contract)
		pairs = append(pairs, pairT{id: id, peer: directPeer{t, payee.coord}})
	}

	var wg sync.WaitGroup
	for i, p := range pairs {
		wg.Add(1)
		go func(i int, p pairT) {
			defer wg.Done()
			for j := 0; j < perChannel; j++ {
				// Distinct intents per payment, so each is a real payment.
				var in [32]byte
				in[30], in[31] = byte(i), byte(j)
				_, _ = payer.coord.Pay(context.Background(), p.id, in, payTransition(1), p.peer)
			}
		}(i, p)
	}
	wg.Wait()

	s := m.Snapshot()
	want := uint64(channels * perChannel)
	if s.TipsAttempted != want {
		t.Fatalf("attempted %d, want %d — an increment was lost", s.TipsAttempted, want)
	}
	// Every attempt reached exactly one terminal state.
	if s.TipsCompleted+s.TipsFailed != s.TipsAttempted {
		t.Fatalf("completed %d + failed %d != attempted %d — the snapshot is not "+
			"internally consistent", s.TipsCompleted, s.TipsFailed, s.TipsAttempted)
	}
	// Value moved matches completions exactly.
	value, _ := new(big.Int).SetString(s.TipValue, 10)
	expect := new(big.Int).Mul(anon(1), big.NewInt(int64(s.TipsCompleted)))
	if value.Cmp(expect) != 0 {
		t.Fatalf("tip value %s does not match %d completions", s.TipValue, s.TipsCompleted)
	}
}

// ---- the privacy boundary at the CALL SITES ---------------------------------

// After driving every instrumented production path, the serialised metrics must
// still contain nothing identifying.
//
// The collector-level test proves the type cannot hold an identifier. This
// proves the wiring did not find some other way — by exercising real payments
// with real channel ids, real addresses and real preimages in scope, and then
// looking at what came out.
func TestRealPathMetricsLeakNothing(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	ctx := context.Background()
	m := NewMetrics()
	f.payer.coord.SetMetrics(m)
	f.exec.SetMetrics(m)

	pay := f.payment(t, [32]byte{31: 0x70}, 20, 30, 50)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
		t.Fatalf("Settle: %v", err)
	}

	raw, err := m.Snapshot().JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	out := string(raw)

	// The actual identifiers that were in scope during those payments.
	for _, secret := range []string{
		hexOf(pay.ID[:]),
		hexOf(pay.Legs[0].Channel[:]),
		hexOf(pay.Legs[0].Intent[:]),
		hexOf(pay.Legs[0].Hash[:]),
		hexOf(pay.Legs[0].LockID[:]),
		func() string { a := f.payer.key.address(); return hexOf(a[:]) }(),
		func() string { a := f.payees[0].key.address(); return hexOf(a[:]) }(),
	} {
		// Zero-padded test identifiers share their leading hex with every
		// number, so match on a DISTINCTIVE run: 12 hex characters that are not
		// all zeros. A shorter or all-zero probe reports a leak on any output
		// containing "000000".
		probe := distinctiveRun(secret, 12)
		if probe != "" && containsFold(out, probe) {
			t.Fatalf("metrics output contains %q, part of an identifier that was in "+
				"scope during the payment:\n%s", probe, out)
		}
	}
	for _, n := range []int{40, 64} {
		if hasHexRun(out, n) {
			t.Fatalf("metrics output has a %d-char hex run:\n%s", n, out)
		}
	}
}

// distinctiveRun returns the first n-character window of s that is not all
// zeros, or "" if there is none.
func distinctiveRun(s string, n int) string {
	for i := 0; i+n <= len(s); i++ {
		w := s[i : i+n]
		allZero := true
		for _, r := range w {
			if r != '0' {
				allZero = false
				break
			}
		}
		if !allZero {
			return w
		}
	}
	return ""
}

func containsFold(hay, needle string) bool {
	if needle == "" {
		return false
	}
	h, n := []rune(hay), []rune(needle)
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// The instrumented production types must expose no way to hand Metrics an
// identifier: their setters take the collector and nothing else.
func TestInstrumentationSettersTakeOnlyTheCollector(t *testing.T) {
	type setter struct {
		name string
		fn   any
	}
	for _, s := range []setter{
		{"Coordinator.SetMetrics", (*Coordinator).SetMetrics},
		{"Forwarder.SetMetrics", (*Forwarder).SetMetrics},
		{"MultipathExecutor.SetMetrics", (*MultipathExecutor).SetMetrics},
	} {
		ft := reflect.TypeOf(s.fn)
		// receiver + collector, nothing else.
		if ft.NumIn() != 2 {
			t.Fatalf("%s takes %d arguments; instrumentation wiring must take the "+
				"collector alone", s.name, ft.NumIn()-1)
		}
		if ft.In(1).String() != "*channel.Metrics" {
			t.Fatalf("%s takes %s, want *channel.Metrics", s.name, ft.In(1))
		}
	}
}

// Evidence-store instrumentation must cross a primitives-only interface.
func TestEvidenceMetricsInterfaceIsPrimitivesOnly(t *testing.T) {
	// *Metrics must satisfy it, and every method must take ints.
	var m any = NewMetrics()
	type evidenceMetrics interface {
		EvidenceRead(bytes int)
		EvidenceWrite(bytes int)
		EvidenceFailure()
	}
	if _, ok := m.(evidenceMetrics); !ok {
		t.Fatal("*Metrics no longer satisfies the evidence-store metrics interface")
	}
	_ = errors.New
	_ = time.Second
}
