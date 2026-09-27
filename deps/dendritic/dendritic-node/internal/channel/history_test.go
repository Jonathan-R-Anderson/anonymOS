package channel

// P7-d. Payment history, derived from the same engines that move the money.
//
// No injected records anywhere here: every entry exists because a payment
// created it, which is the only way the log and the money can be checked
// against each other.

import (
	"context"
	"net"
	"testing"
	"time"
)

func historyOf(t *testing.T, c *Coordinator, id [32]byte) []PaymentRecord {
	t.Helper()
	h, err := c.History(id)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	return h
}

func findRecord(t *testing.T, h []PaymentRecord, intent [32]byte) PaymentRecord {
	t.Helper()
	for _, r := range h {
		if r.Intent == intent {
			return r
		}
	}
	t.Fatalf("no record for intent %x in %d entries", intent[:4], len(h))
	return PaymentRecord{}
}

// ---- direct ---------------------------------------------------------------------

func TestADirectPaymentIsRecordedOnBothSides(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}

	out := findRecord(t, historyOf(t, payer.coord, id), intent(1))
	if out.Status != PayCompleted || out.Route != RouteDirect || out.Incoming {
		t.Fatalf("payer recorded %+v", out)
	}
	if out.Amount != anon(25).String() {
		t.Fatalf("amount %s", out.Amount)
	}
	if out.ResolvedAt == 0 || out.Nonce != 1 {
		t.Fatalf("payer record not resolved properly: %+v", out)
	}

	in := findRecord(t, historyOf(t, payee.coord, id), intent(1))
	if in.Status != PayCompleted || !in.Incoming {
		t.Fatalf("payee recorded %+v, want an incoming completion", in)
	}
}

// One intent, one record, however many times it is retried.
func TestRetryingAPaymentDoesNotDuplicateItsRecord(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	peer := directPeer{t, payee.coord}

	for i := 0; i < 3; i++ {
		if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25), peer); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	h := historyOf(t, payer.coord, id)
	if len(h) != 1 {
		t.Fatalf("%d records for one intent", len(h))
	}
	if h[0].Status != PayCompleted {
		t.Fatalf("status %s", h[0].Status)
	}
}

func TestARejectedPaymentIsRecordedAsRejected(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	// A lock expiring too soon: refused on policy.
	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: payer.clock + 10,
	}
	res, err := payer.coord.Pay(ctx, id, intent(1), add, directPeer{t, payee.coord})
	if err != nil {
		t.Fatalf("pay: %v", err)
	}
	if res.Rejected == "" {
		t.Fatal("the payment was not rejected")
	}
	rec := findRecord(t, historyOf(t, payer.coord, id), intent(1))
	if rec.Status != PayRejected {
		t.Fatalf("recorded %s, want rejected", rec.Status)
	}
	if rec.Detail == "" {
		t.Fatal("no reason recorded")
	}
}

// ---- THE ONE: unknown must be allowed to become the truth ------------------------

func TestAnUnknownOutcomeIsCorrectedByRecovery(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	// A peer that commits the payment and then hangs up without replying.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if env, err := ReadFrame(conn); err == nil {
			_, _ = payee.coord.Handle(ctx, env)
		}
	}()
	dead := &StreamPeer{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
		Timeout: 3 * time.Second,
	}

	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25), dead); err == nil {
		t.Fatal("the interrupted payment reported success")
	}
	<-done
	_ = ln.Close()

	// The payer does not know. It says so, rather than guessing either way.
	rec := findRecord(t, historyOf(t, payer.coord, id), intent(1))
	if rec.Status != PayUnknown {
		t.Fatalf("recorded %s, want unknown", rec.Status)
	}
	if rec.Resolved() {
		t.Fatal("unknown was treated as a settled outcome")
	}

	// The payee did complete it. Recovery finds that out.
	addr, stop := listening(t, payee.coord)
	defer stop()
	outcome, err := payer.coord.Recover(ctx, id, NewStreamPeer(addr))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome != ResyncAdopted {
		t.Fatalf("outcome %s", outcome)
	}

	// And the record changes to what actually happened. This is the phase.
	corrected := findRecord(t, historyOf(t, payer.coord, id), intent(1))
	if corrected.Status != PayCompleted {
		t.Fatalf("after recovery the record still says %s", corrected.Status)
	}
	if corrected.Nonce != 1 || corrected.ResolvedAt == 0 {
		t.Fatalf("corrected record incomplete: %+v", corrected)
	}
	// Still one record — corrected, not appended.
	if h := historyOf(t, payer.coord, id); len(h) != 1 {
		t.Fatalf("%d records after correction", len(h))
	}
}

// A completed payment is final: later noise must not reopen it.
func TestAResolvedRecordIsNotReopened(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	ch, _ := payer.coord.Channel(id)
	ch.NotePayment(PaymentRecord{Intent: intent(1), Status: PayUnknown})
	if got, _ := ch.PaymentAt(intent(1)); got.Status != PayCompleted {
		t.Fatalf("a completed payment was reopened as %s", got.Status)
	}
}

// ---- routed, through the real three-node rig --------------------------------------

func TestARoutedPaymentIsRecordedAsRoutedAtEachHop(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	preimage, hash := secret("recorded")

	if _, err := r.a.coord.Pay(ctx, r.upstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 20000,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("A→Hub: %v", err)
	}

	// While the lock is live it is IN FLIGHT, not completed — the money has not
	// arrived and saying so would be a lie an operator acts on.
	inflight := findRecord(t, historyOf(t, r.a.coord, r.upstream), intent(1))
	if inflight.Status != PayInFlight {
		t.Fatalf("a live lock recorded as %s", inflight.Status)
	}
	if inflight.Route != RouteRouted {
		t.Fatalf("route %s, want routed", inflight.Route)
	}
	if inflight.ResolvedAt != 0 {
		t.Fatal("an in-flight payment was marked resolved")
	}

	// B's side sees it arrive, also as routed and also in flight.
	pending := r.hub.fwd.Pending()
	if _, err := r.hub.fwd.Forward(ctx, pending[0], r.downstream, intent(2), peerAt(r.b)); err != nil {
		t.Fatalf("forward: %v", err)
	}
	bIn := findRecord(t, historyOf(t, r.b.coord, r.downstream), intent(2))
	if !bIn.Incoming || bIn.Route != RouteRouted || bIn.Status != PayInFlight {
		t.Fatalf("B recorded %+v", bIn)
	}

	// B settles: its own record of the settlement completes.
	if _, err := r.b.coord.Pay(ctx, r.downstream, intent(3), StateTransition{
		Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: preimage,
	}, peerAt(r.hub)); err != nil {
		t.Fatalf("B settle: %v", err)
	}
	settle := findRecord(t, historyOf(t, r.b.coord, r.downstream), intent(3))
	if settle.Status != PayCompleted || settle.Route != RouteRouted {
		t.Fatalf("settlement recorded as %+v", settle)
	}

	// The hub's log shows both halves of what it did.
	hubUp := historyOf(t, r.hub.coord, r.upstream)
	hubDown := historyOf(t, r.hub.coord, r.downstream)
	if len(hubUp) == 0 || len(hubDown) == 0 {
		t.Fatalf("hub recorded %d upstream and %d downstream", len(hubUp), len(hubDown))
	}
	for _, r := range append(append([]PaymentRecord{}, hubUp...), hubDown...) {
		if r.Route != RouteRouted {
			t.Fatalf("the hub recorded %s as %s", r.Kind, r.Route)
		}
	}
}

// The failure ending is recorded as a refund, not as a completion and not as a
// silence.
func TestAnExpiredRouteIsRecordedAsRefunded(t *testing.T) {
	r := newRoute(t, 1000)
	defer r.stop()
	ctx := context.Background()
	_, hash := secret("never claimed")

	if _, err := r.hub.coord.Pay(ctx, r.downstream, intent(1), StateTransition{
		Kind: KindLockAdd, Amount: anon(100), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: r.clock + 5000,
	}, peerAt(r.b)); err != nil {
		t.Fatalf("lock: %v", err)
	}
	r.advance(6000)
	if problems := r.hub.fwd.RefundExpired(ctx, func([32]byte) (Peer, error) {
		return peerAt(r.b), nil
	}); len(problems) != 0 {
		t.Fatalf("refund: %v", problems)
	}

	h := historyOf(t, r.hub.coord, r.downstream)
	var refund PaymentRecord
	for _, rec := range h {
		if rec.Kind == KindLockRefund {
			refund = rec
		}
	}
	if refund.Status != PayRefunded {
		t.Fatalf("refund recorded as %q in %d entries", refund.Status, len(h))
	}
	if refund.ResolvedAt == 0 {
		t.Fatal("the refund was not marked resolved")
	}
}

// ---- what history is NOT ----------------------------------------------------------

// History holds no balance. It answers what happened to a payment, not what the
// channel is worth — and a second copy of a balance is a number that can
// disagree with the money.
func TestHistoryCarriesNoBalance(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	rec := findRecord(t, historyOf(t, payer.coord, id), intent(1))

	// The only amount is what MOVED.
	if rec.Amount != anon(25).String() {
		t.Fatalf("amount %s", rec.Amount)
	}
	bal, _ := payer.coord.Balances(id)
	if rec.Amount == bal.Mine.String() {
		t.Fatal("the record appears to be carrying a balance rather than a movement")
	}
}

// It survives a restart, because it is written with the state it describes.
func TestHistorySurvivesARestart(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	reopened, err := OpenStore(payer.dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	ch, ok := reopened.Get(id)
	if !ok {
		t.Fatal("channel missing")
	}
	rec, found := ch.PaymentAt(intent(1))
	if !found || rec.Status != PayCompleted {
		t.Fatalf("after restart: %+v found=%v", rec, found)
	}
}

// The log is bounded, so a busy channel does not make every later payment more
// expensive to write than the one before it.
func TestHistoryIsBounded(t *testing.T) {
	ch := &Channel{}
	for i := 0; i < historyCap+50; i++ {
		ch.NotePayment(PaymentRecord{Intent: [32]byte{byte(i / 256), byte(i % 256)}, Status: PayCompleted})
	}
	if len(ch.History) != historyCap {
		t.Fatalf("history grew to %d, cap is %d", len(ch.History), historyCap)
	}
}
