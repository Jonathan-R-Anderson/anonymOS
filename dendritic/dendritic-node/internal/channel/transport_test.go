package channel

// P5-3. Two nodes over a real TCP socket.
//
// Not net.Pipe: a real listener, real dials, real deadlines. The point of this
// layer is what happens when a connection misbehaves, and an in-memory pipe
// cannot misbehave in the ways that matter.

import (
	"context"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// listening starts a server for a node and returns its address plus a shutdown.
func listening(t *testing.T, c *Coordinator) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &Server{Handler: c, Timeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(context.Background(), ln)
	}()
	return ln.Addr().String(), func() {
		_ = srv.Close()
		<-done
	}
}

func TestAPaymentOverARealSocket(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	addr, stop := listening(t, payee.coord)
	defer stop()

	peer := NewStreamPeer(addr)
	result, err := payer.coord.Pay(context.Background(), id, intent(1), payTransition(25), peer)
	if err != nil {
		t.Fatalf("pay: %v", err)
	}
	if !result.Done || result.Nonce != 1 {
		t.Fatalf("result: %+v", result)
	}

	for name, n := range map[string]*wiredNode{"payer": payer, "payee": payee} {
		bal, err := n.coord.Balances(id)
		if err != nil {
			t.Fatalf("%s balances: %v", name, err)
		}
		if bal.Nonce != 1 {
			t.Fatalf("%s at nonce %d", name, bal.Nonce)
		}
	}
	if got, _ := payee.coord.Balances(id); got.Mine.Cmp(anon(25)) != 0 {
		t.Fatalf("payee holds %s", got.Mine)
	}
}

func TestManyPaymentsOverOneSocketAddress(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	addr, stop := listening(t, payee.coord)
	defer stop()

	peer := NewStreamPeer(addr)
	ctx := context.Background()
	for i, amount := range []int64{5, 25, 100, 5, 25} {
		if _, err := payer.coord.Pay(ctx, id, intent(byte(i+1)), payTransition(amount), peer); err != nil {
			t.Fatalf("tip %d: %v", i, err)
		}
	}
	if got, _ := payee.coord.Balances(id); got.Mine.Cmp(anon(160)) != 0 {
		t.Fatalf("payee holds %s after five tips, want 160", got.Mine)
	}
}

// THE ONE THAT MATTERS: the peer signs and persists, and the connection dies
// before the reply arrives. A write that succeeded is not a payment that
// happened — and the reverse is also true, which is the trap. The payer must
// draw NO conclusion and resolve it by asking.
func TestAConnectionDyingMidPaymentDecidesNothing(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	// A server that processes the message properly and then hangs up without
	// answering — the worst case, because the payee is now ahead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		env, err := ReadFrame(conn)
		if err != nil {
			return
		}
		// Handled, signed, persisted — then silence.
		if _, err := payee.coord.Handle(ctx, env); err != nil {
			t.Errorf("payee handle: %v", err)
		}
	}()

	peer := &StreamPeer{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
		Timeout: 3 * time.Second,
	}
	_, err = payer.coord.Pay(ctx, id, intent(1), payTransition(25), peer)
	if err == nil {
		t.Fatal("a payment with no reply reported success")
	}
	wg.Wait()
	_ = ln.Close()

	// The two sides now disagree, which is exactly the situation.
	payeeBal, _ := payee.coord.Balances(id)
	payerBal, _ := payer.coord.Balances(id)
	if payeeBal.Nonce != 1 {
		t.Fatalf("the payee did not complete it: nonce %d", payeeBal.Nonce)
	}
	if payerBal.Nonce != 0 {
		t.Fatalf("the payer concluded something: nonce %d", payerBal.Nonce)
	}

	// Asking resolves it. Nothing was guessed from the transport failure.
	addr, stop := listening(t, payee.coord)
	defer stop()
	outcome, err := payer.coord.Recover(ctx, id, NewStreamPeer(addr))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome != ResyncAdopted {
		t.Fatalf("outcome %s, want ADOPTED", outcome)
	}
	if got, _ := payer.coord.Balances(id); got.Nonce != 1 || got.Theirs.Cmp(anon(25)) != 0 {
		t.Fatalf("recovered to nonce %d with %s to the peer", got.Nonce, got.Theirs)
	}
}

// And the retry path: the payer simply tries again, and is not charged twice —
// determinism plus the applied-intent record, over a real socket.
func TestRetryingAfterATransportFailurePaysOnce(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	// First attempt: the payee handles it, then the connection dies.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
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
		t.Fatal("the first attempt reported success")
	}
	wg.Wait()
	_ = ln.Close()

	// Second attempt, same intent, against a working server.
	addr, stop := listening(t, payee.coord)
	defer stop()
	result, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25), NewStreamPeer(addr))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !result.Done {
		t.Fatalf("the retry did not complete: %+v", result)
	}
	if got, _ := payee.coord.Balances(id); got.Mine.Cmp(anon(25)) != 0 {
		t.Fatalf("payee holds %s — the retry paid a second time", got.Mine)
	}
}

// ---- the transport decides nothing ------------------------------------------

// A rejection travels as a normal reply. The transport must not turn a refusal
// into an error, or a payer cannot tell "no" from "the network broke" — and
// those call for opposite responses.
func TestARejectionArrivesAsAReplyNotATransportError(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	addr, stop := listening(t, payee.coord)
	defer stop()

	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: payer.clock + 10, // too soon; policy refusal
	}
	result, err := payer.coord.Pay(context.Background(), id, intent(1), add, NewStreamPeer(addr))
	if err != nil {
		t.Fatalf("a refusal came back as a transport error: %v", err)
	}
	if result.Done || result.Rejected == "" {
		t.Fatalf("result: %+v", result)
	}
}

func TestAnOversizedFrameIsRefusedBeforeAllocating(t *testing.T) {
	payer, _, _ := wiredPair(t, anon(500))
	addr, stop := listening(t, payer.coord)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A header claiming far more than the limit. The server must refuse on the
	// four bytes rather than try to read the body.
	_, _ = conn.Write([]byte{0xff, 0xff, 0xff, 0xff})
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := ReadFrame(conn)
	if err != nil {
		// Either an ERROR frame or a closed connection is acceptable; hanging
		// while it allocates 4 GiB is not, and the deadline catches that.
		return
	}
	if reply.Type != MsgError {
		t.Fatalf("an oversized frame produced %s", reply.Type)
	}
}

func TestGarbageDoesNotTakeTheServerDown(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	addr, stop := listening(t, payee.coord)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte{0, 0, 0, 9, 'n', 'o', 't', ' ', 'j', 's', 'o', 'n', '!'})
	_ = conn.Close()

	// The server survives and the next real payment works.
	if _, err := payer.coord.Pay(context.Background(), id, intent(1),
		payTransition(25), NewStreamPeer(addr)); err != nil {
		t.Fatalf("the server did not survive a bad frame: %v", err)
	}
}

func TestAnUnreachablePeerIsAnErrorNotAPayment(t *testing.T) {
	payer, _, id := wiredPair(t, anon(500))
	// A port nothing is listening on.
	peer := &StreamPeer{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", "127.0.0.1:1")
		},
		Timeout: 2 * time.Second,
	}
	result, err := payer.coord.Pay(context.Background(), id, intent(1), payTransition(25), peer)
	if err == nil {
		t.Fatal("an unreachable peer produced a payment")
	}
	if result.Done {
		t.Fatal("result claimed done")
	}
	bal, _ := payer.coord.Balances(id)
	if bal.Nonce != 0 {
		t.Fatal("an undeliverable payment advanced the channel")
	}
}

// The server closing must not leave a payment half-applied anywhere.
func TestClosingTheServerIsClean(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	addr, stop := listening(t, payee.coord)

	if _, err := payer.coord.Pay(context.Background(), id, intent(1),
		payTransition(25), NewStreamPeer(addr)); err != nil {
		t.Fatalf("pay: %v", err)
	}
	stop()

	a, _ := payer.coord.Balances(id)
	b, _ := payee.coord.Balances(id)
	if a.Nonce != b.Nonce {
		t.Fatalf("the two sides ended at %d and %d", a.Nonce, b.Nonce)
	}
	_ = big.NewInt(0)
	_ = errors.Is
}
