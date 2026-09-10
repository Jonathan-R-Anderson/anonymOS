package channel

// SCPP/1 §6, §7, §8. The handshake, resync, and every crash point in the table.
//
// The harness deliberately never passes a state between the two nodes except as
// a serialised Envelope, so a field this package forgets to encode shows up as a
// failing test rather than as two nodes that agree only because they share
// memory.

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"testing"
)

// node is one participant: its own store, on its own disk, plus a session.
type node struct {
	t     *testing.T
	dir   string
	store *Store
	sess  *PeerSession
	key   *signer
	clock int64
}

func newNode(t *testing.T, key *signer, dir string) *node {
	t.Helper()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	n := &node{t: t, dir: dir, store: store, key: key, clock: 1_000_000}
	n.sess = NewPeerSession(store, key.address(), func(raw [32]byte) ([]byte, error) {
		return key.sign(raw), nil
	})
	n.sess.SetClock(func() int64 { return n.clock }, 30, 600)
	return n
}

// restart drops the process and comes back from disk. Everything not persisted
// is gone, which is the point.
func (n *node) restart() {
	n.t.Helper()
	store, err := OpenStore(n.dir)
	if err != nil {
		n.t.Fatalf("restart: %v", err)
	}
	n.store = store
	n.sess = NewPeerSession(store, n.key.address(), func(raw [32]byte) ([]byte, error) {
		return n.key.sign(raw), nil
	})
	n.sess.SetClock(func() int64 { return n.clock }, 30, 600)
}

// track registers a channel the way the node must: by reading the chain, never
// by believing a peer. The FakeChain stands in for ChannelManagerV2.
func (n *node) track(chain *FakeChain, ch *Channel) {
	n.t.Helper()
	occ, err := chain.ReadChannel(context.Background(), ch.Contract, ch.ID)
	if err != nil {
		n.t.Fatalf("chain read: %v", err)
	}
	if err := n.store.TrackFromChain(ch.ChainID, ch.Contract, occ); err != nil {
		n.t.Fatalf("track: %v", err)
	}
}

func (n *node) latest(id [32]byte) State {
	n.t.Helper()
	ch, ok := n.store.Get(id)
	if !ok {
		n.t.Fatal("channel missing")
	}
	return ch.Latest.State
}

func (n *node) balanceOf(id [32]byte, who Address) string {
	n.t.Helper()
	ch, _ := n.store.Get(id)
	return ch.BalanceOf(who).String()
}

// hop serialises a message and reads it back, so nothing crosses by reference.
func hop(t *testing.T, env Envelope) Envelope {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteFrame(&buf, env); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

// pair builds a funded channel known to both nodes.
func pair(t *testing.T) (payer, payee *node, id [32]byte) {
	t.Helper()
	pk, qk := newSigner(t), newSigner(t)
	payer = newNode(t, pk, t.TempDir())
	payee = newNode(t, qk, t.TempDir())

	ch := newFundedChannel(t, pk, qk, anon(500))
	chain := NewFakeChain()
	chain.Add(ch.PartyA, ch.PartyB, ch.DepositA, ch.DepositB)
	payer.track(chain, ch)
	payee.track(chain, ch)
	return payer, payee, ch.ID
}

func intent(n byte) [32]byte { return [32]byte{31: n} }

func payTransition(amount int64) StateTransition {
	return StateTransition{Kind: KindPay, Amount: anon(amount)}
}

// ---- the normal path (§6) --------------------------------------------------

func TestAPaymentCompletesAndBothSidesAgree(t *testing.T) {
	payer, payee, id := pair(t)

	propose, err := payer.sess.Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	reply, err := payee.sess.HandlePropose(hop(t, propose))
	if err != nil {
		t.Fatalf("handle propose: %v", err)
	}
	if reply.Type != MsgStateAccept {
		t.Fatalf("payee replied %s, not an acceptance", reply.Type)
	}
	if err := payer.sess.HandleAccept(hop(t, reply)); err != nil {
		t.Fatalf("handle accept: %v", err)
	}

	if got := payer.balanceOf(id, payee.key.address()); got != anon(25).String() {
		t.Fatalf("payer thinks the payee holds %s", got)
	}
	if got := payee.balanceOf(id, payee.key.address()); got != anon(25).String() {
		t.Fatalf("payee thinks it holds %s", got)
	}
	if payer.latest(id).Nonce != 1 || payee.latest(id).Nonce != 1 {
		t.Fatal("the two sides are at different nonces")
	}
}

func TestManyPaymentsWalkTheChannel(t *testing.T) {
	payer, payee, id := pair(t)
	for i, amount := range []int64{5, 25, 100, 5, 25} {
		propose, err := payer.sess.Propose(id, intent(byte(i+1)), payTransition(amount))
		if err != nil {
			t.Fatalf("tip %d: %v", i, err)
		}
		reply, err := payee.sess.HandlePropose(hop(t, propose))
		if err != nil {
			t.Fatalf("tip %d: %v", i, err)
		}
		if reply.Type != MsgStateAccept {
			var r StateRejectBody
			_ = reply.Body_(&r)
			t.Fatalf("tip %d rejected: %s %s", i, r.Code, r.Detail)
		}
		if err := payer.sess.HandleAccept(hop(t, reply)); err != nil {
			t.Fatalf("tip %d: %v", i, err)
		}
	}
	if got := payee.balanceOf(id, payee.key.address()); got != anon(160).String() {
		t.Fatalf("payee holds %s after five tips, want 160", got)
	}
}

// ---- determinism and idempotence (§5) ---------------------------------------

func TestARetriedProposalIsByteIdentical(t *testing.T) {
	payer, _, id := pair(t)

	first, err := payer.sess.Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	second, err := payer.sess.Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("re-propose: %v", err)
	}
	if !bytes.Equal(first.Body, second.Body) {
		t.Fatalf("a retry differs from the original:\n%s\n%s", first.Body, second.Body)
	}
}

func TestADuplicateProposalIsNotPaidTwice(t *testing.T) {
	payer, payee, id := pair(t)
	propose, _ := payer.sess.Propose(id, intent(1), payTransition(25))

	first, err := payee.sess.HandlePropose(hop(t, propose))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// The acceptance is lost; the payer retries the identical proposal.
	second, err := payee.sess.HandlePropose(hop(t, propose))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if second.Type != MsgStateAccept {
		t.Fatalf("the retry was answered with %s", second.Type)
	}
	if !bytes.Equal(first.Body, second.Body) {
		t.Fatal("the retry got a different counter-signature")
	}
	if payee.latest(id).Nonce != 1 {
		t.Fatalf("the retry advanced the channel to nonce %d", payee.latest(id).Nonce)
	}
	if got := payee.balanceOf(id, payee.key.address()); got != anon(25).String() {
		t.Fatalf("the payee was paid %s — the retry was applied twice", got)
	}
}

// ---- the crash table (§8) ---------------------------------------------------

func TestCrashBeforePersistingLeavesNothing(t *testing.T) {
	payer, _, id := pair(t)
	// Nothing proposed at all: the crash happened before Propose was called.
	payer.restart()
	if _, resync, err := payer.sess.Resume(id); err != nil || resync {
		t.Fatalf("a node with no pending proposal wanted to resync: %v %v", resync, err)
	}
	if payer.latest(id).Nonce != 0 {
		t.Fatal("state appeared from nowhere")
	}
}

func TestCrashAfterPersistingResendsTheIdenticalProposal(t *testing.T) {
	payer, payee, id := pair(t)
	original, err := payer.sess.Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	// The message never went out. On restart, the pending record is still there.
	payer.restart()
	again, err := payer.sess.Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("re-propose after restart: %v", err)
	}
	if !bytes.Equal(original.Body, again.Body) {
		t.Fatal("the proposal changed across a restart")
	}

	reply, err := payee.sess.HandlePropose(hop(t, again))
	if err != nil || reply.Type != MsgStateAccept {
		t.Fatalf("payee refused the resent proposal: %v %s", err, reply.Type)
	}
}

// The row that matters most: the payee signs, and the payer dies before hearing
// about it. The payee holds a completed state the payer has no record of.
func TestPayeeSignsAndThePayerCrashesBeforeHearing(t *testing.T) {
	payer, payee, id := pair(t)

	propose, _ := payer.sess.Propose(id, intent(1), payTransition(25))
	accept, err := payee.sess.HandlePropose(hop(t, propose))
	if err != nil {
		t.Fatalf("handle propose: %v", err)
	}
	_ = accept // never delivered

	payer.restart()
	if payer.latest(id).Nonce != 0 {
		t.Fatal("the payer somehow has the completed state")
	}

	// Resume asks rather than guesses.
	request, resync, err := payer.sess.Resume(id)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !resync {
		t.Fatal("a node with a pending proposal did not want to resync")
	}

	response, err := payee.sess.HandleRequest(hop(t, request))
	if err != nil {
		t.Fatalf("handle request: %v", err)
	}
	outcome, err := payer.sess.HandleResponse(hop(t, response))
	if err != nil {
		t.Fatalf("handle response: %v", err)
	}
	if outcome != ResyncAdopted {
		t.Fatalf("outcome %s, want ADOPTED", outcome)
	}

	if payer.latest(id).Nonce != 1 {
		t.Fatal("the payer did not adopt the completed state")
	}
	if got := payer.balanceOf(id, payee.key.address()); got != anon(25).String() {
		t.Fatalf("payer recovered a balance of %s", got)
	}
	// And the pending record is resolved, so the payment is not attempted again.
	ch, _ := payer.store.Get(id)
	if ch.Pending != nil {
		t.Fatal("the pending proposal survived its own completion")
	}
}

// A payer that recovered a state it does not remember signing must still be
// able to confirm its own signature is on it — signatures recover to an address,
// so no local record is needed to answer "did I sign this".
func TestARecoveredStateCarriesThePayersOwnSignature(t *testing.T) {
	payer, payee, id := pair(t)
	propose, _ := payer.sess.Propose(id, intent(1), payTransition(25))
	if _, err := payee.sess.HandlePropose(hop(t, propose)); err != nil {
		t.Fatalf("handle propose: %v", err)
	}

	payer.restart()
	request, _, _ := payer.sess.Resume(id)
	response, _ := payee.sess.HandleRequest(hop(t, request))
	if _, err := payer.sess.HandleResponse(hop(t, response)); err != nil {
		t.Fatalf("resync: %v", err)
	}

	ch, _ := payer.store.Get(id)
	raw := ch.Latest.State.Digest(ch.ChainID, ch.Contract)
	mine := ch.Latest.SigA
	if !ch.IsA(payer.key.address()) {
		mine = ch.Latest.SigB
	}
	got, err := RecoverSigner(raw, mine)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got != payer.key.address() {
		t.Fatal("the recovered state does not carry the payer's own signature")
	}
}

func TestARejectionChangesNothing(t *testing.T) {
	payer, payee, id := pair(t)

	// More than the channel holds.
	propose, err := payer.sess.Propose(id, intent(1), payTransition(600))
	if err == nil {
		reply, herr := payee.sess.HandlePropose(hop(t, propose))
		if herr != nil {
			t.Fatalf("handle: %v", herr)
		}
		if reply.Type != MsgStateReject {
			t.Fatal("an overdraft was accepted")
		}
		code, rerr := payer.sess.HandleReject(hop(t, reply))
		if rerr != nil {
			t.Fatalf("handle reject: %v", rerr)
		}
		if code.Retryable() {
			t.Fatalf("%s was reported retryable", code)
		}
	}
	// Either way nothing moved: the payer could not even build it.
	if payer.latest(id).Nonce != 0 || payee.latest(id).Nonce != 0 {
		t.Fatal("a refused payment changed state")
	}
}

func TestBothInStepIsNotAConflict(t *testing.T) {
	payer, payee, id := pair(t)
	propose, _ := payer.sess.Propose(id, intent(1), payTransition(25))
	accept, _ := payee.sess.HandlePropose(hop(t, propose))
	if err := payer.sess.HandleAccept(hop(t, accept)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	request, _ := payer.sess.RequestState(id)
	response, _ := payee.sess.HandleRequest(hop(t, request))
	outcome, err := payer.sess.HandleResponse(hop(t, response))
	if err != nil {
		t.Fatalf("resync: %v", err)
	}
	if outcome != ResyncSame {
		t.Fatalf("outcome %s, want IN_STEP", outcome)
	}
}

func TestAStalePeerIsNotAdoptedFrom(t *testing.T) {
	payer, payee, id := pair(t)

	// The payer gets two payments in; the payee only hears about the first.
	first, _ := payer.sess.Propose(id, intent(1), payTransition(25))
	accept, _ := payee.sess.HandlePropose(hop(t, first))
	if err := payer.sess.HandleAccept(hop(t, accept)); err != nil {
		t.Fatalf("first: %v", err)
	}
	second, _ := payer.sess.Propose(id, intent(2), payTransition(30))
	accept2, _ := payee.sess.HandlePropose(hop(t, second))
	if err := payer.sess.HandleAccept(hop(t, accept2)); err != nil {
		t.Fatalf("second: %v", err)
	}

	// A third node pretending to be behind: use the payee's state from before.
	// Simplest faithful version — ask the payer to adopt a nonce it has passed.
	stale, _ := newEnvelope(MsgStateResponse, id, StateResponseBody{
		Have:  true,
		State: encodeStateWire(State{Channel: id, Nonce: 1, BalanceA: anon(1), BalanceB: anon(1)}),
		SigA:  hex.EncodeToString(make([]byte, 65)),
		SigB:  hex.EncodeToString(make([]byte, 65)),
	})
	outcome, err := payer.sess.HandleResponse(hop(t, stale))
	if err != nil {
		t.Fatalf("resync: %v", err)
	}
	if outcome != ResyncStale {
		t.Fatalf("outcome %s, want PEER_IS_STALE", outcome)
	}
	if payer.latest(id).Nonce != 2 {
		t.Fatal("the payer moved backwards")
	}
}

// A peer offering a HIGHER nonce that fails the complete validation is refused.
// Two signatures recovering is authorship, not legality.
func TestAHigherButInvalidStateIsRefused(t *testing.T) {
	payer, payee, id := pair(t)

	// Signed by both, at a high nonce, and paying out more than was deposited.
	bogus := State{Channel: id, Nonce: 99, BalanceA: anon(400), BalanceB: anon(400)}
	signed := signState(t, mustChannel(t, payer, id), bogus, payer.key, payee.key)
	env, _ := newEnvelope(MsgStateResponse, id, StateResponseBody{
		Have:  true,
		State: encodeStateWire(signed.State),
		SigA:  hex.EncodeToString(signed.SigA),
		SigB:  hex.EncodeToString(signed.SigB),
	})

	outcome, err := payer.sess.HandleResponse(hop(t, env))
	if err == nil {
		t.Fatal("an unconserved state was adopted")
	}
	if outcome != ResyncRejected {
		t.Fatalf("outcome %s, want REJECTED", outcome)
	}
	if payer.latest(id).Nonce != 0 {
		t.Fatal("the bogus state was stored anyway")
	}
}

// §7's fourth case, which is not a tie to break.
func TestSameNonceDifferentStateStopsTheChannel(t *testing.T) {
	payer, payee, id := pair(t)

	propose, _ := payer.sess.Propose(id, intent(1), payTransition(25))
	accept, _ := payee.sess.HandlePropose(hop(t, propose))
	if err := payer.sess.HandleAccept(hop(t, accept)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// A different state at the same nonce, signed by both — only possible if a
	// party signed twice, which is what makes this evidence rather than a tie.
	other := State{Channel: id, Nonce: 1, BalanceA: anon(250), BalanceB: anon(250)}
	signed := signState(t, mustChannel(t, payer, id), other, payer.key, payee.key)
	env, _ := newEnvelope(MsgStateResponse, id, StateResponseBody{
		Have:  true,
		State: encodeStateWire(signed.State),
		SigA:  hex.EncodeToString(signed.SigA),
		SigB:  hex.EncodeToString(signed.SigB),
	})

	outcome, err := payer.sess.HandleResponse(hop(t, env))
	if err != nil {
		t.Fatalf("resync: %v", err)
	}
	if outcome != ResyncConflict {
		t.Fatalf("outcome %s, want CONFLICT", outcome)
	}

	// Stopped permanently, and both states kept as the evidence.
	ch, _ := payer.store.Get(id)
	if ch.Conflict == nil || ch.Conflict.Nonce != 1 {
		t.Fatal("no conflict was recorded")
	}
	if _, err := payer.sess.Propose(id, intent(2), payTransition(5)); err != ErrConflicted {
		t.Fatalf("the channel kept working after a conflict: %v", err)
	}

	// And it survives a restart — a conflict that forgets itself is a channel
	// that resumes signing.
	payer.restart()
	if _, err := payer.sess.Propose(id, intent(3), payTransition(5)); err != ErrConflicted {
		t.Fatalf("the conflict did not survive a restart: %v", err)
	}
}

// ---- invariant I4 -----------------------------------------------------------

// A payee that has signed nonce 1 must not sign a DIFFERENT nonce 1, even under
// a fresh intent. This is what makes a same-nonce conflict provable misbehaviour
// rather than an ambiguity — and it has to survive a restart, because a crash is
// exactly when a node would otherwise forget.
func TestANodeWillNotSignTwoStatesAtOneNonce(t *testing.T) {
	payer, payee, id := pair(t)

	// The payee signs nonce 1 for 25.
	first, _ := payer.sess.Propose(id, intent(1), payTransition(25))
	reply, err := payee.sess.HandlePropose(hop(t, first))
	if err != nil || reply.Type != MsgStateAccept {
		t.Fatalf("first proposal: %v %s", err, reply.Type)
	}

	// A different nonce-1 state, under a different intent, hand-built so it
	// bypasses the payer's own bookkeeping.
	ch := mustChannel(t, payer, id)
	other := State{Channel: id, Nonce: 1}
	other.BalanceA, other.BalanceB = anon(400), anon(100)
	if !ch.IsA(payer.key.address()) {
		other.BalanceA, other.BalanceB = anon(100), anon(400)
	}
	raw := other.Digest(ch.ChainID, ch.Contract)
	intentNine := intent(9)
	env, _ := newEnvelope(MsgStatePropose, id, StateProposeBody{
		Intent:     hexOf(intentNine[:]),
		Transition: encodeTransitionWire(payTransition(100)),
		State:      encodeStateWire(other),
		Sig:        hex.EncodeToString(payer.key.sign(raw)),
	})

	second, err := payee.sess.HandlePropose(hop(t, env))
	if err != nil {
		t.Fatalf("second proposal: %v", err)
	}
	if second.Type != MsgStateReject {
		t.Fatal("the payee signed a second, different state at nonce 1")
	}

	// And after a restart it still refuses — the ledger is on disk.
	payee.restart()
	third, err := payee.sess.HandlePropose(hop(t, env))
	if err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if third.Type != MsgStateReject {
		t.Fatal("a restart made the payee willing to double-sign nonce 1")
	}
}

// ---- locks over the same machine (§9) ---------------------------------------

func TestALockIsProposedSettledAndRefundedOverTheProtocol(t *testing.T) {
	payer, payee, id := pair(t)

	var preimage [32]byte
	copy(preimage[:], []byte("routed tip"))
	var hash [32]byte
	copy(hash[:], keccak(preimage[:]))

	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: hash, Expiry: payer.clock + 4000,
	}
	propose, err := payer.sess.Propose(id, intent(1), add)
	if err != nil {
		t.Fatalf("lock add: %v", err)
	}
	reply, err := payee.sess.HandlePropose(hop(t, propose))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if reply.Type != MsgStateAccept {
		var r StateRejectBody
		_ = reply.Body_(&r)
		t.Fatalf("lock refused: %s %s", r.Code, r.Detail)
	}
	if err := payer.sess.HandleAccept(hop(t, reply)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// The 50 is in neither balance.
	st := payee.latest(id)
	if len(st.Pending) != 1 {
		t.Fatal("the lock is not pending on the payee")
	}
	total := new(big.Int).Add(st.BalanceA, st.BalanceB)
	if total.Cmp(anon(450)) != 0 {
		t.Fatalf("balances total %s with 50 locked, want 450", total)
	}

	// The payee learns the secret and settles — the one transition where the
	// proposer gains.
	settle := StateTransition{Kind: KindLockSettle, LockID: [32]byte{31: 1}, Preimage: preimage}
	sp, err := payee.sess.Propose(id, intent(2), settle)
	if err != nil {
		t.Fatalf("settle propose: %v", err)
	}
	sr, err := payer.sess.HandlePropose(hop(t, sp))
	if err != nil {
		t.Fatalf("settle handle: %v", err)
	}
	if sr.Type != MsgStateAccept {
		var r StateRejectBody
		_ = sr.Body_(&r)
		t.Fatalf("settle refused: %s %s", r.Code, r.Detail)
	}
	if err := payee.sess.HandleAccept(hop(t, sr)); err != nil {
		t.Fatalf("settle accept: %v", err)
	}

	if got := payee.balanceOf(id, payee.key.address()); got != anon(50).String() {
		t.Fatalf("payee holds %s after settling a 50 lock", got)
	}
}

// Check 11: a lock that expires too soon is worthless, however well formed.
func TestALockExpiringTooSoonIsRefused(t *testing.T) {
	payer, payee, id := pair(t)
	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: payer.clock + 10, // the payee requires 600
	}
	propose, err := payer.sess.Propose(id, intent(1), add)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	reply, err := payee.sess.HandlePropose(hop(t, propose))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if reply.Type != MsgStateReject {
		t.Fatal("a lock expiring in ten seconds was accepted")
	}
}

// Check 10: an early refund steals a payment that is still legitimately in
// flight, so it is refused until the expiry has actually passed.
func TestARefundBeforeExpiryIsRefused(t *testing.T) {
	payer, payee, id := pair(t)
	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: payer.clock + 4000,
	}
	propose, _ := payer.sess.Propose(id, intent(1), add)
	reply, _ := payee.sess.HandlePropose(hop(t, propose))
	if err := payer.sess.HandleAccept(hop(t, reply)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	refund := StateTransition{Kind: KindLockRefund, LockID: [32]byte{31: 1}}
	rp, err := payer.sess.Propose(id, intent(2), refund)
	if err != nil {
		t.Fatalf("refund propose: %v", err)
	}
	rr, err := payee.sess.HandlePropose(hop(t, rp))
	if err != nil {
		t.Fatalf("refund handle: %v", err)
	}
	if rr.Type != MsgStateReject {
		t.Fatal("a refund was accepted while the lock was still live")
	}
	var body StateRejectBody
	if err := rr.Body_(&body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Code != RejectLockNotExpired {
		t.Fatalf("code %s, want LOCK_NOT_EXPIRED", body.Code)
	}
	if !body.Code.Retryable() {
		t.Fatal("LOCK_NOT_EXPIRED should be retryable later")
	}

	// After it expires, the same refund is accepted.
	payee.clock += 5000
	payer.clock += 5000
	rr2, err := payee.sess.HandlePropose(hop(t, rp))
	if err != nil {
		t.Fatalf("refund handle after expiry: %v", err)
	}
	if rr2.Type != MsgStateAccept {
		var r StateRejectBody
		_ = rr2.Body_(&r)
		t.Fatalf("refund refused after expiry: %s %s", r.Code, r.Detail)
	}
}

func mustChannel(t *testing.T, n *node, id [32]byte) *Channel {
	t.Helper()
	ch, ok := n.store.Get(id)
	if !ok {
		t.Fatal("channel missing")
	}
	return ch
}

// A peer cannot stop a channel by ASSERTING a conflict — only by demonstrating
// one. Otherwise "claim a conflict" is a denial of service against any channel
// whose id a stranger knows.
func TestConflictEvidenceIsCheckedNotBelieved(t *testing.T) {
	payer, payee, id := pair(t)
	propose, _ := payer.sess.Propose(id, intent(1), payTransition(25))
	accept, _ := payee.sess.HandlePropose(hop(t, propose))
	if err := payer.sess.HandleAccept(hop(t, accept)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	ch := mustChannel(t, payer, id)
	real1 := ch.Latest
	fake := State{Channel: id, Nonce: 1, BalanceA: anon(250), BalanceB: anon(250)}

	// Unsigned garbage presented as the second state.
	bogus, _ := newEnvelope(MsgConflict, id, ConflictBody{
		Nonce:  1,
		Mine:   encodeStateWire(fake),
		MineA:  hex.EncodeToString(make([]byte, 65)),
		MineB:  hex.EncodeToString(make([]byte, 65)),
		Yours:  encodeStateWire(real1.State),
		YoursA: hex.EncodeToString(real1.SigA),
		YoursB: hex.EncodeToString(real1.SigB),
	})
	if stopped, err := payer.sess.HandleConflict(hop(t, bogus)); stopped || err == nil {
		t.Fatal("an unsigned state stopped the channel")
	}
	if _, err := payer.sess.Propose(id, intent(2), payTransition(5)); err == ErrConflicted {
		t.Fatal("the channel was stopped by unverified evidence")
	}

	// Two genuinely signed, genuinely different states at one nonce do stop it.
	signedFake := signState(t, ch, fake, payer.key, payee.key)
	good, _ := newEnvelope(MsgConflict, id, ConflictBody{
		Nonce:  1,
		Mine:   encodeStateWire(signedFake.State),
		MineA:  hex.EncodeToString(signedFake.SigA),
		MineB:  hex.EncodeToString(signedFake.SigB),
		Yours:  encodeStateWire(real1.State),
		YoursA: hex.EncodeToString(real1.SigA),
		YoursB: hex.EncodeToString(real1.SigB),
	})
	stopped, err := payer.sess.HandleConflict(hop(t, good))
	if err != nil || !stopped {
		t.Fatalf("real evidence did not stop the channel: %v %v", stopped, err)
	}
	if _, err := payer.sess.Propose(id, intent(3), payTransition(5)); err != ErrConflicted {
		t.Fatalf("the channel kept working: %v", err)
	}
}
