package channel

// The volunteer mailbox and delegate signer — roadmap P15.
//
// The claim under test is narrow and absolute: a mailbox CANNOT sign, and a
// delegate can sign exactly one kind of thing. Most of what follows is
// therefore refusals, and the two structural tests (no key field on a mailbox,
// no way to widen a delegate) matter more than any behavioural one — a
// behaviour can be changed by a later edit, a missing field cannot be used by
// one.

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

const testNode = "node-abc"

func authFor(t *testing.T, who *signer, node string, expires int64) MailboxAuthorization {
	t.Helper()
	a := MailboxAuthorization{
		Recipient: who.address(), NodeID: node,
		Endpoint: "https://volunteer.example/scpp/v1", Expires: expires,
	}
	a.Sig = who.sign(PersonalDigest(keccak32([]byte(a.Message()))))
	return a
}

func newTestMailbox(now int64) *Mailbox {
	return NewMailbox(testNode, func() int64 { return now })
}

// ---- a mailbox cannot sign ---------------------------------------------------

func TestAMailboxHoldsNothingThatCouldSign(t *testing.T) {
	// STRUCTURAL. A mailbox with a key field would be one refactor away from
	// being a delegate, so the absence is asserted rather than the behaviour.
	ty := reflect.TypeOf(Mailbox{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		name := strings.ToLower(f.Name)
		for _, banned := range []string{"key", "sign", "secret", "seed", "wallet", "priv"} {
			if strings.Contains(name, banned) {
				t.Fatalf("Mailbox.%s looks like signing material; a mailbox must hold none", f.Name)
			}
		}
		// Nor a function that could be one.
		if f.Type.Kind() == reflect.Func && f.Name != "Now" {
			t.Fatalf("Mailbox.%s is a function field; the only one allowed is the clock", f.Name)
		}
	}
	// And no method that produces bytes from a digest.
	mt := reflect.TypeOf(&Mailbox{})
	for i := 0; i < mt.NumMethod(); i++ {
		if strings.Contains(strings.ToLower(mt.Method(i).Name), "sign") {
			t.Fatalf("Mailbox has a %s method", mt.Method(i).Name)
		}
	}
}

func TestAMailboxHoldsNoBalanceOrChannelState(t *testing.T) {
	ty := reflect.TypeOf(Mailbox{})
	for i := 0; i < ty.NumField(); i++ {
		name := strings.ToLower(ty.Field(i).Name)
		for _, banned := range []string{"balance", "amount", "store", "channel", "state"} {
			if strings.Contains(name, banned) {
				t.Fatalf("Mailbox.%s holds channel state; it is transport, not a party",
					ty.Field(i).Name)
			}
		}
	}
}

// ---- authorization -----------------------------------------------------------

func TestAMailboxServesOnlyWhereTheRecipientSaidSo(t *testing.T) {
	m := newTestMailbox(1000)
	recipient := newSigner(t)

	if err := m.Serve(authFor(t, recipient, testNode, 2000)); err != nil {
		t.Fatalf("a valid authorization was refused: %v", err)
	}
	if !m.Serves(recipient.address()) {
		t.Fatal("the node does not think it serves a recipient it just accepted")
	}
}

func TestAMailboxRefusesAnAuthorizationForAnotherNode(t *testing.T) {
	// Otherwise a volunteer could pick up a recipient who chose somebody else,
	// and two mailboxes for one recipient is how two states get signed at one
	// nonce.
	m := newTestMailbox(1000)
	recipient := newSigner(t)
	err := m.Serve(authFor(t, recipient, "some-other-node", 2000))
	if !errors.Is(err, ErrWrongNode) {
		t.Fatalf("want ErrWrongNode, got %v", err)
	}
	if m.Serves(recipient.address()) {
		t.Fatal("the node adopted a recipient authorized to somebody else")
	}
}

func TestAMailboxRefusesAForgedAuthorization(t *testing.T) {
	m := newTestMailbox(1000)
	victim := newSigner(t)
	attacker := newSigner(t)

	// The attacker signs a statement naming the victim as recipient.
	a := MailboxAuthorization{
		Recipient: victim.address(), NodeID: testNode,
		Endpoint: "https://volunteer.example/scpp/v1", Expires: 2000,
	}
	a.Sig = attacker.sign(PersonalDigest(keccak32([]byte(a.Message()))))

	if err := m.Serve(a); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("want ErrAuthorizationInvalid, got %v", err)
	}
}

func TestAMailboxRefusesAnExpiredAuthorization(t *testing.T) {
	m := newTestMailbox(3000)
	recipient := newSigner(t)
	if err := m.Serve(authFor(t, recipient, testNode, 2000)); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("want ErrAuthorizationExpired, got %v", err)
	}
}

func TestAnAuthorizationCannotBeMovedToAnotherNode(t *testing.T) {
	// The node id is inside the signed text, so a proof collected by one
	// volunteer cannot be replayed by another to claim the same recipient.
	recipient := newSigner(t)
	a := authFor(t, recipient, testNode, 2000)
	moved := a
	moved.NodeID = "greedy-node"

	other := NewMailbox("greedy-node", func() int64 { return 1000 })
	if err := other.Serve(moved); err == nil {
		t.Fatal("an authorization was replayed onto a node it never named")
	}
}

// ---- delivery and isolation --------------------------------------------------

func TestAMailboxRefusesFramesForSomebodyItDoesNotServe(t *testing.T) {
	m := newTestMailbox(1000)
	stranger := newSigner(t)
	if err := m.Deliver(stranger.address(), Envelope{Type: MsgStatePropose}); !errors.Is(err, ErrNotServed) {
		t.Fatalf("want ErrNotServed, got %v", err)
	}
}

func TestOneRecipientCannotReadAnothersMail(t *testing.T) {
	// THE ISOLATION PROPERTY for a volunteer serving many people.
	m := newTestMailbox(1000)
	alice, bob := newSigner(t), newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	if err := m.Serve(authFor(t, bob, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose, Channel: "aa"}); err != nil {
		t.Fatal(err)
	}

	// Bob proves he is Bob and asks for Alice's queue.
	ch := MailboxChallenge(testNode, alice.address(), "tok")
	if _, err := m.Collect(alice.address(), ch, bob.sign(PersonalDigest(ch))); !errors.Is(err, ErrNotServed) {
		t.Fatalf("bob read alice's mail: %v", err)
	}
	// Alice's frame is still there, untouched.
	if m.Pending(alice.address()) != 1 {
		t.Fatal("a failed collection consumed the queue")
	}

	got, err := m.Collect(alice.address(), ch, alice.sign(PersonalDigest(ch)))
	if err != nil || len(got) != 1 {
		t.Fatalf("alice could not collect her own mail: %v (%d frames)", err, len(got))
	}
}

func TestCollectingEmptiesTheQueueOnlyForTheProvenCaller(t *testing.T) {
	m := newTestMailbox(1000)
	alice, bob := newSigner(t), newSigner(t)
	for _, who := range []*signer{alice, bob} {
		if err := m.Serve(authFor(t, who, testNode, 2000)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(bob.address(), Envelope{Type: MsgStatePropose}); err != nil {
		t.Fatal(err)
	}

	ch := MailboxChallenge(testNode, alice.address(), "tok")
	if _, err := m.Collect(alice.address(), ch, alice.sign(PersonalDigest(ch))); err != nil {
		t.Fatal(err)
	}
	if m.Pending(alice.address()) != 0 {
		t.Fatal("alice's queue was not emptied")
	}
	if m.Pending(bob.address()) != 1 {
		t.Fatal("collecting for alice disturbed bob's queue")
	}
}

func TestAMailboxCarriesFramesVerbatim(t *testing.T) {
	// A mailbox that rewrote a frame could change a payment. It must hand back
	// exactly what it was given.
	m := newTestMailbox(1000)
	alice := newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	sent := Envelope{Type: MsgStatePropose, Channel: "deadbeef", Body: []byte(`{"x":1}`)}
	if err := m.Deliver(alice.address(), sent); err != nil {
		t.Fatal(err)
	}
	ch := MailboxChallenge(testNode, alice.address(), "tok")
	got, err := m.Collect(alice.address(), ch, alice.sign(PersonalDigest(ch)))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Type != sent.Type || got[0].Channel != sent.Channel ||
		string(got[0].Body) != string(sent.Body) {
		t.Fatalf("the mailbox altered the frame:\n sent %+v\n got  %+v", sent, got[0])
	}
}

func TestAMailboxIsBounded(t *testing.T) {
	m := NewMailbox(testNode, func() int64 { return 1000 })
	m.Depth = 3
	alice := newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); !errors.Is(err, ErrMailboxFull) {
		t.Fatalf("want ErrMailboxFull, got %v", err)
	}
}

func TestReplacingAMailboxMovesNoValue(t *testing.T) {
	// The whole point of mailbox mode: changing volunteer is changing a URL.
	// Nothing is transferred, because the volunteer never held anything.
	alice := newSigner(t)
	first := NewMailbox("node-1", func() int64 { return 1000 })
	if err := first.Serve(authFor(t, alice, "node-1", 2000)); err != nil {
		t.Fatal(err)
	}
	second := NewMailbox("node-2", func() int64 { return 1000 })
	if err := second.Serve(authFor(t, alice, "node-2", 2000)); err != nil {
		t.Fatalf("a recipient could not move to another volunteer: %v", err)
	}
	first.Stop(alice.address())
	if first.Serves(alice.address()) {
		t.Fatal("the old volunteer still claims the recipient")
	}
	if !second.Serves(alice.address()) {
		t.Fatal("the new volunteer does not serve the recipient")
	}
}

// ---- the delegate ------------------------------------------------------------

// fakeAuthority stands in for the contract's canSign.
type fakeAuthority struct {
	allow map[uint8]bool
	err   error
	calls int
}

func (f *fakeAuthority) CanSign(_ context.Context, _, _, _ Address, op uint8) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return f.allow[op], nil
}

func newDelegate(t *testing.T, auth *fakeAuthority) (*DelegateSigner, *signer) {
	t.Helper()
	key := newSigner(t)
	d, err := NewDelegateSigner(key.address(),
		func(raw [32]byte) ([]byte, error) { return key.sign(raw), nil },
		auth, Address{7})
	if err != nil {
		t.Fatalf("NewDelegateSigner: %v", err)
	}
	return d, key
}

func TestADelegateRefusesToExistWithoutAChainToAsk(t *testing.T) {
	key := newSigner(t)
	sign := func(raw [32]byte) ([]byte, error) { return key.sign(raw), nil }
	if _, err := NewDelegateSigner(key.address(), sign, nil, Address{7}); err == nil {
		t.Fatal("a delegate was built with no authority; it would have to assume it may sign")
	}
	if _, err := NewDelegateSigner(key.address(), nil, &fakeAuthority{}, Address{7}); err == nil {
		t.Fatal("a delegate was built with no key")
	}
}

func TestADelegateSignsOnlyOrdinaryStates(t *testing.T) {
	auth := &fakeAuthority{allow: map[uint8]bool{OpState: true}}
	d, _ := newDelegate(t, auth)
	recipient := Address{9}

	ok := State{Channel: [32]byte{1}, Nonce: 3, BalanceA: anon(10), BalanceB: anon(5), Op: OpState}
	if _, err := d.SignState(context.Background(), recipient, big.NewInt(1), Address{7}, ok); err != nil {
		t.Fatalf("an ordinary state was refused: %v", err)
	}

	for _, bad := range []struct {
		name  string
		state State
	}{
		{"checkpoint domain", State{Nonce: 3, BalanceA: anon(10), Op: OpCheckpoint}},
		{"cooperative close domain", State{Nonce: 3, BalanceA: anon(10), Op: OpCoopClose}},
		{"a withdrawal in an ordinary domain", State{
			Nonce: 3, BalanceA: anon(10), WithdrawB: anon(1), Op: OpState}},
	} {
		_, err := d.SignState(context.Background(), recipient, big.NewInt(1), Address{7}, bad.state)
		if !errors.Is(err, ErrOperationNotDelegated) {
			t.Fatalf("%s: want ErrOperationNotDelegated, got %v", bad.name, err)
		}
	}
}

func TestADelegateAsksTheChainEveryTime(t *testing.T) {
	// A cached yes is a signature the recipient may already have revoked.
	auth := &fakeAuthority{allow: map[uint8]bool{OpState: true}}
	d, _ := newDelegate(t, auth)
	st := State{Nonce: 3, BalanceA: anon(10), Op: OpState}

	for i := 0; i < 3; i++ {
		if _, err := d.SignState(context.Background(), Address{9}, big.NewInt(1), Address{7}, st); err != nil {
			t.Fatal(err)
		}
	}
	if auth.calls != 3 {
		t.Fatalf("the chain was asked %d times for 3 signatures", auth.calls)
	}
}

func TestARevokedDelegateStopsSigningImmediately(t *testing.T) {
	auth := &fakeAuthority{allow: map[uint8]bool{OpState: true}}
	d, _ := newDelegate(t, auth)
	recipient := Address{9}
	st := State{Nonce: 3, BalanceA: anon(10), Op: OpState}

	if err := d.Adopt(context.Background(), recipient); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SignState(context.Background(), recipient, big.NewInt(1), Address{7}, st); err != nil {
		t.Fatal(err)
	}

	auth.allow[OpState] = false // the recipient revokes on chain

	if _, err := d.SignState(context.Background(), recipient, big.NewInt(1), Address{7}, st); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("a revoked delegate still signed: %v", err)
	}
	// And it stops claiming the recipient, so the operator's console is honest.
	if d.Serves(recipient) {
		t.Fatal("the node still believes it is a delegate after being refused")
	}
}

func TestADelegateRefusesWhenTheChainCannotBeReached(t *testing.T) {
	// NOT an optimistic yes. If the delegation cannot be confirmed, the node
	// does not sign — the same rule the rest of the stack applies to collateral.
	auth := &fakeAuthority{err: errors.New("rpc down")}
	d, _ := newDelegate(t, auth)
	st := State{Nonce: 3, BalanceA: anon(10), Op: OpState}
	if _, err := d.SignState(context.Background(), Address{9}, big.NewInt(1), Address{7}, st); err == nil {
		t.Fatal("a delegate signed without being able to confirm its authority")
	}
}

func TestADelegateCannotAdoptARecipientThatDidNotAuthorizeIt(t *testing.T) {
	auth := &fakeAuthority{allow: map[uint8]bool{}}
	d, _ := newDelegate(t, auth)
	if err := d.Adopt(context.Background(), Address{9}); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("want ErrNotDelegated, got %v", err)
	}
}

func TestADelegateHoldsNoRecipientKey(t *testing.T) {
	// STRUCTURAL, and the most important property of Mode B: the node keeps the
	// recipient's ADDRESS and a key of its own. A field able to hold a
	// recipient's key would be custody wearing a different word.
	ty := reflect.TypeOf(DelegateSigner{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if strings.Contains(strings.ToLower(f.Name), "recipient") {
			t.Fatalf("DelegateSigner.%s: a delegate must not store anything per-recipient "+
				"that could be key material", f.Name)
		}
	}
	// The served set is addresses only.
	d, _ := newDelegate(t, &fakeAuthority{allow: map[uint8]bool{OpState: true}})
	if reflect.TypeOf(d.served).Elem().Kind() != reflect.Struct ||
		reflect.TypeOf(d.served).Elem().NumField() != 0 {
		t.Fatal("the served set carries a value; it must be addresses alone")
	}
}

// ---- retained frames, for a contributor rebuilding its chain (P15 Case B) ----

func TestRetainedFramesSurviveCollection(t *testing.T) {
	// Collecting empties the RECIPIENT's queue — that is what collection means.
	// A contributor still needs its own chain afterwards, so retention has to
	// outlive delivery or tip 2 has nothing to build on.
	m := newTestMailbox(1000)
	alice, recipient := newSigner(t), newSigner(t)
	if err := m.Serve(authFor(t, recipient, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	id := DeriveChannelID(alice.address(), recipient.address())
	ch := poolChannelHex(id)

	if err := m.Deliver(recipient.address(), Envelope{Type: MsgStatePropose, Channel: ch}); err != nil {
		t.Fatal(err)
	}
	tok := MailboxChallenge(testNode, recipient.address(), "t")
	if _, err := m.Collect(recipient.address(), tok, recipient.sign(PersonalDigest(tok))); err != nil {
		t.Fatal(err)
	}
	if m.Pending(recipient.address()) != 0 {
		t.Fatal("the queue was not emptied")
	}
	if m.Retained(ch) != 1 {
		t.Fatal("collection destroyed the contributor's chain")
	}
}

func TestOnlyAPartyMayReadAChannelsRetainedFrames(t *testing.T) {
	m := newTestMailbox(1000)
	alice, recipient, mallory := newSigner(t), newSigner(t), newSigner(t)
	if err := m.Serve(authFor(t, recipient, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	id := DeriveChannelID(alice.address(), recipient.address())
	ch := poolChannelHex(id)
	m.Retain(ch, Envelope{Type: MsgStatePropose, Channel: ch})

	// Alice proves she is Alice, and the id she asks about DERIVES from her
	// address and the recipient's. Nothing is taken on her word.
	c := MailboxChallenge(testNode, alice.address(), "t")
	got, err := m.StatesFor(recipient.address(), alice.address(), ch, c,
		alice.sign(PersonalDigest(c)))
	if err != nil || len(got) != 1 {
		t.Fatalf("a party could not read its own chain: %v (%d)", err, len(got))
	}

	// Mallory proves she is Mallory and asks about Alice's channel. The id does
	// not derive from her address, so there is nothing to look up.
	cm := MailboxChallenge(testNode, mallory.address(), "t")
	if _, err := m.StatesFor(recipient.address(), mallory.address(), ch, cm,
		mallory.sign(PersonalDigest(cm))); !errors.Is(err, ErrNotServed) {
		t.Fatalf("a stranger read another channel's frames: %v", err)
	}

	// And Mallory cannot borrow Alice's identity without Alice's key.
	if _, err := m.StatesFor(recipient.address(), alice.address(), ch, c,
		mallory.sign(PersonalDigest(c))); !errors.Is(err, ErrNotServed) {
		t.Fatalf("an unproven caller read a chain: %v", err)
	}
}

func TestRetentionIsBounded(t *testing.T) {
	m := NewMailbox(testNode, func() int64 { return 1000 })
	m.Depth = 3
	ch := poolChannelHex([32]byte{9})
	for i := 0; i < 6; i++ {
		m.Retain(ch, Envelope{Type: MsgStatePropose, Channel: ch})
	}
	if m.Retained(ch) != 3 {
		t.Fatalf("retained %d frames, want the cap of 3", m.Retained(ch))
	}
}

func TestTheMailboxStillCannotSignAfterRetention(t *testing.T) {
	// Retention gave the mailbox more to hold. It must not have given it more
	// to do: the structural no-key rule still applies.
	ty := reflect.TypeOf(Mailbox{})
	for i := 0; i < ty.NumField(); i++ {
		name := strings.ToLower(ty.Field(i).Name)
		for _, banned := range []string{"key", "sign", "secret", "seed", "priv"} {
			if strings.Contains(name, banned) {
				t.Fatalf("Mailbox.%s appeared alongside retention", ty.Field(i).Name)
			}
		}
	}
}

// ---- non-consuming recipient discovery (P15.5) -------------------------------
//
// The recipient's console must be able to say "a tip is waiting" without
// destroying the tip. Collect is the only other recipient-authorized read and it
// empties the queue, so discovery through Collect would consume the proposal at
// page load — before the recipient had reviewed it.

func TestPeekDoesNotConsumeTheQueue(t *testing.T) {
	m := newTestMailbox(1000)
	alice := newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose, Channel: "ab"}); err != nil {
		t.Fatal(err)
	}
	ch := MailboxChallenge(testNode, alice.address(), "peek")
	proof := alice.sign(PersonalDigest(ch))

	for i := 1; i <= 3; i++ {
		got, err := m.Peek(alice.address(), ch, proof)
		if err != nil {
			t.Fatalf("peek %d: %v", i, err)
		}
		if len(got) != 1 {
			t.Fatalf("peek %d returned %d frames, want 1", i, len(got))
		}
		if m.Pending(alice.address()) != 1 {
			t.Fatalf("peek %d consumed the queue", i)
		}
	}

	// Collect remains the consuming path, and still works afterwards.
	got, err := m.Collect(alice.address(), ch, proof)
	if err != nil || len(got) != 1 {
		t.Fatalf("collect after peek: %v (%d)", err, len(got))
	}
	if m.Pending(alice.address()) != 0 {
		t.Fatal("collect did not consume the queue")
	}
}

func TestPeekNeedsTheRecipientsOwnProof(t *testing.T) {
	m := newTestMailbox(1000)
	alice, mallory := newSigner(t), newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); err != nil {
		t.Fatal(err)
	}
	ch := MailboxChallenge(testNode, alice.address(), "peek")

	if _, err := m.Peek(alice.address(), ch, mallory.sign(PersonalDigest(ch))); !errors.Is(err, ErrNotServed) {
		t.Fatalf("a stranger peeked: %v", err)
	}
	if m.Pending(alice.address()) != 1 {
		t.Fatal("a refused peek consumed the queue")
	}
}

func TestPeekIsRefusedOnceAuthorizationLapses(t *testing.T) {
	// An expired authorization must read as refused, never as an empty mailbox —
	// the recipient would otherwise be told nobody had tipped them.
	m := NewMailbox(testNode, func() int64 { return 1000 })
	alice := newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 1500)); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); err != nil {
		t.Fatal(err)
	}
	m.Now = func() int64 { return 2000 }

	ch := MailboxChallenge(testNode, alice.address(), "peek")
	got, err := m.Peek(alice.address(), ch, alice.sign(PersonalDigest(ch)))
	if !errors.Is(err, ErrNotServed) {
		t.Fatalf("want ErrNotServed, got %v", err)
	}
	if got != nil {
		t.Fatal("a refused peek returned frames")
	}
}

func TestPeekReturnsACopy(t *testing.T) {
	// The caller must not be able to reach into the queue this promised not to
	// touch.
	m := newTestMailbox(1000)
	alice := newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose, Channel: "aa"}); err != nil {
		t.Fatal(err)
	}
	ch := MailboxChallenge(testNode, alice.address(), "peek")
	got, err := m.Peek(alice.address(), ch, alice.sign(PersonalDigest(ch)))
	if err != nil {
		t.Fatal(err)
	}
	got[0].Channel = "tampered"

	again, _ := m.Peek(alice.address(), ch, alice.sign(PersonalDigest(ch)))
	if again[0].Channel != "aa" {
		t.Fatal("a caller mutated the queued frame through a peek result")
	}
}

func TestPeekCannotMakeTheMailboxSign(t *testing.T) {
	// Reading must never produce a signature. The mailbox holds no key at all,
	// so this is structural, but discovery is exactly where somebody would be
	// tempted to add one.
	m := newTestMailbox(1000)
	mt := reflect.TypeOf(m)
	for i := 0; i < mt.NumMethod(); i++ {
		if strings.Contains(strings.ToLower(mt.Method(i).Name), "sign") {
			t.Fatalf("Mailbox gained a %s method", mt.Method(i).Name)
		}
	}
}
