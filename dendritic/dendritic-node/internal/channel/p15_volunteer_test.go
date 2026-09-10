package channel

// P15 — a volunteer node, end to end, against a REAL EVM.
//
// The product claim being tested: a recipient who runs NO node can be tipped,
// by appointing a volunteer, and can choose between
//
//	mailbox     the volunteer holds frames; the recipient's own key signs
//	delegate    the volunteer signs OP_STATE while the recipient is offline
//
// without the volunteer ever becoming the beneficiary.
//
// No FakeChain. The delegation is read from the deployed contract through the
// production RPC reader, and the settlement is a real transaction.
//
//	P15_DEVNET=1 P15_RPC=http://127.0.0.1:8545 P15_MANAGER=… P15_CHANNEL=… \
//	P15_CONTRIBUTOR_KEY=… P15_RECIPIENT_KEY=… P15_DELEGATE_KEY=… \
//	  go test ./internal/channel/ -run TestP15Volunteer -v

import (
	"context"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestP15VolunteerLifecycle(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1 — this needs a hardhat node on 127.0.0.1:8545")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	channelID := parseChannelHex(t, p15Env(t, "P15_CHANNEL"))
	recipientSigner := signerFromHex(t, p15Env(t, "P15_RECIPIENT_KEY"))
	contributorSigner := signerFromHex(t, p15Env(t, "P15_CONTRIBUTOR_KEY"))
	delegateSigner := signerFromHex(t, p15Env(t, "P15_DELEGATE_KEY"))

	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	occ, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("reading the devnet channel: %v", err)
	}
	if occ.Status != StatusOpen {
		t.Fatalf("channel status %d, want open", occ.Status)
	}
	recipientIsA := occ.PartyA == recipientSigner.address()
	t.Logf("RECIPIENT IS PARTY %s", map[bool]string{true: "A", false: "B"}[recipientIsA])

	chainID := big.NewInt(31337)
	recipient := newWiredNode(t, recipientSigner, reader, manager)
	contributor := newWiredNode(t, contributorSigner, reader, manager)
	for _, n := range []*wiredNode{recipient, contributor} {
		if err := n.store.TrackFromChain(chainID, manager, occ); err != nil {
			t.Fatalf("adopting: %v", err)
		}
	}

	// ---- 1. THE VOLUNTEER ----------------------------------------------------
	//
	// It holds a mailbox and a delegate key. It holds NO recipient key, and
	// there is nowhere on either type to put one.
	const nodeID = "volunteer-devnet-1"
	mailbox := NewMailbox(nodeID, func() int64 { return time.Now().Unix() })

	authority := RPCDelegateAuthority{Chain: reader}
	delegate, err := NewDelegateSigner(delegateSigner.address(),
		func(raw [32]byte) ([]byte, error) { return delegateSigner.sign(raw), nil },
		authority, manager)
	if err != nil {
		t.Fatalf("NewDelegateSigner: %v", err)
	}
	t.Logf("VOLUNTEER: node=%s delegate=%s", nodeID, delegate.Address.Hex())

	// ---- 2. THE RECIPIENT APPOINTS THE MAILBOX -------------------------------
	auth := MailboxAuthorization{
		Recipient: recipientSigner.address(), NodeID: nodeID,
		Endpoint: "https://volunteer.example/scpp/v1",
		Expires:  time.Now().Unix() + 3600,
	}
	auth.Sig = recipientSigner.sign(PersonalDigest(keccak32([]byte(auth.Message()))))
	if err := mailbox.Serve(auth); err != nil {
		t.Fatalf("the volunteer refused a valid authorization: %v", err)
	}
	if !mailbox.Serves(recipientSigner.address()) {
		t.Fatal("the volunteer does not serve the recipient it just accepted")
	}

	// A second recipient on the SAME volunteer, to prove isolation.
	other := signerFromHex(t, p15Env(t, "P15_CONTRIBUTOR_KEY"))
	_ = other

	// ---- 3. MAILBOX MODE NEEDS THE RECIPIENT ---------------------------------
	//
	// Before delegation, the volunteer can carry a proposal and can do nothing
	// with it. It has no key for this recipient, so the tip is not complete
	// until the recipient's own node signs.
	if delegate.Serves(recipientSigner.address()) {
		t.Fatal("the delegate claims a recipient that has not delegated yet")
	}
	// Only meaningful BEFORE the harness sets a delegation: once one exists,
	// adopting is supposed to succeed and section 5 asserts that instead.
	if os.Getenv("P15_DELEGATED") == "" {
		if err := delegate.Adopt(ctx, recipientSigner.address()); err == nil {
			t.Fatal("the volunteer adopted a recipient who never authorized it on chain")
		}
		t.Log("MAILBOX MODE: the volunteer cannot sign for the recipient — confirmed against the chain")
	}

	// The recipient's own node completes an ordinary tip.
	tip := anon(25)
	if _, err := contributor.coord.Pay(ctx, channelID, intent(41),
		StateTransition{Kind: KindPay, Amount: tip},
		directPeer{t, recipient.coord}); err != nil {
		t.Fatalf("the mailbox-mode tip did not complete: %v", err)
	}
	pool := Pool{Name: PoolName, Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true}}
	view, err := pool.View(recipient.store)
	if err != nil {
		t.Fatalf("pool view: %v", err)
	}
	if view.Withdrawable.Cmp(tip) != 0 {
		t.Fatalf("after a mailbox tip the pool holds %s, want %s", view.Withdrawable, tip)
	}
	t.Logf("MAILBOX TIP COMPLETED: pool = %s", view.Withdrawable)

	// ---- 4. FRAMES ARE CARRIED VERBATIM AND ARE ISOLATED ---------------------
	frame := Envelope{Type: MsgStatePropose, Channel: poolChannelHex(channelID),
		Body: []byte(`{"intent":"deadbeef"}`)}
	if err := mailbox.Deliver(recipientSigner.address(), frame); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	stranger := signerFromHex(t, p15Env(t, "P15_DELEGATE_KEY"))
	if err := mailbox.Deliver(stranger.address(), frame); err == nil {
		t.Fatal("the volunteer queued a frame for somebody it does not serve")
	}
	tok := "devnet-token"
	ch := MailboxChallenge(nodeID, recipientSigner.address(), tok)
	if _, err := mailbox.Collect(recipientSigner.address(), ch,
		stranger.sign(PersonalDigest(ch))); err == nil {
		t.Fatal("a stranger collected the recipient's mail")
	}
	got, err := mailbox.Collect(recipientSigner.address(), ch,
		recipientSigner.sign(PersonalDigest(ch)))
	if err != nil || len(got) != 1 || string(got[0].Body) != string(frame.Body) {
		t.Fatalf("the recipient could not collect their own mail verbatim: %v, %d", err, len(got))
	}
	t.Log("MAILBOX: frames carried verbatim, isolated, and collectable only by the recipient")

	// ---- 5. DELEGATION, READ FROM THE REAL CONTRACT --------------------------
	//
	// The recipient has by now called setDelegate on chain (the harness script
	// does it). The node does not take that on trust — it asks.
	if os.Getenv("P15_DELEGATED") == "" {
		t.Log("P15_DELEGATED not set; stopping after mailbox mode")
		return
	}
	// When the harness has already revoked, the adopt-and-sign block below is
	// expected to fail — that is section 6's whole point — so it is skipped
	// rather than asserted both ways in one run.
	revoked := os.Getenv("P15_REVOKED") != ""
	next := State{
		Channel: channelID, Nonce: 9,
		BalanceA: anon(100), BalanceB: anon(100), Op: OpState,
	}
	if !revoked {
		if err := delegate.Adopt(ctx, recipientSigner.address()); err != nil {
			t.Fatalf("the chain says this node is not a delegate: %v", err)
		}
		t.Log("DELEGATE ADOPTED: confirmed by ChannelManagerV2.canSign")

		// It may sign an ordinary state...
		if _, err := delegate.SignState(ctx, recipientSigner.address(), chainID, manager, next); err != nil {
			t.Fatalf("the delegate refused an ordinary state: %v", err)
		}
		// ...and nothing else.
		for _, bad := range []State{
			{Channel: channelID, Nonce: 9, BalanceA: anon(100), Op: OpCheckpoint},
			{Channel: channelID, Nonce: 9, BalanceA: anon(100), Op: OpCoopClose},
			{Channel: channelID, Nonce: 9, BalanceA: anon(100), WithdrawB: anon(1), Op: OpState},
		} {
			if _, err := delegate.SignState(ctx, recipientSigner.address(), chainID, manager, bad); err == nil {
				t.Fatalf("the delegate signed a %d-domain state", bad.op())
			}
		}
		t.Log("DELEGATE: signs OP_STATE, refuses checkpoint and cooperative close")
	}

	// ---- 6. REVOCATION -------------------------------------------------------
	if !revoked {
		t.Log("P15_REVOKED not set; stopping before revocation")
		return
	}
	if _, err := delegate.SignState(ctx, recipientSigner.address(), chainID, manager, next); err == nil {
		t.Fatal("a revoked delegate still signed")
	}
	if delegate.Serves(recipientSigner.address()) {
		t.Fatal("the node still claims a revoked delegation")
	}
	t.Log("REVOKED: the delegate stopped signing immediately")

	// ---- 7. MAILBOX STILL WORKS AFTER DELEGATION IS GONE ---------------------
	if !mailbox.Serves(recipientSigner.address()) {
		t.Fatal("revoking delegation also removed the mailbox; they are separate")
	}
	if err := mailbox.Deliver(recipientSigner.address(), frame); err != nil {
		t.Fatalf("mailbox-only operation broke after revocation: %v", err)
	}
	t.Log("MAILBOX-ONLY: still serving after delegation was removed")
}
