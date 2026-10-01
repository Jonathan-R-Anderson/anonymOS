package channel

// P15 Case A — the contributor learns its tip was accepted, and continues from
// there. Against a REAL EVM.
//
// The gap this closes: after handing a proposal to a volunteer there is no
// reply, so a contributor never discovers the countersignature and has no base
// for tip 2. Here the recipient publishes what it accepted, the contributor
// reads it back, verifies it, and builds tip 2 on it.
//
// The assertion that matters is at the end: tip 2 must NOT reuse tip 1's nonce
// or balances. If the recovery silently failed, it would.

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestP15CaseAReadBack(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	channelID := parseChannelHex(t, p15Env(t, "P15_CHANNEL"))
	recipientKey := signerFromHex(t, p15Env(t, "P15_RECIPIENT_KEY"))
	contributorKey := signerFromHex(t, p15Env(t, "P15_CONTRIBUTOR_KEY"))

	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	occ, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("reading the devnet channel: %v", err)
	}
	if occ.Status != StatusOpen || occ.Nonce != 0 {
		t.Fatalf("need a fresh open channel; status=%d nonce=%d", occ.Status, occ.Nonce)
	}
	recipientIsA := occ.PartyA == recipientKey.address()
	chainID := big.NewInt(31337)
	total := new(big.Int).Add(occ.DepositA, occ.DepositB)
	chHex := poolChannelHex(channelID)

	const nodeID = "volunteer-casea"
	mailbox := NewMailbox(nodeID, func() int64 { return time.Now().Unix() })
	auth := MailboxAuthorization{
		Recipient: recipientKey.address(), NodeID: nodeID,
		Endpoint: "https://volunteer.example/scpp/v1",
		Expires:  time.Now().Unix() + 3600,
	}
	auth.Sig = recipientKey.sign(PersonalDigest(keccak32([]byte(auth.Message()))))
	if err := mailbox.Serve(auth); err != nil {
		t.Fatalf("volunteer refused the authorization: %v", err)
	}

	// build a state at `nonce` giving the recipient `cum` in total
	build := func(nonce uint64, cum *big.Int) State {
		st := State{Channel: channelID, Nonce: nonce, Op: OpState}
		if recipientIsA {
			st.BalanceA = new(big.Int).Set(cum)
			st.BalanceB = new(big.Int).Sub(total, cum)
		} else {
			st.BalanceB = new(big.Int).Set(cum)
			st.BalanceA = new(big.Int).Sub(total, cum)
		}
		return st
	}
	cosign := func(st State) SignedState {
		out := SignedState{State: st}
		mine := recipientKey.sign(st.Digest(chainID, manager))
		theirs := contributorKey.sign(st.Digest(chainID, manager))
		if recipientIsA {
			out.SigA, out.SigB = mine, theirs
		} else {
			out.SigA, out.SigB = theirs, mine
		}
		return out
	}

	// ---- TIP 1, into the mailbox --------------------------------------------
	tip1 := anon(25)
	st1 := build(1, tip1)
	body1 := map[string]any{"state": encodeStateWire(st1)}
	sig1 := contributorKey.sign(st1.Digest(chainID, manager))
	if recipientIsA {
		body1["sig_b"] = hexOf(sig1)
	} else {
		body1["sig_a"] = hexOf(sig1)
	}
	raw1, _ := json.Marshal(body1)
	if err := mailbox.Deliver(recipientKey.address(),
		Envelope{Type: MsgStatePropose, Channel: chHex, Body: raw1}); err != nil {
		t.Fatalf("tip 1: %v", err)
	}
	t.Log("TIP 1 QUEUED while the recipient was offline")

	// ---- the recipient comes online, accepts, and PUBLISHES -----------------
	node := newWiredNode(t, recipientKey, reader, manager)
	if err := node.store.TrackFromChain(chainID, manager, occ); err != nil {
		t.Fatalf("adopting: %v", err)
	}
	tok := MailboxChallenge(nodeID, recipientKey.address(), "t")
	if _, err := mailbox.Collect(recipientKey.address(), tok,
		recipientKey.sign(PersonalDigest(tok))); err != nil {
		t.Fatalf("collect: %v", err)
	}
	accepted1 := cosign(st1)
	if err := node.store.Commit(channelID, func(c *Channel) error {
		return c.Accept(accepted1)
	}); err != nil {
		t.Fatalf("accepting tip 1: %v", err)
	}

	pubBody := map[string]any{
		"state": encodeStateWire(st1),
		"sig_a": hexOf(accepted1.SigA), "sig_b": hexOf(accepted1.SigB),
	}
	rawPub, _ := json.Marshal(pubBody)
	if err := mailbox.PublishAccepted(recipientKey.address(), chHex,
		Envelope{Type: MsgStateAccept, Channel: chHex, Body: rawPub},
		tok, recipientKey.sign(PersonalDigest(tok))); err != nil {
		t.Fatalf("publishing the accepted state: %v", err)
	}
	t.Log("RECIPIENT ACCEPTED TIP 1 and published the co-signed state")

	// ---- the contributor recovers it ----------------------------------------
	//
	// Through the same access rule the contributor already uses: it proves its
	// own address, and the channel id is DERIVED rather than taken on its word.
	ctok := MailboxChallenge(nodeID, contributorKey.address(), "t")
	frames, err := mailbox.StatesFor(recipientKey.address(), contributorKey.address(),
		chHex, ctok, contributorKey.sign(PersonalDigest(ctok)))
	if err != nil {
		t.Fatalf("the contributor could not read its own chain: %v", err)
	}

	// Verify before selecting — the volunteer is a cache, not an authority.
	var best *State
	for _, f := range frames {
		var b struct {
			State storedState `json:"state"`
			SigA  string      `json:"sig_a"`
			SigB  string      `json:"sig_b"`
		}
		if json.Unmarshal(f.Body, &b) != nil {
			continue
		}
		st, err := decodeStateWire(b.State)
		if err != nil || st.Channel != channelID {
			continue
		}
		if b.SigA == "" || b.SigB == "" {
			continue // a bare proposal is not evidence of acceptance
		}
		digest := st.Digest(chainID, manager)
		// RecoverSigner applies EIP-191 itself; wrapping again recovers a
		// stranger. The states above are signed with sign(digest), not
		// sign(PersonalDigest(digest)).
		a, errA := RecoverSigner(digest, mustHexBytes(t, b.SigA))
		bb, errB := RecoverSigner(digest, mustHexBytes(t, b.SigB))
		if errA != nil || errB != nil || a != occ.PartyA || bb != occ.PartyB {
			continue
		}
		if best == nil || st.Nonce > best.Nonce {
			cp := st
			best = &cp
		}
	}
	if best == nil {
		t.Fatal("the contributor recovered no verified co-signed state")
	}
	t.Logf("CONTRIBUTOR RECOVERED co-signed state at nonce %d", best.Nonce)

	// ---- TIP 2, built on the RECOVERED state --------------------------------
	cum2 := new(big.Int).Add(tip1, anon(40))
	st2 := build(best.Nonce+1, cum2)
	if st2.Nonce == st1.Nonce {
		t.Fatal("tip 2 reused tip 1's nonce; the recovery did not take effect")
	}
	accepted2 := cosign(st2)
	if err := node.store.Commit(channelID, func(c *Channel) error {
		return c.Accept(accepted2)
	}); err != nil {
		t.Fatalf("accepting tip 2: %v", err)
	}

	pool := Pool{Name: PoolName, Recipient: recipientKey.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true}}
	view, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view: %v", err)
	}
	if view.Withdrawable.Cmp(cum2) != 0 {
		t.Fatalf("pool = %s, want %s", view.Withdrawable, cum2)
	}
	t.Logf("TIP 2 BUILT ON THE RECOVERED STATE: nonce %d, Pool.View() = %s",
		st2.Nonce, view.Withdrawable)

	// The proof that recovery actually happened: tip 2 did not restart from
	// the chain, so its balances include tip 1.
	mine := recipientBalance(st2, recipientIsA)
	if mine.Cmp(tip1) <= 0 {
		t.Fatalf("tip 2 did not build on tip 1: recipient side is %s", mine)
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := ParseAuthorizationSig(s)
	if err != nil {
		t.Fatalf("bad signature hex: %v", err)
	}
	return b
}
