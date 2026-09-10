package channel

// P15 Case B — three tips from ONE contributor while the recipient is offline,
// against a REAL EVM.
//
// The claim: each state subsumes its predecessors, so the recipient
// countersigns only the HIGHEST and realises every tip. If that is true,
// Pool.View() after accepting nonce 3 alone equals the sum of all three tips,
// and nonces 1 and 2 never need to be accepted at all.
//
//	P15_DEVNET=1 P15_RPC=… P15_MANAGER=… P15_CHANNEL=… \
//	P15_CONTRIBUTOR_KEY=… P15_RECIPIENT_KEY=… \
//	  go test ./internal/channel/ -run TestP15CaseB -v

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestP15CaseBHighestStateSubsumes(t *testing.T) {
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

	// ---- the volunteer: holds frames, holds no key --------------------------
	const nodeID = "volunteer-caseb"
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

	// ---- the contributor builds a CHAIN while nobody is listening -----------
	//
	// Exactly what tip-channel.js does in the browser: each state is built from
	// the previous one, so nonce 3 already contains tips 1 and 2.
	tips := []*big.Int{anon(25), anon(40), anon(10)}
	sum := new(big.Int)
	var chain []State
	for i, tip := range tips {
		sum.Add(sum, tip)
		st := State{Channel: channelID, Nonce: uint64(i + 1), Op: OpState}
		if recipientIsA {
			st.BalanceA = new(big.Int).Set(sum)
			st.BalanceB = new(big.Int).Sub(total, sum)
		} else {
			st.BalanceB = new(big.Int).Set(sum)
			st.BalanceA = new(big.Int).Sub(total, sum)
		}
		chain = append(chain, st)

		// Signed by the contributor alone and handed to the volunteer. The
		// recipient has seen none of this.
		sig := contributorKey.sign(st.Digest(chainID, manager))
		body := map[string]any{"state": encodeStateWire(st)}
		if recipientIsA {
			body["sig_b"] = hexOf(sig)
		} else {
			body["sig_a"] = hexOf(sig)
		}
		env := Envelope{Type: MsgStatePropose, Channel: poolChannelHex(channelID),
			Body: mustJSON(t, body)}
		if err := mailbox.Deliver(recipientKey.address(), env); err != nil {
			t.Fatalf("tip %d: %v", i+1, err)
		}
	}
	t.Logf("QUEUED 3 TIPS while the recipient was offline; cumulative = %s", sum)

	// ---- the recipient comes online -----------------------------------------
	node := newWiredNode(t, recipientKey, reader, manager)
	if err := node.store.TrackFromChain(chainID, manager, occ); err != nil {
		t.Fatalf("adopting: %v", err)
	}
	tok := MailboxChallenge(nodeID, recipientKey.address(), "t")
	frames, err := mailbox.Collect(recipientKey.address(), tok,
		recipientKey.sign(PersonalDigest(tok)))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("collected %d frames, want 3", len(frames))
	}

	// ---- accept ONLY the highest --------------------------------------------
	//
	// THE CLAIM UNDER TEST. Nonces 1 and 2 are never accepted; if subsumption
	// holds, the pool still shows all three tips.
	highest := chain[len(chain)-1]
	both := SignedState{State: highest}
	mySig := recipientKey.sign(highest.Digest(chainID, manager))
	theirSig := contributorKey.sign(highest.Digest(chainID, manager))
	if recipientIsA {
		both.SigA, both.SigB = mySig, theirSig
	} else {
		both.SigA, both.SigB = theirSig, mySig
	}
	if err := node.store.Commit(channelID, func(c *Channel) error {
		return c.Accept(both)
	}); err != nil {
		t.Fatalf("accepting the highest state: %v", err)
	}

	pool := Pool{Name: PoolName, Recipient: recipientKey.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true}}
	view, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view: %v", err)
	}
	if view.Withdrawable.Cmp(sum) != 0 {
		t.Fatalf("SUBSUMPTION FAILED: accepted only nonce %d and the pool holds %s, want %s",
			highest.Nonce, view.Withdrawable, sum)
	}
	t.Logf("ACCEPTED ONLY NONCE %d — Pool.View() = %s (all three tips)",
		highest.Nonce, view.Withdrawable)

	// ---- the superseded states must now be refused --------------------------
	for _, old := range chain[:len(chain)-1] {
		stale := SignedState{State: old}
		s1 := recipientKey.sign(old.Digest(chainID, manager))
		s2 := contributorKey.sign(old.Digest(chainID, manager))
		if recipientIsA {
			stale.SigA, stale.SigB = s1, s2
		} else {
			stale.SigA, stale.SigB = s2, s1
		}
		if err := node.store.Commit(channelID, func(c *Channel) error {
			return c.Accept(stale)
		}); err == nil {
			t.Fatalf("a superseded state at nonce %d was accepted after nonce %d",
				old.Nonce, highest.Nonce)
		}
	}
	t.Log("SUPERSEDED STATES REFUSED: nonce cannot regress")

	// ---- duplicate collection changes nothing -------------------------------
	if err := node.store.Commit(channelID, func(c *Channel) error {
		return c.Accept(both)
	}); err == nil {
		t.Fatal("the same state was accepted twice")
	}
	again, err := pool.View(node.store)
	if err != nil {
		t.Fatal(err)
	}
	if again.Withdrawable.Cmp(sum) != 0 {
		t.Fatalf("a duplicate changed the pool: %s -> %s", sum, again.Withdrawable)
	}
	t.Logf("DUPLICATE REFUSED: pool unchanged at %s", again.Withdrawable)
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
