package channel

// P15 — three contributors, three channels, one recipient, against a REAL EVM.
//
// Two claims:
//   1. independent channels accumulate into one pool without interacting;
//   2. checkpointing one channel changes ONLY that channel.
//
// The aggregate is never asserted as a literal. Every channel is read
// independently and the pool is derived from the sum, so a test that passed
// because two errors cancelled would still fail here.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

type contributor struct {
	name string
	key  *signer
	id   [32]byte
	tip  *big.Int
}

func TestP15MultiContributorAndCheckpointSequence(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	recipientKey := signerFromHex(t, p15Env(t, "P15_RECIPIENT_KEY"))
	npx, err := exec.LookPath("npx")
	if err != nil {
		t.Skip("npx not installed")
	}
	root, _ := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))

	people := []contributor{
		{name: "alice", key: signerFromHex(t, p15Env(t, "P15_ALICE_KEY")),
			id: parseChannelHex(t, p15Env(t, "P15_ALICE_CH")), tip: anon(25)},
		{name: "bob", key: signerFromHex(t, p15Env(t, "P15_BOB_KEY")),
			id: parseChannelHex(t, p15Env(t, "P15_BOB_CH")), tip: anon(40)},
		{name: "carol", key: signerFromHex(t, p15Env(t, "P15_CAROL_KEY")),
			id: parseChannelHex(t, p15Env(t, "P15_CAROL_CH")), tip: anon(15)},
	}

	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	chainID := big.NewInt(31337)

	node := newWiredNode(t, recipientKey, reader, manager)
	const nodeID = "volunteer-multi"
	mailbox := NewMailbox(nodeID, func() int64 { return time.Now().Unix() })
	auth := MailboxAuthorization{
		Recipient: recipientKey.address(), NodeID: nodeID,
		Endpoint: "https://volunteer.example/scpp/v1", Expires: time.Now().Unix() + 3600,
	}
	auth.Sig = recipientKey.sign(PersonalDigest(keccak32([]byte(auth.Message()))))
	if err := mailbox.Serve(auth); err != nil {
		t.Fatalf("volunteer refused: %v", err)
	}

	// ---- 1. queue three tips while the recipient is offline -----------------
	type built struct{ st State }
	states := map[string]built{}
	for _, p := range people {
		occ, err := reader.ReadChannel(ctx, manager, p.id)
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		if occ.Status != StatusOpen || occ.Nonce != 0 {
			t.Fatalf("%s needs a fresh channel; status=%d nonce=%d", p.name, occ.Status, occ.Nonce)
		}
		if err := node.store.TrackFromChain(chainID, manager, occ); err != nil {
			t.Fatalf("adopt %s: %v", p.name, err)
		}
		recipientIsA := occ.PartyA == recipientKey.address()
		total := new(big.Int).Add(occ.DepositA, occ.DepositB)

		st := State{Channel: p.id, Nonce: 1, Op: OpState}
		if recipientIsA {
			st.BalanceA = new(big.Int).Set(p.tip)
			st.BalanceB = new(big.Int).Sub(total, p.tip)
		} else {
			st.BalanceB = new(big.Int).Set(p.tip)
			st.BalanceA = new(big.Int).Sub(total, p.tip)
		}
		states[p.name] = built{st}

		body := map[string]any{"state": encodeStateWire(st)}
		sig := p.key.sign(st.Digest(chainID, manager))
		if recipientIsA {
			body["sig_b"] = hexOf(sig)
		} else {
			body["sig_a"] = hexOf(sig)
		}
		raw, _ := json.Marshal(body)
		if err := mailbox.Deliver(recipientKey.address(),
			Envelope{Type: MsgStatePropose, Channel: poolChannelHex(p.id), Body: raw}); err != nil {
			t.Fatalf("queue %s: %v", p.name, err)
		}
	}
	t.Log("QUEUED three tips from three contributors while the recipient was offline")

	// ---- 2. the recipient collects and accepts each --------------------------
	tok := MailboxChallenge(nodeID, recipientKey.address(), "t")
	frames, err := mailbox.Collect(recipientKey.address(), tok,
		recipientKey.sign(PersonalDigest(tok)))
	if err != nil || len(frames) != 3 {
		t.Fatalf("collect: %v (%d frames)", err, len(frames))
	}
	for _, p := range people {
		occ, _ := reader.ReadChannel(ctx, manager, p.id)
		recipientIsA := occ.PartyA == recipientKey.address()
		st := states[p.name].st
		cs := SignedState{State: st}
		mine := recipientKey.sign(st.Digest(chainID, manager))
		theirs := p.key.sign(st.Digest(chainID, manager))
		if recipientIsA {
			cs.SigA, cs.SigB = mine, theirs
		} else {
			cs.SigA, cs.SigB = theirs, mine
		}
		if err := node.store.Commit(p.id, func(c *Channel) error { return c.Accept(cs) }); err != nil {
			t.Fatalf("accept %s: %v", p.name, err)
		}
	}

	// ---- 3. read every channel INDEPENDENTLY and derive the pool ------------
	ids := [][32]byte{}
	for _, p := range people {
		ids = append(ids, p.id)
	}
	freshPool := func() *big.Int {
		// A brand-new Pool every time: the view must be a computation, not a
		// number carried between assertions.
		pool := Pool{Name: PoolName, Recipient: recipientKey.address(),
			Members: append([][32]byte{}, ids...), Policy: PoolPolicy{Enabled: true}}
		v, err := pool.View(node.store)
		if err != nil {
			t.Fatalf("pool view: %v", err)
		}
		return v.Withdrawable
	}
	perChannel := func() map[string]*big.Int {
		out := map[string]*big.Int{}
		for _, p := range people {
			ch, ok := node.store.Get(p.id)
			if !ok {
				t.Fatalf("%s: channel missing", p.name)
			}
			out[p.name] = recipientBalance(ch.Latest.State, ch.PartyA == recipientKey.address())
		}
		return out
	}

	each := perChannel()
	derived := new(big.Int)
	names := []string{}
	for n := range each {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		derived.Add(derived, each[n])
		t.Logf("  %-6s channel = %s", n, each[n])
	}
	if got := freshPool(); got.Cmp(derived) != 0 {
		t.Fatalf("Pool.View() = %s but the channels sum to %s", got, derived)
	}
	for _, p := range people {
		if each[p.name].Cmp(p.tip) != 0 {
			t.Fatalf("%s holds %s, want %s", p.name, each[p.name], p.tip)
		}
	}
	t.Logf("POOL = %s, derived from the three channels independently", derived)

	// ---- 4. checkpoint each, one at a time ----------------------------------
	walletBefore := readToken(t, npx, root, manager, recipientKey.address())
	remaining := new(big.Int).Set(derived)

	for _, p := range people {
		occ, _ := reader.ReadChannel(ctx, manager, p.id)
		recipientIsA := occ.PartyA == recipientKey.address()
		sender := &scriptTxSender{
			t: t, root: root, nodeBin: npx, manager: manager.Hex(),
			channel: "0x" + hex.EncodeToString(p.id[:]),
			watch:   recipientKey.address().Hex(),
		}
		payout := NewPayoutWorker(node.store, reader, NewRPCChainWriter(sender), manager)
		api, err := NewAPI(node.coord, func(_ [32]byte, _ Address) (Peer, error) {
			return cosignerPeer{t: t, key: p.key, chainID: chainID, contract: manager,
				recipientIsA: recipientIsA}, nil
		}, testToken)
		if err != nil {
			t.Fatalf("NewAPI: %v", err)
		}
		// The production checkpoint path: KindCheckpoint through the coordinator,
		// co-signed, encoded by CheckpointCalldata, broadcast for real.
		res, err := node.coord.Checkpoint(ctx, p.id, nil,
			cosignerPeer{t: t, key: p.key, chainID: chainID, contract: manager,
				recipientIsA: recipientIsA})
		if err != nil {
			t.Fatalf("checkpoint %s: %v", p.name, err)
		}
		txHash, err := payout.BroadcastCheckpoint(ctx, p.id)
		if err != nil {
			t.Fatalf("broadcast %s: %v", p.name, err)
		}
		_ = api
		remaining.Sub(remaining, p.tip)
		t.Logf("CHECKPOINT %-6s amount=%s tx=%s", p.name, res.Amount, txHash)

		// Only this channel moved.
		after := perChannel()
		for _, q := range people {
			want := q.tip
			if checkpointedYet(people, p.name, q.name) {
				want = big.NewInt(0)
			}
			if after[q.name].Cmp(want) != 0 {
				t.Fatalf("after checkpointing %s, %s holds %s (want %s) — a checkpoint "+
					"changed another channel", p.name, q.name, after[q.name], want)
			}
		}
		if got := freshPool(); got.Cmp(remaining) != 0 {
			t.Fatalf("after %s: pool = %s, want %s", p.name, got, remaining)
		}
		t.Logf("  pool now %s; other channels untouched", remaining)

		// The channel must still be OPEN — that is what makes it a checkpoint.
		fresh, err := reader.ReadChannel(ctx, manager, p.id)
		if err != nil {
			t.Fatalf("re-read %s: %v", p.name, err)
		}
		if fresh.Status != StatusOpen {
			t.Fatalf("%s closed after a checkpoint (status %d)", p.name, fresh.Status)
		}
	}

	if got := freshPool(); got.Sign() != 0 {
		t.Fatalf("pool = %s after all three checkpoints, want 0", got)
	}

	// ---- 5. the ERC-20 contract is the authority on what was paid -----------
	walletAfter := readToken(t, npx, root, manager, recipientKey.address())
	delta := new(big.Int).Sub(walletAfter, walletBefore)
	if delta.Cmp(derived) != 0 {
		t.Fatalf("the recipient's WALLET gained %s but the pool released %s", delta, derived)
	}
	t.Logf("ERC-20 WALLET DELTA = %s, read from the token contract", delta)
}

func checkpointedYet(people []contributor, upTo, who string) bool {
	for _, p := range people {
		if p.name == who {
			return true
		}
		if p.name == upTo {
			return false
		}
	}
	return false
}

// cosignerPeer answers a checkpoint proposal with the contributor's signature.
type cosignerPeer struct {
	t            *testing.T
	key          *signer
	chainID      *big.Int
	contract     Address
	recipientIsA bool
}

func (p cosignerPeer) Exchange(_ context.Context, out Envelope) (Envelope, error) {
	var body struct {
		Intent string      `json:"intent"`
		State  storedState `json:"state"`
	}
	if err := json.Unmarshal(out.Body, &body); err != nil {
		return Envelope{}, err
	}
	st, err := decodeStateWire(body.State)
	if err != nil {
		return Envelope{}, err
	}
	sig := p.key.sign(st.Digest(p.chainID, p.contract))
	reply, _ := json.Marshal(map[string]any{"intent": body.Intent, "sig": hexOf(sig)})
	return Envelope{V: 1, Type: MsgStateAccept, Channel: out.Channel, Body: reply}, nil
}

// readToken asks the ERC-20 contract directly.
func readToken(t *testing.T, npx, root string, manager Address, who Address) *big.Int {
	t.Helper()
	cmd := exec.Command(npx, "hardhat", "run",
		filepath.Join("scripts", "p15-read-token.ts"), "--network", "localhost")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "P15_MANAGER="+manager.Hex(), "P15_WHO="+who.Hex())
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reading the token: %v\n%s", err, raw)
	}
	for _, line := range splitLines(string(raw)) {
		if len(line) > 14 && line[:14] == "P15_BALANCE_JSON" [:14] {
			var out struct {
				Balance string `json:"balance"`
			}
			if json.Unmarshal([]byte(line[16:]), &out) == nil {
				v, _ := new(big.Int).SetString(out.Balance, 10)
				return v
			}
		}
	}
	t.Fatalf("no balance in:\n%s", raw)
	return nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
