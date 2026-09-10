package channel

// P15 phase 3A — the real devnet join.
//
// The blocker this closes: every existing end-to-end test drives the production
// tip against NewFakeChain(). Real contracts were deployed in hardhat, real
// payments were exchanged in Go, and the two had never met.
//
// Here the recipient's node learns about its channel from the ACTUAL EVM at
// 127.0.0.1:8545, through the production RPCChainReader, and the tip is the
// production browser client. There is no FakeChain in this file, and it FAILS
// rather than falls back if the devnet is unreachable — a silent downgrade to
// FakeChain is exactly how this would come to claim more than it proved.
//
//	P15_DEVNET=1 P15_RPC=http://127.0.0.1:8545 \
//	P15_MANAGER=0x… P15_CHANNEL=0x… P15_CONTRIBUTOR=0x… P15_RECIPIENT_KEY=… \
//	  go test ./internal/channel/ -run TestP15Devnet -v

import (
	"context"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func p15Env(t *testing.T, name string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		t.Skipf("set %s (see the phase 3A harness)", name)
	}
	return v
}

// TestP15DevnetLifecycle: real chain -> real node -> real tip -> Pool.View().
func TestP15DevnetLifecycle(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1 — this needs a hardhat node on 127.0.0.1:8545")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	contributor := mustAddr(t, p15Env(t, "P15_CONTRIBUTOR"))
	recipientKeyHex := p15Env(t, "P15_RECIPIENT_KEY")
	tipperKey := p15Env(t, "P15_CONTRIBUTOR_KEY")

	var channelID [32]byte
	raw := strings.TrimPrefix(p15Env(t, "P15_CHANNEL"), "0x")
	for i := 0; i < 32 && i*2+1 < len(raw); i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := raw[i*2+j]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = c - 'A' + 10
			}
			b = b<<4 | v
		}
		channelID[i] = b
	}

	// ---- 1. THE GO SIDE READS THE REAL CHAIN --------------------------------
	//
	// Production RPCChainReader against the devnet. If this cannot reach the
	// EVM the test fails; it does not substitute anything.
	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	occ, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("RPCChainReader could not read the devnet channel: %v", err)
	}
	if occ.Status != StatusOpen {
		t.Fatalf("the devnet channel is status %d, want open", occ.Status)
	}
	total := new(big.Int).Add(occ.DepositA, occ.DepositB)
	if total.Sign() == 0 {
		t.Fatal("the devnet channel holds no collateral; the deposit did not land")
	}
	t.Logf("READ FROM THE DEVNET: partyA=%s partyB=%s depositA=%s depositB=%s status=%d",
		occ.PartyA.Hex(), occ.PartyB.Hex(), occ.DepositA, occ.DepositB, occ.Status)

	// ---- 2. THE RECIPIENT NODE ADOPTS IT ------------------------------------
	recipientSigner := signerFromHex(t, recipientKeyHex)
	if recipientSigner.address() != occ.PartyA && recipientSigner.address() != occ.PartyB {
		t.Fatalf("the recipient key %s is not a party to the devnet channel",
			recipientSigner.address().Hex())
	}
	chainID := big.NewInt(31337)
	if v := os.Getenv("P15_CHAIN_ID"); v != "" {
		if n, ok := new(big.Int).SetString(v, 10); ok {
			chainID = n
		}
	}

	node := newWiredNode(t, recipientSigner, reader, manager)
	if err := node.store.TrackFromChain(chainID, manager, occ); err != nil {
		t.Fatalf("adopting the devnet channel: %v", err)
	}

	// ---- 3. THE POOL, BEFORE ------------------------------------------------
	pool := Pool{
		Name: "tips", Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID},
		Policy:  PoolPolicy{Enabled: true},
	}
	before, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view before: %v", err)
	}
	t.Logf("POOL VIEW BEFORE: withdrawable=%s members=%d",
		before.Withdrawable, before.Members)

	// ---- 4. THE REAL TIP, THROUGH THE PRODUCTION BROWSER CLIENT -------------
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	root, _ := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))
	script := filepath.Join(root, "browser-test", "pay-node.mjs")

	wp := &WebPeer{Handler: node.coord, Timeout: 20 * time.Second}
	srv := httptest.NewServer(wp.HTTPHandler())
	defer srv.Close()

	amount := anon(25)
	cmd := exec.Command(nodeBin, script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SCPP_URL="+srv.URL+"/scpp/v1",
		"TIP_KEY="+tipperKey,
		"RECIPIENT="+recipientSigner.address().Hex(),
		"MANAGER="+manager.Hex(),
		"CHAIN_ID="+chainID.String(),
		"PARTY_A="+occ.PartyA.Hex(),
		"PARTY_B="+occ.PartyB.Hex(),
		"DEPOSIT_A="+occ.DepositA.String(),
		"DEPOSIT_B="+occ.DepositB.String(),
		"AMOUNT="+amount.String(),
	)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("the production browser client failed: %v\n%s", err, stderr)
	}
	t.Logf("TIP DRIVER: %s", strings.TrimSpace(string(out)))
	if !strings.Contains(string(out), "completed") {
		t.Fatalf("the tip did not complete: %s", out)
	}
	_ = contributor

	// ---- 5. THE POOL, AFTER -------------------------------------------------
	after, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view after: %v", err)
	}
	t.Logf("POOL VIEW AFTER: withdrawable=%s members=%d",
		after.Withdrawable, after.Members)

	gain := new(big.Int).Sub(after.Withdrawable, before.Withdrawable)
	if gain.Cmp(amount) != 0 {
		t.Fatalf("the pool grew by %s, want exactly the tip of %s", gain, amount)
	}

	// ---- 6. RECONSTRUCTION --------------------------------------------------
	// A fresh Pool over the same store. Nothing pool-shaped is persisted, so
	// this is the whole of "recovered after restart".
	rebuilt := Pool{
		Name: "tips", Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID},
		Policy:  PoolPolicy{Enabled: true},
	}
	again, err := rebuilt.View(node.store)
	if err != nil {
		t.Fatalf("pool view after reconstruction: %v", err)
	}
	if again.Withdrawable.Cmp(after.Withdrawable) != 0 {
		t.Fatalf("reconstructed view %s differs from %s",
			again.Withdrawable, after.Withdrawable)
	}
	t.Logf("RECONSTRUCTED: withdrawable=%s (identical)", again.Withdrawable)
}

// signerFromHex builds the recipient wallet from a devnet key supplied at run
// time. Nothing is hardcoded and nothing is logged: the key arrives in the
// environment, is used to sign states, and never leaves this process.
func signerFromHex(t *testing.T, hexKey string) *signer {
	t.Helper()
	raw := strings.TrimPrefix(strings.TrimSpace(hexKey), "0x")
	b := make([]byte, len(raw)/2)
	for i := range b {
		var v byte
		for j := 0; j < 2; j++ {
			c := raw[i*2+j]
			var d byte
			switch {
			case c >= '0' && c <= '9':
				d = c - '0'
			case c >= 'a' && c <= 'f':
				d = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				d = c - 'A' + 10
			default:
				t.Fatalf("the supplied key is not hex")
			}
			v = v<<4 | d
		}
		b[i] = v
	}
	if len(b) != 32 {
		t.Fatalf("the supplied key is %d bytes, want 32", len(b))
	}
	return &signer{priv: secp256k1.PrivKeyFromBytes(b)}
}

// P15 phase 3B — the CORRECT checkpoint, built by the production path.
//
// The first attempt derived the nonce from the ON-CHAIN nonce and produced a
// second signed state at nonce 1, colliding with the state the tip had already
// co-signed. That transaction was real and moved real tokens, but it is NOT
// protocol evidence: it bypassed the node and signed with raw wallets, which is
// exactly how invariant I4 gets skipped.
//
// Here the checkpoint comes from StateTransition{KindCheckpoint}.Apply on the
// channel's ACTUAL post-tip state, so the nonce is chosen by the same machinery
// production uses, and CheckpointCalldata builds the transaction.
func TestP15DevnetCheckpointThroughTheNode(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	recipientSigner := signerFromHex(t, p15Env(t, "P15_RECIPIENT_KEY"))
	contributorSigner := signerFromHex(t, p15Env(t, "P15_CONTRIBUTOR_KEY"))
	channelID := p15Channel(t)

	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	occ, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("reading the devnet channel: %v", err)
	}
	chainID := big.NewInt(31337)

	node := newWiredNode(t, recipientSigner, reader, manager)
	if err := node.store.TrackFromChain(chainID, manager, occ); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// GUARD 1 — the channel must be PRISTINE.
	//
	// This is the check that would have caught the 1450-vs-1475 discrepancy.
	// A channel that has already been checkpointed has REDUCED deposits, so
	// synthesising a "post-tip" state from the current deposits silently
	// describes a different history — and the contract accepts it, because
	// conservation still holds against the reduced figures. The harness bug is
	// masked by the contract being correct.
	if occ.Nonce != 0 {
		t.Fatalf("the devnet channel is already at nonce %d with deposits %s/%s; "+
			"reconstructing a post-tip state from reduced deposits would invent a "+
			"history. Redeploy for a pristine channel.",
			occ.Nonce, occ.DepositA, occ.DepositB)
	}

	// Rebuild the post-tip state the real payment produced: the recipient (party
	// A here, because their address sorts lower) is owed 25 ANON.
	tip := anon(25)
	total := new(big.Int).Add(occ.DepositA, occ.DepositB)
	ch, _ := node.store.Get(channelID)

	// SIDE-AWARE. Which party the recipient is depends on ADDRESS ORDERING, not
	// on who is paying — the trap tip-channel.js documents. Phase 4 happened to
	// put the recipient on party A in both channels, so withdrawB was never
	// exercised; this now follows whichever side the chain actually assigned.
	recipientIsA := occ.PartyA == recipientSigner.address()
	t.Logf("RECIPIENT IS PARTY %s (partyA=%s recipient=%s)",
		map[bool]string{true: "A", false: "B"}[recipientIsA],
		occ.PartyA.Hex(), recipientSigner.address().Hex())
	postTip := State{Channel: channelID, Nonce: 1}
	if recipientIsA {
		postTip.BalanceA = new(big.Int).Set(tip)
		postTip.BalanceB = new(big.Int).Sub(total, tip)
	} else {
		postTip.BalanceB = new(big.Int).Set(tip)
		postTip.BalanceA = new(big.Int).Sub(total, tip)
	}
	// Store.Accept is the production acceptance path: it enforces monotonicity
	// and the I4 rules. Using it rather than writing the struct directly is the
	// whole point of this correction.
	if err := node.store.Accept(channelID,
		signBoth(t, postTip, chainID, manager, recipientSigner, contributorSigner)); err != nil {
		t.Fatalf("accepting the post-tip state: %v", err)
	}
	ch, _ = node.store.Get(channelID)

	pool := Pool{Name: "tips", Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true}}
	before, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view before: %v", err)
	}
	t.Logf("POOL VIEW BEFORE CHECKPOINT: %s", before.Withdrawable)

	// ---- THE PRODUCTION PATH ------------------------------------------------
	// The nonce is the transition machinery's to choose, not the harness's.
	tr := StateTransition{Kind: KindCheckpoint, Amount: new(big.Int).Set(tip)}
	next, err := tr.Apply(ch, recipientSigner.address())
	if err != nil {
		t.Fatalf("KindCheckpoint transition: %v", err)
	}
	if next.Nonce != postTip.Nonce+1 {
		t.Fatalf("the transition produced nonce %d from a state at %d; a checkpoint "+
			"at the same nonce is the I4 violation this test exists for",
			next.Nonce, postTip.Nonce)
	}
	t.Logf("CHECKPOINT STATE from the node: nonce=%d balanceA=%s balanceB=%s withdrawA=%v withdrawB=%v",
		next.Nonce, next.BalanceA, next.BalanceB, next.WithdrawA, next.WithdrawB)

	// The withdrawal must land on the RECIPIENT'S side, whichever that is.
	withdrew, other := next.WithdrawA, next.WithdrawB
	if !recipientIsA {
		withdrew, other = next.WithdrawB, next.WithdrawA
	}
	if withdrew == nil || withdrew.Cmp(tip) != 0 {
		t.Fatalf("the checkpoint withdrew %v on the recipient's side, want %s", withdrew, tip)
	}
	if other != nil && other.Sign() != 0 {
		t.Fatalf("the checkpoint also withdrew %s on the OTHER party's side", other)
	}

	if err := node.store.Accept(channelID,
		signBoth(t, next, chainID, manager, recipientSigner, contributorSigner)); err != nil {
		t.Fatalf("accepting the checkpoint state: %v", err)
	}
	ch, _ = node.store.Get(channelID)

	// ---- I4: the SAME nonce cannot carry a DIFFERENT state -----------------
	clash := next
	clash.BalanceA = new(big.Int).Add(next.BalanceA, big.NewInt(1))
	clash.BalanceB = new(big.Int).Sub(next.BalanceB, big.NewInt(1))
	if err := node.store.Accept(channelID,
		signBoth(t, clash, chainID, manager, recipientSigner, contributorSigner)); err == nil {
		t.Fatalf("a DIFFERENT state at nonce %d was accepted; two signed states "+
			"at one nonce is exactly the defect this phase exists to correct", next.Nonce)
	} else {
		t.Logf("I4 HOLDS: a different state at nonce %d was refused (%v)", next.Nonce, err)
	}

	// GUARD 2 — local state must agree with the chain BEFORE broadcasting.
	//
	// Parties and deposits are the chain's to state; balances are ours. What
	// must hold across the boundary is conservation, exactly as the contract
	// checks it. A harness whose arithmetic has drifted fails here rather than
	// discovering it from a revert — or worse, not discovering it at all.
	fresh, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("re-reading the chain before broadcast: %v", err)
	}
	if fresh.PartyA != occ.PartyA || fresh.PartyB != occ.PartyB {
		t.Fatalf("the chain's parties changed under the harness")
	}
	chainTotal := new(big.Int).Add(fresh.DepositA, fresh.DepositB)
	localTotal := new(big.Int).Add(next.BalanceA, next.BalanceB)
	localTotal.Add(localTotal, orZero(next.WithdrawA))
	localTotal.Add(localTotal, orZero(next.WithdrawB))
	if localTotal.Cmp(chainTotal) != 0 {
		t.Fatalf("REFUSING TO BROADCAST: local state totals %s but the chain holds "+
			"%s of collateral. The harness and the chain disagree about this "+
			"channel's history.", localTotal, chainTotal)
	}
	t.Logf("LOCAL == CHAIN: parties match, conservation %s == %s", localTotal, chainTotal)

	calldata, err := CheckpointCalldata(ch)
	if err != nil {
		t.Fatalf("CheckpointCalldata: %v", err)
	}
	t.Logf("CALLDATA built by the production encoder: %d bytes", len(calldata))

	// ---- POOL VIEW AFTER, AND AFTER RECONSTRUCTION -------------------------
	after, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view after: %v", err)
	}
	rebuilt := Pool{Name: "tips", Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true}}
	again, err := rebuilt.View(node.store)
	if err != nil {
		t.Fatalf("pool view after reconstruction: %v", err)
	}
	t.Logf("POOL VIEW AFTER CHECKPOINT: %s", after.Withdrawable)
	t.Logf("POOL VIEW RECONSTRUCTED    : %s", again.Withdrawable)

	// The RELATIONSHIP, not a literal: whatever left the channel as a
	// withdrawal is no longer withdrawable from it.
	moved := new(big.Int).Sub(before.Withdrawable, after.Withdrawable)
	if moved.Cmp(withdrew) != 0 {
		t.Fatalf("the pool fell by %s but the checkpoint withdrew %s; the view "+
			"and the withdrawal disagree", moved, withdrew)
	}
	if again.Withdrawable.Cmp(after.Withdrawable) != 0 {
		t.Fatalf("reconstructed view %s differs from %s",
			again.Withdrawable, after.Withdrawable)
	}
	t.Logf("RELATIONSHIP HOLDS: pool fell by exactly the %s checkpointed", moved)
	if err := os.WriteFile(os.Getenv("P15_CALLDATA_OUT"),
		[]byte("0x"+hexOf(calldata)), 0o644); err != nil {
		t.Fatalf("writing calldata: %v", err)
	}
}

func p15Channel(t *testing.T) [32]byte {
	t.Helper()
	var id [32]byte
	raw := strings.TrimPrefix(p15Env(t, "P15_CHANNEL"), "0x")
	for i := 0; i < 32; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := raw[i*2+j]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = c - 'A' + 10
			}
			b = b<<4 | v
		}
		id[i] = b
	}
	return id
}

func signBoth(t *testing.T, st State, chainID *big.Int, contract Address,
	a, b *signer) SignedState {
	t.Helper()
	raw := st.Digest(chainID, contract)
	sa, sb := a.sign(raw), b.sign(raw)
	if a.address().Less(b.address()) {
		return SignedState{State: st, SigA: sa, SigB: sb}
	}
	return SignedState{State: st, SigA: sb, SigB: sa}
}
