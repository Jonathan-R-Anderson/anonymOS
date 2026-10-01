package channel

// P15 phase 4 — two contributors, two channels, one derived pool.
//
// The question: can independent contributors tip one recipient without the pool
// becoming a shared pot? The answer has to come from the recipient's TWO
// separate bilateral states — the pool is their sum and nothing else, so
// checkpointing one channel must leave the other untouched.
//
// Real chain throughout. No FakeChain, no inserted balances.

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
)

type p15Leg struct {
	label       string
	id          [32]byte
	contributor *signer
	tip         *big.Int
}

func TestP15MultiContributorPool(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	recipient := signerFromHex(t, p15Env(t, "P15_RECIPIENT_KEY"))
	chainID := big.NewInt(31337)

	legs := []p15Leg{
		{label: "A", id: p15Hex32(t, p15Env(t, "P15_CHANNEL_A")),
			contributor: signerFromHex(t, p15Env(t, "P15_KEY_A")), tip: anon(25)},
		{label: "B", id: p15Hex32(t, p15Env(t, "P15_CHANNEL_B")),
			contributor: signerFromHex(t, p15Env(t, "P15_KEY_B")), tip: anon(40)},
	}

	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	node := newWiredNode(t, recipient, reader, manager)

	occs := map[string]OnChainChannel{}
	for _, leg := range legs {
		occ, err := reader.ReadChannel(ctx, manager, leg.id)
		if err != nil {
			t.Fatalf("channel %s: %v", leg.label, err)
		}
		if occ.Nonce != 0 {
			t.Fatalf("channel %s is already at nonce %d — redeploy for a pristine run",
				leg.label, occ.Nonce)
		}
		if err := node.store.TrackFromChain(chainID, manager, occ); err != nil {
			t.Fatalf("adopt %s: %v", leg.label, err)
		}
		occs[leg.label] = occ
		t.Logf("CHANNEL %s adopted from the devnet: depositB=%s", leg.label, occ.DepositB)
	}

	pool := Pool{Name: "tips", Recipient: recipient.address(),
		Members: [][32]byte{legs[0].id, legs[1].id}, Policy: PoolPolicy{Enabled: true}}

	view := func(stage string) *big.Int {
		v, err := pool.View(node.store)
		if err != nil {
			t.Fatalf("pool view (%s): %v", stage, err)
		}
		// Reconstruct from the same store with a FRESH Pool every time: there is
		// no pool state, so this must always agree.
		again, err := (Pool{Name: "tips", Recipient: recipient.address(),
			Members: pool.Members, Policy: PoolPolicy{Enabled: true}}).View(node.store)
		if err != nil {
			t.Fatalf("reconstructed view (%s): %v", stage, err)
		}
		if again.Withdrawable.Cmp(v.Withdrawable) != 0 {
			t.Fatalf("%s: reconstructed %s != %s", stage, again.Withdrawable, v.Withdrawable)
		}
		t.Logf("POOL %-22s = %s  (reconstructed identical, members=%d)",
			stage, v.Withdrawable, v.Members)
		return v.Withdrawable
	}

	if got := view("before any tip"); got.Sign() != 0 {
		t.Fatalf("pool starts at %s, want 0", got)
	}

	// ---- real tips through the production browser client --------------------
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	root, _ := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))
	wp := &WebPeer{Handler: node.coord, Timeout: 20 * time.Second}
	srv := httptest.NewServer(wp.HTTPHandler())
	defer srv.Close()

	for i, leg := range legs {
		occ := occs[leg.label]
		cmd := exec.Command(nodeBin, filepath.Join(root, "browser-test", "pay-node.mjs"))
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"SCPP_URL="+srv.URL+"/scpp/v1",
			"TIP_KEY="+p15Env(t, map[int]string{0: "P15_KEY_A", 1: "P15_KEY_B"}[i]),
			"RECIPIENT="+recipient.address().Hex(),
			"MANAGER="+manager.Hex(),
			"CHAIN_ID="+chainID.String(),
			"PARTY_A="+occ.PartyA.Hex(), "PARTY_B="+occ.PartyB.Hex(),
			"DEPOSIT_A="+occ.DepositA.String(), "DEPOSIT_B="+occ.DepositB.String(),
			"AMOUNT="+leg.tip.String(),
		)
		out, err := cmd.Output()
		if err != nil {
			var se string
			if ee, ok := err.(*exec.ExitError); ok {
				se = string(ee.Stderr)
			}
			t.Fatalf("tip %s failed: %v\n%s", leg.label, err, se)
		}
		if !strings.Contains(string(out), "completed") {
			t.Fatalf("tip %s did not complete: %s", leg.label, out)
		}
		t.Logf("TIP %s COMPLETED: %s ANON through the production client", leg.label, leg.tip)
	}

	// ---- the aggregate is the SUM of two separate states ---------------------
	for _, leg := range legs {
		ch, _ := node.store.Get(leg.id)
		bal := recipientBalance(ch.Latest.State, ch.PartyA == recipient.address())
		if bal.Cmp(leg.tip) != 0 {
			t.Fatalf("channel %s holds %s for the recipient, want %s", leg.label, bal, leg.tip)
		}
		t.Logf("CHANNEL %s recipient balance = %s (verified independently)", leg.label, bal)
	}
	both := view("after both tips")
	want := new(big.Int).Add(legs[0].tip, legs[1].tip)
	if both.Cmp(want) != 0 {
		t.Fatalf("pool is %s, want %s = %s + %s", both, want, legs[0].tip, legs[1].tip)
	}

	// ---- ISOLATION: checkpoint A only ---------------------------------------
	checkpointLocally(t, node, legs[0], recipient, chainID, manager)
	afterA := view("after A checkpointed")
	if afterA.Cmp(legs[1].tip) != 0 {
		t.Fatalf("after checkpointing A the pool is %s, want B's %s untouched — "+
			"the two channels are not independent", afterA, legs[1].tip)
	}
	chB, _ := node.store.Get(legs[1].id)
	if got := recipientBalance(chB.Latest.State, chB.PartyA == recipient.address()); got.Cmp(legs[1].tip) != 0 {
		t.Fatalf("checkpointing A changed channel B's balance to %s", got)
	}

	checkpointLocally(t, node, legs[1], recipient, chainID, manager)
	if got := view("after B checkpointed"); got.Sign() != 0 {
		t.Fatalf("pool is %s after both checkpoints, want 0", got)
	}

	// ---- DISJOINTNESS -------------------------------------------------------
	if err := CheckDisjoint([]Pool{pool}); err != nil {
		t.Fatalf("a pool over its own two channels was refused: %v", err)
	}
	rival := Pool{Name: "rival", Recipient: recipient.address(),
		Members: [][32]byte{legs[1].id}, Policy: PoolPolicy{Enabled: true}}
	if err := CheckDisjoint([]Pool{pool, rival}); err == nil {
		t.Fatal("a second pool claimed a channel already in the first; the value " +
			"would be counted twice and only one view could be withdrawn")
	} else {
		t.Logf("DISJOINTNESS: the overlapping pool was refused (%v)", err)
	}
}

// checkpointLocally advances one channel through the production KindCheckpoint
// path and writes its calldata out for broadcast.
func checkpointLocally(t *testing.T, node *wiredNode, leg p15Leg,
	recipient *signer, chainID *big.Int, manager Address) {
	t.Helper()
	ch, _ := node.store.Get(leg.id)
	tr := StateTransition{Kind: KindCheckpoint, Amount: new(big.Int).Set(leg.tip)}
	next, err := tr.Apply(ch, recipient.address())
	if err != nil {
		t.Fatalf("checkpoint transition %s: %v", leg.label, err)
	}
	if err := node.store.Accept(leg.id,
		signBoth(t, next, chainID, manager, recipient, leg.contributor)); err != nil {
		t.Fatalf("accept checkpoint %s: %v", leg.label, err)
	}
	ch, _ = node.store.Get(leg.id)
	data, err := CheckpointCalldata(ch)
	if err != nil {
		t.Fatalf("calldata %s: %v", leg.label, err)
	}
	out := os.Getenv("P15_CALLDATA_" + leg.label)
	if out != "" {
		if err := os.WriteFile(out, []byte("0x"+hexOf(data)), 0o644); err != nil {
			t.Fatalf("write calldata %s: %v", leg.label, err)
		}
	}
	t.Logf("CHECKPOINT %s built by the node: nonce=%d withdrawA=%s (%d bytes)",
		leg.label, next.Nonce, next.WithdrawA, len(data))
}

func p15Hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	var id [32]byte
	raw := strings.TrimPrefix(s, "0x")
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
