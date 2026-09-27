package channel

// P15 phase 5 — the WRITE path against a real EVM.
//
// What this closes: the checkpoint HTTP endpoint had unit and HTTP coverage,
// but every one of those tests ran against a FakeChain. A withdrawal that the
// contract would reject looks identical to one it accepts when nothing on the
// other end is a contract.
//
// Here the whole chain of custody is real:
//
//	hardhat EVM ─► RPCChainReader ─► recipient's node ─► POST /v1/pool/checkpoint
//	                                                        │
//	                        co-signed by the contributor ◄──┤
//	                                                        ▼
//	                        ChannelManagerV2.checkpoint on the real EVM
//	                                                        │
//	                       ERC-20 balanceOf, read back ◄────┘
//
// NO FakeChain in this file. It fails rather than falls back.
//
//	P15_DEVNET=1 P15_RPC=http://127.0.0.1:8545 \
//	P15_MANAGER=… P15_CHANNEL=… P15_CONTRIBUTOR=… P15_CONTRIBUTOR_KEY=… \
//	P15_RECIPIENT_KEY=… go test ./internal/channel/ -run TestP15DevnetHTTPCheckpoint -v

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scriptTxSender broadcasts through the hardhat harness.
//
// The node builds the calldata (CheckpointCalldata, from the co-signed state);
// this only puts the bytes on chain, because signing a raw transaction in Go
// would add a second transaction encoder to the trusted path for no benefit to
// what is being tested. The transaction is real either way.
type scriptTxSender struct {
	t       *testing.T
	root    string
	nodeBin string
	manager string
	channel string
	watch   string

	// LastReport is the chain's own account of what happened, read back after
	// the transaction landed.
	LastReport map[string]any
}

func (s *scriptTxSender) Send(ctx context.Context, to Address, data []byte) (string, error) {
	out := filepath.Join(s.t.TempDir(), "calldata.hex")
	if err := os.WriteFile(out, []byte("0x"+hex.EncodeToString(data)), 0o600); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, s.nodeBin, "hardhat", "run",
		filepath.Join("scripts", "p15-broadcast.ts"), "--network", "localhost")
	cmd.Dir = s.root
	cmd.Env = append(os.Environ(),
		"P15_MANAGER="+s.manager,
		"P15_CHANNEL="+s.channel,
		"P15_WATCH_WALLET="+s.watch,
		"P15_CALLDATA_OUT="+out,
	)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("broadcast failed: %v\n%s", err, raw)
	}
	line := ""
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "P15_BROADCAST_JSON ") {
			line = strings.TrimPrefix(l, "P15_BROADCAST_JSON ")
		}
	}
	if line == "" {
		return "", fmt.Errorf("no broadcast report:\n%s", raw)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(line), &report); err != nil {
		return "", err
	}
	s.LastReport = report
	return fmt.Sprint(report["tx"]), nil
}

func TestP15DevnetHTTPCheckpoint(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1 — this needs a hardhat node on 127.0.0.1:8545")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	recipientSigner := signerFromHex(t, p15Env(t, "P15_RECIPIENT_KEY"))
	contributorSigner := signerFromHex(t, p15Env(t, "P15_CONTRIBUTOR_KEY"))
	channelID := parseChannelHex(t, p15Env(t, "P15_CHANNEL"))

	nodeBin, err := exec.LookPath("npx")
	if err != nil {
		t.Skip("npx is not installed")
	}
	root, _ := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))

	// ---- 1. READ THE REAL CHAIN ---------------------------------------------
	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	occ, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("RPCChainReader could not read the devnet channel: %v", err)
	}
	if occ.Status != StatusOpen {
		t.Fatalf("devnet channel status %d, want open", occ.Status)
	}
	if occ.Nonce != 0 {
		t.Fatalf("this harness needs a FRESH channel; on-chain nonce is %d", occ.Nonce)
	}
	recipientIsA := occ.PartyA == recipientSigner.address()
	if !recipientIsA && occ.PartyB != recipientSigner.address() {
		t.Fatalf("the recipient key is not a party to the devnet channel")
	}
	t.Logf("RECIPIENT IS PARTY %s (partyA=%s partyB=%s)",
		map[bool]string{true: "A", false: "B"}[recipientIsA],
		occ.PartyA.Hex(), occ.PartyB.Hex())

	chainID := big.NewInt(31337)
	if v := os.Getenv("P15_CHAIN_ID"); v != "" {
		if n, ok := new(big.Int).SetString(v, 10); ok {
			chainID = n
		}
	}

	// ---- 2. BOTH NODES ADOPT THE REAL CHANNEL -------------------------------
	recipient := newWiredNode(t, recipientSigner, reader, manager)
	contributor := newWiredNode(t, contributorSigner, reader, manager)
	for _, n := range []*wiredNode{recipient, contributor} {
		if err := n.store.TrackFromChain(chainID, manager, occ); err != nil {
			t.Fatalf("adopting: %v", err)
		}
	}

	// ---- 3. A REAL TIP ------------------------------------------------------
	//
	// Through the coordinator's production Pay path, co-signed by both nodes.
	tip := anon(25)
	if _, err := contributor.coord.Pay(ctx, channelID, intent(7),
		StateTransition{Kind: KindPay, Amount: tip}, directPeer{t, recipient.coord}); err != nil {
		t.Fatalf("the tip did not complete: %v", err)
	}

	pool := Pool{
		Name: PoolName, Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true},
	}
	beforeView, err := pool.View(recipient.store)
	if err != nil {
		t.Fatalf("pool view before: %v", err)
	}
	if beforeView.Withdrawable.Cmp(tip) != 0 {
		t.Fatalf("pool before = %s, want %s", beforeView.Withdrawable, tip)
	}
	t.Logf("POOL BEFORE CHECKPOINT: %s", beforeView.Withdrawable)

	// ---- 4. THE HTTP WRITE PATH, WITH A REAL CHAIN WRITER -------------------
	sender := &scriptTxSender{
		t: t, root: root, nodeBin: nodeBin,
		manager: manager.Hex(), channel: "0x" + hex.EncodeToString(channelID[:]),
		watch: recipientSigner.address().Hex(),
	}
	writer := NewRPCChainWriter(sender)
	payout := NewPayoutWorker(recipient.store, reader, writer, manager)

	api, err := NewAPI(recipient.coord, func(_ [32]byte, _ Address) (Peer, error) {
		// The contributor co-signs. A checkpoint needs both signatures, and
		// this is the only place the other party appears.
		return directPeer{t, contributor.coord}, nil
	}, testToken)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.WithPayout(payout).Handler())
	defer srv.Close()

	// The dashboard's exact request: a channel id and nothing else.
	code, body := do(t, srv.Client(), http.MethodPost, srv.URL+"/v1/pool/checkpoint",
		map[string]any{"channel": poolChannelHex(channelID)}, testToken)
	if code != http.StatusOK {
		t.Fatalf("checkpoint over HTTP: %d %v", code, body)
	}
	if body["outcome"] != string(CheckpointBroadcast) {
		t.Fatalf("outcome = %v, want BROADCAST", body["outcome"])
	}
	t.Logf("REAL CHECKPOINT TX: %v (amount %v, nonce %v)",
		body["tx_hash"], body["amount"], body["nonce"])

	// ---- 5. WHAT THE CHAIN SAYS ---------------------------------------------
	report := sender.LastReport
	if report == nil {
		t.Fatal("no broadcast report; the transaction was not sent")
	}
	walletDelta, ok := new(big.Int).SetString(fmt.Sprint(report["walletDelta"]), 10)
	if !ok {
		t.Fatalf("unreadable wallet delta: %v", report["walletDelta"])
	}

	afterView, err := pool.View(recipient.store)
	if err != nil {
		t.Fatalf("pool view after: %v", err)
	}
	poolDelta := new(big.Int).Sub(beforeView.Withdrawable, afterView.Withdrawable)

	t.Logf("WALLET %v -> %v (delta %s)", report["walletBefore"], report["walletAfter"], walletDelta)
	t.Logf("POOL %s -> %s (delta %s)", beforeView.Withdrawable, afterView.Withdrawable, poolDelta)

	// THE ASSERTION THE WHOLE PHASE EXISTS FOR: the money that left the pool is
	// the money that arrived in the wallet. Either side alone can be satisfied
	// by a bug — a pool that decrements without paying, or a payment the view
	// does not notice.
	if walletDelta.Cmp(poolDelta) != 0 {
		t.Fatalf("CONSERVATION BROKEN: wallet gained %s, pool lost %s",
			walletDelta, poolDelta)
	}
	if walletDelta.Cmp(tip) != 0 {
		t.Fatalf("wallet delta %s, want the tip %s", walletDelta, tip)
	}

	// ---- 6. THE CHANNEL IS STILL OPEN ---------------------------------------
	//
	// That is what makes a checkpoint different from a close: value came out
	// and the channel keeps working.
	if open, _ := report["stillOpen"].(bool); !open {
		t.Fatalf("the channel is no longer open after a checkpoint: %v", report["after"])
	}
	fresh, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("re-reading the channel: %v", err)
	}
	if fresh.Status != StatusOpen {
		t.Fatalf("chain says status %d after checkpoint, want open", fresh.Status)
	}

	// ---- 7. A FRESH POOL AGREES ---------------------------------------------
	//
	// The view is a computation, not a record. A brand-new object over the same
	// store must produce the same number, or something is being carried between
	// calls that should not be.
	rebuilt := Pool{
		Name: PoolName, Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true},
	}
	rebuiltView, err := rebuilt.View(recipient.store)
	if err != nil {
		t.Fatalf("rebuilt view: %v", err)
	}
	if rebuiltView.Withdrawable.Cmp(afterView.Withdrawable) != 0 {
		t.Fatalf("a fresh pool disagrees: %s vs %s",
			rebuiltView.Withdrawable, afterView.Withdrawable)
	}
	t.Logf("FRESH RECONSTRUCTION AGREES: %s", rebuiltView.Withdrawable)

	// ---- 8. A REPEAT DOES NOT WITHDRAW AGAIN --------------------------------
	code2, body2 := do(t, srv.Client(), http.MethodPost, srv.URL+"/v1/pool/checkpoint",
		map[string]any{"channel": poolChannelHex(channelID)}, testToken)
	if code2 == http.StatusOK && fmt.Sprint(body2["amount"]) != "0" {
		t.Fatalf("a repeated checkpoint withdrew again: %v", body2)
	}
	t.Logf("REPLAY REFUSED: %d %v", code2, body2["error"])
}

// parseChannelHex reads a 0x-prefixed 32-byte id.
func parseChannelHex(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad channel id %q: %v", s, err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}
