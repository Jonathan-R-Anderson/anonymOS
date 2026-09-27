package channel

// P15 final validation — the dashboard in a REAL browser, against a REAL EVM.
//
// Every layer here is the production one:
//
//	Firefox (geckodriver)          real DOM, real clicks, real window.confirm
//	  └─ pool-init.js / pool-dashboard.js     the shipped modules, unmodified
//	       └─ POST /v1/pool/checkpoint        the real node API
//	            └─ KindCheckpoint, both signatures
//	                 └─ ChannelManagerV2 on hardhat
//
// This is the test that separates "module tested" from "browser tested". The
// Node tests drive the same modules with a fake fetch; here a browser executes
// them, and a human-visible confirmation dialog has to be answered before any
// money moves.
//
//	P15_DEVNET=1 P15_BROWSER=1 P15_RPC=… P15_MANAGER=… P15_CHANNEL=… \
//	P15_CONTRIBUTOR_KEY=… P15_RECIPIENT_KEY=… \
//	  go test ./internal/channel/ -run TestP15BrowserDashboard -v

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestP15BrowserDashboard(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" || os.Getenv("P15_BROWSER") == "" {
		t.Skip("set P15_DEVNET=1 P15_BROWSER=1 — needs hardhat and geckodriver")
	}
	if _, err := os.Stat("/snap/bin/geckodriver"); err != nil {
		t.Skip("geckodriver is not installed")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	npx, err := exec.LookPath("npx")
	if err != nil {
		t.Skip("npx is not installed")
	}

	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	recipientSigner := signerFromHex(t, p15Env(t, "P15_RECIPIENT_KEY"))
	contributorSigner := signerFromHex(t, p15Env(t, "P15_CONTRIBUTOR_KEY"))
	channelID := parseChannelHex(t, p15Env(t, "P15_CHANNEL"))
	root, _ := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))

	// ---- a real channel, a real tip -----------------------------------------
	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	occ, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("reading the devnet channel: %v", err)
	}
	if occ.Status != StatusOpen || occ.Nonce != 0 {
		t.Fatalf("this test needs a FRESH open channel; status=%d nonce=%d",
			occ.Status, occ.Nonce)
	}
	chainID := big.NewInt(31337)

	recipient := newWiredNode(t, recipientSigner, reader, manager)
	contributor := newWiredNode(t, contributorSigner, reader, manager)
	for _, n := range []*wiredNode{recipient, contributor} {
		if err := n.store.TrackFromChain(chainID, manager, occ); err != nil {
			t.Fatalf("adopting: %v", err)
		}
	}

	tip := anon(25)
	if _, err := contributor.coord.Pay(ctx, channelID, intent(21),
		StateTransition{Kind: KindPay, Amount: tip},
		directPeer{t, recipient.coord}); err != nil {
		t.Fatalf("the tip did not complete: %v", err)
	}

	// ---- the recipient's real node, with a real chain writer ----------------
	sender := &scriptTxSender{
		t: t, root: root, nodeBin: npx,
		manager: manager.Hex(), channel: "0x" + hex.EncodeToString(channelID[:]),
		watch: recipientSigner.address().Hex(),
	}
	payout := NewPayoutWorker(recipient.store, reader, NewRPCChainWriter(sender), manager)
	api, err := NewAPI(recipient.coord, func(_ [32]byte, _ Address) (Peer, error) {
		return directPeer{t, contributor.coord}, nil
	}, testToken)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.WithPayout(payout).Handler())
	defer srv.Close()

	// ---- FIREFOX ------------------------------------------------------------
	drive := filepath.Join(root, "browser-test", "drive-dashboard.py")
	cmd := exec.CommandContext(ctx, python, drive, srv.URL, testToken)
	cmd.Dir = root
	raw, err := cmd.CombinedOutput()
	line := ""
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "P15_BROWSER_JSON ") {
			line = strings.TrimPrefix(l, "P15_BROWSER_JSON ")
		}
	}
	if line == "" {
		t.Fatalf("the browser harness produced no report (err %v):\n%s", err, raw)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(line), &report); err != nil {
		t.Fatalf("unreadable browser report: %v\n%s", err, line)
	}
	t.Logf("BROWSER: %v", report["browser"])
	for _, step := range report["steps"].([]any) {
		t.Logf("  ✓ %v", step)
	}
	if ok, _ := report["ok"].(bool); !ok {
		t.Fatalf("the browser run failed: %v", report["error"])
	}

	// ---- what the browser actually showed and did ---------------------------
	if got := fmt.Sprint(report["available_before"]); got != "25" {
		t.Fatalf("the dashboard displayed %q before withdrawing, want 25", got)
	}
	if enabled, _ := report["withdraw_enabled"].(bool); !enabled {
		t.Fatal("the Withdraw button was disabled while value was available")
	}
	if cleared, _ := report["token_field_cleared"].(bool); !cleared {
		t.Fatal("the node access key was left sitting in the DOM after saving")
	}

	// THE CONFIRMATION. window.confirm blocks the page until answered, so a
	// dialog carrying the amount is proof the UI did not withdraw on one click.
	confirm := fmt.Sprint(report["confirm_text"])
	if !strings.Contains(confirm, "25") {
		t.Fatalf("the confirmation did not name the amount: %q", confirm)
	}
	t.Logf("CONFIRMATION SHOWN: %q", confirm)

	if got := fmt.Sprint(report["available_after"]); got != "0" {
		t.Fatalf("the dashboard showed %q after withdrawing, want 0", got)
	}

	// ---- and the chain agrees ------------------------------------------------
	if sender.LastReport == nil {
		t.Fatal("no transaction was broadcast; the browser did not reach the chain")
	}
	delta, ok := new(big.Int).SetString(fmt.Sprint(sender.LastReport["walletDelta"]), 10)
	if !ok || delta.Cmp(tip) != 0 {
		t.Fatalf("wallet delta %v, want %s", sender.LastReport["walletDelta"], tip)
	}
	if open, _ := sender.LastReport["stillOpen"].(bool); !open {
		t.Fatal("the channel closed; a checkpoint must leave it open")
	}
	t.Logf("REAL TX FROM A REAL CLICK: %v", sender.LastReport["tx"])
	t.Logf("RECIPIENT WALLET %v -> %v",
		sender.LastReport["walletBefore"], sender.LastReport["walletAfter"])

	// The node is authoritative: the zero on screen must match a fresh view.
	pool := Pool{
		Name: PoolName, Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID}, Policy: PoolPolicy{Enabled: true},
	}
	view, err := pool.View(recipient.store)
	if err != nil {
		t.Fatalf("pool view: %v", err)
	}
	if view.Withdrawable.Sign() != 0 {
		t.Fatalf("the node still holds %s but the browser showed 0", view.Withdrawable)
	}
}
