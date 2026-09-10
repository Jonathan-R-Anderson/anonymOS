package ethproof

// P12-9 live verification — failover between two REAL Alchemy accounts.
//
//	P129=1 CHAIN_PROBE=1 BEACON_API_URL=... \
//	  ETH_RPC_URL_PRIMARY=... ETH_RPC_URL_SECONDARY=... \
//	  go test ./internal/ethproof/ -run TestP129LiveFailover -v -timeout 20m
//
// HOW THE PRIMARY IS "MADE UNAVAILABLE"
// -------------------------------------
// Alchemy cannot be taken down, so a local reverse proxy sits in front of the
// REAL primary and is switched between forwarding and refusing. Both endpoints
// remain real, paid, independent accounts; only the reachability of the first is
// controlled. A test that pointed the primary at a dead URL would prove the
// transport can count to two, not that failover works against the thing we run.
//
// Every phase re-verifies through the PRODUCTION path — AuthenticateReceipts
// against a beacon-authenticated receiptsRoot — so "the secondary carried it" is
// never accepted without the same proof the primary's bytes need.
//
// NO CREDENTIALS ARE LOGGED. The proxy forwards to a URL it is handed and never
// prints it; every log line below names endpoints by index.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// switchableProxy forwards to upstream, or refuses, depending on a flag.
type switchableProxy struct {
	*httptest.Server
	up       atomic.Bool
	forwards atomic.Int64
	refusals atomic.Int64
}

func newSwitchableProxy(t *testing.T, upstream string) *switchableProxy {
	t.Helper()
	p := &switchableProxy{}
	p.up.Store(true)
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.up.Load() {
			p.refusals.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"injected outage"}`)
			return
		}
		p.forwards.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream, bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(out)
	}))
	t.Cleanup(p.Close)
	return p
}

func TestP129LiveFailoverBetweenRealProviders(t *testing.T) {
	if os.Getenv("P129") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P129=1 CHAIN_PROBE=1")
	}
	primary := os.Getenv("ETH_RPC_URL_PRIMARY")
	secondary := os.Getenv("ETH_RPC_URL_SECONDARY")
	beaconURL := os.Getenv("BEACON_API_URL")
	if primary == "" || secondary == "" || beaconURL == "" {
		t.Skip("set ETH_RPC_URL_PRIMARY, ETH_RPC_URL_SECONDARY and BEACON_API_URL")
	}
	if primary == secondary {
		t.Fatal("primary and secondary are the same endpoint; that is not failover")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// The authenticated reference. Neither execution endpoint supplies it.
	beacon := &BeaconFinalizedSource{Beacon: NewBeaconClient(beaconURL), Spec: SpecAltair}
	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}
	t.Logf("AUTHENTICATED reference: block %d, receiptsRoot %x (from the beacon chain, "+
		"not from either execution provider)", head.Number, head.ReceiptsRoot[:8])

	proxy := newSwitchableProxy(t, primary)
	var failovers atomic.Int64
	var lastReason atomic.Value
	e := NewEndpoints(proxy.URL, secondary)
	e.HTTP = &http.Client{Timeout: 60 * time.Second}
	e.OnFailover = func(from, to int, reason string) {
		failovers.Add(1)
		lastReason.Store(reason)
	}

	// verify fetches through the transport and puts the bytes through the SAME
	// production verification, returning which endpoint served them.
	verify := func(phase string) (idx int, took time.Duration) {
		start := time.Now()
		body, _ := jsonMarshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockReceipts",
			"params": []any{fmt.Sprintf("0x%x", head.Number)},
		})
		raw, served, err := e.Post(ctx, body)
		if err != nil {
			t.Fatalf("%s: transport: %v", phase, err)
		}
		took = time.Since(start)

		receipts, err := decodeReceiptsEnvelope(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", phase, err)
		}
		// THE POINT: identical verification whoever answered.
		if _, err := AuthenticateReceipts(head.ReceiptsRoot, receipts); err != nil {
			t.Fatalf("%s: endpoint %d supplied receipts that FAILED verification: %v",
				phase, served, err)
		}
		t.Logf("  %-28s served by endpoint %d, %d receipts, VERIFIED against the "+
			"authenticated root, %s", phase, served, len(receipts), took.Round(time.Millisecond))
		return served, took
	}

	t.Logf("")
	t.Logf("PHASE A — primary healthy   (%s)", time.Now().UTC().Format(time.RFC3339))
	idxA, _ := verify("primary healthy")
	if idxA != 0 {
		t.Errorf("a healthy primary was not used; endpoint %d answered", idxA)
	}
	if failovers.Load() != 0 {
		t.Errorf("%d failover(s) while the primary was healthy", failovers.Load())
	}

	t.Logf("")
	t.Logf("PHASE B — primary made unavailable (injected 503)  (%s)",
		time.Now().UTC().Format(time.RFC3339))
	proxy.up.Store(false)
	outageStart := time.Now()
	idxB, _ := verify("primary unavailable")
	if idxB != 1 {
		t.Fatalf("the primary was down and endpoint %d answered; the secondary did "+
			"not carry the request", idxB)
	}
	if failovers.Load() == 0 {
		t.Error("the secondary answered but no failover was recorded")
	}
	t.Logf("  failure type: %v", lastReason.Load())

	t.Logf("")
	t.Logf("PHASE C — primary restored  (%s)", time.Now().UTC().Format(time.RFC3339))
	proxy.up.Store(true)
	restored := time.Now()
	idxC, tookC := verify("primary restored")
	recovery := time.Since(restored)
	if idxC != 0 {
		t.Errorf("after restoring the primary, endpoint %d answered; traffic did "+
			"not return", idxC)
	}

	t.Logf("")
	t.Logf("RECORD")
	t.Logf("  providers            : endpoint 0 = primary account (via switchable proxy)")
	t.Logf("                         endpoint 1 = secondary account, independent")
	t.Logf("  primary forwards     : %d", proxy.forwards.Load())
	t.Logf("  primary refusals     : %d (injected)", proxy.refusals.Load())
	t.Logf("  failovers observed   : %d", failovers.Load())
	t.Logf("  failure type         : %v", lastReason.Load())
	t.Logf("  outage duration      : %s", time.Since(outageStart).Round(time.Millisecond))
	t.Logf("  recovery latency     : %s (first request after restore, %s round trip)",
		recovery.Round(time.Millisecond), tookC.Round(time.Millisecond))
	t.Logf("  verification         : every phase re-verified against the "+
		"beacon-authenticated receiptsRoot for block %d", head.Number)
	t.Log("")
	t.Log("THIS DOES NOT VALIDATE THE rpc-failure BUDGET TERM. It shows the " +
		"transport works between two real providers. The term was closed as NOT " +
		"VALIDATED by architectural choice and nothing here reopens it.")
}

// Both endpoints untrusted: a secondary carrying the request still cannot get a
// wrong answer accepted.
func TestP129LiveSecondaryStillVerified(t *testing.T) {
	if os.Getenv("P129") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P129=1 CHAIN_PROBE=1")
	}
	secondary := os.Getenv("ETH_RPC_URL_SECONDARY")
	beaconURL := os.Getenv("BEACON_API_URL")
	if secondary == "" || beaconURL == "" {
		t.Skip("set ETH_RPC_URL_SECONDARY and BEACON_API_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	beacon := &BeaconFinalizedSource{Beacon: NewBeaconClient(beaconURL), Spec: SpecAltair}
	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}

	// Dead primary, so the secondary genuinely carries it.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer dead.Close()

	src := &RPCSource{Transport: NewEndpoints(dead.URL, secondary), MaxRetries: 0}
	receipts, err := src.ReceiptsByNumber(ctx, head.Number)
	if err != nil {
		t.Fatalf("secondary should have carried: %v", err)
	}
	if _, err := AuthenticateReceipts(head.ReceiptsRoot, receipts); err != nil {
		t.Fatalf("the secondary's real receipts failed verification: %v", err)
	}
	t.Logf("secondary carried %d receipts and they VERIFY against the authenticated root",
		len(receipts))

	// And against a root it must not match, the secondary is refused.
	var wrong Root
	wrong[0] = head.ReceiptsRoot[0] ^ 0xFF
	if _, err := AuthenticateReceipts(wrong, receipts); err == nil {
		t.Fatal("the secondary's receipts were accepted against a root they do not " +
			"rebuild to; carrying the request must not confer trust")
	}
	t.Log("and are REFUSED against a root they do not rebuild to — no privilege " +
		"from having been the fallback")
}

// jsonMarshal and decodeReceiptsEnvelope keep the live test's plumbing out of
// the transport, which must stay free of Ethereum shapes.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func decodeReceiptsEnvelope(raw []byte) ([]Receipt, error) {
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	return DecodeRPCReceipts(env.Result)
}
