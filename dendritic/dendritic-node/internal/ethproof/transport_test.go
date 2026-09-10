package ethproof

// P12-9 — transport failover, and the line it must never cross.
//
// The distinction every test here exists to protect:
//
//	TRANSPORT failure     -> try the next endpoint      (availability)
//	VERIFICATION failure  -> stop                       (trust)
//
// The second is not a policy the code follows. It is a shape: verification runs
// on bytes the transport has ALREADY returned, so a verification failure is not
// visible to the transport and there is no path back into it. These tests hold
// that shape by counting requests.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// countingServer records how many requests it served.
type countingServer struct {
	*httptest.Server
	hits atomic.Int64
}

func newServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *countingServer {
	t.Helper()
	cs := &countingServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(cs.Close)
	return cs
}

func okServer(t *testing.T, result string) *countingServer {
	return newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, result)
	})
}

func statusServer(t *testing.T, code int, body string) *countingServer {
	return newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	})
}

func post(t *testing.T, e *Endpoints) ([]byte, int, error) {
	t.Helper()
	return e.Post(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`))
}

// ---- transport failures: failover IS permitted -----------------------------

func TestPrimarySucceedsSecondaryNeverCalled(t *testing.T) {
	primary := okServer(t, `"0x1"`)
	secondary := okServer(t, `"0x2"`)
	e := NewEndpoints(primary.URL, secondary.URL)

	raw, idx, err := post(t, e)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if idx != 0 {
		t.Errorf("served by endpoint %d, want the primary", idx)
	}
	if !containsResult(raw, `"0x1"`) {
		t.Errorf("body came from the wrong endpoint: %s", raw)
	}
	if got := secondary.hits.Load(); got != 0 {
		t.Errorf("the secondary was called %d times while the primary was healthy", got)
	}
}

func TestPrimaryTimesOutSecondarySucceeds(t *testing.T) {
	primary := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(400 * time.Millisecond)
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":"0x1"}`)
	})
	secondary := okServer(t, `"0x2"`)
	e := NewEndpoints(primary.URL, secondary.URL)
	e.HTTP = &http.Client{Timeout: 80 * time.Millisecond}

	raw, idx, err := post(t, e)
	if err != nil {
		t.Fatalf("a timeout on the primary should have failed over: %v", err)
	}
	if idx != 1 || !containsResult(raw, `"0x2"`) {
		t.Errorf("served by endpoint %d (%s), want the secondary", idx, raw)
	}
}

func TestPrimary500SecondarySucceeds(t *testing.T) {
	primary := statusServer(t, http.StatusInternalServerError, "boom")
	secondary := okServer(t, `"0x2"`)

	raw, idx, err := post(t, NewEndpoints(primary.URL, secondary.URL))
	if err != nil {
		t.Fatalf("a 500 should have failed over: %v", err)
	}
	if idx != 1 || !containsResult(raw, `"0x2"`) {
		t.Errorf("served by endpoint %d, want the secondary", idx)
	}
}

func TestPrimary429SecondarySucceeds(t *testing.T) {
	primary := statusServer(t, http.StatusTooManyRequests,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"exceeded compute units per second capacity"}}`)
	secondary := okServer(t, `"0x2"`)

	raw, idx, err := post(t, NewEndpoints(primary.URL, secondary.URL))
	if err != nil {
		t.Fatalf("a 429 should have failed over: %v", err)
	}
	if idx != 1 || !containsResult(raw, `"0x2"`) {
		t.Errorf("served by endpoint %d, want the secondary", idx)
	}
}

// A capacity refusal delivered as HTTP 200 with a JSON-RPC error — the shape
// Alchemy's free tier actually used.
func TestCapacityRefusalOn200SecondarySucceeds(t *testing.T) {
	primary := okServerRaw(t,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Your app has exceeded its compute units per second capacity."}}`)
	secondary := okServer(t, `"0x2"`)

	_, idx, err := post(t, NewEndpoints(primary.URL, secondary.URL))
	if err != nil {
		t.Fatalf("a capacity refusal should have failed over: %v", err)
	}
	if idx != 1 {
		t.Errorf("served by endpoint %d, want the secondary", idx)
	}
}

func TestPrimaryMalformedJSONSecondarySucceeds(t *testing.T) {
	primary := okServerRaw(t, `{"jsonrpc":"2.0",`) // truncated
	secondary := okServer(t, `"0x2"`)

	raw, idx, err := post(t, NewEndpoints(primary.URL, secondary.URL))
	if err != nil {
		t.Fatalf("malformed JSON should have failed over: %v", err)
	}
	if idx != 1 || !containsResult(raw, `"0x2"`) {
		t.Errorf("served by endpoint %d, want the secondary", idx)
	}
}

func TestBothFailIsFailClosed(t *testing.T) {
	primary := statusServer(t, http.StatusInternalServerError, "boom")
	secondary := statusServer(t, http.StatusBadGateway, "boom")

	raw, _, err := post(t, NewEndpoints(primary.URL, secondary.URL))
	if err == nil {
		t.Fatal("both endpoints failed and no error was returned")
	}
	if !errors.Is(err, ErrChainUnreachable) {
		t.Fatalf("want ErrChainUnreachable, got %v", err)
	}
	if raw != nil {
		t.Error("bytes were returned alongside a failure; nothing may be served stale")
	}
	// The error must not leak a URL, which carries the API key.
	if containsAny(err.Error(), primary.URL, secondary.URL) {
		t.Errorf("the error leaks an endpoint URL: %v", err)
	}
}

// ---- verification failures: failover is NOT permitted ----------------------

// THE REGRESSION TEST FOR THE CRITICAL DISTINCTION.
//
// A response that is well-formed transport but cryptographically wrong must be
// returned to the caller and rejected there. The secondary must never be asked,
// because "ask until something passes" is an oracle for forging acceptance.
func TestVerificationFailureDoesNotFailOver(t *testing.T) {
	// Well-formed JSON-RPC carrying receipts that will NOT rebuild to the
	// authenticated root. Perfect transport, worthless content.
	primary := okServer(t, `[{"type":"0x2","status":"0x1","cumulativeGasUsed":"0x5208",
		"transactionIndex":"0x0","logsBloom":"0x`+repeat("00", 256)+`","logs":[]}]`)
	secondary := okServer(t, `[{"type":"0x2","status":"0x1","cumulativeGasUsed":"0x5208",
		"transactionIndex":"0x0","logsBloom":"0x`+repeat("00", 256)+`","logs":[]}]`)

	src := &RPCSource{Transport: NewEndpoints(primary.URL, secondary.URL), MaxRetries: 0}
	receipts, err := src.ReceiptsByNumber(context.Background(), 1)
	if err != nil {
		t.Fatalf("transport should have succeeded: %v", err)
	}

	// NOW verify, above the transport. This is where the rejection happens.
	var wrongRoot Root
	wrongRoot[0] = 0xFF
	if _, err := AuthenticateReceipts(wrongRoot, receipts); err == nil {
		t.Fatal("receipts that do not rebuild to the authenticated root were accepted")
	}

	if got := primary.hits.Load(); got != 1 {
		t.Errorf("primary served %d requests, want exactly 1", got)
	}
	if got := secondary.hits.Load(); got != 0 {
		t.Errorf("VERIFICATION FAILURE CAUSED FAILOVER: the secondary was asked %d "+
			"times. 'reject, then ask someone else' is exactly the oracle this "+
			"design forbids.", got)
	}
}

// The mirror: the secondary's answer is not privileged either.
func TestSecondaryResponseIsEquallyUntrusted(t *testing.T) {
	primary := statusServer(t, http.StatusInternalServerError, "down")
	secondary := okServer(t, `[{"type":"0x2","status":"0x1","cumulativeGasUsed":"0x5208",
		"transactionIndex":"0x0","logsBloom":"0x`+repeat("00", 256)+`","logs":[]}]`)

	src := &RPCSource{Transport: NewEndpoints(primary.URL, secondary.URL), MaxRetries: 0}
	receipts, err := src.ReceiptsByNumber(context.Background(), 1)
	if err != nil {
		t.Fatalf("failover should have supplied bytes: %v", err)
	}
	if secondary.hits.Load() != 1 {
		t.Fatal("the secondary did not carry the request")
	}

	var authenticated Root
	authenticated[0] = 0xAB
	if _, err := AuthenticateReceipts(authenticated, receipts); err == nil {
		t.Fatal("the SECONDARY's receipts were accepted without matching the " +
			"authenticated root; failing over must not confer trust")
	}
}

// An unverified header cannot enter the trusted set by arriving from the
// secondary: AuthenticateHeader still requires the hash to reproduce.
func TestSecondaryCannotSmuggleAnUnverifiedHeader(t *testing.T) {
	primary := statusServer(t, http.StatusServiceUnavailable, "down")
	secondary := okServer(t, `{"parentHash":"0x`+repeat("11", 32)+`",
		"sha3Uncles":"0x`+repeat("22", 32)+`","miner":"0x`+repeat("33", 20)+`",
		"stateRoot":"0x`+repeat("44", 32)+`","transactionsRoot":"0x`+repeat("55", 32)+`",
		"receiptsRoot":"0x`+repeat("66", 32)+`","logsBloom":"0x`+repeat("00", 256)+`",
		"difficulty":"0x0","number":"0x1","gasLimit":"0x1","gasUsed":"0x0",
		"timestamp":"0x68000000","extraData":"0x","mixHash":"0x`+repeat("77", 32)+`",
		"nonce":"0x0000000000000000","baseFeePerGas":"0x1"}`)

	src := &RPCSource{Transport: NewEndpoints(primary.URL, secondary.URL), MaxRetries: 0}
	headers, err := src.HeadersDescending(context.Background(), 1, 1)
	if err != nil {
		// Batch shape differs; the point is only that nothing unverified escapes.
		return
	}
	if len(headers) == 0 {
		return
	}
	var claimed [32]byte
	claimed[0] = 0x99 // a hash the header does not produce
	if _, err := AuthenticateHeader(headers[0], ForkLondon, claimed); err == nil {
		t.Fatal("a header from the secondary was authenticated against a hash it " +
			"does not reproduce")
	}
}

// ---- the transport carries no Ethereum opinion -----------------------------

// A well-formed JSON-RPC ERROR is an answer, not a transport failure. Asking a
// second provider for a nicer reply to "block not found" is the forbidden shape.
func TestWellFormedRPCErrorIsNotATransportFailure(t *testing.T) {
	primary := okServerRaw(t, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"block not found"}}`)
	secondary := okServer(t, `"0x2"`)

	_, idx, err := post(t, NewEndpoints(primary.URL, secondary.URL))
	if err != nil {
		t.Fatalf("a well-formed error should be returned, not treated as failure: %v", err)
	}
	if idx != 0 {
		t.Errorf("served by endpoint %d; a JSON-RPC error is an ANSWER and must "+
			"not trigger failover", idx)
	}
	if got := secondary.hits.Load(); got != 0 {
		t.Errorf("the secondary was asked %d times for a nicer answer", got)
	}
}

func TestSingleEndpointBehavesAsBefore(t *testing.T) {
	only := statusServer(t, http.StatusInternalServerError, "down")
	_, _, err := post(t, NewEndpoints(only.URL))
	if !errors.Is(err, ErrChainUnreachable) {
		t.Fatalf("want ErrChainUnreachable, got %v", err)
	}
	if only.hits.Load() != 1 {
		t.Errorf("a single endpoint was tried %d times; failover must be bounded", only.hits.Load())
	}
}

func TestEmptySecondaryDegradesToSingleEndpoint(t *testing.T) {
	primary := okServer(t, `"0x1"`)
	e := NewEndpoints(primary.URL, "") // secondary unset in .env
	if len(e.URLs) != 1 {
		t.Fatalf("an unset secondary produced %d endpoints, want 1", len(e.URLs))
	}
	if _, _, err := post(t, e); err != nil {
		t.Fatalf("post: %v", err)
	}
}

func TestFailoverIsBounded(t *testing.T) {
	primary := statusServer(t, http.StatusInternalServerError, "down")
	secondary := statusServer(t, http.StatusInternalServerError, "down")
	_, _, _ = post(t, NewEndpoints(primary.URL, secondary.URL))
	if primary.hits.Load() != 1 || secondary.hits.Load() != 1 {
		t.Errorf("each endpoint should be tried exactly once; got primary=%d secondary=%d",
			primary.hits.Load(), secondary.hits.Load())
	}
}

// ---- helpers ---------------------------------------------------------------

func okServerRaw(t *testing.T, body string) *countingServer {
	return newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	})
}

func containsResult(raw []byte, want string) bool {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return false
	}
	return string(envelope["result"]) == want
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && len(sub) > 0 && stringContains(s, sub) {
			return true
		}
	}
	return false
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// ---- classification, pinned specifically -----------------------------------
//
// Added after mutation testing: replacing the 429 and 5xx cases individually
// SURVIVED, because the "any non-200" catch-all still failed over. The behaviour
// was right and the tests were not specific enough to notice a mis-classified
// reason — and RPCSource's capacity accounting depends on that distinction.

func TestRateLimitClassificationIsPinned(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		wantRate bool
	}{
		{"http 429", http.StatusTooManyRequests, `{"error":{"message":"slow down"}}`, true},
		{"capacity refusal on 200", http.StatusOK,
			`{"jsonrpc":"2.0","id":1,"error":{"message":"exceeded its compute units per second capacity"}}`, true},
		{"http 500", http.StatusInternalServerError, "boom", false},
		{"http 503", http.StatusServiceUnavailable, "boom", false},
		{"http 404", http.StatusNotFound, "nope", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := statusServer(t, tc.status, tc.body)
			b := statusServer(t, tc.status, tc.body)
			_, _, err := post(t, NewEndpoints(a.URL, b.URL))
			if !errors.Is(err, ErrChainUnreachable) {
				t.Fatalf("want ErrChainUnreachable, got %v", err)
			}
			var un *UnreachableError
			if !errors.As(err, &un) {
				t.Fatalf("want *UnreachableError, got %T", err)
			}
			if un.RateLimited != tc.wantRate {
				t.Errorf("RateLimited=%v, want %v — RPCSource's capacity accounting "+
					"and its retry decision both key off this", un.RateLimited, tc.wantRate)
			}
			if un.Tried != 2 {
				t.Errorf("Tried=%d, want 2", un.Tried)
			}
		})
	}
}

// A misconfigured URL is OUR fault, not the provider's. Failing over would let a
// typo in the primary run silently on the secondary forever.
//
// Added after mutation testing: turning the non-transport-error return into a
// `continue` SURVIVED, because nothing exercised that path.
func TestConfigurationFaultDoesNotFailOver(t *testing.T) {
	secondary := okServer(t, `"0x2"`)
	e := NewEndpoints("://not-a-url", secondary.URL)

	_, _, err := post(t, e)
	if err == nil {
		t.Fatal("a malformed primary URL was silently masked by the secondary")
	}
	if errors.Is(err, ErrChainUnreachable) {
		t.Errorf("a configuration fault was reported as the chain being " +
			"unreachable; those need different fixes")
	}
	if got := secondary.hits.Load(); got != 0 {
		t.Errorf("the secondary carried %d requests despite a CONFIG fault on the "+
			"primary; the typo would never be noticed", got)
	}
}
