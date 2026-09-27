package ethproof

// Execution-RPC transport failover — roadmap P12-9.
//
// THIS FILE CONTAINS NO ETHEREUM LOGIC, AND THAT IS THE WHOLE POINT.
//
// It answers exactly one question:
//
//	"which configured transport successfully supplied bytes?"
//
// It does not know what a block is, what a proof is, or what any of the bytes
// mean. The existing verifiers answer the other question — "do those bytes prove
// what Ethereum says they prove?" — and nothing here can influence that answer.
//
// TRANSPORT FAILOVER, NOT TRUST FAILOVER
// --------------------------------------
// The dangerous shape this must never grow into:
//
//	provider A rejected  ->  provider B accepted  ->  therefore valid
//
// That is trying providers until one produces something that passes, which turns
// a fleet of endpoints into an oracle for forging acceptance. It cannot happen
// here, and not because of a rule somebody has to remember:
//
//	verification runs ABOVE this layer, on bytes this layer already returned.
//	A verification failure is therefore not visible here and has no path back
//	in. There is no code that could retry on it.
//
// Both providers stay equally untrusted. A response from the secondary is worth
// exactly what a response from the primary is worth: nothing, until verified.
//
// WHAT COUNTS AS A TRANSPORT FAILURE
// ----------------------------------
//	connection refused, DNS, TLS      the endpoint did not answer
//	timeout                           the endpoint did not answer in time
//	HTTP 5xx                          the endpoint failed
//	HTTP 429 / capacity refusal       the endpoint declined to answer
//	unusable JSON-RPC framing         the endpoint answered with nothing usable
//
// A well-formed JSON-RPC error is NOT a transport failure. "execution reverted"
// or "block not found" is the endpoint answering correctly, and asking a second
// provider the same question in the hope of a nicer answer is the exact
// behaviour the section above forbids.
//
// Knowing that a body is a JSON-RPC envelope is framing, not semantics — the
// same way knowing a response is HTTP is framing. Nothing here inspects `result`.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrChainUnreachable means no configured endpoint could supply a response.
//
// It is deliberately NOT a statement about Ethereum. It says we could not look,
// which must never collapse into "nothing happened" — the same distinction
// ErrNoVerifiedEvidence draws downstream.
var ErrChainUnreachable = errors.New(
	"ethproof: no configured execution RPC endpoint could supply a response")

// Endpoints is an ordered transport list. Index 0 is the primary.
//
// One URL behaves exactly as a single endpoint always did: no failover, and the
// same error. Adding a secondary changes availability, never trust.
type Endpoints struct {
	URLs []string
	HTTP *http.Client

	// OnFailover, if set, is told that a failover happened. It receives INDICES
	// and a reason, never URLs — those carry API keys, and an observability hook
	// is exactly the sort of place a credential leaks into a log.
	OnFailover func(from, to int, reason string)
}

// NewEndpoints builds a transport from an ordered URL list, dropping empties so
// an unset secondary degrades to single-endpoint behaviour rather than erroring.
func NewEndpoints(urls ...string) *Endpoints {
	kept := make([]string, 0, len(urls))
	for _, u := range urls {
		if u != "" {
			kept = append(kept, u)
		}
	}
	return &Endpoints{URLs: kept, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (e *Endpoints) client() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// UnreachableError says every configured endpoint failed, and why.
//
// It wraps ErrChainUnreachable so errors.Is keeps working. RateLimited lets a
// caller keep its own capacity accounting honest without this file knowing what
// the caller is counting.
type UnreachableError struct {
	Tried       int
	RateLimited bool
	Reasons     []string
}

func (u *UnreachableError) Error() string {
	return fmt.Sprintf("%s (%d endpoint(s) tried: %v)",
		ErrChainUnreachable.Error(), u.Tried, u.Reasons)
}

func (u *UnreachableError) Unwrap() error { return ErrChainUnreachable }

// transportFailure marks a response as one that justifies trying the next
// endpoint. Its message never carries the URL.
type transportFailure struct {
	reason      string
	rateLimited bool
}

func (t transportFailure) Error() string { return t.reason }

// Post sends body to endpoints in order and returns the first usable response,
// with the index of the endpoint that supplied it.
//
// BOUNDED: each endpoint is tried once, in order, and then it gives up. There is
// no loop, no rotation, no background health state and no retry budget —
// availability machinery that nothing has yet shown to be necessary would be
// more code on the path that protects money.
func (e *Endpoints) Post(ctx context.Context, body []byte) ([]byte, int, error) {
	if len(e.URLs) == 0 {
		return nil, -1, ErrChainUnreachable
	}
	failed := &UnreachableError{Tried: len(e.URLs)}
	for i, url := range e.URLs {
		raw, err := e.postOne(ctx, url, body)
		if err == nil {
			return raw, i, nil
		}
		var tf transportFailure
		if !errors.As(err, &tf) {
			// Not a transport failure — the endpoint answered. Hand it back
			// rather than shopping for a better reply.
			return nil, i, err
		}
		failed.Reasons = append(failed.Reasons, fmt.Sprintf("endpoint %d: %s", i, tf.reason))
		if tf.rateLimited {
			failed.RateLimited = true
		}
		if i+1 < len(e.URLs) && e.OnFailover != nil {
			e.OnFailover(i, i+1, tf.reason)
		}
		// A cancelled or expired CALLER context is not a provider fault, and
		// trying the next endpoint would just fail the same way.
		if ctx.Err() != nil {
			break
		}
	}
	return nil, -1, failed
}

// postOne performs one request and classifies the outcome.
func (e *Endpoints) postOne(ctx context.Context, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		// A malformed URL is a configuration fault, not a provider one. Failing
		// over would hide a typo behind a working secondary.
		return nil, fmt.Errorf("ethproof: building the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client().Do(req)
	if err != nil {
		// Connection refused, DNS, TLS, timeout. The endpoint did not answer.
		return nil, transportFailure{reason: "no response from the endpoint"}
	}
	defer resp.Body.Close()

	raw, readErr := readAllLimited(resp.Body)
	if readErr != nil {
		return nil, transportFailure{reason: "response body could not be read"}
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, transportFailure{reason: "http 429", rateLimited: true}
	case resp.StatusCode >= 500:
		return nil, transportFailure{reason: fmt.Sprintf("http %d", resp.StatusCode)}
	case resp.StatusCode != http.StatusOK:
		return nil, transportFailure{reason: fmt.Sprintf("http %d", resp.StatusCode)}
	}

	if !usableJSONRPC(raw) {
		return nil, transportFailure{reason: "unusable JSON-RPC response"}
	}
	if msg, ok := rpcErrorMessage(raw); ok && isRateLimit(resp.StatusCode, msg) {
		// A capacity refusal delivered as a 200 with a JSON-RPC error. Alchemy
		// does this; it is a refusal to answer, not an answer.
		return nil, transportFailure{reason: "provider capacity refusal", rateLimited: true}
	}
	return raw, nil
}

// usableJSONRPC reports whether the body is JSON-RPC framing we can hand on.
//
// FRAMING ONLY. It accepts a batch array without looking inside, and for a
// single object it requires that `result` or `error` is present — anything else
// is a body the caller cannot act on. It never inspects what `result` contains,
// because that is the verifier's job and this file must not have an opinion.
func usableJSONRPC(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	if trimmed[0] == '[' {
		var batch []json.RawMessage
		return json.Unmarshal(trimmed, &batch) == nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return false
	}
	_, hasResult := envelope["result"]
	_, hasError := envelope["error"]
	return hasResult || hasError
}

// rpcErrorMessage pulls a single response's JSON-RPC error message, if any.
func rpcErrorMessage(raw []byte) (string, bool) {
	var envelope struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &envelope); err != nil || envelope.Error == nil {
		return "", false
	}
	return envelope.Error.Message, true
}

// readAllLimited reads a response with a ceiling, so a hostile or broken
// endpoint cannot exhaust memory. 64 MiB is far above any real receipts payload
// (the largest measured was ~1.3 MB).
func readAllLimited(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	const max = 64 << 20
	var buf bytes.Buffer
	_, err := buf.ReadFrom(&limitedReader{r: r, n: max})
	return buf.Bytes(), err
}

type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("ethproof: response exceeds the size ceiling")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}
