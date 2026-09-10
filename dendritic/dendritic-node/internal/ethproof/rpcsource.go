package ethproof

// The acquisition layer for P14.5 — untrusted data in.
//
// Everything this file returns is unverified, and it says so in its type names
// and its documentation, because the one dangerous mistake around here is a call
// site treating an RPC response as an answer. It fetches; ChainFollower,
// AuthenticateReceipts and AuthenticateHeader decide whether any of it is true.
//
// RATE LIMITS ARE NOT AN IMPLEMENTATION DETAIL
// --------------------------------------------
// The pre-implementation measurement run was refused by the provider for
// exceeding compute units per second — eth_getBlockReceipts is heavy, and a
// watchtower sweeping continuously lives against that limit, hardest during the
// catch-up when it most needs to work.
//
// So a rate limit is COUNTED SEPARATELY and never folded into a latency figure.
// A retry that quietly succeeds after two seconds looks, in an average, exactly
// like a slightly slow request; kept apart, it is a number an operator can watch
// climb before the thing falls over.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrRateLimited means the provider refused for capacity reasons.
//
// A distinct error because it means something different from every other
// failure: the data exists and we are allowed to have it, just not this fast.
var ErrRateLimited = errors.New("ethproof: provider rate limit")

// RPCSource fetches headers and receipts over JSON-RPC.
type RPCSource struct {
	Endpoint string
	Client   *http.Client

	// Metrics records rate-limit events. Optional.
	Metrics FollowerMetrics

	// MaxRetries bounds backoff on a rate limit. Zero disables retrying, which
	// surfaces the limit to the caller immediately.
	MaxRetries int
	// MinInterval throttles outbound calls.
	MinInterval time.Duration
	// MaxBatch caps how many headers go in one request. Zero means "as many as
	// asked for", and the batch shrinks itself when the provider refuses.
	MaxBatch int

	// Transport, when set, supplies TRANSPORT failover across several endpoints.
	// No Ethereum logic; see transport.go. Nil means Endpoint alone.
	Transport *Endpoints

	mu       sync.Mutex
	lastCall time.Time

	stats struct {
		sync.Mutex
		Calls        int
		RateLimited  int
		Retries      int
		BatchShrinks int
		LastBatch    int
	}
}

// RPCStats reports call volume and, separately, refusals.
type RPCStats struct {
	Calls        int
	RateLimited  int
	Retries      int
	BatchShrinks int
	LastBatch    int
}

// Stats returns a snapshot. RateLimited is deliberately its own number.
func (s *RPCSource) Stats() RPCStats {
	s.stats.Lock()
	defer s.stats.Unlock()
	return RPCStats{
		Calls: s.stats.Calls, RateLimited: s.stats.RateLimited,
		Retries: s.stats.Retries, BatchShrinks: s.stats.BatchShrinks,
		LastBatch: s.stats.LastBatch,
	}
}

// ResetStats zeroes the counters, for a measurement that wants one phase.
func (s *RPCSource) ResetStats() {
	s.stats.Lock()
	defer s.stats.Unlock()
	s.stats.Calls, s.stats.RateLimited = 0, 0
	s.stats.Retries, s.stats.BatchShrinks, s.stats.LastBatch = 0, 0, 0
}

func (s *RPCSource) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 120 * time.Second}
}

// endpoints returns the transport to use: the configured failover list, or a
// single-endpoint list built from Endpoint.
func (s *RPCSource) endpoints() *Endpoints {
	if s.Transport != nil {
		return s.Transport
	}
	return &Endpoints{URLs: []string{s.Endpoint}, HTTP: s.client()}
}

// send performs one request through the transport and returns the raw body
// alongside the network time. Rate-limit accounting stays here because it is
// about THIS source's budget, not about which endpoint answered.
func (s *RPCSource) send(ctx context.Context, body []byte) ([]byte, time.Duration, int, error) {
	s.mu.Lock()
	if s.MinInterval > 0 {
		if wait := s.MinInterval - time.Since(s.lastCall); wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				s.mu.Unlock()
				return nil, 0, -1, ctx.Err()
			}
		}
	}
	s.mu.Unlock()

	start := time.Now()
	raw, idx, err := s.endpoints().Post(ctx, body)
	elapsed := time.Since(start)

	s.mu.Lock()
	s.lastCall = time.Now()
	s.mu.Unlock()
	s.stats.Lock()
	s.stats.Calls++
	s.stats.Unlock()
	return raw, elapsed, idx, err
}

// isRateLimit recognises a refusal for capacity.
//
// Both shapes matter: HTTP 429, and a 200 carrying a JSON-RPC error. Providers
// disagree about which they use and some use both.
//
// THE MESSAGE MUST BE AN ERROR MESSAGE, NEVER A RESPONSE BODY. The first live
// run of this code passed whole batch responses in here, and the markers matched
// hex inside ordinary block hashes — a successful batch of sixty headers read as
// a rate limit, retried five times, and failed after a minute of backoff. Loose
// markers over the wrong input turn healthy data into a permanent outage, so
// "429" and a bare "exceeded" are gone and the caller now passes only a decoded
// error string.
func isRateLimit(status int, message string) bool {
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		return true
	}
	if message == "" {
		return false
	}
	m := strings.ToLower(message)
	for _, marker := range []string{
		"compute units", "rate limit", "rate-limit", "ratelimit",
		"too many requests", "capacity", "throughput", "quota",
	} {
		if strings.Contains(m, marker) {
			return true
		}
	}
	return false
}

// call issues one JSON-RPC request, retrying only on a rate limit.
//
// Returns the elapsed NETWORK time, excluding any throttle sleep and any
// backoff. A caller measuring latency must not be handed our own waiting.
func (s *RPCSource) call(ctx context.Context, body []byte) (json.RawMessage, time.Duration, error) {
	backoff := 2 * time.Second
	for attempt := 0; ; attempt++ {
		raw, elapsed, _, err := s.send(ctx, body)
		if err != nil {
			var un *UnreachableError
			if errors.As(err, &un) && un.RateLimited {
				s.noteRateLimited()
				if attempt < s.MaxRetries {
					s.noteRetry()
					select {
					case <-time.After(backoff):
					case <-ctx.Done():
						return nil, 0, ctx.Err()
					}
					backoff *= 2
					continue
				}
				return nil, elapsed, fmt.Errorf("%w: every endpoint refused for capacity", ErrRateLimited)
			}
			return nil, elapsed, err
		}
		var out struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, elapsed, err
		}
		if out.Error != nil {
			return nil, elapsed, fmt.Errorf("ethproof: rpc error: %s", out.Error.Message)
		}
		return out.Result, elapsed, nil
	}
}

func (s *RPCSource) noteRateLimited() {
	s.stats.Lock()
	s.stats.RateLimited++
	s.stats.Unlock()
	if s.Metrics != nil {
		s.Metrics.RateLimited()
	}
}

func (s *RPCSource) noteRetry() {
	s.stats.Lock()
	s.stats.Retries++
	s.stats.Unlock()
}

// ReceiptsByNumber fetches a block's receipts, UNVERIFIED.
func (s *RPCSource) ReceiptsByNumber(ctx context.Context, number uint64) ([]Receipt, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockReceipts",
		"params": []any{fmt.Sprintf("0x%x", number)},
	})
	raw, _, err := s.call(ctx, body)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("ethproof: no receipts for block %d", number)
	}
	return DecodeRPCReceipts(raw)
}

// HeadersDescending fetches headers newest-first, batching adaptively.
//
// Batched because the parentHash chain is serial to VERIFY but not to FETCH —
// measured, 43 ms versus 3.9 ms per header, and that difference is most of what
// makes a week-long catch-up 16 minutes rather than 49.
//
// ADAPTIVE because the provider does not refuse a batch as a whole. The first
// live run had a sixty-header batch accepted and its EIGHTEENTH ITEM refused for
// compute units — so a fixed batch size is a request that works until the day
// the account is busy. On a refusal the batch halves and retries, and every
// shrink is counted.
func (s *RPCSource) HeadersDescending(ctx context.Context, from uint64, count int) ([]ExecutionHeader, error) {
	if count <= 0 {
		return nil, nil
	}
	chunk := count
	if s.MaxBatch > 0 && chunk > s.MaxBatch {
		chunk = s.MaxBatch
	}

	out := make([]ExecutionHeader, 0, count)
	backoff, waited := 2*time.Second, 0
	for len(out) < count {
		n := chunk
		if remaining := count - len(out); n > remaining {
			n = remaining
		}
		headers, err := s.headerBatch(ctx, from-uint64(len(out)), n)
		if err != nil {
			if !errors.Is(err, ErrRateLimited) {
				return nil, err
			}
			// Halve the batch while there is anything left to halve...
			if n > 1 {
				chunk = n / 2
				s.stats.Lock()
				s.stats.BatchShrinks++
				s.stats.Unlock()
				continue
			}
			// ...and once a SINGLE header is being refused, the batch size is
			// not the problem — the account is simply over its budget. Wait.
			// Failing here instead would abandon a catch-up for a condition that
			// clears in a couple of seconds, which is the moment a watchtower is
			// least able to afford giving up.
			if waited >= s.MaxRetries {
				return nil, err
			}
			waited++
			s.stats.Lock()
			s.stats.Retries++
			s.stats.Unlock()
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			backoff *= 2
			continue
		}
		out = append(out, headers...)
		backoff, waited = 2*time.Second, 0
		s.stats.Lock()
		s.stats.LastBatch = n
		s.stats.Unlock()
	}
	return out, nil
}

// headerBatch fetches exactly count headers in one request.
//
// A per-ITEM capacity refusal is reported as ErrRateLimited for the whole batch,
// because that is what it means operationally: this batch was too big right now.
func (s *RPCSource) headerBatch(ctx context.Context, from uint64, count int) ([]ExecutionHeader, error) {
	reqs := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		reqs = append(reqs, map[string]any{
			"jsonrpc": "2.0", "id": i, "method": "eth_getBlockByNumber",
			"params": []any{fmt.Sprintf("0x%x", from-uint64(i)), false},
		})
	}
	body, _ := json.Marshal(reqs)
	raw, _, err := s.callBatch(ctx, body)
	if err != nil {
		return nil, err
	}
	var items []struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("ethproof: batch response: %w", err)
	}
	byID := make(map[int]json.RawMessage, len(items))
	for _, o := range items {
		if o.Error != nil {
			if isRateLimit(http.StatusOK, o.Error.Message) {
				s.stats.Lock()
				s.stats.RateLimited++
				s.stats.Unlock()
				if s.Metrics != nil {
					s.Metrics.RateLimited()
				}
				return nil, fmt.Errorf("%w: batch item %d: %s",
					ErrRateLimited, o.ID, o.Error.Message)
			}
			return nil, fmt.Errorf("ethproof: batch item %d: %s", o.ID, o.Error.Message)
		}
		byID[o.ID] = o.Result
	}
	headers := make([]ExecutionHeader, 0, count)
	for i := 0; i < count; i++ {
		blob, ok := byID[i]
		if !ok || len(blob) == 0 || string(blob) == "null" {
			return nil, fmt.Errorf("ethproof: batch is missing block %d", from-uint64(i))
		}
		h, err := DecodeRPCHeader(blob)
		if err != nil {
			return nil, err
		}
		headers = append(headers, h)
	}
	return headers, nil
}

// callBatch is call() for a batch, whose top level is an ARRAY on success and an
// OBJECT carrying an error when the whole request is refused.
//
// The two shapes are distinguished structurally. Scanning the body for markers
// cannot work: a successful response is full of hex that matches anything short.
func (s *RPCSource) callBatch(ctx context.Context, body []byte) (json.RawMessage, time.Duration, error) {
	backoff := 2 * time.Second
	for attempt := 0; ; attempt++ {
		raw, elapsed, _, err := s.send(ctx, body)
		if err != nil {
			var un *UnreachableError
			if errors.As(err, &un) && un.RateLimited {
				s.noteRateLimited()
				if attempt < s.MaxRetries {
					s.noteRetry()
					select {
					case <-time.After(backoff):
					case <-ctx.Done():
						return nil, 0, ctx.Err()
					}
					backoff *= 2
					continue
				}
				return nil, elapsed, fmt.Errorf("%w: batch refused by every endpoint", ErrRateLimited)
			}
			return nil, elapsed, err
		}
		// A whole-request refusal arrives as a single object with an error; the
		// transport already treated a capacity refusal as a failure, so anything
		// left here is a real answer.
		if len(raw) > 0 && raw[0] == '{' {
			if msg, ok := rpcErrorMessage(raw); ok {
				return nil, elapsed, fmt.Errorf("ethproof: batch refused: %s", msg)
			}
		}
		return raw, elapsed, nil
	}
}

// ---- header decoding -------------------------------------------------------

type rpcHeader struct {
	ParentHash            string  `json:"parentHash"`
	Sha3Uncles            string  `json:"sha3Uncles"`
	Miner                 string  `json:"miner"`
	StateRoot             string  `json:"stateRoot"`
	TransactionsRoot      string  `json:"transactionsRoot"`
	ReceiptsRoot          string  `json:"receiptsRoot"`
	LogsBloom             string  `json:"logsBloom"`
	Difficulty            string  `json:"difficulty"`
	Number                string  `json:"number"`
	GasLimit              string  `json:"gasLimit"`
	GasUsed               string  `json:"gasUsed"`
	Timestamp             string  `json:"timestamp"`
	ExtraData             string  `json:"extraData"`
	MixHash               string  `json:"mixHash"`
	Nonce                 string  `json:"nonce"`
	BaseFeePerGas         *string `json:"baseFeePerGas"`
	WithdrawalsRoot       *string `json:"withdrawalsRoot"`
	BlobGasUsed           *string `json:"blobGasUsed"`
	ExcessBlobGas         *string `json:"excessBlobGas"`
	ParentBeaconBlockRoot *string `json:"parentBeaconBlockRoot"`
	RequestsHash          *string `json:"requestsHash"`
}

// DecodeRPCHeader parses an eth_getBlockByNumber result into an ExecutionHeader.
//
// UNVERIFIED. The returned header is a claim; AuthenticateHeader turns it into a
// fact, or refuses.
func DecodeRPCHeader(raw []byte) (ExecutionHeader, error) {
	var in rpcHeader
	if err := json.Unmarshal(raw, &in); err != nil {
		return ExecutionHeader{}, fmt.Errorf("ethproof: header json: %w", err)
	}
	var h ExecutionHeader
	fixed := []struct {
		dst  []byte
		src  string
		name string
	}{
		{h.ParentHash[:], in.ParentHash, "parentHash"},
		{h.UncleHash[:], in.Sha3Uncles, "sha3Uncles"},
		{h.Coinbase[:], in.Miner, "miner"},
		{h.StateRoot[:], in.StateRoot, "stateRoot"},
		{h.TxRoot[:], in.TransactionsRoot, "transactionsRoot"},
		{h.ReceiptRoot[:], in.ReceiptsRoot, "receiptsRoot"},
		{h.Bloom[:], in.LogsBloom, "logsBloom"},
		{h.MixDigest[:], in.MixHash, "mixHash"},
		{h.Nonce[:], in.Nonce, "nonce"},
	}
	for _, f := range fixed {
		b, err := hexData(f.src, len(f.dst))
		if err != nil {
			return ExecutionHeader{}, fmt.Errorf("header %s: %w", f.name, err)
		}
		copy(f.dst, b)
	}

	var err error
	if h.Difficulty, err = hexBig(in.Difficulty); err != nil {
		return ExecutionHeader{}, fmt.Errorf("header difficulty: %w", err)
	}
	if h.Number, err = hexBig(in.Number); err != nil {
		return ExecutionHeader{}, fmt.Errorf("header number: %w", err)
	}
	if h.GasLimit, err = hexQuantity(in.GasLimit); err != nil {
		return ExecutionHeader{}, fmt.Errorf("header gasLimit: %w", err)
	}
	if h.GasUsed, err = hexQuantity(in.GasUsed); err != nil {
		return ExecutionHeader{}, fmt.Errorf("header gasUsed: %w", err)
	}
	if h.Time, err = hexQuantity(in.Timestamp); err != nil {
		return ExecutionHeader{}, fmt.Errorf("header timestamp: %w", err)
	}
	if h.Extra, err = hexData(in.ExtraData, -1); err != nil {
		return ExecutionHeader{}, fmt.Errorf("header extraData: %w", err)
	}

	if in.BaseFeePerGas != nil {
		if h.BaseFee, err = hexBig(*in.BaseFeePerGas); err != nil {
			return ExecutionHeader{}, fmt.Errorf("header baseFeePerGas: %w", err)
		}
	}
	if in.WithdrawalsRoot != nil {
		var v [32]byte
		b, err := hexData(*in.WithdrawalsRoot, 32)
		if err != nil {
			return ExecutionHeader{}, fmt.Errorf("header withdrawalsRoot: %w", err)
		}
		copy(v[:], b)
		h.WithdrawalsRoot = &v
	}
	if in.BlobGasUsed != nil {
		v, err := hexQuantity(*in.BlobGasUsed)
		if err != nil {
			return ExecutionHeader{}, fmt.Errorf("header blobGasUsed: %w", err)
		}
		h.BlobGasUsed = &v
	}
	if in.ExcessBlobGas != nil {
		v, err := hexQuantity(*in.ExcessBlobGas)
		if err != nil {
			return ExecutionHeader{}, fmt.Errorf("header excessBlobGas: %w", err)
		}
		h.ExcessBlobGas = &v
	}
	if in.ParentBeaconBlockRoot != nil {
		var v [32]byte
		b, err := hexData(*in.ParentBeaconBlockRoot, 32)
		if err != nil {
			return ExecutionHeader{}, fmt.Errorf("header parentBeaconBlockRoot: %w", err)
		}
		copy(v[:], b)
		h.ParentBeaconBlockRoot = &v
	}
	if in.RequestsHash != nil {
		var v [32]byte
		b, err := hexData(*in.RequestsHash, 32)
		if err != nil {
			return ExecutionHeader{}, fmt.Errorf("header requestsHash: %w", err)
		}
		copy(v[:], b)
		h.RequestsHash = &v
	}
	return h, nil
}

func hexBig(s string) (*big.Int, error) {
	t := strings.TrimPrefix(s, "0x")
	if t == "" {
		return new(big.Int), nil
	}
	v, ok := new(big.Int).SetString(t, 16)
	if !ok {
		return nil, fmt.Errorf("%w: quantity %q", ErrReceiptMalformed, s)
	}
	return v, nil
}
