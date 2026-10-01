package channel

// The measurement signer — roadmap P12 phase 2.
//
// WHY THIS SHAPE
// --------------
// TxSender already existed and had no implementation. Its own comment says key
// management belongs behind it, so this is that implementation rather than a
// new parallel abstraction: measurement transactions and settlement
// transactions travel the same seam, and there is one place where signing
// happens rather than two that can drift.
//
// THE KEY IS NOT HERE
// -------------------
// Signing is delegated to an EXTERNAL signer over its own JSON-RPC endpoint —
// clef, or anything that speaks account_signTransaction. This process never
// holds, reads, derives or logs a private key, and neither does this
// repository. What it holds is an address to check against.
//
// That is the whole reason for the split. A raw key in an environment variable
// is defensible for a one-off deployment a human is watching; it is not
// defensible for ninety scripted transactions against a funded account.
//
// WHAT IT REFUSES, AND WHY EACH ONE IS A REFUSAL RATHER THAN A WARNING
// --------------------------------------------------------------------
//	wrong signer address   the treasury is the only account authorised to spend
//	                       here. A signer that answers as somebody else is not a
//	                       misconfiguration to log, it is the wrong money.
//	wrong chain            a measurement of the wrong chain validates nothing,
//	                       and a transaction on the wrong chain is unrecoverable.
//	unverified             Verify() must have run and passed. A signer that has
//	                       not proved who it is has not proved anything.
//
// None of these is checked once at construction and then trusted: Send re-checks
// that verification happened, because a long measurement run outlives the
// moment its configuration was read.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ExternalSigner sends transactions signed by a separate process.
//
// Construct it, call Verify, then use it as a TxSender. Send refuses until
// Verify has succeeded.
type ExternalSigner struct {
	// SignerURL is the external signer's JSON-RPC endpoint — a local socket or
	// loopback address. It is NOT the chain RPC: the signer holds the key, the
	// node holds the chain, and conflating them puts a key behind whatever
	// endpoint somebody pasted into a config.
	SignerURL string
	// NodeURL is the execution endpoint used to read nonces and broadcast.
	NodeURL string
	// From is the ONLY address this signer may sign as. Checked against what the
	// signer actually reports, not assumed.
	From Address
	// ChainID is the chain this signer may send to. Checked against the node.
	ChainID *big.Int
	// HTTP is the client for both endpoints. Nil means a defaulted one.
	HTTP *http.Client

	// Guard is an optional spend limiter (phase 3). Nil means UNLIMITED, which
	// is why the measurement runners must supply one — see SpendGuard.
	Guard SpendGuard

	// Dialect selects the signer's JSON-RPC vocabulary.
	//
	// Clef and Web3Signer do the same job through different namespaces, and
	// neither implements the other's — Web3Signer's documentation names clef's
	// methods explicitly as NOT supported, so this is a real protocol
	// difference rather than an alias:
	//
	//	clef        account_list   account_signTransaction
	//	web3signer  eth_accounts   eth_signTransaction
	//
	// The zero value is clef, so every existing caller and test keeps the
	// behaviour it already had.
	Dialect SignerDialect

	mu       sync.Mutex
	verified bool
}

// SpendGuard authorises one transaction before it is signed.
//
// An interface rather than fields on the signer because the limit is a property
// of a measurement run, not of the key: the same treasury may be used for two
// runs with different ceilings, and the signer should not be the thing that
// remembers.
type SpendGuard interface {
	// Authorise is called with the gas cost this transaction may incur, before
	// anything is signed or sent. Returning an error stops the transaction.
	Authorise(maxCostWei *big.Int) error
}

// SignerDialect names an external signer's JSON-RPC vocabulary.
type SignerDialect int

const (
	// DialectClef is the default: account_list / account_signTransaction.
	DialectClef SignerDialect = iota
	// DialectWeb3Signer is eth_accounts / eth_signTransaction.
	DialectWeb3Signer
)

func (d SignerDialect) listMethod() string {
	if d == DialectWeb3Signer {
		return "eth_accounts"
	}
	return "account_list"
}

func (d SignerDialect) signMethod() string {
	if d == DialectWeb3Signer {
		return "eth_signTransaction"
	}
	return "account_signTransaction"
}

// ErrUnverified is returned by Send when Verify has not run or did not pass.
var ErrUnverified = fmt.Errorf(
	"signer: not verified; call Verify and confirm the address before sending")

// Verify proves the signer controls the expected address on the expected chain.
//
// MUST be called before Send, and its result is not cached across a failure:
// a signer that stops answering is a signer that has stopped proving anything.
func (s *ExternalSigner) Verify(ctx context.Context) error {
	if s.SignerURL == "" || s.NodeURL == "" {
		return fmt.Errorf("signer: both a signer endpoint and a node endpoint are required")
	}
	if s.ChainID == nil || s.ChainID.Sign() <= 0 {
		return fmt.Errorf("signer: no chain id configured; a transaction needs to know where it goes")
	}
	var zero Address
	if s.From == zero {
		return fmt.Errorf("signer: no expected address; there is nothing to verify against")
	}

	// 1. The signer's own account list. This is the proof: the key holder says
	//    which addresses it can sign for, and we check ours is among them.
	var accounts []string
	if err := s.call(ctx, s.SignerURL, s.Dialect.listMethod(), nil, &accounts); err != nil {
		return fmt.Errorf("signer: could not list accounts: %w", err)
	}
	want := strings.ToLower(s.From.Hex())
	found := false
	for _, a := range accounts {
		if strings.ToLower(strings.TrimSpace(a)) == want {
			found = true
			break
		}
	}
	if !found {
		// Deliberately does NOT print the accounts it did find. A refusal should
		// not enumerate somebody's other keys into a log.
		return fmt.Errorf(
			"signer: it does not control %s; refusing to sign as an account it cannot prove",
			s.From.Hex())
	}

	// 2. The node's chain id. A correct signature on the wrong chain is still
	//    the wrong chain.
	var chainHex string
	if err := s.call(ctx, s.NodeURL, "eth_chainId", nil, &chainHex); err != nil {
		return fmt.Errorf("signer: could not read the node's chain id: %w", err)
	}
	got, ok := new(big.Int).SetString(strings.TrimPrefix(chainHex, "0x"), 16)
	if !ok {
		return fmt.Errorf("signer: the node returned an unreadable chain id %q", chainHex)
	}
	if got.Cmp(s.ChainID) != 0 {
		return fmt.Errorf("signer: the node is on chain %s, this signer is for chain %s",
			got, s.ChainID)
	}

	s.mu.Lock()
	s.verified = true
	s.mu.Unlock()
	return nil
}

// Address is the account this signer sends from.
func (s *ExternalSigner) Address() Address { return s.From }

// Send implements TxSender.
//
// The pipeline, in order, and every step can refuse:
//
//	verified? -> nonce -> fees -> gas estimate -> SPEND GUARD -> sign -> broadcast
//
// The guard sits after estimation because it needs a cost to judge, and before
// signing because a transaction that must not be sent must not be signed
// either — a signed transaction is one leak away from being broadcast by
// somebody else.
func (s *ExternalSigner) Send(ctx context.Context, to Address, data []byte) (string, error) {
	s.mu.Lock()
	verified := s.verified
	s.mu.Unlock()
	if !verified {
		return "", ErrUnverified
	}

	nonce, err := s.hexUint(ctx, "eth_getTransactionCount", []any{s.From.Hex(), "pending"})
	if err != nil {
		return "", fmt.Errorf("signer: nonce: %w", err)
	}
	tipCap, err := s.hexBig(ctx, "eth_maxPriorityFeePerGas", nil)
	if err != nil {
		return "", fmt.Errorf("signer: priority fee: %w", err)
	}
	baseFee, err := s.baseFee(ctx)
	if err != nil {
		return "", fmt.Errorf("signer: base fee: %w", err)
	}
	// Room for two base-fee doublings, the usual headroom for a transaction that
	// should confirm without a replacement. Repricing (phase 6) deliberately
	// does NOT use this path.
	feeCap := new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(4)), tipCap)

	call := map[string]any{
		"from": s.From.Hex(), "to": to.Hex(),
		"data": "0x" + hexBytes(data),
	}
	gas, err := s.hexUint(ctx, "eth_estimateGas", []any{call})
	if err != nil {
		return "", fmt.Errorf("signer: gas estimate: %w", err)
	}

	// SPEND GUARD. The worst this transaction can cost is gas x feeCap.
	maxCost := new(big.Int).Mul(new(big.Int).SetUint64(gas), feeCap)
	if s.Guard != nil {
		if err := s.Guard.Authorise(maxCost); err != nil {
			return "", fmt.Errorf("signer: refused before signing: %w", err)
		}
	}

	tx := map[string]any{
		"from": s.From.Hex(), "to": to.Hex(),
		"gas": hexUint(gas), "nonce": hexUint(nonce),
		"maxFeePerGas": hexBig(feeCap), "maxPriorityFeePerGas": hexBig(tipCap),
		"value": "0x0", "data": "0x" + hexBytes(data),
		"chainId": hexBig(s.ChainID),
	}
	// The response shapes differ as much as the method names do: clef wraps the
	// signed transaction in an object, Web3Signer returns the RLP hex directly.
	// Decoded into a RawMessage first so one dialect's branch cannot silently
	// accept the other's shape and hand back an empty string.
	var reply json.RawMessage
	if err := s.call(ctx, s.SignerURL, s.Dialect.signMethod(), []any{tx}, &reply); err != nil {
		return "", fmt.Errorf("signer: signing refused: %w", err)
	}
	var raw string
	if s.Dialect == DialectWeb3Signer {
		if err := json.Unmarshal(reply, &raw); err != nil {
			return "", fmt.Errorf("signer: unreadable signed transaction: %w", err)
		}
	} else {
		var wrapped struct {
			Raw string `json:"raw"`
		}
		if err := json.Unmarshal(reply, &wrapped); err != nil {
			return "", fmt.Errorf("signer: unreadable signed transaction: %w", err)
		}
		raw = wrapped.Raw
	}
	if strings.TrimSpace(raw) == "" || raw == "0x" {
		return "", fmt.Errorf("signer: returned no signed transaction")
	}
	signed := struct{ Raw string }{Raw: raw}

	var hash string
	if err := s.call(ctx, s.NodeURL, "eth_sendRawTransaction", []any{signed.Raw}, &hash); err != nil {
		return "", fmt.Errorf("signer: broadcast: %w", err)
	}
	return hash, nil
}

// ---- plumbing ----------------------------------------------------------------

func (s *ExternalSigner) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s *ExternalSigner) call(ctx context.Context, url, method string, params []any, out any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("unreadable answer from %s: %w", method, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s: %s", method, envelope.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, out)
}

func (s *ExternalSigner) hexUint(ctx context.Context, method string, params []any) (uint64, error) {
	var raw string
	if err := s.call(ctx, s.NodeURL, method, params, &raw); err != nil {
		return 0, err
	}
	v, ok := new(big.Int).SetString(strings.TrimPrefix(raw, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("%s returned %q", method, raw)
	}
	return v.Uint64(), nil
}

func (s *ExternalSigner) hexBig(ctx context.Context, method string, params []any) (*big.Int, error) {
	var raw string
	if err := s.call(ctx, s.NodeURL, method, params, &raw); err != nil {
		return nil, err
	}
	v, ok := new(big.Int).SetString(strings.TrimPrefix(raw, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("%s returned %q", method, raw)
	}
	return v, nil
}

func (s *ExternalSigner) baseFee(ctx context.Context) (*big.Int, error) {
	var head struct {
		BaseFeePerGas string `json:"baseFeePerGas"`
	}
	if err := s.call(ctx, s.NodeURL, "eth_getBlockByNumber", []any{"latest", false}, &head); err != nil {
		return nil, err
	}
	if head.BaseFeePerGas == "" {
		return nil, fmt.Errorf("the chain head reports no base fee")
	}
	v, ok := new(big.Int).SetString(strings.TrimPrefix(head.BaseFeePerGas, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("unreadable base fee %q", head.BaseFeePerGas)
	}
	return v, nil
}

func hexUint(v uint64) string  { return "0x" + big.NewInt(0).SetUint64(v).Text(16) }
func hexBig(v *big.Int) string { return "0x" + v.Text(16) }

func hexBytes(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// ---- confirmation ------------------------------------------------------------
//
// TxSender.Send returns a hash, which is all settlement needs: a payout either
// lands or is retried, and the timing is nobody's evidence. Measurement needs
// more — how long it took, how many blocks passed, and what the fee market
// looked like at broadcast — so the pipeline continues here rather than
// widening the interface every caller already depends on.

// SendReceipt is what a measurement needs and settlement does not.
type SendReceipt struct {
	TxHash string
	Nonce  uint64
	// BaseFeeGwei is the market at BROADCAST, not at inclusion. It records which
	// regime the sample came from; reading it afterwards would describe the
	// block that happened to include it instead.
	BaseFeeGwei float64
	// BroadcastAt and SentBlock are the starting line, taken before the
	// transaction was sent.
	BroadcastAt time.Time
	SentBlock   uint64
}

// SendMeasured broadcasts and reports everything the evidence needs.
//
// Same pipeline as Send — it IS Send, with the intermediate values kept instead
// of discarded.
func (s *ExternalSigner) SendMeasured(ctx context.Context, to Address, data []byte) (SendReceipt, error) {
	s.mu.Lock()
	verified := s.verified
	s.mu.Unlock()
	if !verified {
		return SendReceipt{}, ErrUnverified
	}

	nonce, err := s.hexUint(ctx, "eth_getTransactionCount", []any{s.From.Hex(), "pending"})
	if err != nil {
		return SendReceipt{}, fmt.Errorf("signer: nonce: %w", err)
	}
	head, err := s.hexUint(ctx, "eth_blockNumber", nil)
	if err != nil {
		return SendReceipt{}, fmt.Errorf("signer: head: %w", err)
	}
	baseFee, err := s.baseFee(ctx)
	if err != nil {
		return SendReceipt{}, fmt.Errorf("signer: base fee: %w", err)
	}

	hash, err := s.Send(ctx, to, data)
	if err != nil {
		return SendReceipt{}, err
	}
	// Gwei as a float purely for the Method string. Never used for arithmetic
	// that decides anything — wei stays integral everywhere it matters.
	gwei, _ := new(big.Float).Quo(new(big.Float).SetInt(baseFee), big.NewFloat(1e9)).Float64()
	return SendReceipt{
		TxHash: hash, Nonce: nonce, BaseFeeGwei: gwei,
		BroadcastAt: time.Now(), SentBlock: head,
	}, nil
}

// AwaitInclusion waits for a receipt and reports the sample.
//
// RETURNS AN UNCONFIRMED SAMPLE RATHER THAN AN ERROR when the deadline passes.
// That is deliberate and it matters: InclusionObservation.AsEvidence refuses a
// run containing an abandoned transaction, because the worst case of a run with
// an unconfirmed transaction is UNKNOWN, not the slowest one that landed.
// Dropping the sample here would hide exactly the observation the worst case is
// made of.
func (s *ExternalSigner) AwaitInclusion(ctx context.Context, r SendReceipt, poll time.Duration) InclusionSample {
	sample := InclusionSample{TxHash: r.TxHash, BaseFeeGwei: r.BaseFeeGwei}
	if poll <= 0 {
		poll = 4 * time.Second
	}
	for {
		var receipt *struct {
			BlockNumber string `json:"blockNumber"`
		}
		if err := s.call(ctx, s.NodeURL, "eth_getTransactionReceipt",
			[]any{r.TxHash}, &receipt); err == nil && receipt != nil && receipt.BlockNumber != "" {

			if got, ok := new(big.Int).SetString(strings.TrimPrefix(receipt.BlockNumber, "0x"), 16); ok {
				sample.Confirmed = true
				sample.Delay = time.Since(r.BroadcastAt)
				if b := got.Uint64(); b > r.SentBlock {
					sample.BlocksWaited = b - r.SentBlock
				}
				return sample
			}
		}
		select {
		case <-ctx.Done():
			// Unconfirmed, and said so. The caller files it as-is.
			return sample
		case <-time.After(poll):
		}
	}
}
