package ethproof

// Fetching what a proof needs, and measuring what it costs — roadmap P12-2.
//
// Two calls: a block header for its stateRoot, and eth_getProof for the account
// and storage paths beneath it. Everything the RPC returns is treated as a
// CLAIM and checked by proof.go; nothing here believes an answer because of
// where it came from.
//
// The measurement side is not incidental. doc/ethereum-data-layer.md costs the
// whole architecture on assumed proof sizes — 5 KB accounts, 3 KB slots — and
// those are typical figures somebody wrote down, not measurements. Measurement
// records what the chain actually returns so the estimate can be replaced.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Client is a read-only JSON-RPC client.
type Client struct {
	Endpoint string
	HTTP     *http.Client

	// Transport, when set, supplies TRANSPORT failover across several endpoints.
	// It carries no Ethereum logic and cannot influence verification — see
	// transport.go. When nil, Endpoint is used alone and behaviour is unchanged.
	Transport *Endpoints
}

// NewClient builds one with a bounded timeout.
func NewClient(endpoint string) *Client {
	return &Client{Endpoint: endpoint, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// NewFailoverClient builds a client that tries endpoints in order.
//
// Availability only. Every response, from whichever endpoint, continues through
// the identical verification path.
func NewFailoverClient(urls ...string) *Client {
	e := NewEndpoints(urls...)
	first := ""
	if len(e.URLs) > 0 {
		first = e.URLs[0]
	}
	return &Client{Endpoint: first, HTTP: e.HTTP, Transport: e}
}

// endpoints returns the transport to use: the configured one, or a
// single-endpoint list built from Endpoint so there is ONE request path rather
// than two behaviours to keep in step.
func (c *Client) endpoints() *Endpoints {
	if c.Transport != nil {
		return c.Transport
	}
	return &Endpoints{URLs: []string{c.Endpoint}, HTTP: c.HTTP}
}

func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return err
	}

	// TRANSPORT. Answers only "which endpoint supplied bytes"; everything below
	// this line treats those bytes as equally untrusted whichever answered.
	raw, _, err := c.endpoints().Post(ctx, body)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s: %s", method, envelope.Error.Message)
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return fmt.Errorf("%s: empty result", method)
	}
	return json.Unmarshal(envelope.Result, out)
}

// BlockHeader is the part of a block this needs.
type BlockHeader struct {
	Number string `json:"number"`
	Hash   string `json:"hash"`
	// ParentHash links a header to the one before it. A CONSISTENCY signal
	// only: post-merge there is no proof-of-work, so linkage is free to
	// fabricate — see anchor.go.
	ParentHash  string `json:"parentHash"`
	StateRoot   string `json:"stateRoot"`
	ReceiptRoot string `json:"receiptsRoot"`
	LogsBloom   string `json:"logsBloom"`
	Timestamp   string `json:"timestamp"`
}

// BlockNumber parses the height.
func (h BlockHeader) BlockNumber() uint64 {
	n := new(big.Int)
	n.SetString(strings.TrimPrefix(h.Number, "0x"), 16)
	return n.Uint64()
}

// Header fetches a block header. `which` is "latest" or a hex height.
func (c *Client) Header(ctx context.Context, which string) (BlockHeader, error) {
	var out BlockHeader
	err := c.call(ctx, "eth_getBlockByNumber", []any{which, false}, &out)
	return out, err
}

// ProofResult is eth_getProof's answer, unverified.
type ProofResult struct {
	Address      string   `json:"address"`
	AccountProof []string `json:"accountProof"`
	Balance      string   `json:"balance"`
	CodeHash     string   `json:"codeHash"`
	Nonce        string   `json:"nonce"`
	StorageHash  string   `json:"storageHash"`
	StorageProof []struct {
		Key   string   `json:"key"`
		Value string   `json:"value"`
		Proof []string `json:"proof"`
	} `json:"storageProof"`
}

// GetProof asks for an account and a set of storage slots at a given block.
func (c *Client) GetProof(ctx context.Context, address string, slots [][32]byte, block string) (ProofResult, error) {
	keys := make([]string, len(slots))
	for i, s := range slots {
		keys[i] = "0x" + hex.EncodeToString(s[:])
	}
	var out ProofResult
	err := c.call(ctx, "eth_getProof", []any{address, keys, block}, &out)
	return out, err
}

// SlotMeasurement is one storage slot, proven and measured.
type SlotMeasurement struct {
	Slot [32]byte
	// Value is what the proof COMMITS TO, recovered by walking it — not what
	// the RPC said in its `value` field. The two are compared below, and a
	// disagreement is the whole point of doing this.
	Value    [32]byte
	Claimed  [32]byte
	Agrees   bool
	Absent   bool
	Nodes    int
	ProofLen int
}

// Measurement is a full verified read, with its costs.
type Measurement struct {
	Address     string
	BlockNumber uint64
	StateRoot   string
	// AccountVerified means the account proof held against the header's
	// stateRoot, and the storageHash below was recovered from it rather than
	// taken from the RPC's own field.
	AccountVerified  bool
	StorageRoot      [32]byte
	ClaimedStorage   [32]byte
	StorageRootAgree bool
	AccountNodes     int
	AccountProofLen  int
	Slots            []SlotMeasurement
	Elapsed          time.Duration
}

// TotalBytes is the whole proof payload for this read.
func (m Measurement) TotalBytes() int {
	total := m.AccountProofLen
	for _, s := range m.Slots {
		total += s.ProofLen
	}
	return total
}

// VerifiedRead is the whole chain, end to end:
//
//	header.stateRoot -> account proof -> storageRoot -> storage proof -> value
//
// Every link is checked here. The RPC's own `value` and `storageHash` fields
// are recorded for COMPARISON and never used as inputs — an implementation that
// read them would verify a proof and then return the provider's number anyway,
// which is the mistake this whole package exists to avoid.
func VerifiedRead(ctx context.Context, c *Client, address string, slots [][32]byte, block string) (Measurement, error) {
	started := time.Now()
	out := Measurement{Address: address}

	header, err := c.Header(ctx, block)
	if err != nil {
		return out, fmt.Errorf("header: %w", err)
	}
	out.BlockNumber = header.BlockNumber()
	out.StateRoot = header.StateRoot

	// Pin the proof to the exact block whose header we hold. Asking for
	// "latest" twice can straddle a block boundary and produce a proof against
	// a root we never saw.
	proof, err := c.GetProof(ctx, address, slots, header.Number)
	if err != nil {
		return out, fmt.Errorf("getProof: %w", err)
	}

	stateRoot, err := decodeHex32(header.StateRoot)
	if err != nil {
		return out, err
	}
	addrBytes, err := decodeHexBytes(address)
	if err != nil || len(addrBytes) != 20 {
		return out, fmt.Errorf("ethproof: %q is not an address", address)
	}

	accountNodes, accountLen, err := decodeNodes(proof.AccountProof)
	if err != nil {
		return out, err
	}
	out.AccountNodes, out.AccountProofLen = len(accountNodes), accountLen

	accountRLP, err := VerifyProof(stateRoot[:], addrBytes, accountNodes)
	if err != nil {
		return out, fmt.Errorf("account proof: %w", err)
	}
	storageRoot, err := AccountStorageRoot(accountRLP)
	if err != nil {
		return out, err
	}
	out.AccountVerified = true
	copy(out.StorageRoot[:], storageRoot)
	if claimed, err := decodeHex32(proof.StorageHash); err == nil {
		out.ClaimedStorage = claimed
		out.StorageRootAgree = claimed == out.StorageRoot
	}

	for i, sp := range proof.StorageProof {
		nodes, length, err := decodeNodes(sp.Proof)
		if err != nil {
			return out, err
		}
		raw, err := VerifyProof(storageRoot, slots[i][:], nodes)
		if err != nil {
			return out, fmt.Errorf("storage proof %d: %w", i, err)
		}
		value, err := DecodeSlotValue(raw)
		if err != nil {
			return out, err
		}
		measurement := SlotMeasurement{
			Slot: slots[i], Value: value, Absent: raw == nil,
			Nodes: len(nodes), ProofLen: length,
		}
		if claimed, err := decodeHexPadded32(sp.Value); err == nil {
			measurement.Claimed = claimed
			measurement.Agrees = claimed == value
		}
		out.Slots = append(out.Slots, measurement)
	}

	out.Elapsed = time.Since(started)
	return out, nil
}

func decodeNodes(hexNodes []string) ([][]byte, int, error) {
	out := make([][]byte, 0, len(hexNodes))
	total := 0
	for _, h := range hexNodes {
		raw, err := decodeHexBytes(h)
		if err != nil {
			return nil, 0, err
		}
		total += len(raw)
		out = append(out, raw)
	}
	return out, total, nil
}

func decodeHexBytes(s string) ([]byte, error) {
	t := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(t)%2 == 1 {
		t = "0" + t
	}
	return hex.DecodeString(t)
}

func decodeHex32(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := decodeHexBytes(s)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("ethproof: expected 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// decodeHexPadded32 accepts the short form RPCs use for storage values.
func decodeHexPadded32(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := decodeHexBytes(s)
	if err != nil {
		return out, err
	}
	if len(raw) > 32 {
		return out, fmt.Errorf("ethproof: value is %d bytes", len(raw))
	}
	copy(out[32-len(raw):], raw)
	return out, nil
}
