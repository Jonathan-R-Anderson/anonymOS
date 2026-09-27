package aggregator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Read-only chain access.
//
// Settlement cannot be computed from receipts alone. Three of its inputs are
// facts only the chain holds:
//
//	randomness  — seeds witness selection. If the aggregator chose it, it could
//	              pick a seed whose witness draw favours whoever it likes, and
//	              the whole independence argument collapses.
//	recipients  — nodeId -> payout wallet, from NodeRegistry. A receipt names a
//	              node; only the registry says who gets paid for it.
//	stake       — from StakeVault, the weight in witness selection.
//
// This client only ever reads (eth_call / eth_blockNumber). Submitting an epoch
// spends real ETH and needs a key, which is a separate decision from being able
// to compute one; keeping the reader key-free means an auditor can re-run a
// settlement against mainnet without holding anything.
//
// Calls are ABI-encoded by hand rather than pulling in go-ethereum: every
// signature used here takes and returns static 32-byte words (plus one struct
// of statics), so the encoder is a few lines and the dependency is not worth
// the supply-chain surface for a node that already refuses to hold ETH.

// ChainClient reads the Proof-of-Facilitation contracts over JSON-RPC.
type ChainClient struct {
	RPCURL       string
	EpochManager [20]byte
	NodeRegistry [20]byte
	StakeVault   [20]byte
	HTTP         *http.Client
	rpcID        int
}

// NewChainClient builds a reader. Addresses are the deployed contracts.
func NewChainClient(rpcURL string, epochManager, nodeRegistry, stakeVault [20]byte) *ChainClient {
	return &ChainClient{
		RPCURL: rpcURL, EpochManager: epochManager,
		NodeRegistry: nodeRegistry, StakeVault: stakeVault,
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

// ParseAddress accepts a 0x-prefixed hex address.
func ParseAddress(s string) ([20]byte, error) {
	var out [20]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 40 {
		return out, fmt.Errorf("chain: %q is not a 20-byte address", s)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("chain: address is not hex: %w", err)
	}
	copy(out[:], raw)
	return out, nil
}

func (c *ChainClient) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResponse struct {
	Result string `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

var ErrEmptyResult = errors.New("chain: call returned no data (wrong address, or not a contract)")

// ErrReverted is a call the contract refused. For the views used here that is
// usually a normal answer, not a fault: NodeRegistry.getNode reverts with
// UnknownNode() for an id it has never seen, so "reverted" is how the chain
// says "no such node".
var ErrReverted = errors.New("chain: call reverted")

func isRevert(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "execution reverted")
}

func (c *ChainClient) rpc(ctx context.Context, method string, params ...interface{}) (string, error) {
	c.rpcID++
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: c.rpcID, Method: method, Params: params})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RPCURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("chain: %s: %w", method, err)
	}
	defer resp.Body.Close()
	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("chain: %s: bad response: %w", method, err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("chain: %s: rpc error %d: %s", method, out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

// call performs eth_call and returns the raw return data.
func (c *ChainClient) call(ctx context.Context, to [20]byte, data []byte) ([]byte, error) {
	res, err := c.rpc(ctx, "eth_call", map[string]string{
		"to":   "0x" + hex.EncodeToString(to[:]),
		"data": "0x" + hex.EncodeToString(data),
	}, "latest")
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(res, "0x"))
	if err != nil {
		return nil, fmt.Errorf("chain: result is not hex: %w", err)
	}
	if len(raw) == 0 {
		return nil, ErrEmptyResult
	}
	return raw, nil
}

// selector is the first 4 bytes of keccak256(signature).
func selector(signature string) []byte {
	h := keccak([]byte(signature))
	return h[:4]
}

// word left-pads a value into a 32-byte ABI word.
func word(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func wordUint64(v uint64) []byte { return word(new(big.Int).SetUint64(v).Bytes()) }

// readWord returns the i-th 32-byte word of return data.
func readWord(data []byte, i int) ([32]byte, error) {
	var out [32]byte
	start := i * 32
	if len(data) < start+32 {
		return out, fmt.Errorf("chain: return data too short for word %d (%d bytes)", i, len(data))
	}
	copy(out[:], data[start:start+32])
	return out, nil
}

// LatestEpoch is EpochManager.latestEpoch().
func (c *ChainClient) LatestEpoch(ctx context.Context) (uint64, error) {
	data, err := c.call(ctx, c.EpochManager, selector("latestEpoch()"))
	if err != nil {
		return 0, err
	}
	w, err := readWord(data, 0)
	if err != nil {
		return 0, err
	}
	return new(big.Int).SetBytes(w[:]).Uint64(), nil
}

// RandomnessOf is EpochManager.randomnessOf(epoch) — the seed witness selection
// must use. A zero value means the epoch was never submitted, which callers
// must treat as "cannot settle yet" rather than as a usable seed: a zero seed
// would make every witness draw predictable.
func (c *ChainClient) RandomnessOf(ctx context.Context, epoch uint64) ([32]byte, error) {
	call := append(selector("randomnessOf(uint64)"), wordUint64(epoch)...)
	data, err := c.call(ctx, c.EpochManager, call)
	if err != nil {
		return [32]byte{}, err
	}
	return readWord(data, 0)
}

// IsFinalized is EpochManager.isFinalized(epoch).
func (c *ChainClient) IsFinalized(ctx context.Context, epoch uint64) (bool, error) {
	call := append(selector("isFinalized(uint64)"), wordUint64(epoch)...)
	data, err := c.call(ctx, c.EpochManager, call)
	if err != nil {
		return false, err
	}
	w, err := readWord(data, 0)
	if err != nil {
		return false, err
	}
	return w[31] != 0, nil
}

// OnChainEpoch mirrors EpochManager.Epoch.
type OnChainEpoch struct {
	ReceiptRoot       [32]byte
	RewardRoot        [32]byte
	NodeStateRoot     [32]byte
	Randomness        [32]byte
	TotalRewards      *big.Int
	SubmittedAt       uint64
	ChallengeDeadline uint64
	OpenDisputes      uint32
	Finalized         bool
	Exists            bool
}

// EpochOf reads the public `epochs(uint64)` mapping. Every field is static, so
// the return is nine consecutive words.
func (c *ChainClient) EpochOf(ctx context.Context, epoch uint64) (OnChainEpoch, error) {
	var out OnChainEpoch
	call := append(selector("epochs(uint64)"), wordUint64(epoch)...)
	data, err := c.call(ctx, c.EpochManager, call)
	if err != nil {
		return out, err
	}
	get := func(i int) [32]byte {
		w, e := readWord(data, i)
		if e != nil {
			err = e
		}
		return w
	}
	out.ReceiptRoot = get(0)
	out.RewardRoot = get(1)
	out.NodeStateRoot = get(2)
	out.Randomness = get(3)
	tr := get(4)
	out.TotalRewards = new(big.Int).SetBytes(tr[:])
	sa := get(5)
	out.SubmittedAt = new(big.Int).SetBytes(sa[:]).Uint64()
	cd := get(6)
	out.ChallengeDeadline = new(big.Int).SetBytes(cd[:]).Uint64()
	od := get(7)
	out.OpenDisputes = uint32(new(big.Int).SetBytes(od[:]).Uint64())
	fin := get(8)
	out.Finalized = fin[31] != 0
	if err != nil {
		return out, err
	}
	// submittedAt is the contract's own "does this epoch exist" test.
	out.Exists = out.SubmittedAt != 0
	return out, nil
}

// IsNodeRegistered is NodeRegistry.isRegistered(nodeId).
func (c *ChainClient) IsNodeRegistered(ctx context.Context, nodeID [32]byte) (bool, error) {
	call := append(selector("isRegistered(bytes32)"), nodeID[:]...)
	data, err := c.call(ctx, c.NodeRegistry, call)
	if err != nil {
		return false, err
	}
	w, err := readWord(data, 0)
	if err != nil {
		return false, err
	}
	return w[31] != 0, nil
}

// HasCapability is NodeRegistry.hasCapability(nodeId, cap) — whether a node may
// be rewarded for a service at all. A receipt for a capability a node never
// registered is not a scoring question, it is a rejection.
func (c *ChainClient) HasCapability(ctx context.Context, nodeID [32]byte, capability uint64) (bool, error) {
	call := append(selector("hasCapability(bytes32,uint256)"), nodeID[:]...)
	call = append(call, wordUint64(capability)...)
	data, err := c.call(ctx, c.NodeRegistry, call)
	if err != nil {
		return false, err
	}
	w, err := readWord(data, 0)
	if err != nil {
		return false, err
	}
	return w[31] != 0, nil
}

// NodeOwner returns the payout wallet for a node id, from
// NodeRegistry.getNode(nodeId). The struct's first word is `owner`; the dynamic
// `bytes p2pPublicKey` sits behind an offset, so only the head is decoded here —
// settlement needs the wallet, not the key it already has.
func (c *ChainClient) NodeOwner(ctx context.Context, nodeID [32]byte) ([20]byte, bool, error) {
	var owner [20]byte
	call := append(selector("getNode(bytes32)"), nodeID[:]...)
	data, err := c.call(ctx, c.NodeRegistry, call)
	if err != nil {
		// getNode reverts with UnknownNode() rather than returning an empty
		// struct, so a revert here means "not registered" — an ordinary answer
		// during settlement, when receipts routinely name nodes that never
		// completed registration. Confirmed against the deployed contract.
		if isRevert(err) || errors.Is(err, ErrEmptyResult) {
			return owner, false, nil
		}
		return owner, false, err
	}
	// getNode returns a struct: one offset word, then the head. Tolerate both
	// layouts (some compilers inline a fully-static head) by checking whether
	// word 0 looks like an offset.
	base := 0
	if w0, e := readWord(data, 0); e == nil {
		v := new(big.Int).SetBytes(w0[:])
		if v.IsUint64() && v.Uint64() == 32 {
			base = 1
		}
	}
	w, err := readWord(data, base)
	if err != nil {
		return owner, false, err
	}
	copy(owner[:], w[12:]) // an address is the low 20 bytes of its word
	var zero [20]byte
	return owner, owner != zero, nil
}

// TotalStaked is StakeVault.totalStaked(who) — bonded plus still-slashable
// pending withdrawals, which is the amount that can actually be taken and so
// the amount that should count as weight.
func (c *ChainClient) TotalStaked(ctx context.Context, who [20]byte) (*big.Int, error) {
	call := append(selector("totalStaked(address)"), word(who[:])...)
	data, err := c.call(ctx, c.StakeVault, call)
	if err != nil {
		return nil, err
	}
	w, err := readWord(data, 0)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(w[:]), nil
}

// RecipientsFor resolves a set of node ids to payout wallets. Nodes with no
// registration are omitted rather than defaulted: SettleEpoch rejects receipts
// from unregistered providers, and a zero-address recipient would silently burn
// their reward instead.
func (c *ChainClient) RecipientsFor(ctx context.Context, nodeIDs [][32]byte) (map[[32]byte][20]byte, error) {
	out := make(map[[32]byte][20]byte, len(nodeIDs))
	for _, id := range nodeIDs {
		owner, ok, err := c.NodeOwner(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			out[id] = owner
		}
	}
	return out, nil
}

// CandidatesFor builds the witness pool from on-chain stake. Reputation and
// independence grouping are not on-chain yet: reputation defaults to full and
// Group is left empty (each node its own group) so selection stays correct —
// just less discriminating — until those sources exist.
func (c *ChainClient) CandidatesFor(ctx context.Context, nodeIDs [][32]byte) ([]Candidate, error) {
	out := make([]Candidate, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		owner, ok, err := c.NodeOwner(ctx, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue // unregistered: no wallet to weigh, and nothing to pay
		}
		stake, err := c.TotalStaked(ctx, owner)
		if err != nil {
			return nil, err
		}
		out = append(out, Candidate{NodeID: id, Stake: stake, ReputationBps: 10000})
	}
	return out, nil
}
