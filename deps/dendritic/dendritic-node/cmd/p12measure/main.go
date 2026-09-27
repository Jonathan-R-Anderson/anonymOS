package main

// P12-8 inclusion measurement. Real Ethereum Mainnet.
//
// 30 EIP-1559 self-transfers, value 0, 21000 gas. Measures submission to first
// containing block. Spends only what the protocol requires; the funded balance
// is a CEILING, not a target, and the run aborts if projected spend approaches
// it rather than draining the account.
//
// The private key is read from the environment and never printed.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const (
	chainID  = 1
	gasLimit = 21000
	samples  = 30
	// Hard spend ceiling for the whole run. Well under the funded balance:
	// the protocol needs ~0.0004 ETH at current gas, so this stops a fee spike
	// from quietly consuming the account.
	maxSpendWei = 1_200_000_000_000_000 // 0.0012 ETH
)

func keccak(b []byte) []byte { h := sha3.NewLegacyKeccak256(); h.Write(b); return h.Sum(nil) }

// ---- minimal RLP encoder (the package has a decoder only) -------------------

func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpLen(len(b), 0x80), b...)
}
func rlpList(items ...[]byte) []byte {
	var body []byte
	for _, i := range items {
		body = append(body, i...)
	}
	return append(rlpLen(len(body), 0xC0), body...)
}
func rlpLen(n int, offset byte) []byte {
	if n <= 55 {
		return []byte{offset + byte(n)}
	}
	var l []byte
	for x := n; x > 0; x >>= 8 {
		l = append([]byte{byte(x)}, l...)
	}
	return append([]byte{offset + 55 + byte(len(l))}, l...)
}
// rlpInt: big-endian, no leading zeros; zero is the empty string.
func rlpInt(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return rlpBytes(nil)
	}
	return rlpBytes(v.Bytes())
}
func rlpU64(v uint64) []byte { return rlpInt(new(big.Int).SetUint64(v)) }

// ---- EIP-1559 transaction ---------------------------------------------------

type tx struct {
	nonce                uint64
	maxPriority, maxFee  *big.Int
	to                   []byte
	value                *big.Int
}

// unsigned payload: 0x02 || rlp([chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList])
func (t tx) fields() [][]byte {
	return [][]byte{
		rlpU64(chainID), rlpU64(t.nonce), rlpInt(t.maxPriority), rlpInt(t.maxFee),
		rlpU64(gasLimit), rlpBytes(t.to), rlpInt(t.value), rlpBytes(nil), rlpList(),
	}
}

func (t tx) sign(priv *secp256k1.PrivateKey) ([]byte, string) {
	payload := append([]byte{0x02}, rlpList(t.fields()...)...)
	h := keccak(payload)
	compact := ecdsa.SignCompact(priv, h, false) // v||r||s, v = 27+recid
	r, s := compact[1:33], compact[33:65]
	yParity := uint64(compact[0] - 27)

	signed := append([]byte{0x02}, rlpList(append(t.fields(),
		rlpU64(yParity), rlpBytes(bytes.TrimLeft(r, "\x00")), rlpBytes(bytes.TrimLeft(s, "\x00")))...)...)
	return signed, "0x" + hex.EncodeToString(keccak(signed))
}

// ---- RPC --------------------------------------------------------------------

var endpoint string

func rpc(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 45 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

func hexU64(ctx context.Context, m string, p ...any) (uint64, error) {
	r, err := rpc(ctx, m, p...)
	if err != nil {
		return 0, err
	}
	var s string
	json.Unmarshal(r, &s)
	v := new(big.Int)
	v.SetString(strings.TrimPrefix(s, "0x"), 16)
	return v.Uint64(), nil
}

type sample struct {
	N            int    `json:"sample"`
	Hash         string `json:"tx_hash"`
	Nonce        uint64 `json:"nonce"`
	SubmitBlock  uint64 `json:"submitted_at_block"`
	SubmitUnix   int64  `json:"submitted_unix"`
	IncludeBlock uint64 `json:"included_in_block"`
	IncludeUnix  int64  `json:"included_block_timestamp"`
	DelaySec     float64 `json:"inclusion_delay_seconds"`
	Blocks       uint64 `json:"blocks_waited"`
	MaxFeeGwei   float64 `json:"max_fee_gwei"`
	TipGwei      float64 `json:"priority_fee_gwei"`
	PaidWei      string `json:"fee_paid_wei"`
}

func main() {
	endpoint = os.Getenv("ETH_RPC_URL")
	keyHex := strings.TrimPrefix(os.Getenv("P12_MEASUREMENT_PRIVATE_KEY"), "0x")
	if endpoint == "" || keyHex == "" {
		fmt.Println("need ETH_RPC_URL and P12_MEASUREMENT_PRIVATE_KEY")
		return
	}
	kb, err := hex.DecodeString(keyHex)
	if err != nil || len(kb) != 32 {
		fmt.Println("bad key material")
		return
	}
	priv := secp256k1.PrivKeyFromBytes(kb)
	pub := priv.PubKey().SerializeUncompressed()
	addr := keccak(pub[1:])[12:]
	self := addr
	fmt.Printf("measurement account: 0x%s\n", hex.EncodeToString(addr))

	ctx := context.Background()
	bal, _ := hexU64(ctx, "eth_getBalance", "0x"+hex.EncodeToString(addr), "latest")
	fmt.Printf("balance: %.7f ETH   spend ceiling this run: %.7f ETH\n\n",
		float64(bal)/1e18, float64(maxSpendWei)/1e18)

	nonce, err := hexU64(ctx, "eth_getTransactionCount", "0x"+hex.EncodeToString(addr), "latest")
	if err != nil {
		fmt.Println("nonce:", err)
		return
	}

	var results []sample
	spent := new(big.Int)

	for i := 0; i < samples; i++ {
		// Fee params from live conditions, per the protocol.
		bn, _ := hexU64(ctx, "eth_blockNumber")
		blkRaw, err := rpc(ctx, "eth_getBlockByNumber", fmt.Sprintf("0x%x", bn), false)
		if err != nil {
			fmt.Println("block:", err)
			return
		}
		var blk struct{ BaseFeePerGas string `json:"baseFeePerGas"` }
		json.Unmarshal(blkRaw, &blk)
		base := new(big.Int)
		base.SetString(strings.TrimPrefix(blk.BaseFeePerGas, "0x"), 16)

		tip := big.NewInt(100_000_000) // 0.1 gwei floor, per protocol
		maxFee := new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(2)), tip)

		projected := new(big.Int).Mul(maxFee, big.NewInt(gasLimit))
		if new(big.Int).Add(spent, projected).Cmp(big.NewInt(maxSpendWei)) > 0 {
			fmt.Printf("\nSTOPPING at sample %d: next tx would exceed the run's spend ceiling\n", i)
			break
		}

		t := tx{nonce: nonce, maxPriority: tip, maxFee: maxFee, to: self, value: big.NewInt(0)}
		raw, hash := t.sign(priv)

		submitUnix := time.Now().Unix()
		if _, err := rpc(ctx, "eth_sendRawTransaction", "0x"+hex.EncodeToString(raw)); err != nil {
			fmt.Printf("sample %d submit failed: %v\n", i+1, err)
			return
		}

		// Wait for inclusion.
		var rcpt struct {
			BlockNumber       string `json:"blockNumber"`
			EffectiveGasPrice string `json:"effectiveGasPrice"`
			GasUsed           string `json:"gasUsed"`
		}
		deadline := time.Now().Add(10 * time.Minute)
		for time.Now().Before(deadline) {
			r, err := rpc(ctx, "eth_getTransactionReceipt", hash)
			if err == nil && len(r) > 0 && string(r) != "null" {
				json.Unmarshal(r, &rcpt)
				if rcpt.BlockNumber != "" {
					break
				}
			}
			time.Sleep(3 * time.Second)
		}
		if rcpt.BlockNumber == "" {
			fmt.Printf("sample %d never included within 10m\n", i+1)
			return
		}

		inclBN := new(big.Int)
		inclBN.SetString(strings.TrimPrefix(rcpt.BlockNumber, "0x"), 16)
		ibRaw, _ := rpc(ctx, "eth_getBlockByNumber", rcpt.BlockNumber, false)
		var ib struct{ Timestamp string `json:"timestamp"` }
		json.Unmarshal(ibRaw, &ib)
		its := new(big.Int)
		its.SetString(strings.TrimPrefix(ib.Timestamp, "0x"), 16)

		egp := new(big.Int)
		egp.SetString(strings.TrimPrefix(rcpt.EffectiveGasPrice, "0x"), 16)
		gu := new(big.Int)
		gu.SetString(strings.TrimPrefix(rcpt.GasUsed, "0x"), 16)
		paid := new(big.Int).Mul(egp, gu)
		spent.Add(spent, paid)

		s := sample{
			N: i + 1, Hash: hash, Nonce: nonce,
			SubmitBlock: bn, SubmitUnix: submitUnix,
			IncludeBlock: inclBN.Uint64(), IncludeUnix: its.Int64(),
			DelaySec: float64(its.Int64() - submitUnix),
			Blocks:   inclBN.Uint64() - bn,
			MaxFeeGwei: float64(maxFee.Uint64()) / 1e9,
			TipGwei:    float64(tip.Uint64()) / 1e9,
			PaidWei:    paid.String(),
		}
		results = append(results, s)
		fmt.Printf("  %2d/%d  %s  block %d (+%d)  %.0fs  paid %.9f ETH\n",
			s.N, samples, s.Hash[:18], s.IncludeBlock, s.Blocks, s.DelaySec, float64(paid.Int64())/1e18)
		nonce++
	}

	// Statistics.
	var ds []float64
	for _, r := range results {
		ds = append(ds, r.DelaySec)
	}
	sort.Float64s(ds)
	pct := func(p float64) float64 {
		if len(ds) == 0 { return 0 }
		i := int(p * float64(len(ds)-1))
		return ds[i]
	}
	fmt.Printf("\nsamples=%d  min=%.0fs  median=%.0fs  p95=%.0fs  max=%.0fs\n",
		len(ds), ds[0], pct(0.5), pct(0.95), ds[len(ds)-1])
	fmt.Printf("total spent: %.9f ETH\n", float64(spent.Int64())/1e18)

	out, _ := json.MarshalIndent(map[string]any{
		"chain_id": chainID, "account": "0x" + hex.EncodeToString(addr),
		"endpoint_provider": "alchemy", "gas_limit": gasLimit,
		"tx_type": "eip-1559 self-transfer, value 0",
		"samples": results, "total_spent_wei": spent.String(),
	}, "", "  ")
	os.WriteFile(os.Getenv("OUT"), out, 0o644)
	fmt.Println("provenance written to", os.Getenv("OUT"))
}
