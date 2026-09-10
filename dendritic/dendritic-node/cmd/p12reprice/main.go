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

func inclusionMain() {
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

// ---- P12-8 repricing campaign ----------------------------------------------
//
// Implements doc/p12-8-repricing-protocol.md as approved. Every constant below
// is a protocol term and is not tuned to produce a result.
//
//	stuck        maxFeePerGas < base fee at submission — true from submission
//	trigger      replace after ONE block has passed without inclusion
//	initial fee  maxFeePerGas = 50% of base (a >12.5% single-block drop is
//	             impossible under EIP-1559, so it cannot become mineable in the
//	             one-block window)
//	replacement  tip 0.1 gwei, maxFee = 2*base + tip
//	recovery     original submission block timestamp -> replacement inclusion
//	             block timestamp
//
// Sequential: one pending transaction at a time, no nonce gaps.

const (
	targetSamples = 30
	replTipWei    = 100_000_000 // 0.1 gwei
	campaignCap   = 1_200_000_000_000_000 // 0.0012 ETH hard ceiling
)

type rsample struct {
	N int `json:"sample"`

	OrigHash      string `json:"original_tx_hash"`
	OrigMaxFeeWei string `json:"original_max_fee_wei"`
	OrigTipWei    string `json:"original_priority_fee_wei"`
	SubmitBlock   uint64 `json:"submission_block"`
	SubmitTime    int64  `json:"submission_block_timestamp"`
	BaseFeeWei    string `json:"base_fee_at_submission_wei"`
	Nonce         uint64 `json:"nonce"`

	ReplHash      string `json:"replacement_tx_hash"`
	ReplMaxFeeWei string `json:"replacement_max_fee_wei"`
	ReplTipWei    string `json:"replacement_priority_fee_wei"`
	ReplBlock     uint64 `json:"replacement_inclusion_block"`
	ReplTime      int64  `json:"replacement_inclusion_timestamp"`
	ReplStatus    string `json:"replacement_status"`

	RecoverySec   float64 `json:"recovery_seconds"`
	OrigUnmined   bool    `json:"original_remained_unmined"`
	GasPaidWei    string  `json:"gas_actually_paid_wei"`
	NonceAdvanced bool    `json:"nonce_advanced_by_one"`

	Valid   bool   `json:"valid"`
	Discard string `json:"discard_reason,omitempty"`
}

func blockTime(ctx context.Context, n uint64) int64 {
	r, err := rpc(ctx, "eth_getBlockByNumber", fmt.Sprintf("0x%x", n), false)
	if err != nil {
		return 0
	}
	var b struct{ Timestamp string `json:"timestamp"` }
	json.Unmarshal(r, &b)
	v := new(big.Int)
	v.SetString(strings.TrimPrefix(b.Timestamp, "0x"), 16)
	return v.Int64()
}

func headAndBase(ctx context.Context) (uint64, *big.Int, error) {
	bn, err := hexU64(ctx, "eth_blockNumber")
	if err != nil {
		return 0, nil, err
	}
	r, err := rpc(ctx, "eth_getBlockByNumber", fmt.Sprintf("0x%x", bn), false)
	if err != nil {
		return 0, nil, err
	}
	var b struct{ BaseFeePerGas string `json:"baseFeePerGas"` }
	json.Unmarshal(r, &b)
	base := new(big.Int)
	base.SetString(strings.TrimPrefix(b.BaseFeePerGas, "0x"), 16)
	return bn, base, nil
}

// receiptOf returns (found, blockNumber, status, gasPaid).
func receiptOf(ctx context.Context, hash string) (bool, uint64, string, *big.Int) {
	r, err := rpc(ctx, "eth_getTransactionReceipt", hash)
	if err != nil || len(r) == 0 || string(r) == "null" {
		return false, 0, "", nil
	}
	var rc struct {
		BlockNumber       string `json:"blockNumber"`
		Status            string `json:"status"`
		EffectiveGasPrice string `json:"effectiveGasPrice"`
		GasUsed           string `json:"gasUsed"`
	}
	json.Unmarshal(r, &rc)
	if rc.BlockNumber == "" {
		return false, 0, "", nil
	}
	bn := new(big.Int)
	bn.SetString(strings.TrimPrefix(rc.BlockNumber, "0x"), 16)
	egp, gu := new(big.Int), new(big.Int)
	egp.SetString(strings.TrimPrefix(rc.EffectiveGasPrice, "0x"), 16)
	gu.SetString(strings.TrimPrefix(rc.GasUsed, "0x"), 16)
	return true, bn.Uint64(), rc.Status, new(big.Int).Mul(egp, gu)
}

func main() {
	_ = inclusionMain
	endpoint = os.Getenv("ETH_RPC_URL")
	kb, err := hex.DecodeString(strings.TrimPrefix(os.Getenv("P12_MEASUREMENT_PRIVATE_KEY"), "0x"))
	if err != nil || len(kb) != 32 {
		fmt.Println("bad key material")
		return
	}
	priv := secp256k1.PrivKeyFromBytes(kb)
	pub := priv.PubKey().SerializeUncompressed()
	addr := keccak(pub[1:])[12:]
	ctx := context.Background()

	fmt.Printf("P12-8 repricing campaign — account 0x%s\n", hex.EncodeToString(addr))
	bal, _ := hexU64(ctx, "eth_getBalance", "0x"+hex.EncodeToString(addr), "latest")
	fmt.Printf("balance %.9f ETH   campaign ceiling %.9f ETH\n\n",
		float64(bal)/1e18, float64(campaignCap)/1e18)

	var valid []rsample
	var discarded []rsample
	spent := new(big.Int)
	attempt := 0

	for len(valid) < targetSamples {
		attempt++
		if attempt > targetSamples*3 {
			fmt.Printf("\nSTOPPING: %d attempts for %d valid samples — the method is not converging\n",
				attempt-1, len(valid))
			break
		}

		s := rsample{N: len(valid) + 1}

		nonce, err := hexU64(ctx, "eth_getTransactionCount", "0x"+hex.EncodeToString(addr), "latest")
		if err != nil {
			fmt.Println("nonce read failed:", err)
			break
		}
		s.Nonce = nonce

		bn, base, err := headAndBase(ctx)
		if err != nil {
			fmt.Println("head read failed:", err)
			break
		}

		// Original: 50% of base. Arithmetically unmineable now, and cannot
		// become mineable within one block (EIP-1559 caps the drop at 12.5%).
		origMaxFee := new(big.Int).Div(base, big.NewInt(2))
		origTip := big.NewInt(1)
		s.BaseFeeWei, s.OrigMaxFeeWei, s.OrigTipWei = base.String(), origMaxFee.String(), origTip.String()

		if origMaxFee.Cmp(base) >= 0 { // guard the stuck precondition itself
			s.Discard = "precondition: maxFee not below base fee"
			discarded = append(discarded, s)
			continue
		}

		ot := tx{nonce: nonce, maxPriority: origTip, maxFee: origMaxFee,
			to: addr, value: big.NewInt(0)}
		oraw, ohash := ot.sign(priv)
		s.OrigHash = ohash

		s.SubmitBlock = bn
		s.SubmitTime = blockTime(ctx, bn)
		if _, err := rpc(ctx, "eth_sendRawTransaction", "0x"+hex.EncodeToString(oraw)); err != nil {
			s.Discard = fmt.Sprintf("rpc rejected the original: %v", err)
			discarded = append(discarded, s)
			fmt.Printf("  attempt %d DISCARD — %s\n", attempt, s.Discard)
			continue
		}

		// Trigger: ONE block produced after submission without inclusion.
		for {
			head, _ := hexU64(ctx, "eth_blockNumber")
			if head >= bn+1 {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if found, blk, _, _ := receiptOf(ctx, ohash); found {
			s.Discard = fmt.Sprintf("original mined at block %d before replacement (base fee fell)", blk)
			s.OrigUnmined = false
			discarded = append(discarded, s)
			fmt.Printf("  attempt %d DISCARD — %s\n", attempt, s.Discard)
			continue
		}

		// Replacement, priced to confirm.
		_, baseNow, err := headAndBase(ctx)
		if err != nil {
			s.Discard = "head read failed before replacement"
			discarded = append(discarded, s)
			continue
		}
		replTip := big.NewInt(replTipWei)
		replMaxFee := new(big.Int).Add(new(big.Int).Mul(baseNow, big.NewInt(2)), replTip)
		s.ReplMaxFeeWei, s.ReplTipWei = replMaxFee.String(), replTip.String()

		// All three replacement constraints, checked not assumed.
		minFee := new(big.Int).Div(new(big.Int).Mul(origMaxFee, big.NewInt(11)), big.NewInt(10))
		minTip := new(big.Int).Div(new(big.Int).Mul(origTip, big.NewInt(11)), big.NewInt(10))
		if replMaxFee.Cmp(minFee) < 0 || replTip.Cmp(minTip) < 0 || replMaxFee.Cmp(baseNow) <= 0 {
			s.Discard = "replacement fee failed a constraint check"
			discarded = append(discarded, s)
			continue
		}

		projected := new(big.Int).Mul(replMaxFee, big.NewInt(gasLimit))
		if new(big.Int).Add(spent, projected).Cmp(big.NewInt(campaignCap)) > 0 {
			fmt.Printf("\nSTOPPING at attempt %d: next replacement would cross the spend ceiling\n", attempt)
			break
		}

		rt := tx{nonce: nonce, maxPriority: replTip, maxFee: replMaxFee,
			to: addr, value: big.NewInt(0)}
		rraw, rhash := rt.sign(priv)
		s.ReplHash = rhash
		if _, err := rpc(ctx, "eth_sendRawTransaction", "0x"+hex.EncodeToString(rraw)); err != nil {
			s.Discard = fmt.Sprintf("replacement rejected: %v", err)
			discarded = append(discarded, s)
			fmt.Printf("  attempt %d DISCARD — %s\n", attempt, s.Discard)
			continue
		}

		deadline := time.Now().Add(10 * time.Minute)
		var found bool
		var gasPaid *big.Int
		for time.Now().Before(deadline) {
			var blk uint64
			var st string
			found, blk, st, gasPaid = receiptOf(ctx, rhash)
			if found {
				s.ReplBlock, s.ReplStatus = blk, st
				s.ReplTime = blockTime(ctx, blk)
				break
			}
			time.Sleep(3 * time.Second)
		}
		if !found {
			s.Discard = "replacement not included within 10m"
			discarded = append(discarded, s)
			fmt.Printf("  attempt %d DISCARD — %s\n", attempt, s.Discard)
			continue
		}
		if s.ReplStatus != "0x1" {
			s.Discard = "replacement reverted (status " + s.ReplStatus + ")"
			discarded = append(discarded, s)
			continue
		}

		origFound, _, _, _ := receiptOf(ctx, ohash)
		s.OrigUnmined = !origFound
		if origFound {
			s.Discard = "original obtained a receipt — no repricing occurred"
			discarded = append(discarded, s)
			continue
		}

		newNonce, _ := hexU64(ctx, "eth_getTransactionCount", "0x"+hex.EncodeToString(addr), "latest")
		s.NonceAdvanced = newNonce == nonce+1
		if !s.NonceAdvanced {
			s.Discard = fmt.Sprintf("nonce advanced %d -> %d, expected +1", nonce, newNonce)
			discarded = append(discarded, s)
			continue
		}

		spent.Add(spent, gasPaid)
		s.GasPaidWei = gasPaid.String()
		s.RecoverySec = float64(s.ReplTime - s.SubmitTime)
		s.Valid = true
		valid = append(valid, s)

		fmt.Printf("  %2d/%d  orig %s  repl %s  block %d  recovery %.0fs  paid %.9f ETH\n",
			len(valid), targetSamples, ohash[:12], rhash[:12], s.ReplBlock,
			s.RecoverySec, float64(gasPaid.Int64())/1e18)
	}

	var ds []float64
	for _, v := range valid {
		ds = append(ds, v.RecoverySec)
	}
	sort.Float64s(ds)
	pct := func(p float64) float64 {
		if len(ds) == 0 {
			return 0
		}
		return ds[int(p*float64(len(ds)-1))]
	}

	fmt.Printf("\n=== CAMPAIGN COMPLETE ===\n")
	fmt.Printf("attempts %d   valid %d   discarded %d\n", attempt, len(valid), len(discarded))
	if len(ds) > 0 {
		fmt.Printf("recovery: min=%.0fs median=%.0fs p95=%.0fs max=%.0fs\n",
			ds[0], pct(0.5), pct(0.95), ds[len(ds)-1])
	}
	fmt.Printf("total spent %.9f ETH\n", float64(spent.Int64())/1e18)
	if len(discarded) > 0 {
		fmt.Printf("\ndiscards by reason:\n")
		counts := map[string]int{}
		for _, d := range discarded {
			counts[d.Discard]++
		}
		for r, c := range counts {
			fmt.Printf("  %2d  %s\n", c, r)
		}
	}

	out, _ := json.MarshalIndent(map[string]any{
		"chain_id": chainID, "account": "0x" + hex.EncodeToString(addr),
		"endpoint_provider": "alchemy", "gas_limit": gasLimit,
		"protocol":          "doc/p12-8-repricing-protocol.md",
		"stuck_definition":  "maxFeePerGas below base fee at submission",
		"replacement_trigger": "one block produced without inclusion",
		"limitation": "measures recovery from an arithmetically unmineable transaction " +
			"under the observed mainnet conditions; does NOT establish replacement " +
			"behaviour during sustained fee-market congestion",
		"valid_samples": valid, "discarded_samples": discarded,
		"attempts": attempt, "total_spent_wei": spent.String(),
	}, "", "  ")
	os.WriteFile(os.Getenv("OUT"), out, 0o644)
	fmt.Println("\nprovenance written to", os.Getenv("OUT"))
}
