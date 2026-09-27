package ethproof

// Authenticated transaction receipts — roadmap P14.5.
//
// THE TRUST STATEMENT
// ------------------
// eth_getBlockReceipts is an UNTRUSTED data source and is treated as one. Every
// receipt is decoded here, re-encoded here, and assembled into a trie here; the
// only thing that makes any of it believable is that the resulting root equals a
// receiptsRoot the P12 chain authenticated:
//
//	finalised beacon header -> execution_branch -> ExecutionPayloadHeader
//	                                                     │ ReceiptsRoot
//	                                                     ▼
//	  eth_getBlockReceipts ---> decode ---> encode ---> MPT ---> root
//	                                                             │
//	                                          MUST EQUAL <───────┘
//
// A provider can therefore refuse, stall, or lie in a way that fails. What it
// cannot do is add a receipt, remove one, alter a log, or renumber an index and
// still match — every one of those changes the root.
//
// OMISSION IS THE POINT
// ---------------------
// The reason this exists rather than a call to eth_getLogs: a provider that
// simply LEAVES OUT the CloseStarted for the channel it wants stolen makes a
// log-subscribing watchtower blind, and leaves no trace at all. There is no
// proof of absence to check. Rebuilding the whole trie turns omission into a
// root mismatch, which is a refusal rather than a silence.
//
// WHAT A MISMATCH MEANS
// ---------------------
// "We cannot see", never "there is nothing there". A receipts mismatch says the
// provider's data is unusable, which is a completely different fact from the
// chain proving a channel absent, and conflating the two is how a watchtower
// concludes it is safe to stop watching.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrReceiptsRootMismatch means the rebuilt trie does not equal the
	// authenticated receiptsRoot. Fail closed: the receipts must not be used.
	ErrReceiptsRootMismatch = errors.New("ethproof: rebuilt receipts root does not match the authenticated receiptsRoot")
	// ErrReceiptMalformed means a receipt could not be decoded into a form that
	// can be encoded canonically.
	ErrReceiptMalformed = errors.New("ethproof: receipt is malformed")
)

// Log is one event record inside a receipt.
type Log struct {
	Address [20]byte
	Topics  [][32]byte
	Data    []byte
}

// Receipt is one transaction receipt, in the form the receipts trie stores.
type Receipt struct {
	// TxIndex is the DECLARED transaction index. It is the trie key, so the
	// order receipts arrive in is irrelevant and a renumbering is fatal.
	TxIndex uint64
	// Type is the EIP-2718 transaction type. 0 is legacy and carries no prefix.
	Type uint64

	// Exactly one of these is meaningful. Post-Byzantium blocks use Status;
	// older ones carry a 32-byte intermediate state root.
	Status    uint64
	PostState []byte

	CumulativeGasUsed uint64
	Bloom             [256]byte
	Logs              []Log
}

// Encode produces the exact bytes the receipts trie stores for this receipt.
//
// Legacy receipts are the bare RLP list. EIP-2718 typed receipts are the type
// byte PREPENDED to that list — not wrapped in it and not an RLP string
// containing it, both of which produce a plausible-looking wrong root.
func (r Receipt) Encode() ([]byte, error) {
	if r.Type > 0xFF {
		return nil, fmt.Errorf("%w: transaction type %d does not fit in one byte",
			ErrReceiptMalformed, r.Type)
	}
	if len(r.PostState) != 0 && len(r.PostState) != 32 {
		return nil, fmt.Errorf("%w: post-state root is %d bytes",
			ErrReceiptMalformed, len(r.PostState))
	}
	if len(r.PostState) == 0 && r.Status > 1 {
		return nil, fmt.Errorf("%w: status is %d", ErrReceiptMalformed, r.Status)
	}

	logs := make([][]byte, 0, len(r.Logs))
	for _, l := range r.Logs {
		topics := make([][]byte, 0, len(l.Topics))
		for i := range l.Topics {
			topics = append(topics, EncodeRLPBytes(l.Topics[i][:]))
		}
		addr := l.Address
		logs = append(logs, EncodeRLPList(
			EncodeRLPBytes(addr[:]),
			EncodeRLPList(topics...),
			EncodeRLPBytes(l.Data),
		))
	}

	first := EncodeRLPUint(r.Status)
	if len(r.PostState) == 32 {
		first = EncodeRLPBytes(r.PostState)
	}
	bloom := r.Bloom
	body := EncodeRLPList(
		first,
		EncodeRLPUint(r.CumulativeGasUsed),
		EncodeRLPBytes(bloom[:]),
		EncodeRLPList(logs...),
	)
	if r.Type == 0 {
		return body, nil
	}
	return append([]byte{byte(r.Type)}, body...), nil
}

// ReceiptsRoot rebuilds the receipts trie and returns its root.
//
// The key is RLP(transactionIndex), used RAW — the receipts trie is not a secure
// trie and hashing the key would produce a root matching nothing.
func ReceiptsRoot(receipts []Receipt) ([]byte, error) {
	entries := make([]TrieEntry, 0, len(receipts))
	seen := make(map[uint64]struct{}, len(receipts))
	for i, r := range receipts {
		if _, dup := seen[r.TxIndex]; dup {
			return nil, fmt.Errorf("%w: two receipts claim transaction index %d",
				ErrReceiptMalformed, r.TxIndex)
		}
		seen[r.TxIndex] = struct{}{}
		value, err := r.Encode()
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i, err)
		}
		entries = append(entries, TrieEntry{Key: EncodeRLPUint(r.TxIndex), Value: value})
	}
	return BuildMPT(entries), nil
}

// AuthenticateReceipts is the gate. It returns the receipts only if they rebuild
// to the authenticated root, and an error otherwise.
//
// Deliberately NOT a boolean and NOT a comparison helper. A caller cannot ask
// "do these match" and then decide what to do about it, because that is a check
// a refactor can drop while everything downstream keeps working — the same
// reasoning AuthenticatedStateRoot is built on. The only way to obtain usable
// receipts is to have supplied the authenticated root.
func AuthenticateReceipts(authenticated Root, receipts []Receipt) ([]Receipt, error) {
	got, err := ReceiptsRoot(receipts)
	if err != nil {
		return nil, err
	}
	if len(got) != 32 || string(got) != string(authenticated[:]) {
		return nil, fmt.Errorf("%w: rebuilt %x, authenticated %x, %d receipts",
			ErrReceiptsRootMismatch, got, authenticated[:], len(receipts))
	}
	return receipts, nil
}

// ---- decoding the provider's JSON ------------------------------------------

// rpcReceipt is eth_getBlockReceipts' shape. Everything is a quantity string.
type rpcReceipt struct {
	Type             string `json:"type"`
	Status           string `json:"status"`
	Root             string `json:"root"`
	CumulativeGas    string `json:"cumulativeGasUsed"`
	LogsBloom        string `json:"logsBloom"`
	TransactionIndex string `json:"transactionIndex"`
	Logs             []struct {
		Address string   `json:"address"`
		Topics  []string `json:"topics"`
		Data    string   `json:"data"`
	} `json:"logs"`
}

// DecodeRPCReceipts parses eth_getBlockReceipts' result.
//
// Strict on every field. A receipt that cannot be decoded is refused rather than
// skipped: skipping one would silently produce a trie missing an entry, which is
// indistinguishable from the omission attack this whole file exists to catch.
func DecodeRPCReceipts(raw []byte) ([]Receipt, error) {
	var in []rpcReceipt
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReceiptMalformed, err)
	}
	out := make([]Receipt, 0, len(in))
	for i, r := range in {
		var rec Receipt
		var err error
		if rec.TxIndex, err = hexQuantity(r.TransactionIndex); err != nil {
			return nil, fmt.Errorf("receipt %d transactionIndex: %w", i, err)
		}
		if r.Type != "" {
			if rec.Type, err = hexQuantity(r.Type); err != nil {
				return nil, fmt.Errorf("receipt %d type: %w", i, err)
			}
		}
		if rec.CumulativeGasUsed, err = hexQuantity(r.CumulativeGas); err != nil {
			return nil, fmt.Errorf("receipt %d cumulativeGasUsed: %w", i, err)
		}
		if r.Root != "" {
			if rec.PostState, err = hexData(r.Root, 32); err != nil {
				return nil, fmt.Errorf("receipt %d root: %w", i, err)
			}
		} else {
			if rec.Status, err = hexQuantity(r.Status); err != nil {
				return nil, fmt.Errorf("receipt %d status: %w", i, err)
			}
		}
		bloom, err := hexData(r.LogsBloom, 256)
		if err != nil {
			return nil, fmt.Errorf("receipt %d logsBloom: %w", i, err)
		}
		copy(rec.Bloom[:], bloom)

		for j, l := range r.Logs {
			var lg Log
			addr, err := hexData(l.Address, 20)
			if err != nil {
				return nil, fmt.Errorf("receipt %d log %d address: %w", i, j, err)
			}
			copy(lg.Address[:], addr)
			for k, tp := range l.Topics {
				t, err := hexData(tp, 32)
				if err != nil {
					return nil, fmt.Errorf("receipt %d log %d topic %d: %w", i, j, k, err)
				}
				var topic [32]byte
				copy(topic[:], t)
				lg.Topics = append(lg.Topics, topic)
			}
			if lg.Data, err = hexData(l.Data, -1); err != nil {
				return nil, fmt.Errorf("receipt %d log %d data: %w", i, j, err)
			}
			rec.Logs = append(rec.Logs, lg)
		}
		out = append(out, rec)
	}
	return out, nil
}

// hexQuantity parses a JSON-RPC QUANTITY.
func hexQuantity(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: empty quantity", ErrReceiptMalformed)
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: quantity %q: %v", ErrReceiptMalformed, s, err)
	}
	return v, nil
}

// hexData parses a JSON-RPC DATA field. wantLen of -1 accepts any length.
func hexData(s string, wantLen int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("%w: data %q: %v", ErrReceiptMalformed, s, err)
	}
	if wantLen >= 0 && len(b) != wantLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d",
			ErrReceiptMalformed, wantLen, len(b))
	}
	return b, nil
}
