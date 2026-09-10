// Package facilitation is the storage-client's lightweight Proof-of-Facilitation
// client. The node never runs a chain, holds no ETH, and encodes no Ethereum
// transactions: it holds a secp256k1 wallet key, signs a registration digest
// that the website's NodeRegistry contract can recover the owner from
// (registerWithSig), and POSTs the signed intent to the website's chain gateway,
// which submits it via a paymaster. Keeping the chain surface this small is the
// whole point -- the node just signs and sends.
package facilitation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Capability bits — MUST match NodeRegistry.sol.
const (
	CapDHT              uint64 = 1 << 0
	CapGateway          uint64 = 1 << 1
	CapStorage          uint64 = 1 << 2
	CapLoadBalance      uint64 = 1 << 3
	CapDockerWorker     uint64 = 1 << 4
	CapDockerController uint64 = 1 << 5
	CapWitness          uint64 = 1 << 6
)

// registerTypehash mirrors NodeRegistry.REGISTER_TYPEHASH.
var registerTypehash = keccak256([]byte(
	"Register(uint256 chainId,address registry,bytes32 p2pKeyHash,uint256 capabilities,bytes32 endpointCommitment,uint256 nonce)",
))

func keccak256(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func left32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func u256(n *big.Int) []byte { return left32(n.Bytes()) }

// Wallet is the node's secp256k1 key — its Ethereum account that owns rewards.
type Wallet struct{ priv *secp256k1.PrivateKey }

// LoadOrCreateWallet reads a hex-encoded 32-byte key from path, or generates and
// persists one (0600). This is the only secret the lightweight node needs.
func LoadOrCreateWallet(path string) (*Wallet, error) {
	if raw, err := os.ReadFile(path); err == nil {
		decoded, derr := hex.DecodeString(string(bytes.TrimSpace(raw)))
		if derr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("facilitation: malformed wallet key at %s", path)
		}
		return &Wallet{priv: secp256k1.PrivKeyFromBytes(decoded)}, nil
	}
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Serialize())), 0o600); err != nil {
		return nil, err
	}
	return &Wallet{priv: priv}, nil
}

// Address is the Ethereum/Ethereum address: keccak256(uncompressedPubKey[1:])[12:].
func (w *Wallet) Address() [20]byte {
	pub := w.priv.PubKey().SerializeUncompressed() // 65 bytes, 0x04 || X || Y
	h := keccak256(pub[1:])
	var a [20]byte
	copy(a[:], h[12:])
	return a
}

func (w *Wallet) AddressHex() string {
	a := w.Address()
	return "0x" + hex.EncodeToString(a[:])
}

// NodeID is keccak256(ed25519 p2p public key) — matches nodeId on-chain.
func NodeID(p2pPub ed25519.PublicKey) [32]byte {
	var id [32]byte
	copy(id[:], keccak256([]byte(p2pPub)))
	return id
}

// EndpointCommitment hides the node's reachable endpoint on-chain: only an
// authorized challenger given (endpoint, secret, epoch) can reproduce it.
func EndpointCommitment(endpoint, secret string, epoch uint64) [32]byte {
	var c [32]byte
	copy(c[:], keccak256([]byte(endpoint), []byte(secret), u256(new(big.Int).SetUint64(epoch))))
	return c
}

// RegistrationDigest reproduces NodeRegistry.registrationDigest(...): the
// keccak256 of the abi.encode of the seven 32-byte fields.
func RegistrationDigest(chainID *big.Int, registry [20]byte, p2pPub ed25519.PublicKey,
	capabilities uint64, endpointCommitment [32]byte, nonce *big.Int) [32]byte {
	pre := make([]byte, 0, 7*32)
	pre = append(pre, registerTypehash...)
	pre = append(pre, u256(chainID)...)
	pre = append(pre, left32(registry[:])...)
	pre = append(pre, keccak256([]byte(p2pPub))...)
	pre = append(pre, u256(new(big.Int).SetUint64(capabilities))...)
	pre = append(pre, endpointCommitment[:]...)
	pre = append(pre, u256(nonce)...)
	var d [32]byte
	copy(d[:], keccak256(pre))
	return d
}

// SignDigest returns an Ethereum-style recoverable signature (v ∈ {27,28}, r, s,
// canonical low-s) over a 32-byte digest, compatible with Solidity ecrecover.
// ChannelSeed derives the seed for the node's payment-channel signing key.
//
// The raw wallet key NEVER leaves this type. A domain-separated hash of it goes
// out instead, so the channel package can derive its own hot key without ever
// holding the key that owns this node's rewards.
//
// That separation is the point: a routing node must sign unattended, so its
// channel key is hot by necessity. Handing out the payout key to do that would
// make a routing compromise a total one — the operator would lose not just what
// is committed to channels but everything the node has earned.
//
// One-way by construction: the channel seed cannot be walked back to the wallet
// key, so a leaked channel key exposes channel funds and nothing else.
func (w *Wallet) ChannelSeed() [32]byte {
	mac := hmac.New(sha256.New, []byte("syndichan/wallet/channel-seed/v1"))
	mac.Write(w.priv.Serialize())
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (w *Wallet) SignDigest(digest [32]byte) (v uint8, r [32]byte, s [32]byte) {
	sig := ecdsa.SignCompact(w.priv, digest[:], false) // [v||r||s], v = 27+recid
	v = sig[0]
	copy(r[:], sig[1:33])
	copy(s[:], sig[33:65])
	return
}

// RegisterIntent is the JSON body the node POSTs to the website chain gateway.
// The gateway submits registerWithSig(...) via its paymaster; owner is recovered
// on-chain from (v,r,s), so the gateway is never trusted to name the owner.
type RegisterIntent struct {
	P2PPublicKey       string `json:"p2p_public_key"`      // hex (ed25519, 32 bytes)
	Capabilities       uint64 `json:"capabilities"`        // bitmap
	EndpointCommitment string `json:"endpoint_commitment"` // 0x + 32 bytes
	Nonce              string `json:"nonce"`               // decimal
	Owner              string `json:"owner"`               // 0x address (advisory)
	V                  uint8  `json:"v"`
	R                  string `json:"r"` // 0x + 32 bytes
	S                  string `json:"s"` // 0x + 32 bytes
}

// BuildRegisterIntent assembles + signs a registration intent for this node.
func (w *Wallet) BuildRegisterIntent(chainID *big.Int, registry [20]byte, p2pPub ed25519.PublicKey,
	capabilities uint64, endpointCommitment [32]byte, nonce *big.Int) RegisterIntent {
	digest := RegistrationDigest(chainID, registry, p2pPub, capabilities, endpointCommitment, nonce)
	v, r, s := w.SignDigest(digest)
	return RegisterIntent{
		P2PPublicKey:       hex.EncodeToString([]byte(p2pPub)),
		Capabilities:       capabilities,
		EndpointCommitment: "0x" + hex.EncodeToString(endpointCommitment[:]),
		Nonce:              nonce.String(),
		Owner:              w.AddressHex(),
		V:                  v,
		R:                  "0x" + hex.EncodeToString(r[:]),
		S:                  "0x" + hex.EncodeToString(s[:]),
	}
}

// GatewayClient talks to the website's Proof-of-Facilitation chain gateway.
type GatewayClient struct {
	BaseURL string
	HTTP    *http.Client
}

func NewGatewayClient(baseURL string) *GatewayClient {
	return &GatewayClient{BaseURL: baseURL, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type submitResponse struct {
	TxHash string `json:"tx_hash"`
	NodeID string `json:"node_id"`
	Error  string `json:"error"`
}

// SubmitRegister POSTs the signed intent to the gateway's /pof/register endpoint
// and returns the submitted transaction hash.
func (c *GatewayClient) SubmitRegister(ctx context.Context, intent RegisterIntent) (string, error) {
	body, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	url := c.BaseURL + "/pof/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("facilitation: gateway unreachable: %w", err)
	}
	defer resp.Body.Close()
	var out submitResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 || out.Error != "" {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", fmt.Errorf("facilitation: gateway rejected registration: %s", msg)
	}
	return out.TxHash, nil
}
