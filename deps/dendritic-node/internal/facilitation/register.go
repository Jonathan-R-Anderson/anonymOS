package facilitation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

// Self-service registration.
//
// The node signs its registration twice, and the second signature is not
// ceremony.
//
//	secp256k1 (wallet)  — verified ON-CHAIN by NodeRegistry.registerWithSig.
//	                      Proves who gets paid.
//	ed25519   (p2p key) — verified by the site before queueing.
//	                      Proves the node consented to that payout address.
//
// The second exists because a node's p2p public key is its libp2p peer id:
// public, broadcast, trivially observed. NodeRegistry registers whoever asks
// first and has no way to check that the caller holds the p2p private key, so
// without this proof anyone could bind a stranger's node to their own wallet
// and collect its earnings. The proof closes that on the path the site
// controls; the contract itself remains open to a direct call, which is a
// contract-level issue and not something the node can fix.

// ZeroCommitment is the endpoint commitment for a node reachable only over
// I2P: there is no endpoint worth committing to that would not also say where
// the machine is, which is the thing I2P exists to hide.
const ZeroCommitment = "0x" + "0000000000000000000000000000000000000000000000000000000000000000"

// SelfRegistration is the registration a node files for itself.
//
// It carries no secp256k1 signature, and cannot: the node holds an ed25519
// identity, not a wallet key, and putting a wallet key on a rented server to
// register it would trade the whole point of the payout declaration for a
// convenience. What it does carry is proof that this p2p key consented to this
// payout address, which is the part only the node can supply. Turning that into
// an on-chain record is the wallet owner's job, and costs them gas.
func SelfRegistration(pub ed25519.PublicKey, priv ed25519.PrivateKey,
	wallet string, capabilities uint64, nonce uint64) RegistrationRequest {
	return RegistrationRequest{
		P2PPublicKey:       hex.EncodeToString(pub),
		Wallet:             strings.ToLower(wallet),
		Capabilities:       capabilities,
		EndpointCommitment: ZeroCommitment,
		Nonce:              nonce,
		P2PProof: P2PRegistrationProof(priv, wallet, capabilities, ZeroCommitment,
			new(big.Int).SetUint64(nonce)),
	}
}

// P2PRegistrationProof signs the wallet binding with the node's p2p key. The
// message must match the site's proof_message byte for byte.
func P2PRegistrationProof(priv ed25519.PrivateKey, wallet string, capabilities uint64,
	endpointCommitment string, nonce *big.Int) string {
	n := "0"
	if nonce != nil {
		n = nonce.String()
	}
	msg := strings.Join([]string{
		"syndichan-pof-register:v1",
		strings.ToLower(wallet),
		strconv.FormatUint(capabilities, 10),
		strings.ToLower(endpointCommitment),
		n,
	}, "\n")
	return hex.EncodeToString(ed25519.Sign(priv, []byte(msg)))
}

// RegistrationRequest is what the site's /api/v1/pof/register accepts.
type RegistrationRequest struct {
	P2PPublicKey       string `json:"p2p_public_key"`
	Wallet             string `json:"wallet"`
	Capabilities       uint64 `json:"capabilities"`
	EndpointCommitment string `json:"endpoint_commitment"`
	Nonce              uint64 `json:"nonce"`
	V                  uint8  `json:"v"`
	R                  string `json:"r"`
	S                  string `json:"s"`
	P2PProof           string `json:"p2p_proof"`
}

type registrationResponse struct {
	OK                bool   `json:"ok"`
	Status            string `json:"status"`
	TxHash            string `json:"tx_hash"`
	AlreadyRegistered bool   `json:"already_registered"`
	Error             string `json:"error"`
}

// BuildRegistrationRequest turns a signed intent plus a p2p proof into the
// request body.
func BuildRegistrationRequest(intent RegisterIntent, p2pPriv ed25519.PrivateKey) (RegistrationRequest, error) {
	nonce, err := strconv.ParseUint(intent.Nonce, 10, 64)
	if err != nil {
		return RegistrationRequest{}, fmt.Errorf("facilitation: bad nonce %q: %w", intent.Nonce, err)
	}
	return RegistrationRequest{
		P2PPublicKey:       intent.P2PPublicKey,
		Wallet:             strings.ToLower(intent.Owner),
		Capabilities:       intent.Capabilities,
		EndpointCommitment: intent.EndpointCommitment,
		Nonce:              nonce,
		V:                  intent.V,
		R:                  intent.R,
		S:                  intent.S,
		P2PProof: P2PRegistrationProof(p2pPriv, intent.Owner, intent.Capabilities,
			intent.EndpointCommitment, new(big.Int).SetUint64(nonce)),
	}, nil
}

// Register queues this node for on-chain registration. Idempotent: a node that
// re-registers after a restart gets its existing status back rather than an
// error, so registration can simply run at every startup.
func (c *GatewayClient) Register(ctx context.Context, req RegistrationRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	url := strings.TrimSuffix(c.BaseURL, "/") + "/api/v1/pof/register"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("facilitation: registration endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out registrationResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 || out.Error != "" {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", fmt.Errorf("facilitation: registration refused: %s", msg)
	}
	if out.Status == "" {
		out.Status = "pending"
	}
	return out.Status, nil
}
