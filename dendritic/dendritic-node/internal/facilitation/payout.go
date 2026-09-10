package facilitation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Where a node's earnings go.
//
// The operator types an address into the node dashboard; the node signs that
// choice with its p2p key and publishes it. The aggregator pays whatever the
// node declared, so the operator can use a wallet they already control instead
// of having to extract a key the node generated.
//
// The signature is what makes this safe to accept from anywhere. Without it,
// anyone could publish "node X pays me" and redirect a stranger's earnings; the
// declaration is only honoured if it was signed by the node's own identity key.
// The address is inside the signed bytes for the same reason a wallet is inside
// the registration proof — otherwise a captured signature could be re-pointed.
//
// Sequence exists so a later declaration wins deterministically. A node that
// changes its payout address must not have the outcome depend on which message
// happened to arrive last.

// PayoutDeclarationPrefix versions the signed format.
const PayoutDeclarationPrefix = "syndichan-pof-payout:v1"

// PayoutDeclaration is a node's signed statement of where to send its rewards.
type PayoutDeclaration struct {
	P2PPublicKey string `json:"p2p_public_key"` // hex, 32-byte ed25519
	Payout       string `json:"payout"`         // 0x address
	Sequence     uint64 `json:"sequence"`       // higher wins
	Signature    string `json:"signature"`      // hex ed25519 over the message below
}

// PayoutMessage is the exact text signed. Kept as a function so the node and
// the site cannot drift apart on whitespace or ordering.
func PayoutMessage(payout string, sequence uint64) []byte {
	return []byte(strings.Join([]string{
		PayoutDeclarationPrefix,
		strings.ToLower(strings.TrimSpace(payout)),
		strconv.FormatUint(sequence, 10),
	}, "\n"))
}

// DeclarePayout builds and signs a declaration.
func DeclarePayout(pub ed25519.PublicKey, priv ed25519.PrivateKey, payout string, sequence uint64) PayoutDeclaration {
	return PayoutDeclaration{
		P2PPublicKey: hex.EncodeToString(pub),
		Payout:       strings.ToLower(strings.TrimSpace(payout)),
		Sequence:     sequence,
		Signature:    hex.EncodeToString(ed25519.Sign(priv, PayoutMessage(payout, sequence))),
	}
}

// VerifyPayoutDeclaration checks a declaration really came from that node.
func VerifyPayoutDeclaration(d PayoutDeclaration) bool {
	pub, err := hex.DecodeString(strings.TrimPrefix(d.P2PPublicKey, "0x"))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(d.Signature, "0x"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), PayoutMessage(d.Payout, d.Sequence), sig)
}

// PublishPayout sends the declaration to the site so the aggregator can read it.
func (c *GatewayClient) PublishPayout(ctx context.Context, d PayoutDeclaration) error {
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}
	url := strings.TrimSuffix(c.BaseURL, "/") + "/api/v1/pof/payout"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("facilitation: payout endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 || out.Error != "" {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("facilitation: payout rejected: %s", msg)
	}
	return nil
}
