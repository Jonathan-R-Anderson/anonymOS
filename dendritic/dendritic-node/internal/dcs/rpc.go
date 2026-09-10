package dcs

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ProtocolID is the libp2p stream protocol DCS speaks, alongside the existing
// storage protocol on the same host.
const ProtocolID = "/syndichan/dcs/1.0.0"

// Every DCS request is wrapped in a signed envelope. Transport is already
// Noise-encrypted over I2P; the signature is ADDITIONAL and authenticates the
// request itself, so a compromised transport cannot forge an operation and the
// audit-log entry is independently verifiable against the sender's key. This is
// the same discipline the gateway protocol already applies to registrations.
type Envelope struct {
	Version   int             `json:"version"`
	Operation string          `json:"operation_id"` // client-chosen UUIDv7; idempotency key
	Method    string          `json:"method"`
	FromNode  string          `json:"from_node"`
	FromKey   string          `json:"from_key"` // base64 pubkey, must hash to FromNode
	ToNode    string          `json:"to_node"`  // an envelope for another node is never executed
	IssuedAt  int64           `json:"issued_at"`
	ExpiresAt int64           `json:"expires_at"`
	Nonce     string          `json:"nonce"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// Methods. Kept as constants so a typo is a compile error, not a silent 404.
const (
	MethodPing    = "ping"
	MethodReserve = "reserve"
	MethodLaunch  = "launch"
	MethodStatus  = "status"
	MethodDestroy = "destroy"
)

// EnvelopeSigner is the local node identity. *gateway.FileIdentity and
// *p2p.Node both already satisfy ID/Sign/PublicKey; DCS reuses that signer
// rather than minting a second identity.
type EnvelopeSigner interface {
	ID() string
	Sign([]byte) ([]byte, error)
	PublicKey() ([]byte, error)
}

// MaxEnvelopeSkew bounds both clock skew and the replay-cache retention. Short,
// because I2P round trips are slow but not minutes-slow, and a small window
// keeps the nonce table small.
const MaxEnvelopeSkew = 120 * time.Second

// signedBody is the exact byte sequence covered by the signature: the envelope
// with the signature field cleared. Signing a canonical projection rather than
// the whole wire message means an intermediary cannot append fields.
func (e Envelope) signedBody() ([]byte, error) {
	unsigned := e
	unsigned.Signature = ""
	return json.Marshal(unsigned)
}

// NewEnvelope builds and signs a request.
func NewEnvelope(signer EnvelopeSigner, toNode, method string, payload any, now time.Time) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	key, err := signer.PublicKey()
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	env := Envelope{
		Version:   1,
		Operation: newOperationID(now, nonce),
		Method:    method,
		FromNode:  signer.ID(),
		FromKey:   base64.RawStdEncoding.EncodeToString(key),
		ToNode:    toNode,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(MaxEnvelopeSkew).Unix(),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		Payload:   raw,
	}
	body, err := env.signedBody()
	if err != nil {
		return Envelope{}, err
	}
	signature, err := signer.Sign(body)
	if err != nil {
		return Envelope{}, err
	}
	env.Signature = base64.RawStdEncoding.EncodeToString(signature)
	return env, nil
}

// newOperationID is a sortable-ish id: millisecond timestamp plus nonce. Not a
// true UUIDv7 (this binary avoids Math.random/time-of-day in some paths), but
// unique and monotone enough to be a good idempotency key.
func newOperationID(now time.Time, nonce []byte) string {
	return fmt.Sprintf("%013d-%s", now.UnixMilli(), base64.RawURLEncoding.EncodeToString(nonce[:8]))
}

var (
	ErrEnvelopeVersion   = errors.New("dcs: unsupported envelope version")
	ErrEnvelopeAudience  = errors.New("dcs: envelope addressed to another node")
	ErrEnvelopeExpired   = errors.New("dcs: envelope expired or from the future")
	ErrEnvelopeReplay    = errors.New("dcs: envelope nonce already seen")
	ErrEnvelopeSignature = errors.New("dcs: envelope signature invalid")
	ErrEnvelopeIdentity  = errors.New("dcs: envelope key does not match node id")
)

// Verify authenticates an inbound envelope against selfNodeID. The order is
// deliberate: cheap structural checks first, signature (the expensive one)
// last, and replay only after the signature proves the sender, so a flood of
// forged envelopes cannot fill the nonce table.
func (e Envelope) Verify(selfNodeID string, now time.Time, replay ReplayGuard) error {
	if e.Version != 1 {
		return ErrEnvelopeVersion
	}
	if e.ToNode != selfNodeID {
		return ErrEnvelopeAudience
	}
	if e.ExpiresAt <= now.Unix() || e.IssuedAt > now.Add(MaxEnvelopeSkew).Unix() {
		return ErrEnvelopeExpired
	}

	rawKey, err := base64.RawStdEncoding.DecodeString(e.FromKey)
	if err != nil {
		return ErrEnvelopeSignature
	}
	key, err := crypto.UnmarshalPublicKey(rawKey)
	if err != nil {
		return ErrEnvelopeSignature
	}
	// The key must actually be the sender's claimed identity; otherwise a valid
	// signature by SOME key would pass as the wrong node.
	id, err := peer.IDFromPublicKey(key)
	if err != nil || id.String() != e.FromNode {
		return ErrEnvelopeIdentity
	}

	body, err := e.signedBody()
	if err != nil {
		return err
	}
	rawSig, err := base64.RawStdEncoding.DecodeString(e.Signature)
	if err != nil {
		return ErrEnvelopeSignature
	}
	ok, err := key.Verify(body, rawSig)
	if err != nil || !ok {
		return ErrEnvelopeSignature
	}

	if replay != nil && !replay.Accept(e.Nonce, time.Unix(e.ExpiresAt, 0)) {
		return ErrEnvelopeReplay
	}
	return nil
}

// Bind decodes the payload into v.
func (e Envelope) Bind(v any) error { return json.Unmarshal(e.Payload, v) }

// ReplayGuard remembers nonces until they expire. Accept returns false if the
// nonce was already seen.
type ReplayGuard interface {
	Accept(nonce string, expires time.Time) bool
}
