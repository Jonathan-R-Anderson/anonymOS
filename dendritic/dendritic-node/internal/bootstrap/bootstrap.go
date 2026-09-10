// Package bootstrap finds a way into the DHT without depending on one host.
//
// A joining node has no peers, so it cannot ask the network anything — that is
// what bootstrap is for. It has to learn two things from somewhere: which peers
// to dial, and which coordinator key to accept for storage leases.
//
// WHY THAT SECOND ONE IS THE DANGEROUS PART
// The two payloads carry very different risk. A bad peer costs a failed dial. A
// bad coordinator key means accepting forged storage leases indefinitely, with
// nothing to notice it. Historically a node read that key OUT of the document
// and trusted it, which meant whoever served the document chose it — fine while
// exactly one host under our own TLS served it, and not fine at all once the
// job is spread across volunteer gateways.
//
// THREE RULES, IN ORDER OF STRENGTH
//
//	key pinned          verify the signature; one good gateway is enough, and a
//	                    hostile one is simply ignored.
//	no key pinned       require agreement across several gateways before
//	                    believing anything. Weaker, and strictly better than
//	                    believing whoever answered first — which is the
//	                    behaviour this replaces.
//	pinned AND polled   disagreement becomes evidence: a gateway that served
//	                    something different from the signed document is
//	                    misbehaving, attributably.
//
// WHY CONSENSUS CANNOT REPLACE THE SIGNATURE
// To ask N parties, a node first needs a trustworthy list of who they are, and
// that list comes from DNS, which one party controls. A quorum over a
// DNS-chosen set is that party choosing the participants and therefore the
// answer. Gateways are volunteer-run, so a majority of them is a majority of
// whoever registered the most — the Sybil problem internal quorum rules already
// address by demanding distinct operators rather than counting signatures.
// Agreement is a useful second layer. It is not a first one.
package bootstrap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MessagePrefix begins the signed message. Must match
// backend/services/storage_coordination.bootstrap_message exactly.
const MessagePrefix = "syndichan-storage-bootstrap-v1"

// DefaultAgreement is how many independent sources must return the same peer
// set and coordinator key when no key is pinned.
const DefaultAgreement = 2

var (
	ErrNoSources    = errors.New("no bootstrap source answered")
	ErrBadSignature = errors.New("bootstrap document signature did not verify")
	ErrWrongKey     = errors.New("bootstrap document is signed by an unexpected coordinator")
	ErrUnsigned     = errors.New("bootstrap document carries no signature")
	ErrExpired      = errors.New("bootstrap document has expired")
	ErrNoAgreement  = errors.New("bootstrap sources did not agree")
	ErrMalformed    = errors.New("bootstrap document is malformed")
)

// Document is the published bootstrap record.

// ComputePeer is one node offering compute, as published in the bootstrap
// document.
//
// Carries what the node OFFERS rather than only how to reach it. A joining node
// that had to dial every peer to ask whether it takes GPU work would spend a
// round trip per peer over I2P to learn something already published — and on a
// network of any size that is the difference between choosing a provider in a
// second and in a minute.
type ComputePeer struct {
	NodeID      string `json:"node_id"`
	Destination string `json:"destination"`
	CPU         bool   `json:"cpu"`
	GPU         bool   `json:"gpu"`
	// MicroVM decides whether ARBITRARY code may be placed here. Published
	// because it decides eligibility, and asking a node about its own isolation
	// would be asking it to vouch for itself.
	MicroVM bool `json:"microvm"`
}

// Reachable reports whether this peer can actually be dialed.
//
// A listing without a destination is not a provider, it is a name. Filtering
// here means a caller never builds a plan around a peer it cannot reach.
func (c ComputePeer) Reachable() bool {
	return c.NodeID != "" && c.Destination != ""
}

// Offers reports whether this peer takes a given kind of work.
//
// `arbitrary` requires a microVM, which is the same rule the site enforces at
// placement. Duplicated here deliberately: a node choosing its own peers must
// not depend on the site having filtered correctly, or a compromised directory
// could place arbitrary code on a container node.
func (c ComputePeer) Offers(device string, arbitrary bool) bool {
	if !c.Reachable() {
		return false
	}
	if arbitrary && !c.MicroVM {
		return false
	}
	if len(device) >= 3 && device[:3] == "gpu" {
		return c.GPU
	}
	return c.CPU
}

// ComputePeers returns the reachable compute peers matching a requirement.
func (d Document) ComputePeers(device string, arbitrary bool) []ComputePeer {
	out := make([]ComputePeer, 0, len(d.Compute))
	for _, peer := range d.Compute {
		if peer.Offers(device, arbitrary) {
			out = append(out, peer)
		}
	}
	return out
}

type Document struct {
	Version int      `json:"version"`
	Peers   []string `json:"peers"`
	// Compute lists nodes currently offering CPU or GPU work, so a joining node
	// learns where compute lives from the same signed document that tells it
	// where storage lives.
	//
	// In the bootstrap document rather than a second service on purpose: a
	// separate compute directory would be another thing to sign, another thing
	// to keep fresh, and another place for the two to disagree about which
	// nodes exist. It is also covered by the SAME signature, so a gateway
	// serving the document cannot add compute peers of its own.
	Compute              []ComputePeer `json:"compute,omitempty"`
	CoordinatorPublicKey string        `json:"coordinator_public_key"`
	ExpiresAt            time.Time     `json:"expires_at"`
	Signature            string        `json:"signature"`
}

// Config is how a node is told to bootstrap.
type Config struct {
	// CoordinatorKey is pinned at download time, base64. Empty means no pin,
	// which falls back to requiring agreement.
	CoordinatorKey string `json:"coordinator_key,omitempty"`
	// SRVName is resolved to discover gateways serving the document, so one
	// host being offline costs nothing — the node tries the next.
	SRVName string `json:"srv_name,omitempty"`
	// URLs are tried as well as anything SRV turns up.
	URLs []string `json:"urls,omitempty"`
	// MinimumAgreement when no key is pinned. Zero means DefaultAgreement.
	MinimumAgreement int `json:"minimum_agreement,omitempty"`
}

// Answer is one source's response.
type Answer struct {
	Source   string
	Document *Document
	Err      error
}

// Result is what a bootstrap round concluded.
type Result struct {
	Document *Document
	// Source that supplied the document being used.
	Source string
	// Verified is true when the signature was checked against a PINNED key.
	// False means the document was accepted on agreement alone, which is
	// weaker and worth saying so.
	Verified bool
	// Agreed is how many sources returned the same peer set and coordinator
	// key, including the one used.
	Agreed int
	// Disagreed names sources that returned something different. With a pinned
	// key these are not merely ignored — a gateway serving something other than
	// the signed document is misbehaving, and attributably so.
	Disagreed []string
	// Unreachable sources, which is ordinary rather than suspicious.
	Unreachable []string
}

// Message rebuilds the exact bytes the coordinator signed.
//
// The peer COUNT is signed before the peers, so a truncated list cannot pass as
// a complete one — dropping peers is how a joining node gets steered toward the
// few somebody controls.
func Message(peers []string, coordinatorKey, expiresAt string) []byte {
	lines := []string{
		MessagePrefix,
		"expires_at: " + expiresAt,
		"coordinator: " + coordinatorKey,
		"peers: " + strconv.Itoa(len(peers)),
	}
	lines = append(lines, peers...)
	return []byte(strings.Join(lines, "\n"))
}

// Parse reads a served document, keeping the expiry text exactly as sent.
//
// The raw expiry string is returned alongside the parsed time because Go would
// re-render an RFC 3339 timestamp in its own way — a different string, and so a
// different signature. The message has to be rebuilt from what was actually
// sent, not from a round-trip through time.Time.
func Parse(body []byte) (*Document, string, error) {
	var envelope struct {
		Version              int      `json:"version"`
		Peers                []string `json:"peers"`
		CoordinatorPublicKey string   `json:"coordinator_public_key"`
		ExpiresAt            string   `json:"expires_at"`
		Signature            string   `json:"signature"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if envelope.Version != 1 {
		return nil, "", fmt.Errorf("%w: version %d", ErrMalformed, envelope.Version)
	}
	parsed := time.Time{}
	if envelope.ExpiresAt != "" {
		var err error
		parsed, err = time.Parse(time.RFC3339, envelope.ExpiresAt)
		if err != nil {
			return nil, "", fmt.Errorf("%w: expires_at %q", ErrMalformed, envelope.ExpiresAt)
		}
	}
	return &Document{
		Version:              envelope.Version,
		Peers:                envelope.Peers,
		CoordinatorPublicKey: envelope.CoordinatorPublicKey,
		ExpiresAt:            parsed,
		Signature:            envelope.Signature,
	}, envelope.ExpiresAt, nil
}

// Verify checks a document's signature against a pinned coordinator key.
//
// The pinned key is what makes this meaningful. Verifying against the key
// carried IN the document proves only that the document is self-consistent,
// which any forger can arrange.
func Verify(doc *Document, rawExpiresAt, pinnedKey string) error {
	if doc == nil {
		return ErrMalformed
	}
	if doc.Signature == "" {
		return ErrUnsigned
	}
	pinned, err := decodeKey(pinnedKey)
	if err != nil {
		return fmt.Errorf("%w: pinned key unreadable", ErrWrongKey)
	}
	carried, err := decodeKey(doc.CoordinatorPublicKey)
	if err != nil {
		return fmt.Errorf("%w: document key unreadable", ErrMalformed)
	}
	// The document must ANNOUNCE the key we pinned. Verifying the signature
	// while letting the document name a different coordinator would leave the
	// node using a key it never checked a signature for.
	if !ed25519.PublicKey(pinned).Equal(ed25519.PublicKey(carried)) {
		return fmt.Errorf("%w: announces %s", ErrWrongKey,
			short(doc.CoordinatorPublicKey))
	}
	signature, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pinned, Message(doc.Peers, doc.CoordinatorPublicKey,
		rawExpiresAt), signature) {
		return ErrBadSignature
	}
	return nil
}

func decodeKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty")
	}
	// The origin emits unpadded base64; accept padded too rather than fail on a
	// difference nobody would think to look for.
	for _, decoder := range []*base64.Encoding{
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if raw, err := decoder.DecodeString(value); err == nil &&
			len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, errors.New("not an ed25519 public key")
}

func short(value string) string {
	if len(value) > 12 {
		return value[:12] + "…"
	}
	return value
}

// Fingerprint identifies what a document actually CLAIMS, ignoring the parts
// that legitimately differ between fetches.
//
// Each origin call stamps a fresh expiry and therefore a fresh signature, so
// two gateways proxying the same origin seconds apart return different bytes
// while saying exactly the same thing. Comparing raw bodies would report
// disagreement constantly and mean nothing. What matters is the coordinator key
// and the peer SET — sorted, because ordering is a dial-priority hint rather
// than a claim, and a reorder is not a disagreement worth blocking on.
func Fingerprint(doc *Document) string {
	if doc == nil {
		return ""
	}
	peers := append([]string(nil), doc.Peers...)
	sort.Strings(peers)
	sum := sha256.Sum256([]byte(doc.CoordinatorPublicKey + "\x00" +
		strings.Join(peers, "\x00")))
	return hex.EncodeToString(sum[:8])
}
