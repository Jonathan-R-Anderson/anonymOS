package p2p

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"
)

// Proof-of-Facilitation challenge transport.
//
// This carries OPAQUE bytes. The challenge and response formats, the proofs,
// and the receipt rules all live in internal/facilitation, and nothing here
// imports it: the p2p layer should not gain an opinion about how earnings are
// proven, and facilitation should stay testable without a network. The only
// contract is "deliver these bytes to that node, bring back its answer".
//
// It rides the existing storage protocol as one more operation rather than
// opening a second protocol ID, so challenges reach every node already speaking
// to us — including over I2P, where a second listener would mean a second
// tunnel to build and keep alive.

const challengeOperation = "pof-challenge"

// challengeTimeout bounds a single challenge round trip. Generous because a
// cold I2P dial is slow, but bounded: a peer that will not answer must fail the
// audit rather than stall the epoch.
const challengeTimeout = 90 * time.Second

// SetChallengeHandler installs the function that answers incoming challenges.
// Nodes that store nothing simply never install one and reject the operation,
// which is the honest answer rather than a silent empty proof.
func (n *Node) SetChallengeHandler(fn func(ctx context.Context, payload []byte) ([]byte, error)) {
	n.challengeMu.Lock()
	defer n.challengeMu.Unlock()
	n.challengeHandler = fn
}

func (n *Node) currentChallengeHandler() func(ctx context.Context, payload []byte) ([]byte, error) {
	n.challengeMu.RLock()
	defer n.challengeMu.RUnlock()
	return n.challengeHandler
}

// handleChallengeFrame answers one challenge on an open stream. The payload is
// length-framed the same way every other body on this protocol is.
func (n *Node) handleChallengeFrame(stream interface {
	Write([]byte) (int, error)
}, reader *bufio.Reader, size int64) {
	handler := n.currentChallengeHandler()
	if handler == nil {
		_ = writeJSONFrame(stream, responseHeader{Error: "node answers no challenges"})
		return
	}
	if size <= 0 || size > maxHeaderBytes {
		_ = writeJSONFrame(stream, responseHeader{Error: "invalid challenge size"})
		return
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		_ = writeJSONFrame(stream, responseHeader{Error: "short challenge"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), challengeTimeout)
	defer cancel()
	answer, err := handler(ctx, payload)
	if err != nil {
		_ = writeJSONFrame(stream, responseHeader{Error: err.Error()})
		return
	}
	if err := writeJSONFrame(stream, responseHeader{OK: true, Size: int64(len(answer))}); err != nil {
		return
	}
	_, _ = stream.Write(answer)
}

// SendChallenge delivers a challenge to a peer and returns its answer.
func (n *Node) SendChallenge(ctx context.Context, target peer.ID, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, challengeTimeout)
	defer cancel()
	stream, err := n.host.NewStream(ctx, target, ProtocolID)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(challengeTimeout))

	if err := writeJSONFrame(stream, requestHeader{
		Operation: challengeOperation, Size: int64(len(payload)),
	}); err != nil {
		return nil, err
	}
	if _, err := stream.Write(payload); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(stream)
	var header responseHeader
	if err := readJSONFrame(reader, &header); err != nil {
		return nil, err
	}
	if header.Error != "" {
		return nil, errors.New(header.Error)
	}
	if !header.OK || header.Size <= 0 || header.Size > maxHeaderBytes {
		return nil, errors.New("p2p: peer returned no proof")
	}
	answer := make([]byte, header.Size)
	if _, err := io.ReadFull(reader, answer); err != nil {
		return nil, err
	}
	return answer, nil
}

// NodeIDFromPeer derives the Proof-of-Facilitation node id (keccak256 of the
// ed25519 public key) from a libp2p peer id.
//
// The two identities are the same key, so no registry is needed to link them —
// which also means a peer cannot claim someone else's node id: the id is
// recomputed from the key that authenticated the connection.
func NodeIDFromPeer(p peer.ID) ([32]byte, error) {
	var out [32]byte
	pub, err := p.ExtractPublicKey()
	if err != nil {
		return out, err
	}
	raw, err := pub.Raw()
	if err != nil {
		return out, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return out, errors.New("p2p: peer identity is not ed25519")
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(raw)
	copy(out[:], h.Sum(nil))
	return out, nil
}

// PeerForNodeID finds the connected peer whose identity hashes to nodeID.
// Returns false when that node is not currently reachable, which the caller
// must treat as "could not audit", never as "failed the audit".
func (n *Node) PeerForNodeID(nodeID [32]byte) (peer.ID, bool) {
	for _, p := range n.host.Network().Peers() {
		if id, err := NodeIDFromPeer(p); err == nil && id == nodeID {
			return p, true
		}
	}
	// Fall back to everything known, not just what is dialled: over I2P a peer
	// may be reachable without a live connection.
	for _, p := range n.host.Peerstore().Peers() {
		if id, err := NodeIDFromPeer(p); err == nil && id == nodeID {
			return p, true
		}
	}
	var zero peer.ID
	return zero, false
}

// LocalNodeID is this node's Proof-of-Facilitation id.
func (n *Node) LocalNodeID() ([32]byte, error) { return NodeIDFromPeer(n.host.ID()) }

// SigningKey returns the raw ed25519 keypair behind the libp2p identity.
//
// Deliberately narrow and deliberately raw: Proof-of-Facilitation receipts are
// signed with the SAME key whose keccak256 is the node id, so a receipt's
// signature cannot be separated from the identity it claims. PublicKey() is not
// usable for that — it returns the protobuf-marshalled form, whose hash is a
// different value entirely, and receipts signed against it would be
// unattributable.
//
// The key stays in this process. It must never be logged, written outside
// p2p.key, or sent anywhere: it is the node's whole identity, and anyone
// holding it can claim its earnings.
func (n *Node) SigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	priv := n.host.Peerstore().PrivKey(n.host.ID())
	if priv == nil {
		return nil, nil, errors.New("p2p: node private key unavailable")
	}
	raw, err := priv.Raw()
	if err != nil {
		return nil, nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("p2p: node identity is not ed25519")
	}
	privKey := ed25519.PrivateKey(append([]byte(nil), raw...))
	pubKey := privKey.Public().(ed25519.PublicKey)
	return pubKey, privKey, nil
}
