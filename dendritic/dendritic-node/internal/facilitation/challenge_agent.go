package facilitation

import (
	"crypto/ed25519"
	"errors"
	"time"
)

// The challenge agent: the node's three roles in one place.
//
//	 issue  — pick a peer's shard and demand proof it still holds the data
//	 answer — prove it for a shard this node holds
//	witness — verify someone else's answer and countersign the receipt
//
// A node runs all three. That is the point of the design: work is only paid
// after someone with no stake in the outcome checked it.
//
// The agent deliberately cannot manufacture a receipt on its own. A receipt is
// only built from a challenge that was issued (with a seed the provider could
// not choose) and an answer that verified. There is no path from "I did some
// work" to "here is a receipt", because that path is the entire attack.

var (
	ErrChallengeExpired  = errors.New("facilitation: challenge is too old to answer")
	ErrWrongTarget       = errors.New("facilitation: challenge is addressed to another node")
	ErrProofFailed       = errors.New("facilitation: storage proof did not verify")
	ErrIssuerSignature   = errors.New("facilitation: challenge signature is invalid")
	ErrProviderSignature = errors.New("facilitation: provider signature is invalid")
	ErrSelfWitness       = errors.New("facilitation: a node cannot witness its own work")
)

// ChallengeTTL bounds how long an answer is accepted. Short enough that a node
// cannot fetch data back from a peer after being asked (which would let it pass
// while not actually storing anything), long enough for an I2P round trip.
const ChallengeTTL = 2 * time.Minute

// StorageChallenge asks a node to prove it still holds a shard.
type StorageChallenge struct {
	IssuerNodeID [32]byte          `json:"issuer_node_id"`
	TargetNodeID [32]byte          `json:"target_node_id"`
	AssignmentID [32]byte          `json:"assignment_id"` // which shard
	ShardRoot    [32]byte          `json:"shard_root"`    // committed root being proven against
	Seed         [32]byte          `json:"seed"`          // epoch randomness — NOT chosen by either party
	Epoch        uint64            `json:"epoch"`
	NumChunks    int               `json:"num_chunks"`
	Count        int               `json:"count"` // how many chunks to prove
	IssuedAt     uint64            `json:"issued_at"`
	IssuerPub    ed25519.PublicKey `json:"issuer_pub"`
	IssuerSig    []byte            `json:"issuer_sig"`
}

// canonicalBytes is what the issuer signs. The seed and target are inside it,
// so a challenge cannot be re-pointed at a different node or re-seeded after
// signing — either would let a provider shop for a challenge it can pass.
func (c StorageChallenge) canonicalBytes() []byte {
	buf := make([]byte, 0, 200)
	buf = append(buf, c.IssuerNodeID[:]...)
	buf = append(buf, c.TargetNodeID[:]...)
	buf = append(buf, c.AssignmentID[:]...)
	buf = append(buf, c.ShardRoot[:]...)
	buf = append(buf, c.Seed[:]...)
	buf = append(buf, be64(c.Epoch)...)
	buf = append(buf, be64(uint64(c.NumChunks))...)
	buf = append(buf, be64(uint64(c.Count))...)
	buf = append(buf, be64(c.IssuedAt)...)
	return buf
}

// Hash identifies this challenge; it becomes the receipt's ChallengeHash.
func (c StorageChallenge) Hash() [32]byte { return keccak32(c.canonicalBytes()) }

// Indices are the chunks this challenge demands. Derived, never listed in the
// message: both sides compute them, so a tampered list cannot widen or narrow
// what must be proven.
func (c StorageChallenge) Indices() []int {
	return DeriveStorageChallenge(c.Seed, c.AssignmentID, c.TargetNodeID, c.Count, c.NumChunks)
}

// VerifySignature checks the challenge really came from its stated issuer.
func (c StorageChallenge) VerifySignature() bool {
	if NodeIDOfPub(c.IssuerPub) != c.IssuerNodeID {
		return false
	}
	h := c.Hash()
	return ed25519.Verify(c.IssuerPub, h[:], c.IssuerSig)
}

// NodeIDOfPub is NodeID, named to read clearly at call sites.
func NodeIDOfPub(pub ed25519.PublicKey) [32]byte { return NodeID(pub) }

// StorageResponse is the answer: the proofs, signed by the provider.
type StorageResponse struct {
	ChallengeHash [32]byte          `json:"challenge_hash"`
	ProviderPub   ed25519.PublicKey `json:"provider_pub"`
	Proofs        []ChunkProof      `json:"proofs"`
	AnsweredAt    uint64            `json:"answered_at"`
	ProviderSig   []byte            `json:"provider_sig"`
}

// ResultHash commits to what was actually returned, so a receipt cannot be
// detached from the specific bytes that satisfied the challenge.
func (r StorageResponse) ResultHash() [32]byte {
	buf := make([]byte, 0, 64+len(r.Proofs)*64)
	buf = append(buf, r.ChallengeHash[:]...)
	for _, p := range r.Proofs {
		buf = append(buf, be64(uint64(p.Index))...)
		h := keccak32(p.Chunk)
		buf = append(buf, h[:]...)
	}
	buf = append(buf, be64(r.AnsweredAt)...)
	return keccak32(buf)
}

// Agent holds this node's identity for challenge work.
type Agent struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
	Now  func() time.Time // injectable for tests
}

// NewAgent builds an agent for a node's p2p key.
func NewAgent(pub ed25519.PublicKey, priv ed25519.PrivateKey) *Agent {
	return &Agent{Pub: pub, Priv: priv, Now: time.Now}
}

func (a *Agent) now() uint64 { return uint64(a.Now().Unix()) }

// NodeID is this agent's node id.
func (a *Agent) NodeID() [32]byte { return NodeID(a.Pub) }

// IssueStorageChallenge builds and signs a challenge against a peer's shard.
// `seed` must come from the chain's epoch randomness — if the issuer picks it,
// issuer and provider can collude on a seed whose indices the provider happens
// to hold.
func (a *Agent) IssueStorageChallenge(target, assignmentID, shardRoot, seed [32]byte,
	epoch uint64, numChunks, count int) StorageChallenge {
	c := StorageChallenge{
		IssuerNodeID: a.NodeID(), TargetNodeID: target,
		AssignmentID: assignmentID, ShardRoot: shardRoot, Seed: seed,
		Epoch: epoch, NumChunks: numChunks, Count: count,
		IssuedAt: a.now(), IssuerPub: a.Pub,
	}
	h := c.Hash()
	c.IssuerSig = ed25519.Sign(a.Priv, h[:])
	return c
}

// AnswerStorageChallenge proves the node still holds `data` for the shard.
func (a *Agent) AnswerStorageChallenge(c StorageChallenge, data []byte, chunkSize int) (StorageResponse, error) {
	if c.TargetNodeID != a.NodeID() {
		return StorageResponse{}, ErrWrongTarget
	}
	if !c.VerifySignature() {
		return StorageResponse{}, ErrIssuerSignature
	}
	if a.now() > c.IssuedAt+uint64(ChallengeTTL.Seconds()) {
		return StorageResponse{}, ErrChallengeExpired
	}
	chunks, leaves := ChunkShard(data, chunkSize)
	tree := BuildTree(leaves)
	resp := StorageResponse{
		ChallengeHash: c.Hash(), ProviderPub: a.Pub,
		Proofs:     BuildStorageProof(chunks, tree, c.Indices()),
		AnsweredAt: a.now(),
	}
	rh := resp.ResultHash()
	resp.ProviderSig = ed25519.Sign(a.Priv, rh[:])
	return resp, nil
}

// VerifyStorageResponse is the witness role: check the answer actually proves
// possession before attesting to anything.
func (a *Agent) VerifyStorageResponse(c StorageChallenge, resp StorageResponse) error {
	if !c.VerifySignature() {
		return ErrIssuerSignature
	}
	if resp.ChallengeHash != c.Hash() {
		return ErrProofFailed
	}
	if NodeIDOfPub(resp.ProviderPub) != c.TargetNodeID {
		return ErrProviderSignature
	}
	rh := resp.ResultHash()
	if !ed25519.Verify(resp.ProviderPub, rh[:], resp.ProviderSig) {
		return ErrProviderSignature
	}
	if !VerifyStorageProof(c.ShardRoot, resp.Proofs, c.Indices()) {
		return ErrProofFailed
	}
	return nil
}

// ProvableBytes is the most a challenge/response pair can possibly demonstrate.
//
// The Merkle root commits to exactly NumChunks leaves, and every sampled chunk
// shows how big a leaf is, so the shard cannot be larger than NumChunks leaves
// of the largest size actually seen. Anything above that was not proven; it was
// asserted.
//
// The bound is conservative when every sampled chunk happens to be the short
// final one, which costs an honest provider some credit on that single receipt
// and only when NumChunks is tiny. That is the right way round: rewards are
// shared out of a fixed epoch budget, so an over-claim is not the claimant
// taking extra from nowhere — it is the claimant taking it from everyone else
// who worked that epoch.
func ProvableBytes(c StorageChallenge, resp StorageResponse) uint64 {
	widest := 0
	for _, p := range resp.Proofs {
		if len(p.Chunk) > widest {
			widest = len(p.Chunk)
		}
	}
	if widest <= 0 || c.NumChunks <= 0 {
		return 0
	}
	return uint64(c.NumChunks) * uint64(widest)
}

// ReceiptFor derives the receipt a challenge/response pair earns. Pure and
// deterministic: the provider builds it to sign, and every witness rebuilds it
// independently to know what it is attesting to.
//
// Quantity is CLAMPED to what the evidence supports rather than taken on trust.
// It used to be whatever the caller passed, which meant a provider could name
// its own figure: Score weights payouts linearly by quantity against a fixed
// epoch budget and a per-node cap, so a single receipt claiming a terabyte took
// the entire cap and left every honest node with a rounding error. Clamping
// here rather than at the witness is deliberate — this is the one derivation
// both sides run, so provider and witness arrive at the same number and the
// signatures still match.
func ReceiptFor(c StorageChallenge, resp StorageResponse, provenBytes uint64) ServiceReceipt {
	if limit := ProvableBytes(c, resp); provenBytes > limit {
		provenBytes = limit
	}
	return ServiceReceipt{
		ProviderNodeID: c.TargetNodeID,
		VerifierNodeID: c.IssuerNodeID,
		ServiceType:    ServiceStorage,
		JobID:          c.AssignmentID,
		ChallengeHash:  c.Hash(),
		ResultHash:     resp.ResultHash(),
		Epoch:          c.Epoch,
		StartedAt:      c.IssuedAt,
		CompletedAt:    resp.AnsweredAt,
		Quantity:       provenBytes,
		Quality:        1,
		Nonce:          c.IssuedAt,
	}
}

// BuildReceipt turns a verified challenge/response pair into a signed receipt.
// It re-verifies rather than trusting the caller: this is the only door from
// "work happened" to "work is claimable", so it does its own checking.
//
// Quantity is the proven-held byte count, not a self-declared figure.
func (a *Agent) BuildReceipt(c StorageChallenge, resp StorageResponse, provenBytes uint64) (SignedReceipt, error) {
	if err := a.VerifyStorageResponse(c, resp); err != nil {
		return SignedReceipt{}, err
	}
	if c.TargetNodeID != a.NodeID() {
		return SignedReceipt{}, ErrWrongTarget
	}
	return NewSignedReceipt(a.Pub, a.Priv, ReceiptFor(c, resp, provenBytes)), nil
}

// AttestationFor is the witness side of the same derivation: verify the proof,
// rebuild the receipt from the evidence, and sign that. Returns the signature to
// hand back to the provider.
func (a *Agent) AttestationFor(c StorageChallenge, resp StorageResponse, provenBytes uint64) ([]byte, error) {
	if c.TargetNodeID == a.NodeID() {
		return nil, ErrSelfWitness
	}
	if err := a.VerifyStorageResponse(c, resp); err != nil {
		return nil, err
	}
	h := CanonicalReceiptHash(ReceiptFor(c, resp, provenBytes))
	return ed25519.Sign(a.Priv, h[:]), nil
}

// Attest countersigns a receipt as a witness, after verifying the underlying
// proof itself. A witness that signs on someone's word is exactly what the
// stake bond exists to punish.
func (a *Agent) Attest(sr *SignedReceipt, c StorageChallenge, resp StorageResponse) error {
	if sr.Receipt.ProviderNodeID == a.NodeID() {
		return ErrSelfWitness
	}
	if err := a.VerifyStorageResponse(c, resp); err != nil {
		return err
	}
	if sr.Receipt.ChallengeHash != c.Hash() || sr.Receipt.ResultHash != resp.ResultHash() {
		return ErrProofFailed
	}
	if !VerifyReceiptSignature(sr.ProviderPub, sr.Receipt, sr.ProviderSig) {
		return ErrProviderSignature
	}
	h := sr.Hash()
	if !sr.AddWitness(a.Pub, ed25519.Sign(a.Priv, h[:])) {
		return ErrSelfWitness
	}
	return nil
}
