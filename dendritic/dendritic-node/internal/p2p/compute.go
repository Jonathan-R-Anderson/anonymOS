package p2p

// Compute over the peer protocol.
//
// WHY THIS EXISTS AT ALL
// ----------------------
// The site is Python and cannot speak libp2p. Volunteer nodes are behind home
// NAT and cannot be dialled directly. The compute API those volunteers already
// serve (/compute/admit|submit|result) is plain TCP on a loopback/LAN listener,
// and the address a node advertises to the network is a garlic destination
// carrying LIBP2P STREAMS — not HTTP. So the site had a dispatcher pointing at
// an HTTP-over-I2P listener that does not exist, and every unit failed with
// "none took this job" while the nodes themselves were answering "admitted".
//
// The shape that works is the one storage already uses:
//
//	site --plain HTTP--> its own node --libp2p/I2P--> volunteer node
//
// This file is the second hop. It carries compute as three more OPERATIONS on
// the existing storage protocol, exactly as pof-challenge does, rather than a
// second protocol ID — a second listener would mean a second I2P tunnel to
// build and keep alive, reaching strictly fewer peers.
//
// WHAT TRAVELS
// ------------
// Opaque JSON, in both directions, plus the status the local HTTP handler would
// have returned. Nothing here understands a job: the request bytes are handed
// to whatever this node installed as its ComputeHandler and the answer is
// handed back. That keeps the wire honest when the catalogue grows, and it is
// what lets the receiving node serve a peer's frame through the very handlers
// its loopback API serves — see cmd/syndichan-node/computepeer.go.
//
// REFUSAL IS NOT UNREACHABILITY
// -----------------------------
// The single most important property. The site leaves a job QUEUED when a node
// declines and treats "nobody answered" differently, so the two must not
// collapse into one error on the way through. The rule here is mechanical:
//
//	SendCompute returns an error   -> the peer could not be REACHED.
//	SendCompute returns a status   -> the peer ANSWERED, 503 included.
//
// A node running a build that predates these verbs answers "unsupported
// operation" on the storage protocol. That is an answer, so it comes back as a
// non-retryable refusal rather than as a dial failure.
//
// AUTHORISATION: NO LEASE, AND WHY
// --------------------------------
// The "store" verb demands a coordinator-signed lease because accepting a shard
// costs the holder DISK, indefinitely, for bytes it cannot evaluate — the lease
// is the coordinator saying "this object is in the ledger, this size, to you".
// Compute is not that trade. It costs a bounded slice of CPU and leaves nothing
// behind, and the thing that decides whether it happens is already the
// receiving operator's own policy, which this transport does not bypass:
//
//   - the operator enabled compute and this device at all, or no handler is
//     installed here and every frame is refused;
//   - the catalogue table is closed, so a language or workload the node does
//     not know is refused and never forwarded as an image name;
//   - arbitrary code needs MEASURED microVM isolation, so no peer can talk a
//     container-only node into running a stranger's program;
//   - the governor (load, heat, battery, hours, reserved cores) and one job per
//     device decide whether now is a good time.
//
// Every one of those is enforced by the party paying the cost. A lease would
// add a signer the site does not have for compute and would make the feature
// undeployable until it did, in exchange for a guarantee the node already makes
// for itself.
//
// What the new reach does change is that any peer on the DHT can now spend a
// volunteer's CPU, where before only its own loopback could. Two things bound
// that here: the frame is refused outright unless compute is switched on, and
// the payload is capped explicitly (below). A third lives in the handler —
// results are scoped to the peer that submitted them, so one peer cannot poll
// another's job id and collect its answer.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	syndii2p "github.com/syndichan/maniwani/storage-client/internal/i2p"
)

// The three compute operations, named on the wire. Prefixed rather than bare
// ("admit") so nothing can be confused with a storage verb by a future reader
// or a sloppy dispatcher.
const (
	ComputeAdmit  = "compute-admit"
	ComputeSubmit = "compute-submit"
	ComputeResult = "compute-result"
)

// MaxComputePayload bounds a submitted job.
//
// A submit carries the submitter's FILES, so unlike every other frame on this
// protocol its size is chosen by somebody else. maxNetworkShard is the existing
// precedent for a frame with a payload, and using the same number keeps one
// answer to "how big may a stranger make this node's next allocation".
//
// Admit and result carry a device name and a job id and are held to the header
// cap instead — a 32 MB "would you take this?" is not a request, it is a way to
// make a node allocate.
const MaxComputePayload = maxNetworkShard

// computeTransferTimeout bounds one leg of a compute exchange. Generous because
// 32 MB over I2P is not a loopback write, bounded because a peer that stops
// mid-payload must not hold a stream open for ever.
const computeTransferTimeout = 3 * time.Minute

// computeHandlerTimeout bounds the local handler. Submit returns a ticket
// immediately and result reads a map, so this is a guard against a wedged
// handler rather than a budget anything normally spends.
const computeHandlerTimeout = 60 * time.Second

// ComputeHandler answers one compute frame.
//
// It returns the status and body the node's own /compute/* endpoint would have
// returned for the same request. Deliberately not (body, error): every outcome
// compute has — admitted, declined, busy, unknown workload — is an ANSWER with
// a status, and modelling some of them as errors is how a refusal turns into an
// apparent failure to reach the node.
//
// `from` is the peer that opened the stream — the one identity on it libp2p has
// actually proved, taken from the connection and never from the frame, exactly
// as the delete verb takes it. The handler scopes results by it so one peer
// cannot poll another's job id.
type ComputeHandler func(ctx context.Context, from peer.ID, operation string, payload []byte) (status int, body []byte)

// IsComputeOperation reports whether an operation name is one of the compute
// verbs. Exact matches only: a prefix test would route "compute-anything" into
// the compute path and take those frames away from the switch's default, which
// is the branch that tells a caller the operation is unsupported.
func IsComputeOperation(operation string) bool {
	switch operation {
	case ComputeAdmit, ComputeSubmit, ComputeResult:
		return true
	}
	return false
}

// MaxComputeRequest is the payload ceiling for one operation. Exported because
// the relay checks it BEFORE dialling: an oversized job will not fit however
// many times it is retried, and reporting that as "the peer is unreachable"
// would queue it for ever.
func MaxComputeRequest(operation string) int64 {
	if operation == ComputeSubmit {
		return MaxComputePayload
	}
	return maxHeaderBytes
}

// SetComputeHandler installs the function that answers incoming compute frames.
// A node that lends no compute never installs one, and every frame is then
// refused — which is the honest answer, and different from silence.
func (n *Node) SetComputeHandler(fn ComputeHandler) {
	n.computeMu.Lock()
	defer n.computeMu.Unlock()
	n.computeHandler = fn
}

func (n *Node) currentComputeHandler() ComputeHandler {
	n.computeMu.RLock()
	defer n.computeMu.RUnlock()
	return n.computeHandler
}

// computeStream is the part of a stream this needs: somewhere to write the
// answer, and a deadline to move because a 32 MB payload does not arrive inside
// the storage handler's 30 seconds.
type computeStream interface {
	io.Writer
	SetDeadline(time.Time) error
}

// handleComputeFrame answers one compute frame on an open stream.
//
// Everything it can refuse, it refuses BEFORE allocating or reading: a bad size
// costs one small write and the stream is done. That is what keeps a malformed
// compute frame from becoming this node's problem — it never reaches the point
// where a stranger's number decides how much memory to reserve or how long to
// wait for bytes that are not coming.
func (n *Node) handleComputeFrame(stream computeStream, reader *bufio.Reader, header requestHeader, from peer.ID) {
	handler := n.currentComputeHandler()
	if handler == nil {
		writeComputeRefusal(stream, http.StatusServiceUnavailable,
			"this node does not offer compute")
		return
	}
	limit := MaxComputeRequest(header.Operation)
	if header.Size < 0 || header.Size > limit {
		writeComputeRefusal(stream, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("compute request of %d bytes is over the %d byte limit",
				header.Size, limit))
		return
	}
	payload := make([]byte, header.Size)
	if header.Size > 0 {
		_ = stream.SetDeadline(time.Now().Add(computeTransferTimeout))
		if _, err := io.ReadFull(reader, payload); err != nil {
			writeComputeRefusal(stream, http.StatusBadRequest, "short compute request")
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), computeHandlerTimeout)
	defer cancel()
	status, body := handler(ctx, from, header.Operation, payload)
	if int64(len(body)) > MaxComputePayload {
		// Our own answer, so this is a bug rather than an attack — but a frame
		// the caller cannot read is worse than a refusal it can.
		writeComputeRefusal(stream, http.StatusInternalServerError,
			"this node produced an answer too large to send")
		return
	}
	_ = stream.SetDeadline(time.Now().Add(computeTransferTimeout))
	if err := writeJSONFrame(stream, responseHeader{
		OK: true, Status: status, Size: int64(len(body)),
	}); err != nil {
		return
	}
	_, _ = stream.Write(body)
}

// writeComputeRefusal answers with a status AND a body the caller can parse.
//
// A body even for the node's own refusals, so the relay never has to invent one
// on the site's behalf: the site reads `reason` and `retryable` off every
// answer, and a refusal that arrived as an empty frame would reach it as a
// parse failure — which reads as a broken node rather than an unwilling one.
func writeComputeRefusal(w io.Writer, status int, reason string) {
	body := computeRefusalBody(reason)
	if err := writeJSONFrame(w, responseHeader{
		OK: true, Refused: true, Status: status, Size: int64(len(body)),
	}); err != nil {
		return
	}
	_, _ = w.Write(body)
}

// computeRefusalBody is the shape the site already reads: not admitted, not
// accepted, a reason, and not worth asking again. Everything refused at this
// layer is a property of the node or of the request itself, neither of which
// changes by being asked a second time.
func computeRefusalBody(reason string) []byte {
	body, err := json.Marshal(map[string]any{
		"admitted": false, "accepted": false, "reason": reason, "retryable": false,
	})
	if err != nil {
		return []byte(`{"admitted":false,"accepted":false,"retryable":false,` +
			`"reason":"this node refused the request"}`)
	}
	return body
}

// SendCompute delivers a compute request to a peer and returns its answer.
//
// The error is reserved for NOT REACHING the peer. Any status returned — 200,
// 400, 503 — means the peer spoke, and the caller must pass it on as an answer
// rather than as a failure. See the file comment: the site charges a job
// differently depending on which of those two happened.
func (n *Node) SendCompute(ctx context.Context, target peer.ID, operation string, payload []byte) (int, []byte, error) {
	if !IsComputeOperation(operation) {
		return 0, nil, fmt.Errorf("p2p: %q is not a compute operation", operation)
	}
	if limit := MaxComputeRequest(operation); int64(len(payload)) > limit {
		// Refused here rather than sent and refused there: an oversized job burns
		// an I2P round trip to learn something already known locally.
		return 0, nil, fmt.Errorf("p2p: %s payload is %d bytes, over the %d byte limit",
			operation, len(payload), limit)
	}
	stream, err := n.host.NewStream(ctx, target, ProtocolID)
	if err != nil {
		return 0, nil, err
	}
	defer stream.Close()
	deadline := time.Now().Add(computeTransferTimeout)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	_ = stream.SetDeadline(deadline)
	if err := writeJSONFrame(stream, requestHeader{
		Operation: operation, Size: int64(len(payload)),
	}); err != nil {
		return 0, nil, err
	}
	if len(payload) > 0 {
		if _, err := stream.Write(payload); err != nil {
			return 0, nil, err
		}
	}
	reader := bufio.NewReader(stream)
	var response responseHeader
	if err := readJSONFrame(reader, &response); err != nil {
		return 0, nil, err
	}
	if response.Status == 0 {
		if response.Error != "" {
			// An answer from a node whose switch has no compute case — every
			// build before this one. It said no, and saying no is not the same as
			// being unreachable, so the caller gets a refusal it will not retry
			// rather than a dial error it would.
			return http.StatusServiceUnavailable, computeRefusalBody(response.Error), nil
		}
		return 0, nil, errors.New("p2p: peer gave no usable compute answer")
	}
	if response.Size < 0 || response.Size > MaxComputePayload {
		return 0, nil, fmt.Errorf("p2p: peer announced a %d byte compute answer", response.Size)
	}
	body := make([]byte, response.Size)
	if response.Size > 0 {
		if _, err := io.ReadFull(reader, body); err != nil {
			return 0, nil, err
		}
	}
	return response.Status, body, nil
}

// AddPeerDestination teaches this node how to dial a peer at the garlic
// destination that peer reported in ITS OWN heartbeat.
//
// The destination is a dialling hint, not an identity: the peer id is what the
// Noise handshake proves, and a wrong destination produces a failed dial rather
// than a conversation with the wrong node. Which is what makes it safe to take
// from the coordinator's listing — the same listing that decided this peer was
// eligible in the first place.
func (n *Node) AddPeerDestination(id peer.ID, destination string) error {
	address, err := syndii2p.Multiaddr(destination)
	if err != nil {
		return err
	}
	// The same TTL worker discovery uses. Long enough to survive a job, short
	// enough that a node which has moved is not dialled at its old address for
	// the life of the process.
	n.host.Peerstore().AddAddrs(id, []multiaddr.Multiaddr{address}, 30*time.Minute)
	return nil
}
