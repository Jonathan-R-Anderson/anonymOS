// Package place makes storage capacity a property of the NETWORK rather than of
// whichever node happened to receive a write.
//
// THE PROBLEM THIS FIXES
// ----------------------
// Store.PutObject writes to the local filesystem, checks the local capacity,
// and then advertises to the DHT that this node holds the object. The DHT was
// therefore a directory of who-has-what layered over independent local disks:
// when the receiving node's store was full, the write FAILED, even with peers
// on the network sitting on terabytes of free space. "There is a DHT, capacity
// should not matter" was true as an expectation and false as an implementation.
//
// HOW PLACEMENT WORKS
// -------------------
// Nodes advertise free space at a rendezvous CID, exactly as DCS workers
// advertise deploy capacity. When a local write cannot fit, the node finds peers
// with room and streams the blob to one of them over the existing libp2p host —
// the same Noise handshake and I2P tunnels the rest of the protocol uses, no
// second network. The receiving node verifies, stores, and advertises itself as
// a provider, so a later lookup by digest finds it there.
//
// WHY THIS IS SAFE WITHOUT TRUSTING THE PEER
// ------------------------------------------
// Blobs are content-addressed. The receiver recomputes the digest and refuses a
// mismatch, and the placer confirms the stored digest in the reply. A hostile
// peer can therefore refuse to store, or lie about having stored — both of
// which are detected — but it cannot substitute different bytes under a digest
// somebody will later fetch and trust.
//
// A peer that overstates its free space costs one wasted attempt and is skipped
// on the next candidate. That is why capacity records do not need to be signed
// for this to be correct: the worst outcome is a retry, not a bad write.
package place

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// ProtocolID is the stream protocol a node uses to hand a blob to a peer.
const ProtocolID = "/syndichan/blobplace/1.0.0"

// RendezvousSeed is hashed into the CID nodes advertise storage capacity at.
// Separate from the DCS worker rendezvous because the two answer different
// questions: "who can run a container" and "who can hold bytes" are not the
// same set, and a storage-only node should not appear as a deploy target.
const RendezvousSeed = "syndichan-storage-capacity-rendezvous/1"

// MaxBlobBytes bounds a single placement. Matches the build-context ceiling —
// this exists to move build contexts and object shards, not arbitrary uploads,
// and an unbounded frame is a memory exhaustion primitive for any peer.
const MaxBlobBytes int64 = 64 << 20

// RecordTTL is how long a capacity record is trusted. Free space changes as a
// node fills, so a stale record is worse than none: it sends writes to a node
// that filled up an hour ago.
const RecordTTL = 10 * time.Minute

// Record is what a node publishes about the space it will accept.
type Record struct {
	RecordType  string `json:"record_type"` // "storage_capacity"
	NodeID      string `json:"node_id"`
	Destination string `json:"destination"` // <b32>.i2p
	FreeBytes   int64  `json:"free_bytes"`
	Capacity    int64  `json:"capacity_bytes"`
	// Draining says this node is being retired: do not send it anything, and if
	// you are the owner of shards already on it, move them off.
	//
	// IT TRAVELS HERE, in the record the node already publishes about its own
	// disk, because of the asymmetry the mover resolved: only an OWNER can shed a
	// shard safely (it alone holds the placement ledger, can obtain a revocation,
	// and can confirm a copy landed before authorising a delete), so a node that
	// wants to be emptied has to make that intent known to owners it does not
	// know the identity of. This record is already read by exactly the code that
	// has to act on it, on a ten-minute TTL, with no new verb, no new rendezvous
	// and no site involvement -- a volunteer can retire their own machine without
	// asking anybody.
	//
	// UNSIGNED, like the rest of the record, and that is survivable for the same
	// reason: FindStoragePeers refuses a record that names a node id other than
	// the publisher's, so the only node anybody can declare to be draining is
	// themselves. The worst a liar achieves is that the network stops writing to
	// them and starts taking their shards back, which is a cost paid entirely by
	// the liar.
	//
	// omitempty, unlike the config field: this is a wire record read by builds
	// older than this one, and a record for a node that is NOT draining should
	// stay byte-identical to what those builds already publish and parse.
	Draining  bool      `json:"draining,omitempty"`
	Published time.Time `json:"published"`
}

// Fresh reports whether the record is recent enough to act on.
func (r Record) Fresh(now time.Time) bool {
	return !r.Published.IsZero() && now.Sub(r.Published) < RecordTTL
}

// Fits reports whether this node claims room for n more bytes. The margin
// stops a node being filled to exactly zero, which would leave it unable to
// take even its own writes.
func (r Record) Fits(n int64) bool {
	const margin = 16 << 20
	return r.FreeBytes-margin >= n
}

// Finder discovers peers advertising storage capacity. Implemented by the p2p
// node; an interface so this package can be tested without a libp2p host.
type Finder interface {
	FindStoragePeers(ctx context.Context, limit int) ([]Record, error)
}

// Local is the subset of the object store placement needs.
type Local interface {
	PutLocal(digest string, data []byte) error
	HasLocal(digest string) bool
}

// request is the wire frame: a small JSON header then the raw bytes, so a
// receiver can decide from the header whether it wants the body at all.
type request struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type response struct {
	Stored bool   `json:"stored"`
	Digest string `json:"digest"`
	Error  string `json:"error,omitempty"`
}

// Digest is the canonical content address for a blob.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Placer streams blobs to peers when the local store cannot take them.
type Placer struct {
	host    host.Host
	finder  Finder
	logger  *log.Logger
	timeout time.Duration
	// Dial resolves a node id + destination to something the host can reach.
	// Injected so tests can avoid I2P.
	dial func(ctx context.Context, r Record) (peer.ID, error)
}

func NewPlacer(h host.Host, finder Finder, logger *log.Logger,
	dial func(context.Context, Record) (peer.ID, error)) *Placer {
	return &Placer{host: h, finder: finder, logger: logger,
		timeout: 120 * time.Second, dial: dial}
}

// ErrNoCapacity means no peer would take the blob. Distinct from a transport
// failure so a caller can tell "the network is full" from "the network is
// unreachable" — they need different responses from an operator.
var ErrNoCapacity = errors.New("no peer has room for this blob")

// Place streams data to a peer with room and returns the node id that took it.
//
// Candidates are tried largest-free-space first, so writes spread toward the
// emptiest nodes rather than repeatedly filling whichever peer answers first.
func (p *Placer) Place(ctx context.Context, digest string, data []byte) (string, error) {
	if int64(len(data)) > MaxBlobBytes {
		return "", fmt.Errorf("blob is %d bytes, over the %d limit", len(data), MaxBlobBytes)
	}
	if actual := Digest(data); actual != digest {
		return "", fmt.Errorf("refusing to place %s: bytes hash to %s", digest, actual)
	}

	records, err := p.finder.FindStoragePeers(ctx, 32)
	if err != nil {
		return "", fmt.Errorf("find storage peers: %w", err)
	}
	now := time.Now()
	var usable []Record
	for _, r := range records {
		if r.Fresh(now) && r.Fits(int64(len(data))) {
			usable = append(usable, r)
		}
	}
	if len(usable) == 0 {
		return "", ErrNoCapacity
	}
	sort.Slice(usable, func(i, j int) bool { return usable[i].FreeBytes > usable[j].FreeBytes })

	var lastErr error
	for _, candidate := range usable {
		node, err := p.send(ctx, candidate, digest, data)
		if err == nil {
			return node, nil
		}
		lastErr = err
		if p.logger != nil {
			p.logger.Printf("place: %s declined %s: %v", candidate.NodeID, digest, err)
		}
	}
	return "", fmt.Errorf("every candidate declined: %w", lastErr)
}

func (p *Placer) send(ctx context.Context, r Record, digest string, data []byte) (string, error) {
	target, err := p.dial(ctx, r)
	if err != nil {
		return "", err
	}
	dialCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	stream, err := p.host.NewStream(dialCtx, target, protocol.ID(ProtocolID))
	if err != nil {
		return "", fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(p.timeout))

	header, err := json.Marshal(request{Digest: digest, Size: int64(len(data))})
	if err != nil {
		return "", err
	}
	if err := writeFrame(stream, header); err != nil {
		return "", fmt.Errorf("write header: %w", err)
	}
	if _, err := stream.Write(data); err != nil {
		return "", fmt.Errorf("write body: %w", err)
	}
	if err := stream.CloseWrite(); err != nil {
		return "", fmt.Errorf("close write: %w", err)
	}

	replyBytes, err := readFrame(stream, 64<<10)
	if err != nil {
		return "", fmt.Errorf("read reply: %w", err)
	}
	var reply response
	if err := json.Unmarshal(replyBytes, &reply); err != nil {
		return "", fmt.Errorf("decode reply: %w", err)
	}
	if !reply.Stored {
		return "", fmt.Errorf("peer refused: %s", reply.Error)
	}
	// The peer echoes what it stored. A mismatch means it kept something other
	// than what was sent, which makes its advertisement worthless to us.
	if reply.Digest != digest {
		return "", fmt.Errorf("peer stored %s, not %s", reply.Digest, digest)
	}
	return r.NodeID, nil
}

// Server accepts placements from peers.
type Server struct {
	host   host.Host
	local  Local
	logger *log.Logger
	// Accept decides whether this node has room. Separate from the store so the
	// same capacity rule governs local writes and accepted placements.
	accept func(size int64) bool
}

func NewServer(h host.Host, local Local, logger *log.Logger, accept func(int64) bool) *Server {
	return &Server{host: h, local: local, logger: logger, accept: accept}
}

func (s *Server) Start() { s.host.SetStreamHandler(protocol.ID(ProtocolID), s.handle) }
func (s *Server) Stop()  { s.host.RemoveStreamHandler(protocol.ID(ProtocolID)) }

func (s *Server) handle(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(120 * time.Second))

	headerBytes, err := readFrame(stream, 64<<10)
	if err != nil {
		s.reply(stream, response{Error: "bad header"})
		return
	}
	var req request
	if err := json.Unmarshal(headerBytes, &req); err != nil {
		s.reply(stream, response{Error: "bad header json"})
		return
	}
	if req.Size <= 0 || req.Size > MaxBlobBytes {
		s.reply(stream, response{Error: "size out of range"})
		return
	}
	// Answered from the header, before reading the body: refusing a 60MB blob
	// after receiving it wastes the bandwidth this check exists to save.
	if s.accept != nil && !s.accept(req.Size) {
		s.reply(stream, response{Error: "no room"})
		return
	}
	if s.local.HasLocal(req.Digest) {
		// Idempotent: already holding it is success, not a conflict.
		s.reply(stream, response{Stored: true, Digest: req.Digest})
		return
	}

	data, err := io.ReadAll(io.LimitReader(stream, req.Size))
	if err != nil || int64(len(data)) != req.Size {
		s.reply(stream, response{Error: "short body"})
		return
	}
	// The whole reason this is safe without trusting the sender.
	if actual := Digest(data); actual != req.Digest {
		s.reply(stream, response{Error: "digest mismatch"})
		if s.logger != nil {
			s.logger.Printf("place: rejected %s, bytes hash to %s", req.Digest, actual)
		}
		return
	}
	if err := s.local.PutLocal(req.Digest, data); err != nil {
		s.reply(stream, response{Error: "store failed: " + err.Error()})
		return
	}
	if s.logger != nil {
		s.logger.Printf("place: accepted %s (%d bytes) from a peer", req.Digest, len(data))
	}
	s.reply(stream, response{Stored: true, Digest: req.Digest})
}

func (s *Server) reply(stream network.Stream, r response) {
	body, err := json.Marshal(r)
	if err != nil {
		return
	}
	_ = writeFrame(stream, body)
}

func writeFrame(w io.Writer, payload []byte) error {
	var size [4]byte
	n := len(payload)
	size[0], size[1], size[2], size[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(size[0])<<24 | int(size[1])<<16 | int(size[2])<<8 | int(size[3])
	if n < 0 || n > limit {
		return nil, fmt.Errorf("frame of %d bytes exceeds the %d limit", n, limit)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
