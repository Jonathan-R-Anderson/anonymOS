package dcs

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	syndii2p "github.com/syndichan/maniwani/storage-client/internal/i2p"
)

// StreamTransport carries DCS envelopes over the node's existing libp2p host,
// which already runs the I2P transport. It does NOT open a second network: a
// DCS request to a worker is a new stream on the /syndichan/dcs/1.0.0 protocol
// to that worker's garlic destination, over the same host that exchanges
// shards. Reusing the host means reusing its Noise handshake, its peer
// authentication and its I2P tunnels for free.
type StreamTransport struct {
	host    host.Host
	timeout time.Duration
}

func NewStreamTransport(h host.Host) *StreamTransport {
	return &StreamTransport{host: h, timeout: 90 * time.Second}
}

const maxFrameBytes = 1 << 20 // 1 MiB: an envelope is small; this is a DoS bound.

// RoundTrip sends env to worker and returns the reply payload bytes.
func (t *StreamTransport) RoundTrip(ctx context.Context, worker WorkerRecord, env Envelope) ([]byte, error) {
	target, err := peer.Decode(worker.NodeID)
	if err != nil {
		return nil, fmt.Errorf("dcs: worker node id %q: %w", worker.NodeID, err)
	}
	addr, err := syndii2p.Multiaddr(worker.Destination)
	if err != nil {
		return nil, fmt.Errorf("dcs: worker destination %q: %w", worker.Destination, err)
	}
	// Teach the host how to reach this worker. The record binds NodeID to
	// Destination and is signed by NodeID's key, so trusting the pairing here
	// is exactly as strong as trusting the record.
	t.host.Peerstore().AddAddr(target, addr, time.Duration(MaxEnvelopeSkew)+t.timeout)

	dialCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	stream, err := t.host.NewStream(dialCtx, target, protocol.ID(ProtocolID))
	if err != nil {
		return nil, fmt.Errorf("dcs: open stream to %s: %w", worker.NodeID, err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(t.timeout))

	if err := writeFrame(stream, env); err != nil {
		return nil, err
	}
	var reply replyFrame
	if err := readFrame(bufio.NewReader(stream), &reply); err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return nil, fmt.Errorf("dcs: worker rejected request: %s", reply.Error)
	}
	return reply.Payload, nil
}

// replyFrame is the worker's answer: either an error string or a payload.
type replyFrame struct {
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// StreamServer is the worker side. It registers the DCS protocol handler on the
// node's host and dispatches verified envelopes to the Agent.
type StreamServer struct {
	host   host.Host
	agent  *Agent
	self   string
	replay ReplayGuard
	now    func() time.Time
}

// NewStreamServer wires the agent to the host. Call Start to register the
// handler; the host is the same one the storage protocol runs on.
func NewStreamServer(h host.Host, agent *Agent, selfNodeID string) *StreamServer {
	return &StreamServer{
		host: h, agent: agent, self: selfNodeID,
		replay: NewMemReplayGuard(), now: time.Now,
	}
}

func (s *StreamServer) Start() {
	s.host.SetStreamHandler(protocol.ID(ProtocolID), s.handle)
}

func (s *StreamServer) Stop() {
	s.host.RemoveStreamHandler(protocol.ID(ProtocolID))
}

func (s *StreamServer) handle(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(90 * time.Second))
	reader := bufio.NewReader(stream)

	var env Envelope
	if err := readFrame(reader, &env); err != nil {
		_ = writeFrame(stream, replyFrame{Error: "invalid request frame"})
		return
	}

	// The stream is already authenticated at the libp2p layer, but the envelope
	// signature is verified regardless: it authenticates the REQUEST, binds the
	// operation id for idempotency, and makes the audit entry independently
	// checkable. Defence in depth, and the audit record needs it.
	if err := env.Verify(s.self, s.now(), s.replay); err != nil {
		_ = writeFrame(stream, replyFrame{Error: err.Error()})
		return
	}

	// A stream whose libp2p peer is not the envelope's claimed sender is a
	// mismatch we refuse: someone relayed a validly-signed envelope they did
	// not originate. The signature still proves the ORIGINAL author, but for a
	// mutating operation we require the connection itself to be that author.
	if stream.Conn().RemotePeer().String() != env.FromNode {
		_ = writeFrame(stream, replyFrame{Error: "stream peer does not match envelope sender"})
		return
	}

	reply, err := s.dispatch(stream, env)
	if err != nil {
		_ = writeFrame(stream, replyFrame{Error: err.Error()})
		return
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		_ = writeFrame(stream, replyFrame{Error: "internal error"})
		return
	}
	_ = writeFrame(stream, replyFrame{Payload: raw})
}

func (s *StreamServer) dispatch(stream network.Stream, env Envelope) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	switch env.Method {
	case MethodPing:
		return map[string]string{"pong": s.self}, nil
	case MethodLaunch:
		return s.agent.HandleLaunch(ctx, env)
	case MethodDestroy:
		if err := s.agent.HandleDestroy(ctx, env); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, nil
	case MethodStatus:
		var body struct {
			Ticket string `json:"ticket"`
		}
		_ = env.Bind(&body)
		reply, ok := s.agent.HandleQueueStatus(body.Ticket)
		if !ok {
			return nil, fmt.Errorf("dcs: no such ticket")
		}
		return reply, nil
	default:
		return nil, fmt.Errorf("dcs: unknown method %q", env.Method)
	}
}

// ---------------------------------------------------------------------------
// Framing: 4-byte big-endian length prefix + JSON body. Identical in shape to
// the storage protocol's framing so the two are easy to reason about together.
// ---------------------------------------------------------------------------

func writeFrame(w io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) > maxFrameBytes {
		return errors.New("dcs: frame exceeds maximum size")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readFrame(r *bufio.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxFrameBytes {
		return errors.New("dcs: frame exceeds maximum size")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, target)
}
