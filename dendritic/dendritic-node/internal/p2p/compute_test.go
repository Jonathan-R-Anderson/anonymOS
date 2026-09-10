package p2p

// What these tests are for, in one line each:
//
//   - a compute frame really crosses the protocol and brings back the node's
//     own answer, not a shape invented on the way;
//   - a malformed compute frame is answered instantly and costs storage
//     nothing, even while a store is in flight on the same node;
//   - a decline is reported as a decline and unreachability as unreachability,
//     because the site charges a job differently for each;
//   - the payload cap is enforced by the RECEIVER, which is the only side an
//     attacker does not control.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// computeTestNode opens a plain TCP node. Not I2P: what is under test is the
// protocol, and a garlic tunnel would add minutes of setup to prove nothing
// about the frames.
func computeTestNode(t *testing.T, ctx context.Context) (*Node, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	storage, err := store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, storage,
		log.New(io.Discard, "", 0), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	return node, storage
}

func connectNodes(t *testing.T, ctx context.Context, from, to *Node) {
	t.Helper()
	if err := from.host.Connect(ctx, peer.AddrInfo{ID: to.host.ID(), Addrs: to.host.Addrs()}); err != nil {
		t.Fatal(err)
	}
}

// A compute frame reaches the handler and returns the node's REAL answer:
// the status it chose, the body it wrote, and the request it was actually given.
func TestAComputeFrameReachesTheHandlerAndReturnsItsAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	site, _ := computeTestNode(t, ctx)
	volunteer, _ := computeTestNode(t, ctx)
	connectNodes(t, ctx, site, volunteer)

	var sawOperation, sawRequest string
	var sawFrom peer.ID
	volunteer.SetComputeHandler(func(_ context.Context, from peer.ID, operation string, payload []byte) (int, []byte) {
		sawOperation, sawRequest, sawFrom = operation, string(payload), from
		return http.StatusOK, []byte(`{"admitted":true}`)
	})

	status, body, err := site.SendCompute(ctx, volunteer.host.ID(), ComputeAdmit,
		[]byte(`{"device":"cpu","workload":"embed"}`))
	if err != nil {
		t.Fatalf("the frame never reached the handler: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("got status %d, want 200", status)
	}
	if string(body) != `{"admitted":true}` {
		t.Fatalf("the node's answer came back as %q", body)
	}
	if sawOperation != ComputeAdmit {
		t.Fatalf("handler saw operation %q", sawOperation)
	}
	if sawRequest != `{"device":"cpu","workload":"embed"}` {
		t.Fatalf("handler saw request %q", sawRequest)
	}
	// The submitter's identity comes from the connection, so the handler can
	// scope a job to whoever actually asked for it.
	if sawFrom != site.host.ID() {
		t.Fatalf("handler saw the request as coming from %s, want %s", sawFrom, site.host.ID())
	}
}

// A node that lends nothing DECLINES rather than falling silent, and the
// decline carries a body the caller can read.
func TestANodeWithoutComputeDeclinesRatherThanIgnoring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	site, _ := computeTestNode(t, ctx)
	volunteer, _ := computeTestNode(t, ctx)
	connectNodes(t, ctx, site, volunteer)

	status, body, err := site.SendCompute(ctx, volunteer.host.ID(), ComputeAdmit, []byte(`{}`))
	if err != nil {
		t.Fatalf("a node that lends no compute must ANSWER, not fail to be reached: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want 503", status)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the refusal was not readable JSON: %q", body)
	}
	if decoded["admitted"] != false || decoded["retryable"] != false {
		t.Fatalf("the refusal did not say it was one, and permanent: %s", body)
	}
}

// A REFUSAL is not unreachability. The node answered 503 and the caller must be
// able to tell that apart from never having got an answer.
func TestARefusalComesBackAsAnAnswerNotAsAFailedDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	site, _ := computeTestNode(t, ctx)
	volunteer, _ := computeTestNode(t, ctx)
	connectNodes(t, ctx, site, volunteer)

	volunteer.SetComputeHandler(func(context.Context, peer.ID, string, []byte) (int, []byte) {
		return http.StatusServiceUnavailable,
			[]byte(`{"admitted":false,"reason":"the machine is warm","retryable":true}`)
	})

	status, body, err := site.SendCompute(ctx, volunteer.host.ID(), ComputeAdmit, []byte(`{}`))
	if err != nil {
		t.Fatalf("a declining node was reported as unreachable: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want the node's own 503", status)
	}
	if !strings.Contains(string(body), "the machine is warm") {
		t.Fatalf("the node's own reason was lost: %q", body)
	}
}

// UNREACHABILITY is not a refusal. A peer that cannot be dialled produces an
// error and no status, so nothing downstream can mistake it for a considered no.
func TestAnUnreachablePeerIsAnErrorAndNotAStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	site, _ := computeTestNode(t, ctx)
	// A node that exists and is then closed: a real peer id with nothing behind
	// it, which is what a volunteer whose router went down looks like.
	gone, _ := computeTestNode(t, ctx)
	goneID := gone.host.ID()
	if err := gone.Close(); err != nil {
		t.Fatal(err)
	}

	status, body, err := site.SendCompute(ctx, goneID, ComputeAdmit, []byte(`{}`))
	if err == nil {
		t.Fatalf("an unreachable peer answered with status %d and %q", status, body)
	}
	if status != 0 {
		t.Fatalf("an unreachable peer produced status %d; a status means the peer spoke", status)
	}
}

// A malformed compute frame must be answered at once and must not disturb the
// storage traffic sharing the protocol.
//
// The frame here announces a payload far over the cap and then sends none of
// it. Without the receiver's size check the handler would sit in ReadFull until
// the stream deadline — holding a stream and 64 MB of allocation on a stranger's
// say-so — and this test would time out waiting for its answer while the store
// it runs alongside is still expected to complete untouched.
func TestAMalformedComputeFrameDoesNotDisturbAConcurrentStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	site, siteStore := computeTestNode(t, ctx)
	volunteer, volunteerStore := computeTestNode(t, ctx)
	connectNodes(t, ctx, site, volunteer)
	volunteer.SetComputeHandler(func(context.Context, peer.ID, string, []byte) (int, []byte) {
		t.Error("a frame the receiver should have refused reached the handler")
		return http.StatusOK, []byte(`{}`)
	})

	// A real shard to store across the same protocol, at the same time.
	if err := siteStore.CreateBucket("compute-coexist"); err != nil {
		t.Fatal(err)
	}
	manifest, err := siteStore.PutObject("compute-coexist", "object.bin",
		"application/octet-stream", bytes.NewReader(bytes.Repeat([]byte{7, 3, 1}, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	ref := manifest.Chunks[0].Shards[0]
	value, err := siteStore.ReadShard(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	volunteer.coordKey = publicKey
	lease := &Lease{
		Version: 1, ObjectID: manifest.ObjectID, ShardID: ref.ID,
		Size: int64(len(value)), Recipient: volunteer.ID(), ExpiresAt: time.Now().Unix() + 300,
	}
	lease.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, leaseMessage(*lease)))

	var wg sync.WaitGroup
	var storeErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		storeErr = site.storeOnPeer(ctx, volunteer.host.ID(), manifest.ObjectID, ref.ID, value, lease)
	}()

	// The malformed frame, written by hand because SendCompute would refuse to
	// send it — the point is what the RECEIVER does with a size it did not choose.
	answered := make(chan responseHeader, 1)
	go func() {
		stream, err := site.host.NewStream(ctx, volunteer.host.ID(), ProtocolID)
		if err != nil {
			t.Error(err)
			return
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
		if err := writeJSONFrame(stream, requestHeader{
			Operation: ComputeSubmit, Size: MaxComputePayload * 2,
		}); err != nil {
			t.Error(err)
			return
		}
		var reply responseHeader
		if err := readJSONFrame(bufio.NewReader(stream), &reply); err != nil {
			t.Error(err)
			return
		}
		answered <- reply
	}()

	select {
	case reply := <-answered:
		if reply.Status != http.StatusRequestEntityTooLarge {
			t.Fatalf("an oversized frame got status %d, want 413", reply.Status)
		}
		if !reply.Refused {
			t.Fatal("an oversized frame was not marked refused")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an oversized compute frame was never answered — the receiver " +
			"waited for a payload a stranger promised and did not send")
	}

	wg.Wait()
	if storeErr != nil {
		t.Fatalf("a store sharing the protocol with a malformed compute frame failed: %v", storeErr)
	}
	if stored, err := volunteerStore.ReadShard(ref.ID); err != nil {
		t.Fatalf("the shard did not survive: %v", err)
	} else if !bytes.Equal(stored, value) {
		t.Fatal("the stored shard differs from what was sent")
	}
	// And the protocol still works afterwards, for storage and for compute.
	if fetched, err := site.fetchFromPeer(ctx, volunteer.host.ID(), ref.ID); err != nil {
		t.Fatalf("a get after a malformed compute frame failed: %v", err)
	} else if !bytes.Equal(fetched, value) {
		t.Fatal("the fetched shard differs")
	}
}

// An operation this build has never heard of falls to the switch's default and
// is told so. It must NOT be swallowed by the compute branch, which is what a
// prefix match on "compute-" would do — the caller would then get a compute
// refusal for a verb compute knows nothing about.
func TestAnUnknownComputeLikeOperationIsStillUnsupported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	site, _ := computeTestNode(t, ctx)
	volunteer, _ := computeTestNode(t, ctx)
	connectNodes(t, ctx, site, volunteer)
	volunteer.SetComputeHandler(func(context.Context, peer.ID, string, []byte) (int, []byte) {
		t.Error("an operation compute does not define reached the compute handler")
		return http.StatusOK, []byte(`{}`)
	})

	stream, err := site.host.NewStream(ctx, volunteer.host.ID(), ProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(20 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{Operation: "compute-teleport"}); err != nil {
		t.Fatal(err)
	}
	var reply responseHeader
	if err := readJSONFrame(bufio.NewReader(stream), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Error != "unsupported operation" {
		t.Fatalf("got %+v, want the default branch's refusal", reply)
	}
}

// The payload cap is enforced by the RECEIVER — the only side an attacker does
// not control. The sender's own check is a courtesy; this one is the boundary.
func TestTheReceiverEnforcesTheComputePayloadCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	site, _ := computeTestNode(t, ctx)
	volunteer, _ := computeTestNode(t, ctx)
	connectNodes(t, ctx, site, volunteer)
	reached := false
	volunteer.SetComputeHandler(func(context.Context, peer.ID, string, []byte) (int, []byte) {
		reached = true
		return http.StatusOK, []byte(`{"accepted":true}`)
	})

	// One byte over, and the bytes are actually sent: this is not a lying header,
	// it is a job genuinely too big to accept.
	oversized := bytes.Repeat([]byte("x"), int(MaxComputePayload)+1)
	stream, err := site.host.NewStream(ctx, volunteer.host.ID(), ProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(60 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{
		Operation: ComputeSubmit, Size: int64(len(oversized)),
	}); err != nil {
		t.Fatal(err)
	}
	// Written from a goroutine: the receiver answers and stops reading, so a
	// blocking write of 32 MB into a closed window would deadlock the test.
	go func() { _, _ = stream.Write(oversized) }()

	var reply responseHeader
	if err := readJSONFrame(bufio.NewReader(stream), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized submit got status %d, want 413", reply.Status)
	}
	if reached {
		t.Fatal("an oversized submit was handed to the handler anyway")
	}

	// And an admit is held to the much smaller header cap, because a 32 MB
	// "would you take this?" is not a question, it is a way to make a node
	// allocate.
	if MaxComputeRequest(ComputeAdmit) != maxHeaderBytes {
		t.Fatalf("admit's cap is %d, want the header cap %d",
			MaxComputeRequest(ComputeAdmit), maxHeaderBytes)
	}
	if _, _, err := site.SendCompute(ctx, volunteer.host.ID(), ComputeAdmit,
		bytes.Repeat([]byte("x"), maxHeaderBytes+1)); err == nil {
		t.Fatal("an oversized admit was sent anyway")
	}
}

// A frame that lies about its size in the other direction — announcing a small
// payload and closing — is answered rather than leaving the stream hanging.
func TestAShortComputePayloadIsAnsweredNotAwaited(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	site, _ := computeTestNode(t, ctx)
	volunteer, _ := computeTestNode(t, ctx)
	connectNodes(t, ctx, site, volunteer)
	volunteer.SetComputeHandler(func(context.Context, peer.ID, string, []byte) (int, []byte) {
		return http.StatusOK, []byte(`{}`)
	})

	stream, err := site.host.NewStream(ctx, volunteer.host.ID(), ProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(20 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{Operation: ComputeSubmit, Size: 4096}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var reply responseHeader
	if err := readJSONFrame(bufio.NewReader(stream), &reply); err != nil {
		t.Fatalf("a truncated compute payload was never answered: %v", err)
	}
	if reply.Status != http.StatusBadRequest {
		t.Fatalf("a truncated payload got status %d, want 400", reply.Status)
	}
}

// A build that predates these verbs answers "unsupported operation" on the
// storage protocol. That is an ANSWER — the node said no — so it must surface
// as a permanent refusal and not as a peer nobody could reach, or the site would
// keep the job queued for a node that will never take it.
func TestAnOlderBuildsRefusalIsARefusalNotAFailedDial(t *testing.T) {
	answer := responseHeader{Error: "unsupported operation"}
	encoded, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	var framed bytes.Buffer
	if err := binary.Write(&framed, binary.BigEndian, uint32(len(encoded))); err != nil {
		t.Fatal(err)
	}
	framed.Write(encoded)

	var header responseHeader
	if err := readJSONFrame(bufio.NewReader(&framed), &header); err != nil {
		t.Fatal(err)
	}
	if header.Status != 0 {
		t.Fatalf("an old build's answer carried status %d", header.Status)
	}
	// The mapping SendCompute applies to exactly this shape.
	if header.Error == "" {
		t.Fatal("an old build's refusal carried no reason to pass on")
	}
	body := computeRefusalBody(header.Error)
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["retryable"] != false {
		t.Fatalf("an old build's refusal was marked worth retrying: %s", body)
	}
	if !strings.Contains(string(body), "unsupported operation") {
		t.Fatalf("the node's own words were lost: %s", body)
	}
}
