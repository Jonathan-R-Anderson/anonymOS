package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime/runtimetest"
	axontransport "github.com/rabbiit/maniwani/storage-client/internal/axon/transport"
	"github.com/rabbiit/maniwani/storage-client/internal/store"
)

// heartbeatSink points the presence beacon at a local server for the test and
// returns what it received.
func heartbeatSink(t *testing.T) <-chan map[string]any {
	t.Helper()
	got := make(chan map[string]any, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		body["_user_agent"] = r.Header.Get("User-Agent")
		select {
		case got <- body:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"active_nodes":1}`)
	}))
	t.Cleanup(server.Close)
	previous := heartbeatEndpoint
	heartbeatEndpoint = server.URL
	t.Cleanup(func() { heartbeatEndpoint = previous })
	return got
}

func openOverlayNode(t *testing.T, seeds []string, origin string) (*Node, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	storage, err := store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	node, err := Open(ctx, dir, Overlay{Runtime: runtimetest.Client(t, seeds), Origin: origin},
		storage, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	return node, storage
}

// The production node's only address is its AXON service: nothing an IP could
// be read from, and its heartbeat reports that address for others to dial.
func TestProductionNodeAdvertisesOnlyAxon(t *testing.T) {
	beats := heartbeatSink(t)
	seeds := runtimetest.Network(t, 6)
	node, _ := openOverlayNode(t, seeds, "")

	addresses := node.Addresses()
	if len(addresses) != 1 || !strings.HasPrefix(addresses[0], "/axon/") {
		t.Fatalf("production node exposed non-AXON addresses: %v", addresses)
	}
	joined := strings.Join(addresses, " ")
	if strings.Contains(joined, "/ip4/") || strings.Contains(joined, "/ip6/") ||
		strings.Contains(joined, "/garlic32/") {
		t.Fatalf("production node leaked a non-overlay address: %v", addresses)
	}
	if !strings.HasSuffix(node.AxonAddress(), ".key.axon") {
		t.Fatalf("AxonAddress = %q", node.AxonAddress())
	}
	select {
	case body := <-beats:
		if body["_user_agent"] != StorageUserAgent {
			t.Fatalf("heartbeat User-Agent is %v, want %q", body["_user_agent"], StorageUserAgent)
		}
		if body["axon_address"] != node.AxonAddress() {
			t.Fatalf("heartbeat reported %v, want %s", body["axon_address"], node.AxonAddress())
		}
		if _, ok := body["i2p_destination"]; ok {
			t.Fatal("heartbeat still carries an I2P destination")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("storage heartbeat was not sent")
	}
}

// Two production nodes that know each other only by /axon address find each
// other through the overlay and move an encrypted shard under a lease -- the
// path every dispersal takes.
func TestShardTransferOverAxon(t *testing.T) {
	heartbeatSink(t)
	seeds := runtimetest.Network(t, 6)
	source, sourceStore := openOverlayNode(t, seeds, "")
	target, targetStore := openOverlayNode(t, seeds, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	source.connectBootstrapPeers(ctx, target.Addresses())
	conns := source.host.Network().ConnsToPeer(target.host.ID())
	if len(conns) == 0 {
		t.Fatal("source did not reach the target through AXON")
	}
	if !axontransport.IsAxonAddr(conns[0].RemoteMultiaddr()) {
		t.Fatalf("connection is not over AXON: %s", conns[0].RemoteMultiaddr())
	}

	if err := sourceStore.CreateBucket("transfer-test"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("transfer-test", "object.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{1, 3, 3, 7}, 1000)))
	if err != nil {
		t.Fatal(err)
	}
	ref := manifest.Chunks[0].Shards[0]
	value, err := sourceStore.ReadShard(ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target.coordKey = publicKey
	lease := &Lease{Version: 1, ObjectID: manifest.ObjectID, ShardID: ref.ID,
		Size: int64(len(value)), Recipient: target.ID(), ExpiresAt: time.Now().Unix() + 300}
	lease.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, leaseMessage(*lease)))
	if err := source.storeOnPeer(ctx, target.host.ID(), manifest.ObjectID, ref.ID, value, lease); err != nil {
		t.Fatal(err)
	}
	stored, err := targetStore.ReadShard(ref.ID)
	if err != nil || !bytes.Equal(stored, value) {
		t.Fatalf("transferred shard differs: %v", err)
	}
}

// Coordinator calls reach the origin's AXON service, not the clearnet host in
// their URL -- and the origin can still tell which name was asked for.
func TestCoordinatorCallsGoToTheOriginOverAxon(t *testing.T) {
	heartbeatSink(t)
	seeds := runtimetest.Network(t, 6)

	originRT := runtimetest.Client(t, seeds)
	var seed [32]byte
	rand.Read(seed[:])
	service, err := originRT.Listen(seed)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	go http.Serve(service.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host+r.URL.Path)
		mu.Unlock()
		io.WriteString(w, "origin")
	}))

	node, _ := openOverlayNode(t, seeds, "")
	if node.coordinatorHTTP() != node.directHTTP {
		t.Fatal("with no origin known, coordinator calls must go direct")
	}
	// The bootstrap document names the origin; the node adopts it.
	node.useOrigin(service.Addr())
	client := node.coordinatorHTTP()
	if client == node.directHTTP {
		t.Fatal("the origin named by the bootstrap document was not adopted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://rabbiit.io"+leasePath, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("lease endpoint through AXON: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "origin" {
		t.Fatalf("answered by %q, not the origin service", body)
	}
	// The node's own bootstrap loop may also have fetched the document through
	// the origin by now, which is the same path working; the lease call is the
	// one this test made.
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, s := range seen {
		found = found || s == "rabbiit.io"+leasePath
	}
	if !found {
		t.Fatalf("origin saw %v, not the lease request", seen)
	}
}

// An operator-configured origin wins over one a document names.
func TestConfiguredOriginIsNotReplacedByTheDocument(t *testing.T) {
	heartbeatSink(t)
	seeds := runtimetest.Network(t, 6)
	var a, b [32]byte
	rand.Read(a[:])
	rand.Read(b[:])
	rt := runtimetest.Client(t, seeds)
	configured, err := rt.Listen(a)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rt.Listen(b)
	if err != nil {
		t.Fatal(err)
	}
	node, _ := openOverlayNode(t, seeds, configured.Addr())
	before := node.coordinatorHTTP()
	node.useOrigin(other.Addr())
	if node.coordinatorHTTP() != before || node.overlay.Origin != configured.Addr() {
		t.Fatal("a bootstrap document replaced the operator's configured origin")
	}
}
