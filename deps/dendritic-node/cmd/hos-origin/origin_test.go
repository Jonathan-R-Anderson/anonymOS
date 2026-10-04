package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/rabbiit/maniwani/storage-client/internal/bootstrap"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	var out []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, big.NewInt(58), mod)
		out = append([]byte{base58Alphabet[mod.Int64()]}, out...)
	}
	for _, x := range b {
		if x != 0 {
			break
		}
		out = append([]byte{'1'}, out...)
	}
	return string(out)
}

// peerIDFor builds a libp2p peer ID for an Ed25519 key: identity multihash of the protobuf key.
func peerIDFor(pub ed25519.PublicKey) string {
	msg := append([]byte{0x08, 0x01, 0x12, 0x20}, pub...)
	return base58Encode(append([]byte{0x00, byte(len(msg))}, msg...))
}

func newCoord(t *testing.T) (*Coordinator, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewCoordinator(priv, []string{"/axon/" + strings.Repeat("a", 56) + "/p2p/12D3KooWseed"}, store), pub
}

func signedHeartbeat(t *testing.T, nodeKey ed25519.PrivateKey, ts int64, nonce string) ([]byte, string, string) {
	id := peerIDFor(nodeKey.Public().(ed25519.PublicKey))
	body, _ := json.Marshal(map[string]any{"version": 1, "node_id": id, "timestamp": ts, "nonce": nonce,
		"capacity_bytes": int64(1 << 30), "platform": "anonymos/amd64", "axon_address": strings.Repeat("b", 56) + ".key.axon"})
	sig := strings.TrimRight(base64.StdEncoding.EncodeToString(ed25519.Sign(nodeKey, body)), "=")
	return body, id, sig
}

func TestPeerIDRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	got, err := peerPublicKey(peerIDFor(pub))
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("peerPublicKey: %v", err)
	}
}

func TestHeartbeatValidAndReplayRefused(t *testing.T) {
	c, _ := newCoord(t)
	_, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
	body, id, sig := signedHeartbeat(t, nodeKey, time.Now().Unix(), "0123456789abcdef0123")
	hb, err := c.ValidateHeartbeat(body, id, sig, storageUserAgent)
	if err != nil {
		t.Fatalf("valid heartbeat refused: %v", err)
	}
	c.Record(hb)
	if c.ActiveCount() != 1 {
		t.Fatalf("active = %d", c.ActiveCount())
	}
	if _, err := c.ValidateHeartbeat(body, id, sig, storageUserAgent); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	peers := c.LivePeers(3, "")
	if len(peers) != 1 || !reBootstrap.MatchString(peers[0]) {
		t.Fatalf("live peers = %v", peers)
	}
}

func TestHeartbeatRefusals(t *testing.T) {
	c, _ := newCoord(t)
	_, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	body, id, sig := signedHeartbeat(t, nodeKey, time.Now().Unix(), "aaaaaaaaaaaaaaaaaaaa")
	if _, err := c.ValidateHeartbeat(body, id, sig, "curl/8"); err == nil {
		t.Error("wrong user agent accepted")
	}
	tampered := bytes.Replace(body, []byte(`"anonymos/amd64"`), []byte(`"anonymos/arm64"`), 1)
	if _, err := c.ValidateHeartbeat(tampered, id, sig, storageUserAgent); err == nil {
		t.Error("tampered body accepted")
	}
	_, _, otherSig := signedHeartbeat(t, otherKey, time.Now().Unix(), "aaaaaaaaaaaaaaaaaaaa")
	if _, err := c.ValidateHeartbeat(body, id, otherSig, storageUserAgent); err == nil {
		t.Error("signature by another key accepted")
	}
	old, oid, osig := signedHeartbeat(t, nodeKey, time.Now().Unix()-3600, "bbbbbbbbbbbbbbbbbbbb")
	if _, err := c.ValidateHeartbeat(old, oid, osig, storageUserAgent); err == nil {
		t.Error("hour-old heartbeat accepted")
	}
}

// verifyLikeNode checks a document with the node's own verifier: internal/bootstrap parses the
// served bytes and rebuilds the signed message from them, exactly as a joining node does.
func verifyLikeNode(raw []byte, pinned ed25519.PublicKey) (*bootstrap.Document, error) {
	doc, rawExpires, err := bootstrap.Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := bootstrap.Verify(doc, rawExpires, base64.StdEncoding.EncodeToString(pinned)); err != nil {
		return nil, err
	}
	if time.Now().After(doc.ExpiresAt) {
		return nil, fmt.Errorf("expired")
	}
	return doc, nil
}

func TestBootstrapDocumentVerifies(t *testing.T) {
	c, coordPub := newCoord(t)
	relay := "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWE4cFJCDqC8j9u7P2ZvbFpXo2mQpdE95ojGCoSJPR8ofb"
	origin := "t2wjif2vwjmam26dhdjpi5uoy2vszh6ndhe4offhcaq6a3jhyc4yieyb.key.axon"
	c.SetOverlay([]string{relay, "not a relay"}, origin)
	srv := httptest.NewServer(func() http.Handler { m := http.NewServeMux(); c.Register(m); return m }())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/rabbiit/storage-node.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	doc, err := verifyLikeNode(raw, coordPub)
	if err != nil {
		t.Fatalf("bootstrap document: %v", err)
	}
	if len(doc.Peers) != 1 || len(doc.Relays) != 1 || doc.Relays[0] != relay || doc.Origin != origin {
		t.Fatalf("peers = %v, relays = %v, origin = %q", doc.Peers, doc.Relays, doc.Origin)
	}
	var tampered map[string]any
	json.Unmarshal(raw, &tampered)
	tampered["relays"] = []string{"/ip4/198.51.100.66/tcp/4001/p2p/12D3KooWevil"}
	forged, _ := json.Marshal(tampered)
	if _, err := verifyLikeNode(forged, coordPub); err == nil {
		t.Fatal("a document with a swapped relay still verified")
	}
	json.Unmarshal(raw, &tampered)
	tampered["peers"] = append(doc.Peers, "/axon/"+strings.Repeat("c", 56)+"/p2p/12D3KooWevil")
	forged, _ = json.Marshal(tampered)
	if _, err := verifyLikeNode(forged, coordPub); err == nil {
		t.Fatal("a peer list with an added peer still verified")
	}
}

func TestCrashSchemaRefusesUnknownFields(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	ci := NewCrashIntake(store)
	m := http.NewServeMux()
	ci.Register(m)
	srv := httptest.NewServer(m)
	defer srv.Close()
	good := `{"report_id":"0123456789abcdef0123456789abcdef","os_version":"0.2.0","program":"wl-files",` +
		`"build_id":"ab12","kind":"segfault","code":11,"frames":["wl-files+0x1a2b"],"uptime_min":42}`
	resp, _ := http.Post(srv.URL+"/api/v1/crash", "application/json", strings.NewReader(good))
	if resp.StatusCode != 200 {
		t.Fatalf("good report: %d", resp.StatusCode)
	}
	leaky := strings.Replace(good, `"uptime_min":42`, `"uptime_min":42,"hostname":"alice-laptop"`, 1)
	resp, _ = http.Post(srv.URL+"/api/v1/crash", "application/json", strings.NewReader(leaky))
	if resp.StatusCode != 400 {
		t.Fatalf("report with an unknown field: %d (must be refused)", resp.StatusCode)
	}
	path := strings.Replace(good, `"wl-files+0x1a2b"`, `"/home/alice/x+0x1"`, 1)
	resp, _ = http.Post(srv.URL+"/api/v1/crash", "application/json", strings.NewReader(path))
	if resp.StatusCode != 400 {
		t.Fatalf("report with a path in a frame: %d (must be refused)", resp.StatusCode)
	}
}
