package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	return NewCoordinator(priv, []string{"/garlic32/" + strings.Repeat("a", 52) + "/p2p/12D3KooWseed"}, store), pub
}

func signedHeartbeat(t *testing.T, nodeKey ed25519.PrivateKey, ts int64, nonce string) ([]byte, string, string) {
	id := peerIDFor(nodeKey.Public().(ed25519.PublicKey))
	body, _ := json.Marshal(map[string]any{"version": 1, "node_id": id, "timestamp": ts, "nonce": nonce,
		"capacity_bytes": int64(1 << 30), "platform": "anonymos/amd64", "i2p_destination": strings.Repeat("b", 52)})
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

// verifyLikeNode re-checks a document the way the node's internal/bootstrap does: rebuild the
// signed message from the parsed fields and verify it against the pinned key.
func verifyLikeNode(doc bootstrapDocument, pinned ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return err
	}
	if doc.CoordinatorPublicKey != strings.TrimRight(base64.StdEncoding.EncodeToString(pinned), "=") {
		return fmt.Errorf("signed by an unexpected coordinator")
	}
	if !ed25519.Verify(pinned, BootstrapMessage(doc.Peers, doc.CoordinatorPublicKey, doc.ExpiresAt), sig) {
		return fmt.Errorf("signature did not verify")
	}
	exp, err := time.Parse(time.RFC3339Nano, doc.ExpiresAt)
	if err != nil || time.Now().After(exp) {
		return fmt.Errorf("expired or malformed expiry: %v", err)
	}
	return nil
}

func TestBootstrapDocumentVerifies(t *testing.T) {
	c, coordPub := newCoord(t)
	srv := httptest.NewServer(func() http.Handler { m := http.NewServeMux(); c.Register(m); return m }())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/syndichan/storage-node.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc bootstrapDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if err := verifyLikeNode(doc, coordPub); err != nil {
		t.Fatalf("bootstrap document: %v", err)
	}
	if len(doc.Peers) != 1 {
		t.Fatalf("peers = %v", doc.Peers)
	}
	doc.Peers = append(doc.Peers, "/garlic32/"+strings.Repeat("c", 52)+"/p2p/12D3KooWevil")
	if verifyLikeNode(doc, coordPub) == nil {
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
