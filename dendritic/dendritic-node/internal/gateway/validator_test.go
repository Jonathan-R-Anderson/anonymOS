package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A validator's receipts are the only ones eligible for quorum, so the ways it
// could put a WRONG receipt into that pool matter more than the happy path.

type capturedReport struct {
	Gateway      string `json:"gateway"`
	ObjectKey    string `json:"object_key"`
	Result       string `json:"result"`
	ObserverKind string `json:"observer_kind"`
	ObserverKey  string `json:"observer_key"`
	Signature    string `json:"signature"`
	ObjectHash   string `json:"object_hash"`
	Version      int64  `json:"version"`
}

func hashOf(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func hostOf(rawURL string) string {
	return strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
}

// signedGateway serves `body` under a genuine origin signature over `signed`.
// Passing different values is exactly what a tampering gateway does: a real
// signature attached to bytes it does not cover.
func signedGateway(t *testing.T, private ed25519.PrivateKey, signed, body []byte,
	nodeID string) *httptest.Server {
	t.Helper()
	message := []byte("syndichan-object:v1\n/\n1\n" + hashOf(signed))
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Syndichan-Version", "1")
		w.Header().Set("X-Syndichan-Signature", signature)
		if nodeID != "" {
			w.Header().Set("X-Syndichan-Gateway", nodeID)
		}
		_, _ = w.Write(body)
	}))
}

// fakeOrigin publishes the signing key and directories, and collects receipts.
func fakeOrigin(t *testing.T, public ed25519.PublicKey, entries []map[string]any) (
	*httptest.Server, func() []capturedReport) {
	t.Helper()
	var mu sync.Mutex
	reports := []capturedReport{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/syndichan/origin-key.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"public_key": base64.StdEncoding.EncodeToString(public), "signing": true})
	})
	mux.HandleFunc("/api/v1/gateways", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(entries)
	})
	mux.HandleFunc("/api/v1/gateway/spot-checks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects": []map[string]any{{"object_key": "/", "version": 1}}})
	})
	mux.HandleFunc("/api/v1/gateway/audit", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var report capturedReport
		_ = json.Unmarshal(raw, &report)
		mu.Lock()
		reports = append(reports, report)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	server := httptest.NewServer(mux)
	return server, func() []capturedReport {
		mu.Lock()
		defer mu.Unlock()
		return append([]capturedReport(nil), reports...)
	}
}

// auditOnce runs a single round against a TLS gateway, trusting its test cert.
func auditOnce(t *testing.T, signer Signer, origin string, gateway *httptest.Server) {
	t.Helper()
	validator := NewValidator(signer, origin, nil, 1)
	validator.SampleSize = 1
	// Trust the test certificate while keeping the validator's own timeout and
	// redirect policy, which are part of what is under test.
	validator.client.Transport = gateway.Client().Transport
	if err := validator.round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
}

func TestValidatorReportsAlteredBytesAsMismatch(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	real := []byte("<html>real</html>")
	gateway := signedGateway(t, private, real, []byte("<html>ALTERED</html>"), "12D3KooWTarget")
	defer gateway.Close()

	origin, collected := fakeOrigin(t, public, []map[string]any{
		{"node_id": "12D3KooWTarget", "hostname": hostOf(gateway.URL), "healthy": true}})
	defer origin.Close()

	auditOnce(t, newTestSigner(t), origin.URL, gateway)

	reports := collected()
	if len(reports) != 1 {
		t.Fatalf("expected one receipt, got %d", len(reports))
	}
	if reports[0].Result != "mismatch" {
		t.Errorf("result = %q, want mismatch: the gateway served bytes the "+
			"origin signature does not cover", reports[0].Result)
	}
	if reports[0].Gateway != "12D3KooWTarget" {
		t.Errorf("receipt attributed to %q", reports[0].Gateway)
	}
}

func TestValidatorReportsHonestContentAsPass(t *testing.T) {
	// Guards the test above: a validator that reported "mismatch" for
	// everything would pass it while being useless.
	public, private, _ := ed25519.GenerateKey(nil)
	real := []byte("<html>real</html>")
	gateway := signedGateway(t, private, real, real, "12D3KooWTarget")
	defer gateway.Close()

	origin, collected := fakeOrigin(t, public, []map[string]any{
		{"node_id": "12D3KooWTarget", "hostname": hostOf(gateway.URL), "healthy": true}})
	defer origin.Close()

	auditOnce(t, newTestSigner(t), origin.URL, gateway)

	reports := collected()
	if len(reports) != 1 || reports[0].Result != "pass" {
		t.Fatalf("honest content was not reported as pass: %+v", reports)
	}
}

func TestValidatorSignsReceiptsWithItsOwnIdentity(t *testing.T) {
	// Unsigned, a validator receipt is worth no more than a stranger's: the
	// origin demotes any validator claim it cannot tie to a registered key.
	public, private, _ := ed25519.GenerateKey(nil)
	real := []byte("<html>real</html>")
	gateway := signedGateway(t, private, real, real, "12D3KooWTarget")
	defer gateway.Close()

	origin, collected := fakeOrigin(t, public, []map[string]any{
		{"node_id": "12D3KooWTarget", "hostname": hostOf(gateway.URL), "healthy": true}})
	defer origin.Close()

	signer := newTestSigner(t)
	auditOnce(t, signer, origin.URL, gateway)

	reports := collected()
	if len(reports) != 1 {
		t.Fatalf("expected one receipt, got %d", len(reports))
	}
	report := reports[0]
	if report.ObserverKind != "validator" {
		t.Errorf("observer_kind = %q", report.ObserverKind)
	}
	key, err := base64.StdEncoding.DecodeString(report.ObserverKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatalf("observer_key is not an Ed25519 public key: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(report.Signature)
	if err != nil {
		t.Fatal(err)
	}
	// The signature must cover every field that gives the receipt meaning, or
	// it could be lifted onto a different observation in the same name.
	message := []byte(strings.Join([]string{
		"syndichan-audit:v1", report.Gateway, report.ObjectKey, "1",
		report.ObjectHash, report.Result}, "\n"))
	if !ed25519.Verify(key, message, signature) {
		t.Error("receipt signature does not verify over the canonical message")
	}
}

func TestValidatorNeverAuditsItself(t *testing.T) {
	// A gateway confirming its own honesty is not evidence, and a self-signed
	// "pass" would land in the very pool the quorum draws from.
	signer := newTestSigner(t)
	public, _, _ := ed25519.GenerateKey(nil)

	origin, collected := fakeOrigin(t, public, []map[string]any{
		{"node_id": signer.ID(), "hostname": "self.example.com", "healthy": true}})
	defer origin.Close()

	validator := NewValidator(signer, origin.URL, nil, 1)
	validator.SampleSize = 1
	_ = validator.round(context.Background())

	if reports := collected(); len(reports) != 0 {
		t.Errorf("the validator filed %d receipt(s) about itself", len(reports))
	}
}

func TestValidatorFlagsAGatewayClaimingAnotherIdentity(t *testing.T) {
	// A gateway that answers under someone else's node id would file its own
	// misbehaviour under a rival's key if taken at its word.
	public, private, _ := ed25519.GenerateKey(nil)
	real := []byte("<html>real</html>")
	gateway := signedGateway(t, private, real, real, "12D3KooWSomeoneElse")
	defer gateway.Close()

	origin, collected := fakeOrigin(t, public, []map[string]any{
		{"node_id": "12D3KooWTarget", "hostname": hostOf(gateway.URL), "healthy": true}})
	defer origin.Close()

	auditOnce(t, newTestSigner(t), origin.URL, gateway)

	reports := collected()
	if len(reports) != 1 {
		t.Fatalf("expected one receipt, got %d", len(reports))
	}
	if reports[0].Gateway != "12D3KooWTarget" {
		t.Errorf("receipt filed against %q, not the gateway that was asked",
			reports[0].Gateway)
	}
	if reports[0].Result != "mismatch" {
		t.Errorf("result = %q; a gateway answering under another identity "+
			"should not read as honest service", reports[0].Result)
	}
}

func TestValidatorSkipsUnhealthyGateways(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(nil)
	origin, collected := fakeOrigin(t, public, []map[string]any{
		{"node_id": "12D3KooWTarget", "hostname": "down.example.com", "healthy": false}})
	defer origin.Close()

	validator := NewValidator(newTestSigner(t), origin.URL, nil, 1)
	validator.SampleSize = 1
	_ = validator.round(context.Background())

	if reports := collected(); len(reports) != 0 {
		t.Errorf("audited a gateway the directory reported unhealthy")
	}
}
