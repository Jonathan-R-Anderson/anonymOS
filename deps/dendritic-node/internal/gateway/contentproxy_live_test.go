package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Opt-in check against the real origin. Skipped by default: the unit tests own
// the behaviour, and a suite that fails when a remote host is down is a suite
// people learn to ignore.
//
//	SYNDICHAN_LIVE_ORIGIN=51.79.71.153:443 go test ./internal/gateway/ -run Live -v
//
// What it proves that the unit tests cannot: the origin's signature headers
// survive a real fetch, and the body still hashes to what the signature covers.
// If a gateway broke either, a reader's verification would fail and the gateway
// would be blamed for the origin's content being unverifiable.
func TestLiveOriginContentSurvivesTheProxy(t *testing.T) {
	address := os.Getenv("SYNDICHAN_LIVE_ORIGIN")
	if address == "" {
		t.Skip("set SYNDICHAN_LIVE_ORIGIN=host:port to run")
	}
	origin, err := url.Parse("https://syndichan.org")
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewContentProxy(origin, "syndichan.org", "12D3KooWLiveTest", address)

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	for _, header := range []string{"X-Syndichan-Version", "X-Syndichan-Hash", "X-Syndichan-Signature"} {
		if recorder.Header().Get(header) == "" {
			t.Errorf("%s did not survive the proxy; the reader has nothing to verify", header)
		}
	}
	if got := recorder.Header().Get("X-Syndichan-Gateway"); got != "12D3KooWLiveTest" {
		t.Errorf("gateway header = %q, want this gateway's identity", got)
	}
	if !strings.Contains(recorder.Body.String(), "<") {
		t.Error("body does not look like a document")
	}
	// The property everything else rests on. The origin signs the UNCOMPRESSED
	// body, and Go's transport negotiates and transparently decompresses gzip on
	// our behalf — so if that ever stopped lining up, the bytes a reader
	// received would not hash to the signed value, every reader through this
	// gateway would see a mismatch, and the gateway would be blamed for content
	// it relayed faithfully.
	digest := sha256.Sum256(recorder.Body.Bytes())
	if got, want := hex.EncodeToString(digest[:]), recorder.Header().Get("X-Syndichan-Hash"); got != want {
		t.Fatalf("proxied body hash = %s, signed hash = %s: a reader would see a "+
			"forgery that never happened", got, want)
	}
	t.Logf("version=%s hash=%s bytes=%d",
		recorder.Header().Get("X-Syndichan-Version"),
		recorder.Header().Get("X-Syndichan-Hash"),
		recorder.Body.Len())
}
