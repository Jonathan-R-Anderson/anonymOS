package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"
)

// The three rules, which are the whole point of spreading bootstrap across
// gateways rather than trusting one host.

type captureLog struct{ lines []string }

func (c *captureLog) Printf(format string, v ...interface{}) {
	c.lines = append(c.lines, strings.ToLower(fmt.Sprintf(format, v...)))
}

func (c *captureLog) says(needle string) bool {
	for _, line := range c.lines {
		if strings.Contains(line, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

var testNow = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

func coordinator(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return private, base64.RawStdEncoding.EncodeToString(public)
}

// serveDoc stands up a source. `signer` nil means the document is unsigned.
func serveDoc(t *testing.T, signer ed25519.PrivateKey, publicKey string,
	peers []string, expires time.Time) *httptest.Server {
	t.Helper()
	raw := expires.Format(time.RFC3339)
	doc := map[string]interface{}{
		"version": 1, "peers": peers,
		"coordinator_public_key": publicKey, "expires_at": raw,
	}
	if signer != nil {
		doc["signature"] = base64.StdEncoding.EncodeToString(
			ed25519.Sign(signer, Message(peers, publicKey, raw)))
	}
	body, _ := json.Marshal(doc)
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }))
}

func urls(servers ...*httptest.Server) []string {
	var out []string
	for _, s := range servers {
		out = append(out, s.URL+DocumentPath)
	}
	return out
}

func fetch(t *testing.T, cfg Config, log Logger) (*Result, error) {
	t.Helper()
	return Fetch(context.Background(), nil, fakeResolver{}, cfg, log, testNow)
}

var peersA = []string{"/garlic32/aaaa/p2p/12D3KooWA", "/garlic32/bbbb/p2p/12D3KooWB"}
var peersEvil = []string{"/garlic32/evil/p2p/12D3KooWEvil"}

// --- rule 1: key pinned, one good gateway is enough ----------------------

func TestOneGoodGatewayIsEnoughWhenTheKeyIsPinned(t *testing.T) {
	signer, public := coordinator(t)
	good := serveDoc(t, signer, public, peersA, testNow.Add(time.Hour))
	defer good.Close()

	result, err := fetch(t, Config{CoordinatorKey: public, URLs: urls(good)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.Agreed != 1 {
		t.Fatalf("%+v", result)
	}
}

func TestAHostileGatewayCannotWinAgainstAPinnedKey(t *testing.T) {
	// Even outnumbered. This is why a signature is the first layer and
	// agreement is only the second: two forgers do not outvote one signature.
	signer, public := coordinator(t)
	good := serveDoc(t, signer, public, peersA, testNow.Add(time.Hour))
	defer good.Close()
	evilSigner, evilPublic := coordinator(t)
	evil1 := serveDoc(t, evilSigner, evilPublic, peersEvil, testNow.Add(time.Hour))
	defer evil1.Close()
	evil2 := serveDoc(t, evilSigner, evilPublic, peersEvil, testNow.Add(time.Hour))
	defer evil2.Close()

	log := &captureLog{}
	result, err := fetch(t, Config{CoordinatorKey: public,
		URLs: urls(evil1, evil2, good)}, log)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified {
		t.Fatal("the signed document did not win")
	}
	if result.Document.Peers[0] != peersA[0] {
		t.Fatalf("dialled the wrong peers: %v", result.Document.Peers)
	}
	if len(result.Disagreed) != 2 {
		t.Fatalf("the two forgers were not named: %+v", result.Disagreed)
	}
	if !log.says("refused") {
		t.Fatalf("refusal not logged: %v", log.lines)
	}
}

// --- rule 2: no key pinned, agreement is required ------------------------

func TestOneSourceIsNotEnoughWithoutAPinnedKey(t *testing.T) {
	// The behaviour this replaces was "believe whoever answered first".
	_, public := coordinator(t)
	only := serveDoc(t, nil, public, peersA, testNow.Add(time.Hour))
	defer only.Close()

	log := &captureLog{}
	result, err := fetch(t, Config{URLs: urls(only)}, log)
	if !errors.Is(err, ErrNoAgreement) {
		t.Fatalf("a lone unverifiable source was accepted: %v %+v", err, result)
	}
	if !log.says("no coordinator key is pinned") {
		t.Fatalf("the reason was not explained: %v", log.lines)
	}
}

func TestTwoAgreeingSourcesAreAcceptedWithoutAPinnedKey(t *testing.T) {
	_, public := coordinator(t)
	one := serveDoc(t, nil, public, peersA, testNow.Add(time.Hour))
	defer one.Close()
	two := serveDoc(t, nil, public, peersA, testNow.Add(2*time.Hour))
	defer two.Close()

	log := &captureLog{}
	result, err := fetch(t, Config{URLs: urls(one, two)}, log)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Fatal("corroborated was reported as verified")
	}
	if result.Agreed != 2 {
		t.Fatalf("agreement not counted: %+v", result)
	}
	// Different expiries, same claim -- must not read as disagreement.
	if len(result.Disagreed) != 0 {
		t.Fatalf("a fresh expiry was treated as disagreement: %+v", result.Disagreed)
	}
	if !log.says("corroborated rather than verified") {
		t.Fatalf("the weaker guarantee was not stated: %v", log.lines)
	}
}

func TestDisagreeingSourcesWithoutAPinnedKeyAreRefused(t *testing.T) {
	// Two sources, two different stories, nothing to tell them apart. The only
	// honest answer is to act on neither.
	_, public := coordinator(t)
	one := serveDoc(t, nil, public, peersA, testNow.Add(time.Hour))
	defer one.Close()
	_, otherPublic := coordinator(t)
	two := serveDoc(t, nil, otherPublic, peersEvil, testNow.Add(time.Hour))
	defer two.Close()

	if _, err := fetch(t, Config{URLs: urls(one, two)}, nil); !errors.Is(err, ErrNoAgreement) {
		t.Fatalf("acted on a split answer: %v", err)
	}
}

// --- rule 3: disagreement is evidence ------------------------------------

func TestDisagreementIsNamedNotJustIgnored(t *testing.T) {
	signer, public := coordinator(t)
	good := serveDoc(t, signer, public, peersA, testNow.Add(time.Hour))
	defer good.Close()
	liar := serveDoc(t, signer, public, peersEvil, testNow.Add(time.Hour))
	defer liar.Close()

	log := &captureLog{}
	result, _ := fetch(t, Config{CoordinatorKey: public, URLs: urls(good, liar)}, log)
	if len(result.Disagreed) != 1 || !strings.Contains(result.Disagreed[0], liar.URL) {
		t.Fatalf("the misbehaving gateway was not identified: %+v", result.Disagreed)
	}
	if !log.says("disagreed") {
		t.Fatalf("not reported: %v", log.lines)
	}
}

// --- ordinary failure modes ----------------------------------------------

func TestAnOfflineGatewayIsJustSkipped(t *testing.T) {
	// The point of the whole exercise: one host offline costs nothing.
	signer, public := coordinator(t)
	dead := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "down", http.StatusBadGateway)
		}))
	defer dead.Close()
	good := serveDoc(t, signer, public, peersA, testNow.Add(time.Hour))
	defer good.Close()

	result, err := fetch(t, Config{CoordinatorKey: public, URLs: urls(dead, good)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || len(result.Unreachable) != 1 {
		t.Fatalf("%+v", result)
	}
	// Unreachable is ordinary, not suspicious -- it must not be reported as
	// misbehaviour or every restart looks like an attack.
	if len(result.Disagreed) != 0 {
		t.Fatalf("an offline host was called a liar: %+v", result.Disagreed)
	}
}

func TestAnExpiredDocumentIsNotActedOn(t *testing.T) {
	// Expiry is signed, so a stale document is not a forgery -- but its peers
	// may be long gone, and dialling them is wasted time during a join.
	signer, public := coordinator(t)
	stale := serveDoc(t, signer, public, peersA, testNow.Add(-time.Hour))
	defer stale.Close()

	log := &captureLog{}
	if _, err := fetch(t, Config{CoordinatorKey: public, URLs: urls(stale)}, log); err == nil {
		t.Fatal("an expired document was used")
	}
	if !log.says("expired") {
		t.Fatalf("not explained: %v", log.lines)
	}
}

func TestNoSourcesAtAll(t *testing.T) {
	if _, err := fetch(t, Config{}, nil); !errors.Is(err, ErrNoSources) {
		t.Fatalf("got %v", err)
	}
}

func TestGarbageIsNotADocument(t *testing.T) {
	junk := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("<html>not json</html>"))
		}))
	defer junk.Close()
	_, public := coordinator(t)
	if _, err := fetch(t, Config{CoordinatorKey: public, URLs: urls(junk)}, nil); err == nil {
		t.Fatal("garbage was accepted")
	}
}
