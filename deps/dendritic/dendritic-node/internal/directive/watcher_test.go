package directive

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type capturingLog struct{ lines []string }

func (c *capturingLog) Printf(format string, v ...interface{}) {
	c.lines = append(c.lines, strings.ToLower(fmt.Sprintf(format, v...)))
}

func (c *capturingLog) contains(needle string) bool {
	for _, line := range c.lines {
		if strings.Contains(line, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func serve(t *testing.T, key *secp256k1.PrivateKey, d *Directive) *httptest.Server {
	t.Helper()
	message := Canonical(d)
	doc := Document{
		Directive: d, Canonical: message,
		Signature: signPersonal(t, key, message),
		Signer:    addressOf(key.PubKey()),
		Wallet:    addressOf(key.PubKey()),
	}
	body, _ := json.Marshal(doc)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	}))
}

func newWatcher(t *testing.T, wallet string, sources ...string) (*Watcher, *Store, *capturingLog) {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := &capturingLog{}
	return &Watcher{
		Wallet: wallet, Sources: sources, Store: store, Log: log,
		Now: func() int64 { return 2_000_000_000 },
	}, store, log
}

func TestAdoptsAVerifiedDirective(t *testing.T) {
	key, _ := secp256k1.GeneratePrivateKey()
	d := &Directive{Kind: KindMove, Sequence: 3, OriginDomain: "syndichan.net",
		NotBefore: 1_000_000_000}
	server := serve(t, key, d)
	defer server.Close()

	w, store, _ := newWatcher(t, addressOf(key.PubKey()), server.URL)
	var adopted *Directive
	w.OnAdopt = func(got *Directive) { adopted = got }
	w.Poll(context.Background())

	if adopted == nil || adopted.Sequence != 3 {
		t.Fatalf("did not adopt: %+v", adopted)
	}
	if store.Held() == nil || store.Held().OriginDomain != "syndichan.net" {
		t.Fatalf("not stored: %+v", store.Held())
	}
}

func TestRefusesADirectiveFromAnotherWallet(t *testing.T) {
	key, _ := secp256k1.GeneratePrivateKey()
	other, _ := secp256k1.GeneratePrivateKey()
	d := &Directive{Kind: KindMove, Sequence: 3, OriginDomain: "evil.example",
		NotBefore: 1_000_000_000}
	server := serve(t, key, d)
	defer server.Close()

	w, store, log := newWatcher(t, addressOf(other.PubKey()), server.URL)
	w.Poll(context.Background())

	if store.Held() != nil {
		t.Fatal("adopted a directive signed by the wrong wallet")
	}
	if !log.contains("refused") {
		t.Fatalf("the refusal was not logged: %v", log.lines)
	}
}

func TestWaitsUntilEffective(t *testing.T) {
	// The delay is the window in which an operator can notice a directive they
	// did not issue. A watcher that ignores it removes the only defence there
	// is against a stolen wallet.
	key, _ := secp256k1.GeneratePrivateKey()
	d := &Directive{Kind: KindMove, Sequence: 3, OriginDomain: "syndichan.net",
		NotBefore: 2_000_000_600}
	server := serve(t, key, d)
	defer server.Close()

	w, store, log := newWatcher(t, addressOf(key.PubKey()), server.URL)
	w.Poll(context.Background())
	if store.Held() != nil {
		t.Fatal("acted before not_before")
	}
	if !log.contains("not effective") {
		t.Fatalf("did not explain the wait: %v", log.lines)
	}
}

func TestEmergencyIsAdoptedImmediatelyAndLoudly(t *testing.T) {
	key, _ := secp256k1.GeneratePrivateKey()
	d := &Directive{Kind: KindMove, Sequence: 4, OriginDomain: "syndichan.net",
		NotBefore: 2_000_000_000, Emergency: true}
	server := serve(t, key, d)
	defer server.Close()

	w, store, log := newWatcher(t, addressOf(key.PubKey()), server.URL)
	w.Poll(context.Background())

	if store.Held() == nil {
		t.Fatal("an emergency directive was not adopted")
	}
	if !log.contains("emergency") {
		t.Fatalf("an emergency directive was adopted quietly: %v", log.lines)
	}
}

func TestTheSequenceFloorSurvivesRestart(t *testing.T) {
	// The sequence rule is only worth anything if the floor is remembered. A
	// node that forgets on restart would accept a directive replayed from a
	// year ago -- exactly what the sequence exists to stop.
	dir := t.TempDir()
	key, _ := secp256k1.GeneratePrivateKey()

	store, _ := OpenStore(dir)
	if err := store.Adopt(&Directive{Kind: KindMove, Sequence: 9,
		OriginDomain: "current.example"}, "sig", "signer", 1); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Held() == nil || reopened.Held().Sequence != 9 {
		t.Fatalf("floor lost across restart: %+v", reopened.Held())
	}

	old := &Directive{Kind: KindMove, Sequence: 5, OriginDomain: "evil.example",
		NotBefore: 1_000_000_000}
	server := serve(t, key, old)
	defer server.Close()

	w := &Watcher{Wallet: addressOf(key.PubKey()), Sources: []string{server.URL},
		Store: reopened, Now: func() int64 { return 2_000_000_000 }}
	w.Poll(context.Background())
	if reopened.Held().OriginDomain != "current.example" {
		t.Fatal("a replayed older directive won")
	}
}

func TestACorruptStoreRefusesToStart(t *testing.T) {
	// Treating it as "nothing held" would silently drop the sequence floor and
	// re-open the replay window on a file only this node should ever write.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, StoreFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("a corrupt store was accepted as empty")
	}
}

func TestNoPinnedWalletMeansNoDirectives(t *testing.T) {
	key, _ := secp256k1.GeneratePrivateKey()
	d := &Directive{Kind: KindMove, Sequence: 3, OriginDomain: "evil.example",
		NotBefore: 1_000_000_000}
	server := serve(t, key, d)
	defer server.Close()

	w, store, log := newWatcher(t, "", server.URL)
	w.Run(context.Background()) // returns immediately

	if store.Held() != nil {
		t.Fatal("a node with no pinned wallet followed a directive")
	}
	if !log.contains("no wallet is pinned") {
		t.Fatalf("was not loud about it: %v", log.lines)
	}
}

func TestFallsThroughToASecondSource(t *testing.T) {
	// The source that depends on the current domain is exactly the one that
	// fails in the situation a directive exists for.
	key, _ := secp256k1.GeneratePrivateKey()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusServiceUnavailable)
	}))
	defer dead.Close()
	d := &Directive{Kind: KindMove, Sequence: 3, OriginDomain: "syndichan.net",
		NotBefore: 1_000_000_000}
	alive := serve(t, key, d)
	defer alive.Close()

	w, store, _ := newWatcher(t, addressOf(key.PubKey()), dead.URL, alive.URL)
	w.Poll(context.Background())
	if store.Held() == nil {
		t.Fatal("a dead first source stopped the second from being tried")
	}
}

func TestOriginBase(t *testing.T) {
	if got := OriginBase(nil, "https://syndichan.org"); got != "https://syndichan.org" {
		t.Fatalf("no directive should keep the configured origin, got %s", got)
	}
	held := &Directive{Kind: KindMove, OriginDomain: "syndichan.net"}
	if got := OriginBase(held, "https://syndichan.org"); got != "https://syndichan.net" {
		t.Fatalf("got %s", got)
	}
	// A freeze pins where we are; it must not be read as a move to nowhere.
	frozen := &Directive{Kind: KindFreeze}
	if got := OriginBase(frozen, "https://syndichan.org"); got != "https://syndichan.org" {
		t.Fatalf("a freeze changed the origin: %s", got)
	}
}

func TestGarbageBodyIsNotAdopted(t *testing.T) {
	key, _ := secp256k1.GeneratePrivateKey()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("x", 200)))
	}))
	defer server.Close()
	w, store, _ := newWatcher(t, addressOf(key.PubKey()), server.URL)
	w.Poll(context.Background())
	if store.Held() != nil {
		t.Fatal("adopted garbage")
	}
	_ = hex.EncodeToString(nil)
}
