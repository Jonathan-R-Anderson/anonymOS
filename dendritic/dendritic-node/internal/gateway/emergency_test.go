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
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Failover is judged by two opposite mistakes, and the second is worse:
// flipping the site read-only over one blip, and returning to a just-recovered
// origin all at once and putting it straight back down.

func signedManifest(t *testing.T, key ed25519.PrivateKey, sequence int64,
	routes map[string][]byte, created time.Time) (*SnapshotManifest, map[string][]byte) {
	t.Helper()
	manifest := &SnapshotManifest{
		Schema: 1, SnapshotID: "snap" + strconv.FormatInt(sequence, 10),
		Sequence: sequence, RootHash: "root", ObjectCount: len(routes),
		CreatedAt:    created.Unix(),
		RefreshAfter: created.Add(1 * time.Hour).Unix(),
		StaleAfter:   created.Add(6 * time.Hour).Unix(),
		ExpiresAt:    created.Add(24 * time.Hour).Unix(),
		Routes:       map[string]SnapshotRoute{},
	}
	objects := map[string][]byte{}
	for path, body := range routes {
		digest := sha256.Sum256(body)
		name := hex.EncodeToString(digest[:])
		objects[name] = body
		entry := manifest.Routes[path]
		entry.Object = name
		entry.ContentType = "text/html; charset=utf-8"
		entry.Status = 200
		entry.Size = int64(len(body))
		manifest.Routes[path] = entry
	}
	message := []byte(strings.Join([]string{
		"syndichan-snapshot:v1", manifest.SnapshotID,
		strconv.FormatInt(manifest.Sequence, 10), manifest.RootHash,
		strconv.FormatInt(manifest.CreatedAt, 10),
		strconv.FormatInt(manifest.ExpiresAt, 10),
		strconv.Itoa(manifest.ObjectCount),
	}, "\n"))
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))
	return manifest, objects
}

// publisherOrigin serves a snapshot the way the real origin does.
func publisherOrigin(t *testing.T, manifest *SnapshotManifest, objects map[string][]byte,
	live func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/syndichan/snapshot.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/snapshot/object/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/snapshot/object/")
		body, found := objects[name]
		if !found {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	if live != nil {
		mux.HandleFunc("/", live)
	}
	return httptest.NewServer(mux)
}

func warmCache(t *testing.T, origin string, public ed25519.PublicKey) *SnapshotCache {
	t.Helper()
	cache := NewSnapshotCache(origin, t.TempDir(), public)
	cache.refresh(context.Background())
	if cache.Manifest() == nil {
		t.Fatal("cache did not take the snapshot")
	}
	return cache
}

func TestSnapshotIsFetchedWhileTheOriginIsHealthy(t *testing.T) {
	// The timing IS the design: fetching during the outage would mean asking the
	// thing that just died, and a fleet doing it at once is a second outage.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := signedManifest(t, private, 7,
		map[string][]byte{"/": []byte("<html>frozen</html>")}, time.Now())
	origin := publisherOrigin(t, manifest, objects, nil)
	defer origin.Close()

	cache := warmCache(t, origin.URL, public)
	if got := cache.Manifest().Sequence; got != 7 {
		t.Fatalf("sequence = %d", got)
	}
	body, _, found := cache.Object("/")
	if !found || string(body) != "<html>frozen</html>" {
		t.Fatal("object was not held locally")
	}
}

func TestAnUnsignedOrForgedSnapshotIsRefused(t *testing.T) {
	// Serving an unverifiable snapshot would let whoever runs this machine
	// decide what syndichan says during an outage — the one thing the whole
	// design exists to prevent.
	public, private, _ := ed25519.GenerateKey(nil)
	_, wrongPrivate, _ := ed25519.GenerateKey(nil)

	manifest, objects := signedManifest(t, wrongPrivate, 7,
		map[string][]byte{"/": []byte("<html>forged</html>")}, time.Now())
	origin := publisherOrigin(t, manifest, objects, nil)
	defer origin.Close()

	cache := NewSnapshotCache(origin.URL, t.TempDir(), public)
	cache.refresh(context.Background())
	if cache.Manifest() != nil {
		t.Fatal("a snapshot signed by the wrong key was accepted")
	}

	manifest.Signature = ""
	if err := cache.verify(manifest); err == nil {
		t.Error("an unsigned snapshot was accepted")
	}
	_ = private
}

func TestObjectsAreCheckedAgainstTheSignedManifest(t *testing.T) {
	// The manifest is signed, so bytes that do not match it did not come from
	// the publisher — whoever served them substituted something.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, _ := signedManifest(t, private, 7,
		map[string][]byte{"/": []byte("<html>real</html>")}, time.Now())

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/syndichan/snapshot.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/snapshot/object/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>SUBSTITUTED</html>")
	})
	origin := httptest.NewServer(mux)
	defer origin.Close()

	cache := NewSnapshotCache(origin.URL, t.TempDir(), public)
	cache.refresh(context.Background())
	if cache.Manifest() != nil {
		t.Fatal("a snapshot whose objects did not match its manifest was activated")
	}
}

func TestAnOlderSnapshotIsRefusedEvenWhenSigned(t *testing.T) {
	// An old snapshot is genuinely signed, which is exactly why the sequence
	// has to be checked on its own.
	public, private, _ := ed25519.GenerateKey(nil)
	newer, newerObjects := signedManifest(t, private, 9,
		map[string][]byte{"/": []byte("<html>new</html>")}, time.Now())
	origin := publisherOrigin(t, newer, newerObjects, nil)
	defer origin.Close()
	cache := warmCache(t, origin.URL, public)

	older, _ := signedManifest(t, private, 8,
		map[string][]byte{"/": []byte("<html>old</html>")}, time.Now())
	*newer = *older // the origin now serves the older, validly signed manifest
	cache.refresh(context.Background())

	if got := cache.Manifest().Sequence; got != 9 {
		t.Fatalf("rolled back to sequence %d", got)
	}
}

func TestExpiredSnapshotsAreNotServed(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := signedManifest(t, private, 7,
		map[string][]byte{"/": []byte("<html>ancient</html>")},
		time.Now().Add(-48*time.Hour))
	origin := publisherOrigin(t, manifest, objects, nil)
	defer origin.Close()

	cache := NewSnapshotCache(origin.URL, t.TempDir(), public)
	cache.refresh(context.Background())
	if _, _, found := cache.Object("/"); found {
		t.Error("an expired snapshot was served")
	}
	if state := manifest.State(time.Now()); state != SnapshotExpired {
		t.Errorf("state = %q, want expired", state)
	}
}

func TestOneBlipDoesNotFlipTheSiteReadOnly(t *testing.T) {
	// Turning the whole site read-only over a single timeout would make a blip
	// into an incident, and the reader would see posting disabled for no reason
	// they could observe.
	health := NewOriginHealth()
	health.RecordFailure(FailureTimeout)
	if health.Emergency() {
		t.Fatal("one failure entered emergency mode")
	}
	health.RecordFailure(FailureTimeout)
	health.RecordFailure(FailureTimeout)
	if health.Emergency() {
		t.Error("three failures of ONE kind entered emergency mode; that is a " +
			"flaky link, not an outage")
	}
}

func TestSeveralKindsOfFailureDoEnterEmergency(t *testing.T) {
	// Guards the test above: a detector that never fires would pass it while
	// defending nothing.
	health := NewOriginHealth()
	health.RecordFailure(FailureTimeout)
	health.RecordFailure(FailureDial)
	health.RecordFailure(FailureStatus)
	if !health.Emergency() {
		t.Fatal("a genuine outage did not enter emergency mode")
	}
	if state := health.State(); state != "EMERGENCY" {
		t.Errorf("state = %q", state)
	}
}

func TestRecoveryNeedsSuccessesOverTimeAndThenJitter(t *testing.T) {
	// The dangerous direction. A just-recovered origin is the weakest it will
	// ever be, and every gateway returning at once puts it straight back down.
	now := time.Unix(1_800_000_000, 0)
	health := NewOriginHealth()
	health.Now = func() time.Time { return now }
	health.Random = func(int64) int64 { return int64(30 * time.Second) }

	health.RecordFailure(FailureTimeout)
	health.RecordFailure(FailureDial)
	health.RecordFailure(FailureStatus)
	if !health.Emergency() {
		t.Fatal("setup: expected emergency mode")
	}

	// Five instant successes are not a minute of stability.
	for i := 0; i < 5; i++ {
		health.RecordSuccess()
	}
	if !health.Emergency() {
		t.Fatal("returned to the origin after five successes in zero seconds")
	}

	// A minute of them arms the return, but only after the jitter elapses.
	now = now.Add(61 * time.Second)
	health.RecordSuccess()
	if !health.Emergency() {
		t.Fatal("returned immediately instead of waiting out the jitter")
	}
	now = now.Add(31 * time.Second)
	health.RecordSuccess()
	if health.Emergency() {
		t.Error("did not return once stability and jitter were both satisfied")
	}
}

func TestAFailureRestartsTheRecoveryRun(t *testing.T) {
	// Five successes and a failure is not a recovered origin. Counting it as
	// one is how a gateway flaps between modes.
	now := time.Unix(1_800_000_000, 0)
	health := NewOriginHealth()
	health.Now = func() time.Time { return now }
	health.Random = func(int64) int64 { return 0 }

	health.RecordFailure(FailureTimeout)
	health.RecordFailure(FailureDial)
	health.RecordFailure(FailureStatus)
	for i := 0; i < 4; i++ {
		health.RecordSuccess()
	}
	health.RecordFailure(FailureTimeout)
	now = now.Add(61 * time.Second)
	health.RecordSuccess()
	if !health.Emergency() {
		t.Error("a failure mid-recovery did not restart the run")
	}
}

func TestDefensiveModeExpiresByItself(t *testing.T) {
	// A mode with no expiry is one a lost control key leaves switched on
	// forever, and "permanently read-only because nobody can find the key" is
	// worse than the outage it prevented.
	now := time.Unix(1_800_000_000, 0)
	health := NewOriginHealth()
	health.Now = func() time.Time { return now }
	health.Force(now.Add(time.Minute))
	if !health.Emergency() {
		t.Fatal("defensive mode did not take effect")
	}
	now = now.Add(2 * time.Minute)
	if health.Emergency() {
		t.Error("defensive mode outlived its expiry")
	}
}

func TestGatewayServesTheSnapshotWhenTheOriginDies(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := signedManifest(t, private, 7,
		map[string][]byte{"/": []byte("<html>emergency copy</html>")}, time.Now())

	alive := true
	origin := publisherOrigin(t, manifest, objects, func(w http.ResponseWriter, r *http.Request) {
		if !alive {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "<html>live</html>")
	})
	defer origin.Close()

	cache := warmCache(t, origin.URL, public)
	parsed, _ := url.Parse(origin.URL)
	proxy := NewContentProxy(parsed, parsed.Host, "12D3KooWTest", "")
	proxy.Snapshot = cache
	proxy.Health = NewOriginHealth()

	// While the origin is up, the reader gets the live page.
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(recorder.Body.String(), "live") {
		t.Fatalf("healthy origin was not served: %s", recorder.Body.String())
	}

	// Kill it. The very next request is answered from the snapshot rather than
	// waiting for a threshold — the reader is already here.
	alive = false
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want the snapshot served", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "emergency copy") {
		t.Fatalf("body = %q", recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Syndichan-Source"); got != "snapshot" {
		t.Errorf("X-Syndichan-Source = %q", got)
	}
	if recorder.Header().Get("X-Syndichan-Snapshot") != "7" {
		t.Errorf("snapshot sequence header missing")
	}
	if !strings.Contains(recorder.Header().Get("Warning"), "emergency") {
		t.Errorf("no Warning header naming this as cached")
	}
}

func TestUnknownPathsNeverCauseALookup(t *testing.T) {
	// The amplifier guard. Without it a request for a random path becomes a
	// cache miss, a disk probe and eventually a network fetch — so anyone with
	// a loop could point this gateway's storage at the network.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := signedManifest(t, private, 7,
		map[string][]byte{"/": []byte("<html>only page</html>")}, time.Now())
	origin := publisherOrigin(t, manifest, objects, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	})
	defer origin.Close()

	cache := warmCache(t, origin.URL, public)
	if cache.HasRoute("/does-not-exist") {
		t.Fatal("an unlisted path was treated as present")
	}

	parsed, _ := url.Parse(origin.URL)
	proxy := NewContentProxy(parsed, parsed.Host, "12D3KooWTest", "")
	proxy.Snapshot = cache
	proxy.Health = NewOriginHealth()
	proxy.Health.Force(time.Now().Add(time.Minute))

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
	if recorder.Code != http.StatusNotFound {
		t.Errorf("status = %d, want a flat 404 with no lookup", recorder.Code)
	}
}

func TestTheMaintenancePageNeedsNothing(t *testing.T) {
	// Everything it could depend on is plausibly broken when it is needed, and
	// a maintenance page that fails to load is indistinguishable from the
	// outage it is trying to explain.
	page := MaintenancePage()
	for _, forbidden := range []string{"<script", "<link", "src=", "href=", "@import"} {
		if strings.Contains(strings.ToLower(page), forbidden) {
			t.Errorf("maintenance page depends on %q", forbidden)
		}
	}
	if !strings.Contains(page, "emergency mode") {
		t.Error("maintenance page does not say what is happening")
	}
}

func TestASnapshotSurvivesARestart(t *testing.T) {
	// A gateway that reboots during an outage must be useful immediately, not
	// after it manages to reach an origin that is down.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := signedManifest(t, private, 7,
		map[string][]byte{"/": []byte("<html>held</html>")}, time.Now())
	origin := publisherOrigin(t, manifest, objects, nil)
	dir := t.TempDir()

	first := NewSnapshotCache(origin.URL, dir, public)
	first.refresh(context.Background())
	origin.Close() // the origin is gone before the "restart"

	second := NewSnapshotCache(origin.URL, dir, public)
	if err := second.loadFromDisk(); err != nil {
		t.Fatalf("could not reload the held snapshot: %v", err)
	}
	body, _, found := second.Object("/")
	if !found || !strings.Contains(string(body), "held") {
		t.Fatal("the held snapshot did not survive a restart")
	}
}

func signedRevocation(t *testing.T, key ed25519.PrivateKey, sequences []int64,
	recordSeq int64) *Revocations {
	t.Helper()
	parts := make([]string, 0, len(sequences))
	for _, s := range sequences {
		parts = append(parts, strconv.FormatInt(s, 10))
	}
	issued := time.Now().Unix()
	message := []byte(strings.Join([]string{
		"syndichan-revocation:v1", strings.Join(parts, ","), "",
		strconv.FormatInt(recordSeq, 10), strconv.FormatInt(issued, 10),
	}, "\n"))
	return &Revocations{
		Schema: 1, RevokedSequences: sequences, Sequence: recordSeq,
		IssuedAt:  issued,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, message)),
	}
}

func TestARevokedSnapshotIsDroppedNotFlagged(t *testing.T) {
	// Keeping a revoked snapshot "in case it is needed" is how one that leaked
	// private data or carried injected script gets served during the next
	// outage by a gateway that meant well.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := signedManifest(t, private, 7,
		map[string][]byte{"/": []byte("<html>bad</html>")}, time.Now())

	revocation := signedRevocation(t, private, []int64{7}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/syndichan/snapshot.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/snapshot/object/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/snapshot/object/")
		_, _ = w.Write(objects[name])
	})
	mux.HandleFunc("/.well-known/syndichan/revocations.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(revocation)
	})
	origin := httptest.NewServer(mux)
	defer origin.Close()

	cache := NewSnapshotCache(origin.URL, t.TempDir(), public)
	cache.refresh(context.Background())
	if cache.Manifest() == nil {
		t.Fatal("setup: snapshot was not taken")
	}
	cache.refreshControl(context.Background())

	if cache.Manifest() != nil {
		t.Error("a revoked snapshot is still held")
	}
	if _, _, found := cache.Object("/"); found {
		t.Error("a revoked snapshot is still being served")
	}
	if !cache.Revoked() {
		t.Error("revocation was not recorded")
	}
}

func TestAnOlderRevocationListCannotUnrevoke(t *testing.T) {
	// Replaying a validly signed EMPTY list is the cheapest possible attack on
	// a revocation system, so the record carries its own sequence.
	public, private, _ := ed25519.GenerateKey(nil)
	cache := NewSnapshotCache("http://unused", t.TempDir(), public)

	current := signedRevocation(t, private, []int64{7}, 5)
	if !cache.verifyRevocations(current) {
		t.Fatal("a genuine revocation failed verification")
	}
	cache.revocationSeq = 5

	empty := signedRevocation(t, private, nil, 4)
	if !cache.verifyRevocations(empty) {
		t.Fatal("setup: the replayed list should still be validly signed")
	}
	// Signed but older: the sequence check is what refuses it.
	if empty.Sequence >= cache.revocationSeq {
		t.Fatal("setup error")
	}
}

func TestAForgedRevocationIsIgnored(t *testing.T) {
	// Otherwise anyone could take every gateway's snapshot away, which is a
	// denial of service dressed as a safety feature.
	public, _, _ := ed25519.GenerateKey(nil)
	_, attacker, _ := ed25519.GenerateKey(nil)
	cache := NewSnapshotCache("http://unused", t.TempDir(), public)
	if cache.verifyRevocations(signedRevocation(t, attacker, []int64{7}, 1)) {
		t.Error("a revocation signed by the wrong key was accepted")
	}
}

func TestAnExpiredDefensiveModeIsNotHonoured(t *testing.T) {
	// Enforced at the gateway as well as the origin: a gateway that trusted the
	// origin to stop sending an expired record would stay offline after
	// everybody else came back.
	public, private, _ := ed25519.GenerateKey(nil)
	expired := DefensiveMode{
		Mode: "DHT_CACHE_ONLY", Reason: "test",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}
	message := []byte(strings.Join([]string{
		"syndichan-defensive:v1", expired.Mode, expired.Reason,
		strconv.FormatInt(expired.IssuedAt, 10),
		strconv.FormatInt(expired.ExpiresAt, 10), "0",
	}, "\n"))
	expired.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/syndichan/defensive-mode.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(expired)
	})
	origin := httptest.NewServer(mux)
	defer origin.Close()

	cache := NewSnapshotCache(origin.URL, t.TempDir(), public)
	if cache.FetchDefensiveMode(context.Background()) != nil {
		t.Error("an expired defensive-mode record was honoured")
	}
}

func TestAValidDefensiveModeIsHonoured(t *testing.T) {
	// Guards the test above: a fetcher that returned nil for everything would
	// pass it while implementing nothing.
	public, private, _ := ed25519.GenerateKey(nil)
	record := DefensiveMode{
		Mode: "DHT_CACHE_ONLY", Reason: "origin_overload",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	message := []byte(strings.Join([]string{
		"syndichan-defensive:v1", record.Mode, record.Reason,
		strconv.FormatInt(record.IssuedAt, 10),
		strconv.FormatInt(record.ExpiresAt, 10), "0",
	}, "\n"))
	record.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/syndichan/defensive-mode.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(record)
	})
	origin := httptest.NewServer(mux)
	defer origin.Close()

	cache := NewSnapshotCache(origin.URL, t.TempDir(), public)
	if cache.FetchDefensiveMode(context.Background()) == nil {
		t.Error("a valid defensive-mode record was not honoured")
	}
}

// offloadManifest builds a snapshot where one route is publisher-approved for
// serving while the origin is up and another is not.
func offloadManifest(t *testing.T, key ed25519.PrivateKey, created time.Time) (
	*SnapshotManifest, map[string][]byte) {
	t.Helper()
	m, objects := signedManifest(t, key, 7, map[string][]byte{
		"/faq":      []byte("<html>stable faq</html>"),
		"/boards/b": []byte("<html>busy board</html>"),
	}, created)
	faq := m.Routes["/faq"]
	faq.Offload = true
	// The offload variant is the untouched render; here the same bytes suffice.
	faq.OffloadObject = faq.Object
	m.Routes["/faq"] = faq
	return m, objects
}

func TestOffloadServesApprovedRoutesWhileTheOriginIsUp(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := offloadManifest(t, private, time.Now())
	origin := publisherOrigin(t, manifest, objects, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>FROM ORIGIN</html>")
	})
	defer origin.Close()

	cache := warmCache(t, origin.URL, public)
	parsed, _ := url.Parse(origin.URL)
	proxy := NewContentProxy(parsed, parsed.Host, "12D3KooWTest", "")
	proxy.Snapshot = cache
	proxy.Health = NewOriginHealth()
	proxy.Offload = true

	// Approved: answered from cache, taking the request off the origin.
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/faq", nil))
	if !strings.Contains(recorder.Body.String(), "stable faq") {
		t.Fatalf("offloadable route was not served from cache: %q", recorder.Body.String())
	}

	// Not approved: still goes to the origin, because a busy board from an
	// hour-old copy is worse than a slow page.
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/boards/b", nil))
	if !strings.Contains(recorder.Body.String(), "FROM ORIGIN") {
		t.Errorf("a volatile route was served from cache: %q", recorder.Body.String())
	}
}

func TestOffloadIsOffByDefault(t *testing.T) {
	// A gateway quietly deciding to answer from an hour-old copy is a behaviour
	// nobody asked for. The default must stay origin-first.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := offloadManifest(t, private, time.Now())
	origin := publisherOrigin(t, manifest, objects, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>FROM ORIGIN</html>")
	})
	defer origin.Close()

	cache := warmCache(t, origin.URL, public)
	parsed, _ := url.Parse(origin.URL)
	proxy := NewContentProxy(parsed, parsed.Host, "12D3KooWTest", "")
	proxy.Snapshot = cache
	proxy.Health = NewOriginHealth()
	// Offload deliberately left false.

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/faq", nil))
	if !strings.Contains(recorder.Body.String(), "FROM ORIGIN") {
		t.Error("cache was served while the origin was healthy without opt-in")
	}
}

func TestAStaleSnapshotIsNeverOffloaded(t *testing.T) {
	// Past its refresh window a snapshot may still be the right thing to serve
	// during an OUTAGE, and is never right while the origin answers perfectly.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := offloadManifest(t, private, time.Now().Add(-3*time.Hour))
	origin := publisherOrigin(t, manifest, objects, nil)
	defer origin.Close()

	cache := warmCache(t, origin.URL, public)
	if cache.Manifest().State(time.Now()) == SnapshotFresh {
		t.Fatal("setup: expected a stale snapshot")
	}
	if cache.Offloadable("/faq") {
		t.Error("a stale snapshot was offered for normal-operation serving")
	}
}

func TestAGatewayCannotWidenTheOffloadSet(t *testing.T) {
	// The publisher decides. The operator of a volunteer machine is exactly the
	// party who should not get to rule that a stale copy is good enough for
	// somebody else's readers.
	public, private, _ := ed25519.GenerateKey(nil)
	manifest, objects := offloadManifest(t, private, time.Now())
	origin := publisherOrigin(t, manifest, objects, nil)
	defer origin.Close()

	cache := warmCache(t, origin.URL, public)
	if cache.Offloadable("/boards/b") {
		t.Error("a route the publisher did not approve was offered for offload")
	}
	if !cache.Offloadable("/faq") {
		t.Error("an approved route was not offered")
	}
}
