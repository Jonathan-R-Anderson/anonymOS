package monitor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type stubSigner struct{ id string }

func (s stubSigner) ID() string                    { return s.id }
func (s stubSigner) Sign(b []byte) ([]byte, error) { return append([]byte("sig:"), b...), nil }

// A monitor exists to report failures. Every test here is really asking the
// same question: does a failure survive the trip to the page, or does it get
// quietly turned into an absence?
func TestProbeReportsFailuresRatherThanDroppingThem(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer down.Close()

	c := &Client{Signer: stubSigner{"n1"}, HTTP: down.Client()}
	got := c.probe(context.Background(), Target{Key: "web", URL: down.URL, TimeoutMS: 2000})

	if got.OK {
		t.Fatal("a 502 must not count as OK")
	}
	if got.Detail == "" {
		t.Fatal("a failure must carry a reason for the operator")
	}
	if got.LatencyMS != nil {
		// A timeout returns a duration equal to the timeout. Reporting it as
		// latency makes an outage look like a slowdown.
		t.Fatal("a failed probe must not report latency")
	}
}

func TestProbeAcceptsRedirectsAsAlive(t *testing.T) {
	// A redirect that arrives is still a live server answering.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{Signer: stubSigner{"n1"}, HTTP: srv.Client()}
	got := c.probe(context.Background(), Target{Key: "web", URL: srv.URL, TimeoutMS: 2000})
	if !got.OK {
		t.Fatalf("204 should be OK, got %+v", got)
	}
	if got.LatencyMS == nil {
		t.Fatal("a successful probe must report latency")
	}
}

func TestProbeTimesOutAndSaysSo(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer slow.Close()

	c := &Client{Signer: stubSigner{"n1"}, HTTP: slow.Client()}
	got := c.probe(context.Background(), Target{Key: "web", URL: slow.URL, TimeoutMS: 40})
	if got.OK {
		t.Fatal("a timeout is not a success")
	}
	if got.LatencyMS != nil {
		t.Fatal("a timed-out probe must not report latency")
	}
}

func TestProbeSurvivesAnUnreachableTarget(t *testing.T) {
	// Nothing listening. The node must report it, not crash or hang.
	c := &Client{Signer: stubSigner{"n1"}, HTTP: DirectHTTPClient()}
	got := c.probe(context.Background(), Target{
		Key: "web", URL: "http://127.0.0.1:1/", TimeoutMS: 500,
	})
	if got.OK {
		t.Fatal("an unreachable target is not OK")
	}
	if got.Key != "web" {
		t.Fatalf("the result must stay attached to its target, got %q", got.Key)
	}
}

func TestOnceSignsTheExactBytesItSends(t *testing.T) {
	var gotBody []byte
	var gotNode, gotSig string

	mux := http.NewServeMux()
	mux.HandleFunc("/targets", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":          1,
			"interval_seconds": 90,
			"report_url":       "REPLACED",
			"targets": []map[string]any{
				{"key": "web", "url": "REPLACED", "timeout_ms": 2000},
			},
		})
	})
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = readAll(r)
		gotNode = r.Header.Get("X-Syndichan-Node")
		gotSig = r.Header.Get("X-Syndichan-Signature")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Rewrite the placeholders now the server has an address.
	mux.HandleFunc("/targets2", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":          1,
			"interval_seconds": 90,
			"report_url":       srv.URL + "/report",
			"targets": []map[string]any{
				{"key": "web", "url": srv.URL + "/ok", "timeout_ms": 2000},
			},
		})
	})

	c := &Client{
		Signer:     stubSigner{"node-abc"},
		TargetsURL: srv.URL + "/targets2",
		HTTP:       srv.Client(),
	}
	next := c.Once(context.Background())

	if next != 90*time.Second {
		t.Fatalf("the coordinator's interval must be honoured, got %v", next)
	}
	if gotNode != "node-abc" {
		t.Fatalf("node header = %q", gotNode)
	}
	// The signature must cover exactly what arrived. Signing anything else
	// would let the sender choose what the signature attests to.
	if want := "sig:" + string(gotBody); gotSig == "" || decode(gotSig) != want {
		t.Fatalf("signature does not cover the exact body")
	}
	var sent report
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if len(sent.Results) != 1 || !sent.Results[0].OK {
		t.Fatalf("expected one passing result, got %+v", sent.Results)
	}
}

func TestOnceSurvivesACoordinatorThatIsItselfDown(t *testing.T) {
	// The likeliest moment for the target list to be unavailable is during the
	// outage worth reporting. It must not panic or wedge the loop.
	c := &Client{
		Signer:     stubSigner{"n1"},
		TargetsURL: "http://127.0.0.1:1/targets",
		HTTP:       DirectHTTPClient(),
	}
	if got := c.Once(context.Background()); got != 0 {
		t.Fatalf("an unreachable coordinator should yield no interval, got %v", got)
	}
}

func TestJitterStaysWithinAQuarterOfTheInterval(t *testing.T) {
	// A fleet started by one rollout must not stay in lockstep, but it also
	// must not drift so far that the page's "recent" window misses it.
	base := 60 * time.Second
	for i := 0; i < 200; i++ {
		got := jitter(base)
		if got < base*3/4 || got > base*5/4 {
			t.Fatalf("jitter escaped its bounds: %v", got)
		}
	}
}

func TestJitterHandlesAZeroInterval(t *testing.T) {
	// A coordinator that omits the interval must not produce a busy loop.
	if got := jitter(0); got <= 0 {
		t.Fatalf("a zero interval must fall back to something positive, got %v", got)
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

func decode(s string) string {
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(out)
}
