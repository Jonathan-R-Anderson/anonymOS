//go:build linux

package main

// The rule under test: a node that offers compute must be able to run any
// catalogue workload, so a node that cannot obtain an image stops advertising
// the capability rather than advertising it and refusing.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/computeimage"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
)

// recordingReporter is the heartbeat, reduced to the one thing that matters:
// what it was last told about this node's ability to honour its offer.
type recordingReporter struct {
	said []bool
}

func (r *recordingReporter) SetComputeCatalogueReady(ready bool) {
	r.said = append(r.said, ready)
}

func (r *recordingReporter) last(t *testing.T) bool {
	t.Helper()
	if len(r.said) == 0 {
		t.Fatal("nothing was ever reported about the catalogue")
	}
	return r.said[len(r.said)-1]
}

type stubRuntime struct {
	present map[string]bool
	loads   int
	appears string
}

func (s *stubRuntime) ImageExists(_ context.Context, reference string) (bool, error) {
	return s.present[reference], nil
}

func (s *stubRuntime) LoadImage(_ context.Context, tarball io.Reader) error {
	if _, err := io.Copy(io.Discard, tarball); err != nil {
		return err
	}
	s.loads++
	if s.appears != "" {
		s.present[s.appears] = true
	}
	return nil
}

func quiet() *log.Logger { return log.New(io.Discard, "", 0) }

// oneSweep runs the sweep exactly once and returns what it announced.
//
// The context is cancelled BY the announcement, not before it. Cancelling first
// would look like it stops the loop after one pass, and would in fact stop the
// HTTP fetch inside that pass — so every test would exercise "the context was
// cancelled" and the ones expecting a failure would pass without ever reaching
// the behaviour they name.
func oneSweep(t *testing.T, loader *computeimage.Loader,
	workloads []compute.Workload) *recordingReporter {
	t.Helper()
	reporter := &recordingReporter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	announce := func(ready bool) {
		catalogueAnnouncer(reporter)(ready)
		cancel()
	}
	go func() {
		sweepCatalogue(ctx, loader, workloads, time.Hour, quiet(), announce)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the catalogue sweep never finished")
	}
	return reporter
}

// TestANodeThatCannotObtainAnImageStopsAdvertisingCompute.
//
// THE FAILURE THIS PREVENTS, measured on the live fleet: nodes advertised
// cpu_compute they could not perform, so placement chose them, they accepted the
// unit and died `No such image` — which reads as a failed execution rather than
// a missing prerequisite, so placement chose them again.
func TestANodeThatCannotObtainAnImageStopsAdvertisingCompute(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer origin.Close()

	runtime := &stubRuntime{present: map[string]bool{}}
	loader := &computeimage.Loader{Runtime: runtime, BaseURL: origin.URL,
		ScratchDir: t.TempDir(), Logger: quiet()}

	reporter := oneSweep(t, loader, compute.CatalogueWorkloads())

	if reporter.last(t) {
		t.Fatal("a node that could not obtain its catalogue images still " +
			"advertised compute — which is the claim it cannot honour")
	}
}

// TestANodeThatObtainsItsImagesAdvertisesCompute — the other half, because a
// gate that never opens is not a gate, it is compute switched off.
func TestANodeThatObtainsItsImagesAdvertisesCompute(t *testing.T) {
	workloads := compute.CatalogueWorkloads()
	if len(workloads) == 0 {
		t.Skip("no catalogue workloads to fetch")
	}
	// One artifact, served for every request, with the digest each workload
	// expects — the loader is the thing under test here, not the catalogue.
	bodies := map[string][]byte{}
	for _, w := range workloads {
		bodies["/"+w.Artifact] = []byte("tarball for " + w.Name)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer origin.Close()

	runtime := &stubRuntime{present: map[string]bool{}}
	// Every workload's image becomes present after a load. With one workload in
	// the catalogue this is exact; with more it is still the case being tested,
	// which is "the fetch succeeded".
	for _, w := range workloads {
		runtime.appears = w.Image
	}
	patched := make([]compute.Workload, 0, len(workloads))
	for _, w := range workloads {
		sum := sha256.Sum256(bodies["/"+w.Artifact])
		w.Digest = hex.EncodeToString(sum[:])
		patched = append(patched, w)
	}

	loader := &computeimage.Loader{Runtime: runtime, BaseURL: origin.URL,
		ScratchDir: t.TempDir(), Logger: quiet()}
	reporter := oneSweep(t, loader, patched)

	if !reporter.last(t) {
		t.Fatal("a node holding every catalogue image did not advertise compute")
	}
	if runtime.loads != len(patched) {
		t.Fatalf("expected %d loads, got %d", len(patched), runtime.loads)
	}
}

// TestAnImageThatGoesAwayTakesTheAdvertisementWithIt. The sweep exists for
// exactly this: withdrawing a capability is the correct response to losing it.
func TestAnImageThatGoesAwayTakesTheAdvertisementWithIt(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer origin.Close()

	workloads := compute.CatalogueWorkloads()
	runtime := &stubRuntime{present: map[string]bool{}}
	for _, w := range workloads {
		runtime.present[w.Image] = true
	}
	loader := &computeimage.Loader{Runtime: runtime, BaseURL: origin.URL,
		ScratchDir: t.TempDir(), Logger: quiet()}

	if !oneSweep(t, loader, workloads).last(t) {
		t.Fatal("a node holding its images did not advertise")
	}

	for _, w := range workloads {
		delete(runtime.present, w.Image)
	}
	if oneSweep(t, loader, workloads).last(t) {
		t.Fatal("an image disappeared and the node kept advertising compute")
	}
}

// TestTheAnnouncerSkipsAbsentReporters. A nil *p2p.Node arrives as a NON-nil
// interface holding a nil pointer, and compute is off on most nodes — so a
// naive loop would panic on the machines this feature is least involved with.
func TestTheAnnouncerSkipsAbsentReporters(t *testing.T) {
	var node *p2p.Node
	var api *computeAPI
	reporter := &recordingReporter{}
	announce := catalogueAnnouncer(node, api, nil, reporter)
	announce(true)
	if len(reporter.said) != 1 || !reporter.said[0] {
		t.Fatalf("the live reporter was not told: %v", reporter.said)
	}
}

// TestTheComputeAPIRefusesUntilTheCatalogueIsReady.
//
// The advertisement is the real fix; this is what stops a stale site listing
// from getting a job accepted by a node that cannot run it. Retryable, because
// a node in the middle of a download is not a node that has declined.
func TestTheComputeAPIRefusesUntilTheCatalogueIsReady(t *testing.T) {
	api, _ := testComputeAPI(t, compute.Policy{Enabled: true, OfferCPU: true})
	api.SetComputeCatalogueReady(false)

	for _, probe := range []struct {
		what    string
		handler http.HandlerFunc
		body    map[string]any
	}{
		{"admit", api.handleAdmit, map[string]any{"device": "cpu"}},
		{"submit", api.handleSubmit, map[string]any{
			"job_id": "1", "device": "cpu", "workload": "embed",
			"files": map[string]string{"input.jsonl": "{}"},
		}},
	} {
		raw, err := json.Marshal(probe.body)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		probe.handler(recorder, httptest.NewRequest(http.MethodPost, "/compute/"+probe.what,
			bytes.NewReader(raw)))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: a node without its images answered HTTP %d, not 503",
				probe.what, recorder.Code)
		}
		var answer map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
			t.Fatalf("%s: %v", probe.what, err)
		}
		if answer["retryable"] != true {
			t.Fatalf("%s: a node fetching its images refused permanently: %v",
				probe.what, answer)
		}
	}

	// And accepts once the images are there, or the gate would simply be
	// compute switched off.
	api.SetComputeCatalogueReady(true)
	recorder := httptest.NewRecorder()
	api.handleAdmit(recorder, httptest.NewRequest(http.MethodPost, "/compute/admit",
		bytes.NewReader([]byte(`{"device":"cpu"}`))))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a ready node refused admit: HTTP %d %s", recorder.Code, recorder.Body)
	}
}
