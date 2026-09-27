//go:build !linux

package main

// A non-Linux node may EXPOSE the compute API. It must be impossible for it to
// claim a workload was admitted or executed.
//
// These exercise the real handlers through real requests rather than scanning
// source: the failure worth catching is a handler that answers 200 with an
// empty body, and no amount of reading the file proves it does not.

import (
	"encoding/json"
	"reflect"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/config"
)

func offeringConfig() config.Config {
	var cfg config.Config
	cfg.Compute.Enabled = true
	cfg.Compute.OfferCPU = true
	return cfg
}

func quietLogger() *log.Logger { return log.New(new(strings.Builder), "", 0) }

func TestNonLinuxComputeAPIExistsWhenTheOperatorOffersADevice(t *testing.T) {
	// It must be non-nil, or dcsapi.go's `if compute != nil` unmounts the
	// routes and a deliberate platform limit becomes an unexplained 404.
	if newComputeAPI(offeringConfig(), quietLogger()) == nil {
		t.Fatal("compute was offered but the API is nil, so the routes will not mount")
	}
}

func TestNonLinuxComputeAPIStaysSilentWhenNothingIsOffered(t *testing.T) {
	// Same consent rule as Linux: a node lending nothing does not answer
	// "would you take this?" at all.
	var off config.Config
	if newComputeAPI(off, quietLogger()) != nil {
		t.Fatal("a node offering no device built a compute API anyway")
	}
}

// call runs one handler and returns its status and decoded body.
func call(t *testing.T, h func(http.ResponseWriter, *http.Request), path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"device":"cpu"}`)))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s returned unparseable body %q", path, rec.Body.String())
	}
	return rec.Code, body
}

func TestNonLinuxComputeNeverAcceptsOrExecutes(t *testing.T) {
	api := newComputeAPI(offeringConfig(), quietLogger())
	if api == nil {
		t.Fatal("no API to test")
	}
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		path    string
		// The field whose truth would mean this node had taken the job.
		claim string
	}{
		{"admit", api.handleAdmit, "/compute/admit", "admitted"},
		{"submit", api.handleSubmit, "/compute/submit", "accepted"},
		{"result", api.handleResult, "/compute/result", "done"},
	} {
		code, body := call(t, tc.handler, tc.path)

		// Never a success status. 2xx here is a node saying yes.
		if code/100 == 2 {
			t.Errorf("%s answered %d — a non-Linux node accepted compute work", tc.name, code)
		}
		if code != http.StatusNotImplemented {
			t.Errorf("%s answered %d, want 501", tc.name, code)
		}
		// The claim field must be present AND false. Absent would let a lenient
		// caller read the zero value as "not stated" rather than "no".
		v, ok := body[tc.claim]
		if !ok {
			t.Errorf("%s does not state %q at all", tc.name, tc.claim)
		}
		if v == true {
			t.Errorf("%s reported %s=true on a platform with no executor", tc.name, tc.claim)
		}
		// It must name the platform limit, not imply something is missing that
		// could be installed.
		reason, _ := body["reason"].(string)
		for _, want := range []string{"Linux", "KVM"} {
			if !strings.Contains(reason, want) {
				t.Errorf("%s reason does not mention %s: %q", tc.name, want, reason)
			}
		}
		// Not retryable: waiting will not make this host Linux.
		if body["retryable"] == true {
			t.Errorf("%s told the caller to retry a permanent platform limit", tc.name)
		}
	}
}

func TestNonLinuxCatalogueReadinessChangesNothing(t *testing.T) {
	// Holding every image does not make a platform able to isolate what runs in
	// them. Admission must refuse identically before and after.
	api := newComputeAPI(offeringConfig(), quietLogger())
	before, _ := call(t, api.handleAdmit, "/compute/admit")
	api.SetComputeCatalogueReady(true)
	after, body := call(t, api.handleAdmit, "/compute/admit")

	if before != after {
		t.Fatalf("catalogue readiness changed admission: %d then %d", before, after)
	}
	if body["admitted"] == true {
		t.Fatal("a ready catalogue admitted work on a platform that cannot run it")
	}
}

func TestNonLinuxComputeAPICarriesNoExecutor(t *testing.T) {
	// Structural: the type must hold nothing that could execute. A field added
	// here later would be the beginning of a second, unaudited compute path.
	api := newComputeAPI(offeringConfig(), quietLogger())
	if got := reflect.TypeOf(*api).NumField(); got != 0 {
		t.Fatalf("the non-Linux computeAPI grew %d field(s); it must hold no executor", got)
	}
}
