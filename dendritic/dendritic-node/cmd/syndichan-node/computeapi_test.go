//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/computeworker"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
)

// recordingRuntime is a container runtime that starts nothing. What these tests
// are about is which IMAGE the node decided to run and on whose say-so, and that
// decision is made entirely before anything is created.
type recordingRuntime struct {
	mu    sync.Mutex
	specs []dcs.ContainerSpec
	seen  chan dcs.ContainerSpec
	// produced is what the "container" wrote, keyed by full in-container path.
	// Nil means it wrote nothing, which is the default because that is the case
	// the node used to report as a clean success.
	produced map[string][]byte
	// gets records every path the worker asked for. A workload dispatched with
	// no Outputs asks for none, which is the defect these tests exist for.
	gets []string
}

func (r *recordingRuntime) Create(_ context.Context, spec dcs.ContainerSpec) (string, error) {
	r.mu.Lock()
	r.specs = append(r.specs, spec)
	r.mu.Unlock()
	select {
	case r.seen <- spec:
	default:
	}
	return "container-1", nil
}

func (r *recordingRuntime) Start(context.Context, string) error { return nil }
func (r *recordingRuntime) Wait(context.Context, string) (int, error) {
	return 0, nil
}

func (r *recordingRuntime) Logs(context.Context, string) ([]byte, []byte, error) {
	return []byte("embed-digest sha256:deadbeef count:2\n"), nil, nil
}
func (r *recordingRuntime) Remove(context.Context, string, bool) error { return nil }

// PutArchive accepts the submitter's data without inspecting it. These tests are
// about the DECISION — which image, on whose say-so — and that is settled before
// a byte is delivered.
func (r *recordingRuntime) PutArchive(context.Context, string, string, []byte) error {
	return nil
}

// GetArchive answers with what the container "wrote", or reports the path
// absent. ErrArchiveMissing is the real runtime's answer for an absent path, so
// a fake that returned an empty tar instead would exercise a case Docker never
// produces.
func (r *recordingRuntime) GetArchive(_ context.Context, _, containerPath string) ([]byte, error) {
	r.mu.Lock()
	r.gets = append(r.gets, containerPath)
	data, ok := r.produced[containerPath]
	r.mu.Unlock()
	if !ok {
		return nil, dcs.ErrArchiveMissing
	}
	return tarOf(containerPath[strings.LastIndex(containerPath, "/")+1:], data), nil
}

// tarOf wraps one file the way Docker's archive endpoint does: a single-entry
// tar named after the path's last element.
func tarOf(name string, data []byte) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{
		Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)),
	})
	_, _ = tw.Write(data)
	_ = tw.Close()
	return buf.Bytes()
}

// awaitResult polls the result endpoint the way the site does. Submit answers
// before the job has run, so the result only exists a moment later.
func awaitResult(t *testing.T, api *computeAPI, jobID string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		body := strings.NewReader(`{"job_id":"` + jobID + `"}`)
		api.handleResult(rec, httptest.NewRequest(http.MethodPost, "/compute/result", body))
		var decoded map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("result was not JSON (%d): %q", rec.Code, rec.Body.String())
		}
		if decoded["done"] == true {
			result, _ := decoded["result"].(map[string]any)
			if result == nil {
				t.Fatalf("a finished job carried no result: %s", rec.Body.String())
			}
			return result
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s never finished", jobID)
	return nil
}

// awaitSpec waits for the background goroutine to reach the runtime. Submit
// answers before the job runs — deliberately, so a site request thread is not
// held for a minute of compute — so the spec arrives slightly after the
// response.
func (r *recordingRuntime) awaitSpec(t *testing.T) dcs.ContainerSpec {
	t.Helper()
	select {
	case spec := <-r.seen:
		return spec
	case <-time.After(5 * time.Second):
		t.Fatal("no container was ever created for an accepted job")
		return dcs.ContainerSpec{}
	}
}

// steadySensors is a machine that is plainly free: cool, plugged in, idle.
type steadySensors struct{}

func (steadySensors) LoadAverage1() float64 { return 0.05 }
func (steadySensors) OnBattery() bool       { return false }
func (steadySensors) HottestC() int         { return 40 }
func (steadySensors) GPUBusyPercent() int   { return 0 }

func testComputeAPI(t *testing.T, policy compute.Policy) (*computeAPI, *recordingRuntime) {
	t.Helper()
	policy = policy.Normalise()
	profile := compute.Profile{CPU: compute.CPUInfo{PhysicalCores: 8, LogicalCores: 16}}
	runtime := &recordingRuntime{seen: make(chan dcs.ContainerSpec, 8)}
	api := &computeAPI{
		worker: computeworker.New(runtime, compute.NewGovernor(policy, profile, steadySensors{}), policy),
		// Container isolation, and micro deliberately nil: this is the ordinary
		// node, the one that must refuse arbitrary code rather than fall back.
		isolation: computeworker.IsolationContainer,
		policy:    policy,
		results:   map[string]computeworker.Result{},
		running:   map[string]bool{},
	}
	// These tests are about the catalogue rule, the isolation rule and the
	// governor — every one of which is asked AFTER the node has established it
	// holds its images. A node that has not is refused before any of them, which
	// is the subject of TestCatalogueImages, so it is set here rather than left
	// at its zero value and defeating everything else in this file.
	api.SetComputeCatalogueReady(true)
	return api, runtime
}

func submitTo(t *testing.T, api *computeAPI, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	api.handleSubmit(rec, httptest.NewRequest(http.MethodPost, "/compute/submit", bytes.NewReader(raw)))
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response was not JSON (%d): %q", rec.Code, rec.Body.String())
	}
	return rec, decoded
}

func lendingCPU() compute.Policy { return compute.Policy{Enabled: true, OfferCPU: true} }

// THE CLOSED-TABLE PROPERTY, at the boundary that matters.
//
// An unknown workload is refused, and the refusal must not leak what the node
// WOULD have run. A response that echoed a resolved image would both tell a
// prober what this machine has and blur the line between "you named a workload"
// and "you named an image".
func TestAnUnknownWorkloadIsRefusedAndNamesNoImage(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-1", "device": "cpu", "workload": "definitely-not-a-workload",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	text := rec.Body.String()
	for _, leak := range []string{"registry.local", "compute-embed", "latest"} {
		if strings.Contains(text, leak) {
			t.Fatalf("the refusal leaked %q: %s", leak, text)
		}
	}
	if !strings.Contains(text, "definitely-not-a-workload") {
		t.Fatalf("the refusal did not say what was refused: %s", text)
	}
	if body["accepted"] == true {
		t.Fatal("an unknown workload was accepted")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 0 {
		t.Fatalf("an unknown workload still started %d container(s)", len(runtime.specs))
	}
}

// The path M10 slice 1 actually takes: a workload name in, a unit digest back,
// and the catalogue image running as DATA work.
func TestAKnownWorkloadIsAcceptedAsDataNotCode(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-2", "device": "cpu", "workload": "embed",
		"params": map[string]string{"model": "minilm"}, "seed": 11,
		"timeout_seconds": 300,
		"files":           map[string]string{"input.jsonl": "{\"id\":\"1\",\"text\":\"hello\"}"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if body["accepted"] != true {
		t.Fatalf("workload not accepted: %s", rec.Body.String())
	}

	embed, _ := compute.LookupWorkload("embed")
	want, err := compute.UnitFor(embed, "cpu", map[string]string{"model": "minilm"}, 11, 300)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := body["ticket"].(string); got != want.Digest() {
		t.Fatalf("ticket = %q, want the unit digest %q", got, want.Digest())
	}
	if want.Deterministic != true {
		t.Fatal("the ticket describes non-deterministic work, which M5 cannot check by hash")
	}

	// Arbitrary stayed false, demonstrated rather than asserted on a field: this
	// node has no microVM, so an arbitrary submission would have been refused
	// outright, and the work reached the CONTAINER path with the catalogue image
	// the table names.
	if api.micro != nil {
		t.Fatal("test node unexpectedly has a microVM; the assertion below proves nothing")
	}
	spec := runtime.awaitSpec(t)
	if spec.Image != embed.Image {
		t.Fatalf("ran %q, want the catalogue image %q", spec.Image, embed.Image)
	}
	if spec.MemoryLimitBytes <= 0 {
		t.Fatal("the container ran uncapped; a runaway job takes the volunteer's machine")
	}
	// This job was HANDED a file, and the daemon refuses to extract an archive
	// into a read-only rootfs at all, so the writable root is not a slip — it is
	// the documented price of delivering data. What must not slip is everything
	// else, so the scratch mount is still checked here.
	if !spec.WritableRootfs {
		t.Fatal("a job carrying files got a read-only root; the archive delivery cannot succeed")
	}
	if spec.TmpfsMounts["/tmp"] == "" {
		t.Fatal("no memory-backed scratch; the job's temporary files would outlive nothing but cost the disk")
	}
}

// THE DEFECT THIS FILE NOW GUARDS.
//
// A workload's answer is a FILE. Submit built the job without ever setting
// Outputs, so the worker fetched nothing, the file was destroyed with the
// container, and the site received a stdout digest, exit 0, and no vectors —
// which it verified by hash, marked done and paid for.
func TestAWorkloadsProducedFileLeavesTheNode(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	embed, _ := compute.LookupWorkload("embed")
	vectors := "{\"dim\":384,\"id\":0,\"vec\":\"beef\"}\n"
	runtime.mu.Lock()
	runtime.produced = map[string][]byte{
		computeworker.WorkDir + "/" + embed.OutputFile: []byte(vectors),
	}
	runtime.mu.Unlock()

	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-out-1", "device": "cpu", "workload": "embed",
		"files": map[string]string{"input.jsonl": "{\"id\":0,\"text\":\"hi\"}"},
	})
	if rec.Code != http.StatusOK || body["accepted"] != true {
		t.Fatalf("workload refused (%d): %s", rec.Code, rec.Body.String())
	}

	result := awaitResult(t, api, "job-out-1")
	outputs, _ := result["outputs"].(map[string]any)
	if outputs[embed.OutputFile] != vectors {
		t.Fatalf("the produced file did not come back: %#v (asked for %v)",
			result["outputs"], runtime.gets)
	}
	if result["error"] != nil {
		t.Errorf("a complete run reported an error: %v", result["error"])
	}
	// The path is relative to the job's working directory, which is where the
	// image writes and the only place the worker looks.
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.gets) != 1 || runtime.gets[0] != computeworker.WorkDir+"/"+embed.OutputFile {
		t.Fatalf("the node asked for %v, want just %s/%s",
			runtime.gets, computeworker.WorkDir, embed.OutputFile)
	}
}

// The silent charge. A run whose product never arrived must not be reportable
// as a success — the site's verification hashes stdout, so a node that returned
// a digest and no file would otherwise agree with an honest replica and be paid
// for vectors that do not exist.
func TestAWorkloadThatProducedNoFileIsNotReportedAsASuccess(t *testing.T) {
	api, _ := testComputeAPI(t, lendingCPU())
	rec, _ := submitTo(t, api, map[string]any{
		"job_id": "job-out-2", "device": "cpu", "workload": "embed",
		"files": map[string]string{"input.jsonl": "{\"id\":0,\"text\":\"hi\"}"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("workload refused (%d): %s", rec.Code, rec.Body.String())
	}

	result := awaitResult(t, api, "job-out-2")
	missing, _ := result["missing_outputs"].([]any)
	if len(missing) != 1 || missing[0] != "output.jsonl" {
		t.Fatalf("the node did not say its product was absent: %#v", result["missing_outputs"])
	}
	text, _ := result["error"].(string)
	if !strings.Contains(text, "output.jsonl") {
		t.Fatalf("error %q does not name what never arrived", text)
	}
}

// A language job's whole answer is its stdout. It asks for no files back, and
// the required-output rule must not reach it — a python program that writes
// nothing has still answered.
func TestALanguageJobAsksForNoFilesBack(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	rec, _ := submitTo(t, api, map[string]any{
		"job_id": "job-out-3", "device": "cpu", "language": "python",
		"entrypoint": "main.py", "files": map[string]string{"main.py": "print(1)"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("language job refused (%d): %s", rec.Code, rec.Body.String())
	}
	result := awaitResult(t, api, "job-out-3")
	if result["error"] != nil {
		t.Errorf("a language job was failed for producing no file: %v", result["error"])
	}
	if result["missing_outputs"] != nil {
		t.Errorf("a language job was told it owed a file: %v", result["missing_outputs"])
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.gets) != 0 {
		t.Errorf("a language job reached into the container for %v", runtime.gets)
	}
}

// The operator's consent, and the shape of the refusal. Permanent, because the
// operator wrote it and it will say the same thing in an hour — a queue that
// retried it would never drain and never explain why.
func TestAWorkloadTheOperatorDidNotAllowIsRefusedPermanently(t *testing.T) {
	policy := lendingCPU()
	policy.Workloads = []string{"some-other-workload"}
	api, runtime := testComputeAPI(t, policy)

	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-3", "device": "cpu", "workload": "embed",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if body["admitted"] != false {
		t.Fatalf("did not report a refusal: %s", rec.Body.String())
	}
	if body["retryable"] != false {
		t.Fatalf("a permanent refusal was reported as retryable: %s", rec.Body.String())
	}
	if reason, _ := body["reason"].(string); reason == "" || !strings.Contains(reason, "embed") {
		t.Fatalf("reason %q does not say what was refused", reason)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 0 {
		t.Fatal("a refused workload still started a container")
	}
}

func TestAnAllowedWorkloadStillRuns(t *testing.T) {
	policy := lendingCPU()
	policy.Workloads = []string{"embed"}
	api, _ := testComputeAPI(t, policy)
	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-4", "device": "cpu", "workload": "embed",
	})
	if rec.Code != http.StatusOK || body["accepted"] != true {
		t.Fatalf("an opted-in workload was refused (%d): %s", rec.Code, rec.Body.String())
	}
}

// Language jobs keep their exact behaviour: the same closed table, the same
// job-id ticket compute_bridge already depends on.
func TestLanguageJobsAreUnchanged(t *testing.T) {
	api, runtime := testComputeAPI(t, lendingCPU())
	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-5", "device": "cpu", "language": "python",
		"entrypoint": "main.py", "files": map[string]string{"main.py": "print(1)"},
	})
	if rec.Code != http.StatusOK || body["accepted"] != true {
		t.Fatalf("language job refused (%d): %s", rec.Code, rec.Body.String())
	}
	if got, _ := body["ticket"].(string); got != "job-5" {
		t.Fatalf("ticket = %q, want the job id", got)
	}
	if spec := runtime.awaitSpec(t); spec.Image != catalogueImages["python"] {
		t.Fatalf("ran %q, want the python image", spec.Image)
	}

	rec, _ = submitTo(t, api, map[string]any{
		"job_id": "job-6", "device": "cpu", "language": "brainfuck",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown language got %d, want 400", rec.Code)
	}
}

// A workload allowlist gates WORKLOADS. It must not become a second, accidental
// gate on the language images — those are already gated by the arbitrary-code
// rule, and stacking a silent second refusal on them would look like a broken
// node.
func TestAWorkloadAllowlistDoesNotGateLanguageJobs(t *testing.T) {
	policy := lendingCPU()
	policy.Workloads = []string{"embed"}
	api, _ := testComputeAPI(t, policy)
	rec, body := submitTo(t, api, map[string]any{
		"job_id": "job-7", "device": "cpu", "language": "python",
		"entrypoint": "main.py", "files": map[string]string{"main.py": "print(1)"},
	})
	if rec.Code != http.StatusOK || body["accepted"] != true {
		t.Fatalf("a workload allowlist refused a language job (%d): %s", rec.Code, rec.Body.String())
	}
}

// Resubmission of work already in flight answers with the SAME ticket and does
// not start it twice. The site retries on a timeout it cannot distinguish from
// a lost request, and running the job again would bill the work twice.
func TestResubmissionReturnsTheSameUnitDigest(t *testing.T) {
	api, _ := testComputeAPI(t, lendingCPU())
	api.mu.Lock()
	api.running["job-8"] = true
	api.mu.Unlock()

	_, body := submitTo(t, api, map[string]any{
		"job_id": "job-8", "device": "cpu", "workload": "embed", "seed": 5,
	})
	embed, _ := compute.LookupWorkload("embed")
	want, err := compute.UnitFor(embed, "cpu", nil, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := body["ticket"].(string); got != want.Digest() {
		t.Fatalf("ticket = %q, want the unit digest %q", got, want.Digest())
	}
}
