package computeimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

// fakeRuntime is a Docker daemon that remembers what it was asked to do.
//
// `present` is a set rather than a flag so a test can say "this image is
// missing, and it appears once something loads it" — which is the whole
// behaviour under test, and a bool would let a broken loader pass by reporting
// success without the tag ever existing.
type fakeRuntime struct {
	present map[string]bool
	// loaded holds the bytes handed to `docker load`, in order. Its LENGTH is
	// the assertion that matters most here: the digest-mismatch test passes only
	// if it is still zero afterwards.
	loaded [][]byte
	// appears is the tag that becomes present after a load. Empty means the load
	// produces nothing, which is how a mislabelled artifact is simulated.
	appears  string
	loadErr  error
	existErr error
}

func (f *fakeRuntime) ImageExists(_ context.Context, reference string) (bool, error) {
	if f.existErr != nil {
		return false, f.existErr
	}
	return f.present[reference], nil
}

func (f *fakeRuntime) LoadImage(_ context.Context, tarball io.Reader) error {
	body, err := io.ReadAll(tarball)
	if err != nil {
		return err
	}
	f.loaded = append(f.loaded, body)
	if f.loadErr != nil {
		return f.loadErr
	}
	if f.appears != "" {
		if f.present == nil {
			f.present = map[string]bool{}
		}
		f.present[f.appears] = true
	}
	return nil
}

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// serving returns a server handing out `body` at any path, and a count of how
// many times it was asked.
func serving(t *testing.T, body []byte) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func testLoader(t *testing.T, runtime Runtime, base string) *Loader {
	t.Helper()
	return &Loader{
		Runtime:    runtime,
		BaseURL:    base,
		ScratchDir: t.TempDir(),
		Logger:     quietLogger(),
	}
}

// TestANodeLackingAnImageFetchesAndLoadsIt is the whole point of the package.
//
// Before this existed there was no image pull path anywhere in the node, so a
// node missing a catalogue image accepted the job, returned a ticket and died
// `No such image`.
func TestANodeLackingAnImageFetchesAndLoadsIt(t *testing.T) {
	artifact := []byte("a docker save tarball, as far as this layer is concerned")
	server, hits := serving(t, artifact)

	runtime := &fakeRuntime{present: map[string]bool{}, appears: "registry.local/compute-embed:latest"}
	loader := testLoader(t, runtime, server.URL)

	workload := compute.Workload{
		Name:     "embed",
		Image:    "registry.local/compute-embed:latest",
		Artifact: "compute-embed.tar",
		Digest:   digestOf(artifact),
	}
	if err := loader.EnsureOne(context.Background(), workload); err != nil {
		t.Fatalf("a fetchable image was not obtained: %v", err)
	}
	if *hits != 1 {
		t.Fatalf("expected exactly one download, got %d", *hits)
	}
	if len(runtime.loaded) != 1 {
		t.Fatalf("expected the artifact to be loaded once, got %d loads", len(runtime.loaded))
	}
	if string(runtime.loaded[0]) != string(artifact) {
		t.Fatalf("the bytes loaded are not the bytes served")
	}
	if !runtime.present[workload.Image] {
		t.Fatalf("the image is still not present after a successful load")
	}
}

// TestTheArtifactURLIsTheBaseAndTheArtifactName pins the address, because the
// site publishes at exactly one shape and a node that asked for a different one
// would 404 forever with a message about the network.
func TestTheArtifactURLIsTheBaseAndTheArtifactName(t *testing.T) {
	artifact := []byte("bytes")
	var asked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_, _ = w.Write(artifact)
	}))
	defer server.Close()

	runtime := &fakeRuntime{present: map[string]bool{}, appears: "img"}
	loader := testLoader(t, runtime, server.URL+"/dl/")
	err := loader.EnsureOne(context.Background(), compute.Workload{
		Name: "embed", Image: "img", Artifact: "compute-embed.tar",
		Digest: digestOf(artifact),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asked != "/dl/compute-embed.tar" {
		t.Fatalf("fetched %q, expected /dl/compute-embed.tar", asked)
	}
}

// TestADigestMismatchAbortsAndDoesNotLoad is the security property.
//
// This process is root-adjacent and `docker load` installs an executable
// filesystem image that will then be RUN. A mismatch is the case where somebody
// served something other than what this build was built to accept, and the only
// safe response is to install none of it.
func TestADigestMismatchAbortsAndDoesNotLoad(t *testing.T) {
	served := []byte("not the artifact this node expects")
	server, hits := serving(t, served)

	runtime := &fakeRuntime{present: map[string]bool{}, appears: "registry.local/compute-embed:latest"}
	scratch := t.TempDir()
	loader := &Loader{Runtime: runtime, BaseURL: server.URL, ScratchDir: scratch,
		Logger: quietLogger()}

	err := loader.EnsureOne(context.Background(), compute.Workload{
		Name:     "embed",
		Image:    "registry.local/compute-embed:latest",
		Artifact: "compute-embed.tar",
		Digest:   digestOf([]byte("the artifact this node expects")),
	})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected a digest mismatch, got %v", err)
	}
	if *hits != 1 {
		t.Fatalf("expected the artifact to have been fetched once, got %d", *hits)
	}
	if len(runtime.loaded) != 0 {
		t.Fatalf("BYTES THAT FAILED VERIFICATION WERE LOADED (%d times)", len(runtime.loaded))
	}
	if runtime.present["registry.local/compute-embed:latest"] {
		t.Fatalf("the image became present despite a failed verification")
	}
	// Both digests in the message, so an operator can tell a truncated download
	// from an artifact that is simply not the one this build expects.
	if !strings.Contains(err.Error(), digestOf(served)) {
		t.Fatalf("the error does not say what was actually received: %v", err)
	}
	// Nothing left staged. A rejected image tarball sitting on disk beside a
	// good one is an invitation to load the wrong file by hand later.
	left, _ := filepath.Glob(filepath.Join(scratch, "*"))
	if len(left) != 0 {
		t.Fatalf("the rejected download was left behind: %v", left)
	}
}

// TestASuccessfulLoadLeavesNothingStaged: ~190 MB per image is not a cache to
// keep on a volunteer's disk once the daemon holds its own copy.
func TestASuccessfulLoadLeavesNothingStaged(t *testing.T) {
	artifact := []byte("tarball")
	server, _ := serving(t, artifact)
	runtime := &fakeRuntime{present: map[string]bool{}, appears: "img"}
	scratch := t.TempDir()
	loader := &Loader{Runtime: runtime, BaseURL: server.URL, ScratchDir: scratch,
		Logger: quietLogger()}
	if err := loader.EnsureOne(context.Background(), compute.Workload{
		Name: "embed", Image: "img", Artifact: "a.tar", Digest: digestOf(artifact),
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(scratch, "*"))
	if len(left) != 0 {
		t.Fatalf("a staged download survived a successful load: %v", left)
	}
}

// TestAnImageAlreadyPresentIsNotDownloaded. The operator who ran
// compute-images/build.sh must not be made to download 190 MB to be told what
// they already have.
func TestAnImageAlreadyPresentIsNotDownloaded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("an image that is already present was downloaded anyway")
	}))
	defer server.Close()

	runtime := &fakeRuntime{present: map[string]bool{"img": true}}
	loader := testLoader(t, runtime, server.URL)
	if err := loader.EnsureOne(context.Background(), compute.Workload{
		Name: "embed", Image: "img", Artifact: "a.tar", Digest: digestOf([]byte("x")),
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runtime.loaded) != 0 {
		t.Fatalf("a present image was loaded again")
	}
}

// TestAWorkloadWithNoPublishedDigestIsNeverDownloaded.
//
// Downloading an executable image with nothing to check it against is the one
// thing the digest exists to prevent, so a catalogue entry that forgot its
// digest must fail closed rather than fetch on trust.
func TestAWorkloadWithNoPublishedDigestIsNeverDownloaded(t *testing.T) {
	for _, missing := range []compute.Workload{
		{Name: "a", Image: "img", Artifact: "a.tar", Digest: ""},
		{Name: "b", Image: "img", Artifact: "a.tar", Digest: "sha256:" + strings.Repeat("a", 64)},
		{Name: "c", Image: "img", Artifact: "a.tar", Digest: strings.Repeat("z", 64)},
		{Name: "d", Image: "img", Artifact: "", Digest: strings.Repeat("a", 64)},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Errorf("%s: an unverifiable image was downloaded", missing.Name)
		}))
		runtime := &fakeRuntime{present: map[string]bool{}}
		loader := testLoader(t, runtime, server.URL)
		err := loader.EnsureOne(context.Background(), missing)
		if !errors.Is(err, ErrNotFetchable) {
			t.Fatalf("%s: expected ErrNotFetchable, got %v", missing.Name, err)
		}
		server.Close()
	}
}

// TestALoadThatDoesNotProduceTheExpectedTagFails. `docker load` installs
// whatever tags the tarball declares; a verified artifact carrying the wrong tag
// would otherwise be a successful load of an image that is still missing.
func TestALoadThatDoesNotProduceTheExpectedTagFails(t *testing.T) {
	artifact := []byte("tarball carrying some other tag")
	server, _ := serving(t, artifact)
	runtime := &fakeRuntime{present: map[string]bool{}, appears: ""}
	loader := testLoader(t, runtime, server.URL)

	err := loader.EnsureOne(context.Background(), compute.Workload{
		Name: "embed", Image: "registry.local/compute-embed:latest",
		Artifact: "compute-embed.tar", Digest: digestOf(artifact),
	})
	if err == nil {
		t.Fatal("a load that produced nothing was reported as success")
	}
	if !strings.Contains(err.Error(), "does not carry that tag") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// TestAnOversizedArtifactIsRefused. Without a cap, a server answering with an
// endless stream fills a volunteer's disk.
func TestAnOversizedArtifactIsRefused(t *testing.T) {
	big := make([]byte, 4096)
	server, _ := serving(t, big)
	runtime := &fakeRuntime{present: map[string]bool{}, appears: "img"}
	loader := testLoader(t, runtime, server.URL)
	loader.MaxBytes = 1024

	err := loader.EnsureOne(context.Background(), compute.Workload{
		Name: "embed", Image: "img", Artifact: "a.tar", Digest: digestOf(big),
	})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected a size refusal, got %v", err)
	}
	if len(runtime.loaded) != 0 {
		t.Fatal("an oversized artifact was loaded")
	}
}

// TestAFailedFetchIsReportedRatherThanIgnored: a 404 or a dead origin must not
// look like a satisfied catalogue.
func TestAFailedFetchIsReportedRatherThanIgnored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	runtime := &fakeRuntime{present: map[string]bool{}}
	loader := testLoader(t, runtime, server.URL)
	err := loader.Ensure(context.Background(), []compute.Workload{{
		Name: "embed", Image: "img", Artifact: "a.tar", Digest: digestOf([]byte("x")),
	}})
	if err == nil {
		t.Fatal("a 404 left the catalogue looking satisfied")
	}
	if !strings.Contains(err.Error(), "embed") {
		t.Fatalf("the failure does not name the workload: %v", err)
	}
}

// TestEnsureNamesEveryWorkloadThatFailed, so an operator debugging a fetch gets
// the list once rather than one name per restart.
func TestEnsureNamesEveryWorkloadThatFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	runtime := &fakeRuntime{present: map[string]bool{"third": true}}
	loader := testLoader(t, runtime, server.URL)
	err := loader.Ensure(context.Background(), []compute.Workload{
		{Name: "first", Image: "one", Artifact: "a.tar", Digest: digestOf([]byte("1"))},
		{Name: "second", Image: "two", Artifact: "b.tar", Digest: digestOf([]byte("2"))},
		{Name: "third", Image: "third", Artifact: "c.tar", Digest: digestOf([]byte("3"))},
	})
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, want := range []string{"first", "second"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%s missing from %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "third") {
		t.Fatalf("a workload that WAS present was reported as failed: %v", err)
	}
}

// TestAnEmptyCatalogueIsSatisfied — Ensure over nothing must not report a
// failure, or a build with no workloads would take compute off every node.
func TestAnEmptyCatalogueIsSatisfied(t *testing.T) {
	loader := testLoader(t, &fakeRuntime{}, "http://127.0.0.1:1")
	if err := loader.Ensure(context.Background(), nil); err != nil {
		t.Fatalf("an empty catalogue was reported as a failure: %v", err)
	}
}

// TestScratchDirIsUnderTheDataDir. /tmp is a tmpfs on many Linux installs, and
// staging 190 MB in RAM on a Raspberry Pi is how this feature would earn a
// reputation for killing the machines that volunteer for it.
func TestScratchDirIsUnderTheDataDir(t *testing.T) {
	if got := ScratchDirFor("/var/lib/syndichan"); got != filepath.Join("/var/lib/syndichan", "compute-images") {
		t.Fatalf("unexpected scratch dir %q", got)
	}
	if got := ScratchDirFor(""); got != "" {
		t.Fatalf("an unset data dir should not invent a path, got %q", got)
	}
}

// TestTheDefaultBaseURLIsUsedWhenNoneIsConfigured, because the ordinary node has
// no image_base_url in its config at all.
func TestTheDefaultBaseURLIsUsedWhenNoneIsConfigured(t *testing.T) {
	loader := &Loader{}
	if loader.baseURL() != DefaultBaseURL {
		t.Fatalf("unconfigured loader points at %q", loader.baseURL())
	}
	loader.BaseURL = "https://example.test/dl/"
	if loader.baseURL() != "https://example.test/dl" {
		t.Fatalf("trailing slash not trimmed: %q", loader.baseURL())
	}
}

// TestADaemonFailureIsNotAMissingImage. ImageExists returning an error means the
// daemon is broken, and treating that as "absent" would send the node
// downloading 190 MB it cannot load.
func TestADaemonFailureIsNotAMissingImage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("downloaded despite the daemon being unreachable")
	}))
	defer server.Close()

	runtime := &fakeRuntime{existErr: errors.New("dial unix: no such file")}
	loader := testLoader(t, runtime, server.URL)
	if err := loader.EnsureOne(context.Background(), compute.Workload{
		Name: "embed", Image: "img", Artifact: "a.tar", Digest: digestOf([]byte("x")),
	}); err == nil {
		t.Fatal("a broken daemon was reported as a satisfied catalogue")
	}
}

// TestTheRealCatalogueIsDistributable. Every shipped workload must name an
// artifact and a well-formed digest, or a volunteer who did not build the image
// by hand has no way to obtain it and the node will not advertise compute.
func TestTheRealCatalogueIsDistributable(t *testing.T) {
	workloads := compute.CatalogueWorkloads()
	if len(workloads) == 0 {
		t.Fatal("the catalogue is empty")
	}
	for _, w := range workloads {
		if ok, why := w.Fetchable(); !ok {
			t.Fatalf("%s cannot be distributed: %s — a node that did not build "+
				"this image by hand can never obtain it, so it will stop "+
				"advertising compute", w.Name, why)
		}
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
