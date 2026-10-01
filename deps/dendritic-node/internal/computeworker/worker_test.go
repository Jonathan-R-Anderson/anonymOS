package computeworker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
)

type putCall struct {
	destDir string
	tar     []byte
}

type fakeRuntime struct {
	mu       sync.Mutex
	created  []dcs.ContainerSpec
	removed  []string
	puts     []putCall
	gets     []string
	exitCode int
	stdout   string
	stderr   string
	startErr error
	putErr   error
	waitFor  time.Duration
	// files the container "wrote", keyed by full in-container path.
	produced map[string][]byte
	// getErr overrides the archive answer for a specific path.
	getErr map[string]error
	// events records the order of runtime calls, because WHEN files are
	// delivered is the whole correctness question: after Start is too late.
	events []string
}

func (f *fakeRuntime) record(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *fakeRuntime) Create(_ context.Context, spec dcs.ContainerSpec) (string, error) {
	f.mu.Lock()
	f.created = append(f.created, spec)
	f.events = append(f.events, "create")
	f.mu.Unlock()
	return "c-" + spec.Name, nil
}
func (f *fakeRuntime) Start(_ context.Context, _ string) error {
	f.record("start")
	return f.startErr
}
func (f *fakeRuntime) Wait(ctx context.Context, _ string) (int, error) {
	f.record("wait")
	if f.waitFor > 0 {
		select {
		case <-time.After(f.waitFor):
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	}
	return f.exitCode, nil
}
func (f *fakeRuntime) Logs(_ context.Context, _ string) ([]byte, []byte, error) {
	f.record("logs")
	return []byte(f.stdout), []byte(f.stderr), nil
}
func (f *fakeRuntime) PutArchive(_ context.Context, _ string, destDir string, tarBytes []byte) error {
	f.mu.Lock()
	f.puts = append(f.puts, putCall{destDir: destDir, tar: append([]byte(nil), tarBytes...)})
	f.events = append(f.events, "put")
	f.mu.Unlock()
	return f.putErr
}
func (f *fakeRuntime) GetArchive(_ context.Context, _ string, containerPath string) ([]byte, error) {
	f.mu.Lock()
	f.gets = append(f.gets, containerPath)
	f.events = append(f.events, "get:"+containerPath)
	f.mu.Unlock()
	if err, ok := f.getErr[containerPath]; ok {
		return nil, err
	}
	data, ok := f.produced[containerPath]
	if !ok {
		return nil, fmt.Errorf("%w: %s", dcs.ErrArchiveMissing, containerPath)
	}
	return tarOf(pathBase(containerPath), data), nil
}
func (f *fakeRuntime) Remove(_ context.Context, id string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	f.events = append(f.events, "remove")
	return nil
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// tarOf builds the single-entry archive Docker returns for one file.
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

// tarEntries reads back a delivered archive: name -> contents, plus the order
// the entries appeared in and their headers.
func tarEntries(t *testing.T, blob []byte) ([]string, map[string]*tar.Header, map[string]string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(blob))
	var order []string
	headers := map[string]*tar.Header{}
	bodies := map[string]string{}
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("delivered archive is not a readable tar: %v", err)
		}
		order = append(order, header.Name)
		copied := *header
		headers[header.Name] = &copied
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		bodies[header.Name] = string(body)
	}
	return order, headers, bodies
}

func cpuPolicy() compute.Policy {
	return compute.Policy{Enabled: true, OfferCPU: true}
}

func job(device string) Job {
	return Job{ID: "job1", Device: device, Image: "img@sha256:abc", Timeout: 2 * time.Second}
}

// The operator's switch is a permanent no, and the caller must be able to tell.
// A queue that retries a permanent refusal forever never drains and never says
// why.
func TestDeclinedDeviceIsANonRetryableRefusal(t *testing.T) {
	w := New(&fakeRuntime{}, nil, cpuPolicy())
	err := w.Admit("gpu:cuda")
	if err == nil {
		t.Fatal("admitted GPU work the operator did not offer")
	}
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("got %T, want *Refusal", err)
	}
	if refusal.Retryable {
		t.Error("a declined device was reported as retryable")
	}
	if !strings.Contains(refusal.Reason, "gpu:cuda") {
		t.Errorf("reason %q does not name the device", refusal.Reason)
	}
}

func TestComputeOffIsRefused(t *testing.T) {
	w := New(&fakeRuntime{}, nil, compute.Policy{Enabled: false, OfferCPU: true})
	if err := w.Admit("cpu"); err == nil {
		t.Fatal("admitted work with compute disabled")
	}
}

func TestOfferedDeviceIsAdmitted(t *testing.T) {
	w := New(&fakeRuntime{}, nil, cpuPolicy())
	if err := w.Admit("cpu"); err != nil {
		t.Fatalf("refused offered CPU work: %v", err)
	}
}

// One job at a time per device, and the second must be told it is busy rather
// than silently queued or run alongside.
func TestSecondJobOnTheSameDeviceIsRefusedWhileBusy(t *testing.T) {
	rt := &fakeRuntime{waitFor: 400 * time.Millisecond}
	w := New(rt, nil, cpuPolicy())

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		_, _ = w.Run(context.Background(), job("cpu"))
		close(done)
	}()
	<-started
	time.Sleep(80 * time.Millisecond)

	err := w.Admit("cpu")
	if err == nil {
		t.Fatal("admitted a second job while one was running")
	}
	var refusal *Refusal
	if errors.As(err, &refusal) && !refusal.Retryable {
		t.Error("a busy slot should be retryable — it clears on its own")
	}
	<-done

	// And the slot must free afterwards, or the node accepts one job ever.
	if err := w.Admit("cpu"); err != nil {
		t.Errorf("slot did not free after the job finished: %v", err)
	}
}

func TestSuccessfulRunReturnsOutput(t *testing.T) {
	rt := &fakeRuntime{exitCode: 0, stdout: "hello\n", stderr: ""}
	w := New(rt, nil, cpuPolicy())
	got, err := w.Run(context.Background(), job("cpu"))
	if err != nil {
		t.Fatal(err)
	}
	if got.ExitCode != 0 || got.Stdout != "hello\n" {
		t.Errorf("got %+v", got)
	}
	if got.TimedOut {
		t.Error("a job that finished was reported as timed out")
	}
}

// A timeout must still collect output. The logs of a program that ran too long
// are usually the only evidence of what it was doing.
func TestTimeoutStillCollectsOutput(t *testing.T) {
	rt := &fakeRuntime{waitFor: 3 * time.Second, stdout: "partial work\n"}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Timeout = 150 * time.Millisecond

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatalf("a timeout should be a result, not an error: %v", err)
	}
	if !got.TimedOut {
		t.Error("timeout not reported")
	}
	if got.Stdout != "partial work\n" {
		t.Errorf("output was discarded on timeout: %q", got.Stdout)
	}
	if got.Error == "" {
		t.Error("timed-out job carries no explanation")
	}
}

// The container must be removed even when it never started — otherwise every
// start failure leaks one.
func TestContainerIsRemovedEvenWhenStartFails(t *testing.T) {
	rt := &fakeRuntime{startErr: errors.New("no such image")}
	w := New(rt, nil, cpuPolicy())
	if _, err := w.Run(context.Background(), job("cpu")); err == nil {
		t.Fatal("expected a start failure")
	}
	// Give the deferred removal a moment; it uses its own context.
	time.Sleep(50 * time.Millisecond)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.removed) == 0 {
		t.Fatal("a container was leaked after a start failure")
	}
}

// Every job gets a fresh container with a read-only root and a memory-backed
// /tmp — one submitter's leftovers must not become the next one's environment.
func TestEachJobGetsAFreshHardenedContainer(t *testing.T) {
	rt := &fakeRuntime{}
	w := New(rt, nil, cpuPolicy())
	for i := 0; i < 3; i++ {
		if _, err := w.Run(context.Background(), job("cpu")); err != nil {
			t.Fatal(err)
		}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.created) != 3 {
		t.Fatalf("created %d containers for 3 jobs", len(rt.created))
	}
	if len(rt.removed) != 3 {
		t.Fatalf("removed %d containers for 3 jobs", len(rt.removed))
	}
	for i, spec := range rt.created {
		if spec.WritableRootfs {
			t.Errorf("container %d has a writable root", i)
		}
		if spec.TmpfsMounts["/tmp"] == "" {
			t.Errorf("container %d has no tmpfs /tmp", i)
		}
	}
	// A job that was given no files and asked for no files back must not have
	// been handed an archive either — nothing about the old path changes.
	// (The mutex is already held from the top of this test.)
	if len(rt.puts) != 0 {
		t.Errorf("delivered %d archives to jobs with no files", len(rt.puts))
	}
	if len(rt.gets) != 0 {
		t.Errorf("retrieved %d archives for jobs that asked for none", len(rt.gets))
	}
}

// A job id must never escape into the container name — it arrives from the
// site and is not this node's to trust.
func TestJobIDIsSanitisedIntoTheContainerName(t *testing.T) {
	rt := &fakeRuntime{}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.ID = "../../etc/passwd; rm -rf /"
	if _, err := w.Run(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	name := rt.created[0].Name
	for _, bad := range []string{"/", ";", " ", ".."} {
		if strings.Contains(name, bad) {
			t.Errorf("container name %q contains %q", name, bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Data in, data out
// ---------------------------------------------------------------------------

// The container has no network, no bind mount and no volume, so the archive is
// the only way a submitter's data reaches the program. If it does not land in
// /work, every catalogue image exits 2 on its first line and the whole
// dispatched-job path is dead — which is exactly the state this fixes.
func TestJobFilesAreDeliveredIntoWorkBeforeTheProgramStarts(t *testing.T) {
	rt := &fakeRuntime{}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Files = map[string]string{
		"input.jsonl":  "{\"id\":1}\n",
		"sub/dir/a.py": "print(1)\n",
	}
	if _, err := w.Run(context.Background(), j); err != nil {
		t.Fatal(err)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.puts) != 1 {
		t.Fatalf("delivered %d archives, want exactly 1", len(rt.puts))
	}
	if rt.puts[0].destDir != "/" {
		t.Errorf("archive extracted at %q; it must be rooted at / so it carries "+
			"/work itself, or an image without that directory 404s", rt.puts[0].destDir)
	}

	order, headers, bodies := tarEntries(t, rt.puts[0].tar)
	if bodies["work/input.jsonl"] != j.Files["input.jsonl"] {
		t.Errorf("input.jsonl arrived as %q", bodies["work/input.jsonl"])
	}
	if bodies["work/sub/dir/a.py"] != j.Files["sub/dir/a.py"] {
		t.Errorf("nested file arrived as %q", bodies["work/sub/dir/a.py"])
	}
	// /work itself must arrive, writable: the images run unprivileged and the
	// directory comes root-owned from the image, so a workload that writes its
	// result there fails at the very end of the job without this.
	dir := headers["work/"]
	if dir == nil {
		t.Fatalf("archive has no /work directory entry; entries were %v", order)
	}
	if dir.Typeflag != tar.TypeDir {
		t.Errorf("work/ is not a directory entry")
	}
	if dir.FileInfo().Mode().Perm()&0o222 == 0 {
		t.Errorf("work/ arrives mode %v; an unprivileged job cannot write there", dir.FileInfo().Mode())
	}
	if order[0] != "work/" {
		t.Errorf("entry order %v puts a file before its parent directory", order)
	}

	// Ordering: files must be in place BEFORE the program's first instruction.
	// Delivering after Start races the image's entrypoint, which checks for its
	// input immediately.
	put, start := indexOf(rt.events, "put"), indexOf(rt.events, "start")
	if put < 0 || start < 0 || put > start {
		t.Fatalf("archive was not delivered before start: %v", rt.events)
	}
	if create := indexOf(rt.events, "create"); create > put {
		t.Fatalf("archive was delivered before the container existed: %v", rt.events)
	}
}

// Go randomises map iteration, so an unsorted archive differs run to run. This
// workload is verified by comparing digests of its output across nodes; a
// nondeterministic INPUT would make two honest nodes disagree.
func TestDeliveredArchiveIsByteIdenticalAcrossRuns(t *testing.T) {
	files := map[string]string{
		"a.txt": "alpha", "b.txt": "beta", "c/d.txt": "delta",
		"e.txt": "epsilon", "f.txt": "phi", "g.txt": "gamma",
	}
	var first []byte
	for run := 0; run < 8; run++ {
		rt := &fakeRuntime{}
		w := New(rt, nil, cpuPolicy())
		j := job("cpu")
		j.Files = files
		if _, err := w.Run(context.Background(), j); err != nil {
			t.Fatal(err)
		}
		got := rt.puts[0].tar
		if run == 0 {
			first = got
			continue
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("run %d produced a different archive for identical files", run)
		}
	}
	// And no timestamp of the moment it was packed: two nodes packing the same
	// job a day apart must produce the same bytes.
	_, headers, _ := tarEntries(t, first)
	for name, header := range headers {
		if !header.ModTime.Equal(time.Unix(0, 0).UTC()) {
			t.Errorf("entry %q carries mtime %v rather than a fixed epoch", name, header.ModTime)
		}
		if header.Uname != "" || header.Gname != "" {
			t.Errorf("entry %q carries user names %q/%q from the packing machine",
				name, header.Uname, header.Gname)
		}
	}
}

// Refused, not sanitised. A submitter who asked for "../../etc/passwd" and
// silently got "etc/passwd" ran a job that did something other than what they
// asked, and neither side finds out.
func TestUnsafeFilePathsAreRefusedWithoutCreatingAContainer(t *testing.T) {
	for _, bad := range []string{"../escape.txt", "/etc/passwd", "a/../../b", "", "a/./b", "sub/"} {
		rt := &fakeRuntime{}
		w := New(rt, nil, cpuPolicy())
		j := job("cpu")
		j.Files = map[string]string{bad: "x"}
		if _, err := w.Run(context.Background(), j); !errors.Is(err, ErrUnsafeJobPath) {
			t.Errorf("path %q was accepted (err=%v)", bad, err)
		}
		if len(rt.created) != 0 {
			t.Errorf("path %q created a container before being refused", bad)
		}
	}
	// The same rule applies to the paths a job asks to have brought BACK.
	rt := &fakeRuntime{}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"../../etc/shadow"}
	if _, err := w.Run(context.Background(), j); !errors.Is(err, ErrUnsafeJobPath) {
		t.Errorf("an escaping output path was accepted: %v", err)
	}
}

// The produced FILE is the answer for a workload like embedding generation —
// stdout carries only its digest. Without this the node returns a digest of
// vectors nobody can read.
func TestRequestedOutputsComeBack(t *testing.T) {
	rt := &fakeRuntime{
		stdout:   "embed-digest sha256:abc count:3\n",
		produced: map[string][]byte{"/work/output.jsonl": []byte("[0.1,0.2]\n")},
	}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Files = map[string]string{"input.jsonl": "hello\n"}
	j.Outputs = []string{"output.jsonl"}

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outputs["output.jsonl"] != "[0.1,0.2]\n" {
		t.Fatalf("outputs came back as %#v", got.Outputs)
	}
	if got.OutputTruncated {
		t.Error("a small output was reported as truncated")
	}
	if got.Error != "" {
		t.Errorf("a successful run reported %q", got.Error)
	}
	// Retrieved while the container still exists: after Remove the layer holding
	// the file is gone.
	get, remove := indexOf(rt.events, "get:/work/output.jsonl"), indexOf(rt.events, "remove")
	if get < 0 {
		t.Fatalf("no retrieval happened: %v", rt.events)
	}
	if remove >= 0 && remove < get {
		t.Fatalf("output was retrieved after the container was removed: %v", rt.events)
	}
}

// A job that wrote nothing still has an exit code and stdout, and those are a
// real answer. Failing it would turn "this input produced no rows" into an
// outage.
func TestMissingOutputIsNotAFailure(t *testing.T) {
	rt := &fakeRuntime{exitCode: 0, stdout: "nothing to do\n"}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"output.jsonl"}

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatalf("a missing output file failed the run: %v", err)
	}
	if len(got.Outputs) != 0 {
		t.Errorf("outputs %#v for a job that wrote none", got.Outputs)
	}
	if got.Error != "" {
		t.Errorf("a missing output was reported as an error: %q", got.Error)
	}
	if got.OutputTruncated {
		t.Error("a missing output was reported as truncated")
	}
	if got.Stdout != "nothing to do\n" {
		t.Errorf("stdout lost: %q", got.Stdout)
	}
}

// --- A REQUIRED product, and what a run that does not deliver it may claim ---
//
// The failure these pin: a workload's answer is its FILE, stdout carries only a
// digest OF that file, and until now a run that produced no file at all came
// back as exit 0 with an empty outputs map. The site hashed the stdout digest,
// found it matched a replica, called the job verified, marked it done and paid
// the volunteers — for vectors that did not exist.

func TestARequiredOutputThatNeverArrivedIsNotASuccess(t *testing.T) {
	rt := &fakeRuntime{exitCode: 0, stdout: "embed-digest sha256:abc count:3\n"}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Files = map[string]string{"input.jsonl": "x"}
	j.Outputs = []string{"output.jsonl"}
	j.RequireOutputs = true

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MissingOutputs) != 1 || got.MissingOutputs[0] != "output.jsonl" {
		t.Fatalf("the node did not name what was missing: %#v", got.MissingOutputs)
	}
	if got.Error == "" {
		t.Fatal("a run that produced nothing reported no error, which is the silent success itself")
	}
	// The container's own answer survives. It is the diagnosis, it is what the
	// site uses to tell an honest failure from this, and it is on the
	// verification digest.
	if got.ExitCode != 0 {
		t.Errorf("the container's exit code was overwritten with %d", got.ExitCode)
	}
	if got.Stdout != "embed-digest sha256:abc count:3\n" {
		t.Errorf("stdout was lost: %q", got.Stdout)
	}
}

func TestARequiredOutputThatArrivedReportsNothingWrong(t *testing.T) {
	rt := &fakeRuntime{
		stdout:   "embed-digest sha256:abc count:1\n",
		produced: map[string][]byte{"/work/output.jsonl": []byte("{\"id\":0}\n")},
	}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"output.jsonl"}
	j.RequireOutputs = true

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MissingOutputs) != 0 || got.Error != "" {
		t.Fatalf("a delivered product was reported as missing: %#v / %q", got.MissingOutputs, got.Error)
	}
}

// An EMPTY file is not a smaller result. For a workload whose whole answer is
// the file, zero bytes is the same nothing as never having written it — and
// letting it through would leave the same hole with one extra step in it.
func TestAnEmptyRequiredOutputCountsAsMissing(t *testing.T) {
	rt := &fakeRuntime{
		stdout:   "embed-digest sha256:abc count:0\n",
		produced: map[string][]byte{"/work/output.jsonl": {}},
	}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"output.jsonl"}
	j.RequireOutputs = true

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MissingOutputs) != 1 {
		t.Fatalf("an empty product passed as a product: %#v", got.MissingOutputs)
	}
}

// A run that FAILED and wrote nothing needs no second opinion from the node:
// its exit code already says so, and that code is the only thing telling the
// submitter which line of their input was wrong. The node adds the fact that
// the product is absent and nothing else.
func TestAFailedRunKeepsItsOwnDiagnosis(t *testing.T) {
	rt := &fakeRuntime{exitCode: 3, stderr: "line 5 is not a JSON object\n"}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"output.jsonl"}
	j.RequireOutputs = true

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExitCode != 3 {
		t.Fatalf("exit code = %d, want the image's own 3 — the submitter needs the line number", got.ExitCode)
	}
	if got.Error != "" {
		t.Errorf("a job that already reported why it failed was given a second, vaguer reason: %q", got.Error)
	}
	if len(got.MissingOutputs) != 1 {
		t.Errorf("the absent product was not reported: %#v", got.MissingOutputs)
	}
}

// The language images ask for nothing back and must stay unaffected: their
// whole answer IS stdout, and an optional file a program chose not to write is
// still an honest answer.
func TestAnOptionalOutputIsStillNotAFailure(t *testing.T) {
	rt := &fakeRuntime{exitCode: 0, stdout: "hello\n"}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"output.jsonl"} // no RequireOutputs

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if got.Error != "" || len(got.MissingOutputs) != 0 {
		t.Fatalf("an optional output was treated as a product: %q / %#v", got.Error, got.MissingOutputs)
	}
}

// A daemon that could not be reached is the NODE failing, not the job, and it
// must not look identical to a job that wrote nothing.
func TestATransportFailureIsReportedRatherThanLookingEmpty(t *testing.T) {
	rt := &fakeRuntime{
		getErr: map[string]error{"/work/output.jsonl": errors.New("connection reset")},
	}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"output.jsonl"}

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Error, "connection reset") {
		t.Errorf("a retrieval failure was swallowed: %q", got.Error)
	}
}

// The cap is what keeps a program that writes forever from handing the node an
// out-of-memory kill as its result. Over it, the run still succeeds and the
// stdout digest still stands.
func TestOversizeOutputIsTruncatedNotCarried(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxOutputBytes+1)
	rt := &fakeRuntime{
		stdout:   "embed-digest sha256:abc count:1\n",
		produced: map[string][]byte{"/work/output.jsonl": big},
	}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Outputs = []string{"output.jsonl"}

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if !got.OutputTruncated {
		t.Fatal("an oversize output was not reported as truncated")
	}
	if _, ok := got.Outputs["output.jsonl"]; ok {
		t.Error("an oversize output was carried anyway")
	}
	if got.Stdout == "" {
		t.Error("the stdout digest was lost with the output")
	}
	// The runtime's own size sentinel means the same thing.
	rt2 := &fakeRuntime{getErr: map[string]error{
		"/work/output.jsonl": fmt.Errorf("%w: /work/output.jsonl", dcs.ErrArchiveTooLarge),
	}}
	w2 := New(rt2, nil, cpuPolicy())
	got2, err := w2.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if !got2.OutputTruncated || got2.Error != "" {
		t.Errorf("ErrArchiveTooLarge was not treated as a truncation: %+v", got2)
	}
}

// A job that ran out of time may still have written a partial result, and on
// that path the run context is already dead — so retrieval has to use a fresh
// one, exactly like log collection does.
func TestOutputsAreRetrievedEvenWhenTheJobTimesOut(t *testing.T) {
	rt := &fakeRuntime{
		waitFor:  3 * time.Second,
		stdout:   "partial\n",
		produced: map[string][]byte{"/work/output.jsonl": []byte("half a result\n")},
	}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Timeout = 150 * time.Millisecond
	j.Files = map[string]string{"input.jsonl": "x"}
	j.Outputs = []string{"output.jsonl"}

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TimedOut {
		t.Fatal("timeout not reported")
	}
	if got.Outputs["output.jsonl"] != "half a result\n" {
		t.Errorf("a partial result was discarded on timeout: %#v", got.Outputs)
	}
}

// Delivery failing must fail the job. Starting the program against an empty
// /work would give the language images exit 2 and the embedding image a
// confident digest of nothing.
func TestADeliveryFailureFailsTheJobRatherThanRunningItBlind(t *testing.T) {
	rt := &fakeRuntime{putErr: errors.New("no space left on device")}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Files = map[string]string{"input.jsonl": "x"}

	if _, err := w.Run(context.Background(), j); err == nil {
		t.Fatal("the job ran with no input")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if indexOf(rt.events, "start") >= 0 {
		t.Fatalf("the container was started despite a delivery failure: %v", rt.events)
	}
	if len(rt.removed) == 0 {
		t.Fatal("a container was leaked after a delivery failure")
	}
}

// The archive endpoint refuses a container whose rootfs is read-only, and a
// tmpfs at /work would mask everything delivered there — so a job that needs
// files must ask for a writable root, and a job that does not must not.
func TestOnlyJobsThatNeedFilesGetAWritableRoot(t *testing.T) {
	cases := []struct {
		name  string
		job   func(Job) Job
		wantW bool
	}{
		{"stdout only", func(j Job) Job { return j }, false},
		{"with files", func(j Job) Job {
			j.Files = map[string]string{"a.py": "x"}
			return j
		}, true},
		{"outputs only", func(j Job) Job { j.Outputs = []string{"out.jsonl"}; return j }, true},
	}
	for _, tc := range cases {
		rt := &fakeRuntime{}
		w := New(rt, nil, cpuPolicy())
		if _, err := w.Run(context.Background(), tc.job(job("cpu"))); err != nil {
			t.Fatal(err)
		}
		spec := rt.created[0]
		if spec.WritableRootfs != tc.wantW {
			t.Errorf("%s: WritableRootfs=%v, want %v", tc.name, spec.WritableRootfs, tc.wantW)
		}
		if spec.TmpfsMounts["/tmp"] == "" {
			t.Errorf("%s: lost the tmpfs /tmp", tc.name)
		}
		// /work must NOT be a tmpfs: the archive endpoint writes through the
		// image layer, so a tmpfs mounted there hides the delivered files from
		// the program and takes the produced file with it on exit.
		if _, mounted := spec.TmpfsMounts[WorkDir]; mounted {
			t.Errorf("%s: %s is a tmpfs; delivered files would be invisible", tc.name, WorkDir)
		}
	}
}

func indexOf(events []string, want string) int {
	for i, event := range events {
		if event == want {
			return i
		}
	}
	return -1
}

func TestSanitiseKeepsNamesBounded(t *testing.T) {
	if got := sanitise(strings.Repeat("a", 500)); len(got) > 48 {
		t.Errorf("name is %d chars", len(got))
	}
	if got := sanitise(""); got == "" {
		t.Error("empty id produced an empty container name")
	}
}
