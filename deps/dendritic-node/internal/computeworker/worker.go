// Package computeworker runs a submitted program on this machine, under the
// operator's own limits.
//
// This is the piece that was missing between the site's arcade queue and a
// volunteer's hardware: the queue could accept programs and the node could
// declare it had spare cores, and nothing connected the two.
//
// WHAT ADMISSION MEANS HERE
// -------------------------
// A submitted program runs only if THREE independent things agree:
//
//  1. the operator offered this device at all (Policy.OfferCPU / OfferGPU)
//  2. the governor says the machine is free right now (load, heat, battery,
//     hours, reserved cores)
//  3. there is a slot — one job at a time per device
//
// They are checked separately and reported separately, because they mean
// different things to whoever is waiting. "You did not offer a GPU" is
// permanent until the owner changes it; "the machine is busy" clears on its
// own; "no free slot" clears in seconds. Collapsing them into one "unavailable"
// makes a permanent refusal look like a queue.
//
// WHY EACH JOB IS A FRESH CONTAINER
// ---------------------------------
// The unit of isolation is the unit of work. A reused container carries
// whatever the last program left in /tmp, in its process table and in its
// environment — so one submitter's leftovers become the next submitter's
// starting state, which is both a correctness problem and an information leak
// between strangers. Creating and destroying per job costs a few hundred
// milliseconds and removes the whole class.
//
// Until M2's microVM runner can extract results, this uses the hardened
// container profile the DCS worker already uses. That is a weaker boundary than
// a VM and the roadmap says so; it is the same boundary this node already
// accepts for container deployments, so it adds no new exposure.
package computeworker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
)

// Runtime is the container surface this needs. An interface so the worker is
// testable without Docker, and so a microVM backend can replace it later
// without touching admission.
type Runtime interface {
	Create(ctx context.Context, spec dcs.ContainerSpec) (string, error)
	Start(ctx context.Context, id string) error
	Wait(ctx context.Context, id string) (int, error)
	Logs(ctx context.Context, id string) (stdout, stderr []byte, err error)
	// PutArchive extracts a tar inside the container. The only way data reaches
	// a catalogue image: the container has no network, no bind mount and no
	// volume, by design.
	PutArchive(ctx context.Context, id, destDir string, tarBytes []byte) error
	// GetArchive reads a path back out as a tar, returning dcs.ErrArchiveMissing
	// when the job wrote nothing there.
	GetArchive(ctx context.Context, id, containerPath string) ([]byte, error)
	Remove(ctx context.Context, id string, force bool) error
}

// Job is a submitted program.
type Job struct {
	ID string
	// Device is "cpu" or "gpu:<api>", matching the job classes the governor
	// policy accepts.
	Device string
	// Image is a digest-pinned catalogue image. NOT submitter-chosen — until
	// M2 ships, a volunteer runs catalogue images only, and this field is set
	// by the node from the language, never from the request.
	Image string
	Cmd   []string
	Env   []string
	// Files is the submitter's DATA, delivered into WorkDir before the program
	// starts. Keys are relative paths; an absolute path or one containing ".."
	// is refused, never rewritten.
	Files map[string]string
	// Outputs names files under WorkDir to bring back after the run. Empty for
	// a job whose whole answer is its stdout — the language images — and set for
	// a workload that PRODUCES something, like the embedding image's
	// output.jsonl. A named file that the job never wrote is not an error
	// unless RequireOutputs says it is.
	Outputs []string
	// RequireOutputs makes every name in Outputs a PRODUCT rather than an
	// extra: a run that ends without one has not succeeded, whatever its exit
	// code claims.
	//
	// A separate flag rather than a rule about Outputs, because both meanings
	// are real. A program asked for an optional log file that it chose not to
	// write has answered honestly; a catalogue workload that returns no
	// output.jsonl has not, because the file IS what was bought — stdout
	// carries only a digest OF it. Collapsing the two would either fail honest
	// jobs or, as it did until now, pass empty ones.
	RequireOutputs bool
	Timeout        time.Duration
	MemoryLimit    int64
}

// Result is what came back.
type Result struct {
	JobID      string `json:"job_id"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	RanSeconds int    `json:"ran_seconds"`
	TimedOut   bool   `json:"timed_out"`
	// Outputs maps each requested output path to its contents. Absent keys mean
	// the job did not write that file. This is the ONLY channel by which a
	// produced file leaves the node, so a workload whose answer is a file rather
	// than a line of stdout depends on it entirely.
	//
	// Contents are carried as text because they are JSON-encoded on the way to
	// the site: a genuinely binary output would be mangled by that encoding, so
	// catalogue workloads write text.
	Outputs map[string]string `json:"outputs,omitempty"`
	// OutputTruncated says some requested output was too big to carry, so the
	// caller knows the missing bytes are a limit and not a job that wrote
	// nothing. The stdout digest still stands: it is computed by the job itself.
	OutputTruncated bool `json:"output_truncated,omitempty"`
	// MissingOutputs names the REQUIRED products this run did not hand back.
	//
	// A positive statement, because its absence could not be one: `outputs` is
	// omitempty, so "the workload produced nothing" and "this node's build
	// predates outputs entirely" were the same empty wire state — and the site
	// read both as a clean success. Non-empty here means the node ran the job,
	// looked for what it was told the job produces, and did not find it.
	MissingOutputs []string `json:"missing_outputs,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// Refusal explains why a job was not admitted. A typed error rather than a
// string so the caller can tell a permanent no from a temporary one.
type Refusal struct {
	Reason string
	// Retryable distinguishes "busy, try later" from "this machine does not do
	// that". A queue that retries a permanent refusal forever is a queue that
	// never drains and never says why.
	Retryable bool
}

func (r *Refusal) Error() string { return r.Reason }

var ErrNoSlot = &Refusal{Reason: "this node is already running a job on that device", Retryable: true}

// Worker admits and runs one job at a time per device.
type Worker struct {
	runtime  Runtime
	governor *compute.Governor
	policy   compute.Policy

	mu      sync.Mutex
	running map[string]bool // device -> busy
}

func New(runtime Runtime, governor *compute.Governor, policy compute.Policy) *Worker {
	return &Worker{
		runtime:  runtime,
		governor: governor,
		policy:   policy,
		running:  map[string]bool{},
	}
}

// Admit reports whether a job would be accepted right now, without running it.
//
// Exported separately so the bridge can answer "would you take this?" without
// side effects — a queue asking every node in turn should not have to start a
// container to find out.
func (w *Worker) Admit(device string) error {
	if !w.policy.Enabled {
		return &Refusal{Reason: "this node is not lending compute", Retryable: false}
	}
	// The operator's device switch. Permanent until they change it, so the
	// caller must not retry against this node for this device.
	if !w.policy.AcceptsClass(device) {
		return &Refusal{
			Reason:    fmt.Sprintf("this node does not offer %s work", device),
			Retryable: false,
		}
	}
	if w.governor != nil {
		grant := w.governor.Decide(w.runningCount())
		if !grant.Allowed() {
			// The governor's Reason is already written for the machine's owner,
			// so it is passed through rather than reworded — and it is
			// retryable by definition: load, heat and battery all change.
			return &Refusal{Reason: grant.Reason, Retryable: true}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running[device] {
		return ErrNoSlot
	}
	return nil
}

func (w *Worker) runningCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, busy := range w.running {
		if busy {
			n++
		}
	}
	return n
}

// Run admits and executes a job, blocking until it finishes.
func (w *Worker) Run(ctx context.Context, job Job) (Result, error) {
	// The submitter's paths are checked before anything is admitted or created.
	// A job that can never be delivered should not occupy a slot, and a
	// container created for it would have to be torn down again.
	needsWork := len(job.Files) > 0 || len(job.Outputs) > 0
	var archive []byte
	if needsWork {
		var err error
		if archive, err = workArchive(job.Files); err != nil {
			return Result{JobID: job.ID}, err
		}
		for _, name := range job.Outputs {
			if err := checkJobPath(name); err != nil {
				return Result{JobID: job.ID}, err
			}
		}
	}

	if err := w.Admit(job.Device); err != nil {
		return Result{JobID: job.ID}, err
	}

	// Claim the slot. Re-checked under the lock because Admit's check and this
	// claim are not atomic together, and two submissions arriving at once would
	// otherwise both pass.
	w.mu.Lock()
	if w.running[job.Device] {
		w.mu.Unlock()
		return Result{JobID: job.ID}, ErrNoSlot
	}
	w.running[job.Device] = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.running, job.Device)
		w.mu.Unlock()
	}()

	if job.Timeout <= 0 {
		job.Timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, job.Timeout)
	defer cancel()

	spec := dcs.ContainerSpec{
		Name:             "compute-" + sanitise(job.ID),
		Image:            job.Image,
		Cmd:              job.Cmd,
		Env:              job.Env,
		Labels:           map[string]string{"syndichan.compute": "1"},
		MemoryLimitBytes: job.MemoryLimit,
		// Memory-backed scratch, so nothing a program writes there survives the
		// container. A submitted program needs somewhere to work; it does not
		// need that somewhere to persist.
		TmpfsMounts: map[string]string{"/tmp": "rw,noexec,nosuid,size=256m"},
		// A job that is handed files, or that must hand a file back, cannot have
		// a read-only root: the daemon refuses to extract an archive into such a
		// container at all, and a file written to a tmpfs is unreadable
		// afterwards because the tmpfs is gone. WorkDir is therefore an ordinary
		// directory on the container's own layer, which is destroyed with it.
		//
		// Jobs that need neither — anything whose whole answer is stdout — keep
		// the read-only root. The weaker profile applies to the jobs that
		// require it and to no others.
		WritableRootfs: needsWork,
	}

	started := time.Now()
	id, err := w.runtime.Create(runCtx, spec)
	if err != nil {
		return Result{JobID: job.ID}, fmt.Errorf("computeworker: create: %w", err)
	}
	// Removal is deferred immediately after creation, so a failure to START
	// still cleans up. Ordering this after Start would leak a container on
	// every start failure.
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer rmCancel()
		_ = w.runtime.Remove(rmCtx, id, true)
	}()

	// Data goes in between Create and Start — the same window in which the DCS
	// agent attaches a network identity, and for the same reason: the container
	// must never run for even an instant in a state it was not meant to be in.
	// Delivering after Start would race the image's own entrypoint, which checks
	// for its input on its first line.
	//
	// A delivery failure fails the job. Starting the program anyway would run it
	// against an empty WorkDir, and the language images exit 2 on that while the
	// embedding image would produce a digest of nothing — a wrong answer that
	// M5 then compares against another node's wrong answer.
	if needsWork {
		if err := w.runtime.PutArchive(runCtx, id, "/", archive); err != nil {
			return Result{JobID: job.ID}, fmt.Errorf("computeworker: deliver files: %w", err)
		}
	}

	if err := w.runtime.Start(runCtx, id); err != nil {
		return Result{JobID: job.ID}, fmt.Errorf("computeworker: start: %w", err)
	}

	code, waitErr := w.runtime.Wait(runCtx, id)
	timedOut := errors.Is(runCtx.Err(), context.DeadlineExceeded)

	// Logs are collected on EVERY path including timeout and error, using a
	// fresh context — the run context is already dead in the timeout case, and
	// the output of a program that timed out is usually the only evidence of
	// what it was doing.
	logCtx, logCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer logCancel()
	stdout, stderr, logErr := w.runtime.Logs(logCtx, id)

	// Produced files come back on the SAME paths, for the same reason, and while
	// the container still exists — the deferred Remove above has not fired yet,
	// and once it does the file is gone with the layer. A job that timed out may
	// still have written a partial result, and a partial result is evidence.
	outputs, truncated, outErr := w.collectOutputs(job, id)
	missing := missingOutputs(job, outputs)

	result := Result{
		JobID:           job.ID,
		ExitCode:        code,
		Stdout:          string(stdout),
		Stderr:          string(stderr),
		RanSeconds:      int(time.Since(started).Seconds()),
		TimedOut:        timedOut,
		Outputs:         outputs,
		OutputTruncated: truncated,
		MissingOutputs:  missing,
	}
	switch {
	case timedOut:
		result.ExitCode = -1
		result.Error = fmt.Sprintf("the job exceeded its %s limit", job.Timeout)
	case waitErr != nil:
		result.Error = waitErr.Error()
	case logErr != nil:
		// The program ran; only its output could not be read. Reported rather
		// than failing the job, because the exit code is still a real answer.
		result.Error = "output could not be collected: " + logErr.Error()
	case outErr != nil:
		result.Error = "output files could not be collected: " + outErr.Error()
	case len(missing) > 0 && code == 0:
		// THE CONTRADICTION. The program says it succeeded and the thing it was
		// run to produce is not there.
		//
		// Said HERE because this is the earliest point anything can say it
		// truthfully: the file lived in a container that no other part of the
		// system can open and that the deferred Remove above is about to
		// destroy. A node that stays quiet about it hands the site an exit 0, a
		// stdout digest and an empty outputs map — which the site verified by
		// hash and paid for, because a hash of stdout is a claim ABOUT the file
		// rather than the file.
		//
		// The container's own exit code is deliberately NOT overwritten:
		//
		//   - it is the diagnosis. The embed image exits 2 for "the runner
		//     never delivered my input", 3 and 4 for a malformed line WITH the
		//     line number. Replacing that with a generic "no output" would
		//     destroy the only thing that tells a submitter which line to fix.
		//   - the site needs it to tell an honest failure from this. A run that
		//     exited non-zero and wrote nothing is a job that failed, and the
		//     node still spent the electricity; this is a run that claims to
		//     have worked. They are paid differently, and a synthetic exit code
		//     would make them indistinguishable.
		//   - it is on the verification path. compute_verify.output_digest
		//     hashes stdout and the exit code, so inventing one here would make
		//     an honest node disagree with its own replica.
		result.Error = "the job exited 0 without producing " +
			strings.Join(missing, ", ") + "; the run cannot be treated as successful"
	}
	return result, nil
}

// missingOutputs lists the REQUIRED products a run did not hand back.
//
// Empty unless the job declared its outputs required: a program asked for an
// optional file it decided not to write has still answered, and the language
// images depend on that staying true.
//
// A file that came back EMPTY counts as missing. Zero bytes is not a smaller
// result — for a workload whose whole purpose is the file, it is the same
// nothing as never having written it, and letting it through would leave the
// exact hole this closes with one extra step in it.
func missingOutputs(job Job, collected map[string]string) []string {
	if !job.RequireOutputs {
		return nil
	}
	var missing []string
	for _, name := range job.Outputs {
		if collected[name] == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// WorkDir is where a job's data lives inside the container: the working
// directory every catalogue image declares, the path its entrypoint reads its
// input from and writes its result to.
const WorkDir = "/work"

// MaxOutputBytes caps what one job may hand back through its files, across all
// of them together.
//
// The stdout cap (dcs.MaxLogBytes) exists because a program can print forever;
// this exists because a program can write forever, and the node reads what it
// wrote into memory before posting it to the site. 8 MiB is generous for the
// text results catalogue workloads produce and small enough that a hostile job
// cannot use it as an amplifier.
const MaxOutputBytes = 8 << 20

// workDirMode is the mode given to WorkDir on delivery: world-writable with the
// sticky bit, exactly like /tmp.
//
// The catalogue images run as an unprivileged uid, but WorkDir arrives from the
// image owned by root — so without this the embedding image finds its own
// working directory unwritable and exits before computing anything. Setting it
// here rather than in each image keeps the rule in one place.
const workDirMode = 0o1777

// ErrUnsafeJobPath rejects a delivery path that would escape WorkDir.
//
// Refused, never sanitised: a submitter who asked for "../../etc/passwd" and
// silently received "etc/passwd" is a submitter whose job did something other
// than what they asked, and neither of us finds out.
var ErrUnsafeJobPath = errors.New("computeworker: job file paths must be relative and stay inside " + WorkDir)

// checkJobPath validates one relative path from a submitted job.
func checkJobPath(p string) error {
	if p == "" || strings.ContainsRune(p, 0) {
		return fmt.Errorf("%w: %q", ErrUnsafeJobPath, p)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: %q is absolute", ErrUnsafeJobPath, p)
	}
	if p != path.Clean(p) {
		// "a/./b", "a//b" and "a/b/" are refused too. They are harmless in
		// themselves, but accepting them means two different strings name one
		// file, and this image's premise is that identical input produces
		// identical bytes.
		return fmt.Errorf("%w: %q is not a clean path", ErrUnsafeJobPath, p)
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." {
			return fmt.Errorf("%w: %q escapes the directory", ErrUnsafeJobPath, p)
		}
	}
	return nil
}

// workArchive tars a job's files for delivery, rooted at "/" so the archive
// carries WorkDir itself.
//
// Extracting at "/" rather than at WorkDir is what lets the archive set the
// directory's MODE as well as its contents, and it works even on an image that
// has no WorkDir at all — extracting into a directory that does not exist is a
// 404 from the daemon, and "your input never arrived" is a miserable thing to
// debug.
//
// The bytes are DETERMINISTIC: sorted entries, a fixed epoch mtime, numeric
// ids and no user names. Go randomises map iteration, so an unsorted archive
// would differ between two runs of the same job — and the entire verification
// story for this workload is that identical input yields identical output. A
// nondeterministic input archive makes an honest node look like a liar.
func workArchive(files map[string]string) ([]byte, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		if err := checkJobPath(name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	sort.Strings(names)

	base := strings.TrimPrefix(WorkDir, "/")
	epoch := time.Unix(0, 0).UTC()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// The directory entry comes first: a tar reader that meets a file before its
	// parent has to invent the parent, with whatever mode it likes.
	if err := tw.WriteHeader(&tar.Header{
		Name: base + "/", Typeflag: tar.TypeDir, Mode: workDirMode, ModTime: epoch,
	}); err != nil {
		return nil, err
	}
	for _, name := range names {
		data := []byte(files[name])
		if err := tw.WriteHeader(&tar.Header{
			Name:     path.Join(base, name),
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(data)),
			ModTime:  epoch,
			Uid:      0, Gid: 0,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// collectOutputs retrieves the files a job was asked to produce.
//
// A missing file is NOT an error and never fails the job: a job that decided it
// had nothing to write, or died before writing, still has an exit code and
// stdout, and those are a real answer. A daemon that could not be reached IS
// reported, because that is the node failing rather than the job.
func (w *Worker) collectOutputs(job Job, id string) (map[string]string, bool, error) {
	if len(job.Outputs) == 0 {
		return nil, false, nil
	}
	// A fresh context, like the Logs call above and for the same reason: on the
	// timeout path the run context is already dead, and that is precisely the
	// path where a partial result is most worth having.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	outputs := map[string]string{}
	truncated := false
	var firstErr error
	budget := MaxOutputBytes

	for _, name := range job.Outputs {
		blob, err := w.runtime.GetArchive(ctx, id, path.Join(WorkDir, name))
		switch {
		case errors.Is(err, dcs.ErrArchiveMissing):
			continue
		case errors.Is(err, dcs.ErrArchiveTooLarge):
			truncated = true
			continue
		case err != nil:
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		data, tooBig, err := untarFile(blob, budget)
		switch {
		case tooBig:
			truncated = true
			continue
		case err != nil:
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", name, err)
			}
			continue
		case data == nil:
			// The path existed but held no regular file — a directory, say.
			continue
		}
		budget -= len(data)
		outputs[name] = string(data)
	}
	if len(outputs) == 0 {
		outputs = nil
	}
	return outputs, truncated, firstErr
}

// untarFile pulls the first regular file out of the tar Docker returns for a
// single path. Reports tooBig rather than a partial read, because half a result
// file is not a smaller result — it is a wrong one, and it would be indistinguishable
// from a job that legitimately produced less.
func untarFile(blob []byte, limit int) (data []byte, tooBig bool, err error) {
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size > int64(limit) {
			return nil, true, nil
		}
		out := make([]byte, header.Size)
		if _, err := io.ReadFull(tr, out); err != nil {
			return nil, false, err
		}
		return out, false, nil
	}
}

// sanitise makes a job id safe as a container name.
func sanitise(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 48 {
		out = out[:48]
	}
	if out == "" {
		out = "job"
	}
	return out
}
