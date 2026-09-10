// Package computeimage obtains the catalogue images a node needs in order to
// honour the compute it advertises.
//
// THE PROBLEM THIS EXISTS FOR
// ---------------------------
// A node could advertise `cpu_compute` while holding none of the images the
// catalogue names. `registry.local` is not a real registry and there was no
// image pull path anywhere in the node, so such a node accepted a dispatched
// unit, returned a ticket, and died `No such image` — which reads at every
// layer above as a failed EXECUTION rather than a missing prerequisite, so
// placement kept choosing it. Measured on the live fleet: every dispatched unit
// failed, and the images existed only where a human had hand-loaded a tarball.
//
// THE RULE THIS IMPLEMENTS
// ------------------------
// A node that offers compute does not get to choose which catalogue workloads
// it will run. So the fix is not a cheaper refusal — it is that the claim
// becomes true, or the claim is withdrawn:
//
//	every catalogue image present  ->  advertise compute
//	any one of them unobtainable   ->  advertise nothing
//
// This package answers the first half. cmd/syndichan-node/computeimages.go
// wires the answer to the heartbeat, which is where the second half happens.
//
// WHY AN IMAGE IS DOWNLOADED WHEN A MICROVM KERNEL IS NOT
// -------------------------------------------------------
// config.ComputeConfig says a guest kernel is supplied by the operator and
// never fetched, because "a node that fetched and booted a kernel somebody else
// chose would have handed over the machine in the act of protecting it". That
// is right, and it does not apply here, for a reason worth stating rather than
// assuming: the kernel IS the boundary, and a boundary you downloaded protects
// you from nothing. A catalogue image runs INSIDE a boundary the operator
// already established, under a hardened profile with no network, and — the part
// that does the work — it is pinned by a SHA-256 compiled into the binary the
// operator chose to install. The site can publish whatever it likes under the
// artifact's name; a node will refuse all of it until its operator installs a
// build that expects those bytes.
package computeimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

// Runtime is the container surface this needs: enough to ask what is present
// and to install what is not. An interface so the fetch-and-verify logic is
// testable without a Docker daemon, which matters because the behaviour most
// worth testing is the one where nothing is loaded at all.
type Runtime interface {
	ImageExists(ctx context.Context, reference string) (bool, error)
	LoadImage(ctx context.Context, tarball io.Reader) error
}

// ErrDigestMismatch means the downloaded artifact is not the one this build
// expects. Typed because it is the only error here that describes an attack as
// readily as an accident, and a caller must be able to tell it from "the
// download failed".
var ErrDigestMismatch = errors.New("computeimage: the downloaded image does not match its published digest")

// ErrNotFetchable means the catalogue names an image that cannot be obtained
// from anywhere — no artifact, or no digest to check it against.
var ErrNotFetchable = errors.New("computeimage: this workload's image cannot be fetched")

// DefaultBaseURL is where published artifacts live, and it is a constant rather
// than a default in a config file for the same reason heartbeat.Endpoint is:
// the node has one home, and a node that could be pointed at another place to
// download executable images by editing a JSON file is a node whose safety rests
// on that file. The digest is what actually protects the load; this only decides
// where to look.
const DefaultBaseURL = "https://syndichan.org/dl"

// MaxArtifactBytes bounds a single download.
//
// The catalogue's one image is ~190 MB; 1 GiB leaves room for a GPU workload's
// runtime without leaving room for a server that answers this request with an
// infinite stream. Without a cap, the failure is a volunteer's disk filling up.
const MaxArtifactBytes = 1 << 30

// Loader obtains catalogue images. The zero value is not usable: Runtime is
// required, and everything else has a default.
type Loader struct {
	Runtime Runtime
	// HTTP is the client used to fetch artifacts. Supplied by the caller so the
	// node can hand over the one it already uses for direct (non-proxied)
	// requests, the same client the heartbeat goes out on.
	HTTP *http.Client
	// BaseURL is where artifacts are published. Empty means DefaultBaseURL.
	BaseURL string
	// ScratchDir is where a download is staged. It should be on the node's own
	// data volume rather than /tmp: /tmp is a tmpfs on a good many Linux
	// installs, and staging 190 MB in RAM on a Raspberry Pi is how this feature
	// would earn a reputation for killing volunteers' machines.
	ScratchDir string
	Logger     *log.Logger
	// MaxBytes overrides MaxArtifactBytes, for tests.
	MaxBytes int64
}

func (l *Loader) logf(format string, args ...any) {
	if l.Logger != nil {
		l.Logger.Printf(format, args...)
	}
}

func (l *Loader) baseURL() string {
	if strings.TrimSpace(l.BaseURL) == "" {
		return DefaultBaseURL
	}
	return strings.TrimRight(strings.TrimSpace(l.BaseURL), "/")
}

func (l *Loader) maxBytes() int64 {
	if l.MaxBytes > 0 {
		return l.MaxBytes
	}
	return MaxArtifactBytes
}

func (l *Loader) client() *http.Client {
	if l.HTTP != nil {
		return l.HTTP
	}
	return &http.Client{Timeout: 15 * time.Minute}
}

// Ensure makes every named workload's image present, fetching what is missing.
//
// Returns nil only when ALL of them are there. That is the point: the caller
// turns this into "may this node advertise compute", and a partial success is a
// node that advertises a catalogue it can only half run — the state this whole
// package exists to abolish. The error names every workload that failed, not
// just the first, because an operator debugging a fetch wants the list once.
func (l *Loader) Ensure(ctx context.Context, workloads []compute.Workload) error {
	if l.Runtime == nil {
		return errors.New("computeimage: no container runtime")
	}
	var failed []string
	for _, w := range workloads {
		if err := l.EnsureOne(ctx, w); err != nil {
			// Logged as it happens as well as collected, because the whole set
			// can take minutes and an operator watching the journal should not
			// have to wait for the summary to learn the first one broke.
			l.logf("compute: catalogue image for %s unavailable: %v", w.Name, err)
			failed = append(failed, w.Name)
			if ctx.Err() != nil {
				break
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("computeimage: no usable image for %s",
			strings.Join(failed, ", "))
	}
	return nil
}

// EnsureOne makes one workload's image present.
//
// An image the daemon ALREADY holds is accepted without a download and without a
// digest check, and that is deliberate rather than an omission. The digest
// guards the network path, which is the untrusted one; a tag that is already on
// the machine got there because the operator built it (compute-images/build.sh
// does exactly that) or because this function loaded it earlier. Re-checking it
// is not possible anyway — the digest describes a `docker save` tarball, and the
// daemon's own image ID is a different hash of different bytes.
func (l *Loader) EnsureOne(ctx context.Context, w compute.Workload) error {
	if strings.TrimSpace(w.Image) == "" {
		return fmt.Errorf("computeimage: workload %q names no image", w.Name)
	}
	have, err := l.Runtime.ImageExists(ctx, w.Image)
	if err != nil {
		return err
	}
	if have {
		l.logf("compute: catalogue image %s is already present", w.Image)
		return nil
	}
	if ok, why := w.Fetchable(); !ok {
		return fmt.Errorf("%w: %s (%s)", ErrNotFetchable, w.Image, why)
	}

	url := l.baseURL() + "/" + w.Artifact
	l.logf("compute: fetching catalogue image %s from %s", w.Image, url)
	path, size, err := l.download(ctx, url, w.Digest)
	if err != nil {
		return err
	}
	// The staged file is removed on EVERY path including success. It is ~190 MB
	// of bytes the daemon now holds a copy of, and a node that kept one per
	// image would spend a volunteer's disk on a cache nothing reads.
	defer os.Remove(path)

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	l.logf("compute: loading %s (%d bytes, sha256 %s)", w.Image, size, w.Digest[:12])
	if err := l.Runtime.LoadImage(ctx, file); err != nil {
		return err
	}

	// Confirmed rather than assumed. `docker load` installs whatever tags the
	// tarball declares, so a correct-but-wrong artifact — one that verifies
	// because it IS what we published, and carries a different tag because
	// somebody saved the wrong image — would otherwise be reported as a
	// successful load of an image that is still missing, and the node would
	// advertise on the strength of it.
	have, err = l.Runtime.ImageExists(ctx, w.Image)
	if err != nil {
		return err
	}
	if !have {
		return fmt.Errorf("computeimage: loaded %s but %s is still not present; "+
			"the artifact does not carry that tag", w.Artifact, w.Image)
	}
	l.logf("compute: catalogue image %s is ready", w.Image)
	return nil
}

// download streams an artifact to a file, hashing as it goes, and returns the
// path only if the hash is the expected one.
//
// The bytes hit DISK before they are checked and are never handed to the daemon
// until the whole file has been hashed. Streaming straight into `docker load`
// while hashing would be faster and would mean the daemon had already unpacked
// most of an unverified image by the time the mismatch was noticed — which is
// the entire failure the digest is here to prevent, arrived at by an
// optimisation.
func (l *Loader) download(ctx context.Context, url, want string) (string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := l.client().Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("computeimage: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("computeimage: fetching %s: HTTP %d", url, resp.StatusCode)
	}

	dir := l.ScratchDir
	if strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	file, err := os.CreateTemp(dir, "catalogue-image-*.tar")
	if err != nil {
		return "", 0, err
	}
	path := file.Name()
	// Removed unless this function returns it. A download that fails halfway
	// leaves nothing behind; a mismatched one leaves nothing behind ESPECIALLY,
	// because a rejected image tarball sitting on disk beside a correct one is
	// an invitation to load the wrong file by hand later.
	keep := false
	defer func() {
		file.Close()
		if !keep {
			os.Remove(path)
		}
	}()

	limit := l.maxBytes()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hasher),
		io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", 0, fmt.Errorf("computeimage: fetching %s: %w", url, err)
	}
	if written > limit {
		return "", 0, fmt.Errorf("computeimage: %s is larger than the %d-byte limit",
			url, limit)
	}
	if err := file.Sync(); err != nil {
		return "", 0, err
	}

	got := hex.EncodeToString(hasher.Sum(nil))
	if got != want {
		// Loud, and with both values, because this is a root-adjacent process
		// declining to install an executable image somebody served it. The
		// operator needs to be able to tell a truncated download from bytes that
		// are simply not the ones this build was built to accept, and the only
		// way to tell is to see both.
		l.logf("compute: REFUSED %s — sha256 %s, expected %s. Nothing was loaded.",
			url, got, want)
		return "", 0, fmt.Errorf("%w: %s is %s, expected %s", ErrDigestMismatch,
			url, got, want)
	}
	keep = true
	return path, written, nil
}

// ScratchDirFor is where downloads are staged for a node rooted at dataDir.
func ScratchDirFor(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	return filepath.Join(dataDir, "compute-images")
}
