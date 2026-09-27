//go:build linux

package computeworker

// Deciding what a submitted program is allowed to be.
//
// THE RULE THIS FILE ENFORCES
// ---------------------------
// The GPGPU roadmap's catalogue rule exists because a CONTAINER is not a
// boundary to bet a volunteer's desktop on. So until M2 shipped, a volunteer ran
// signed catalogue images only and supplied data — never arbitrary code.
//
// A microVM is a different boundary. Hardware virtualisation means the guest
// cannot read host memory even having fully compromised its own kernel, and
// privileged instructions trap to the hypervisor. That is qualitatively stronger
// than namespaces and seccomp, and it is why the roadmap says M2 is the one
// place the catalogue rule may be relaxed.
//
// This file is that relaxation, made explicit rather than allowed to drift:
//
//	microVM available  →  arbitrary code permitted
//	container only     →  catalogue images only, arbitrary code REFUSED
//
// The refusal is the important half. A node without KVM that quietly ran
// arbitrary code in a container would be exactly the outcome the catalogue rule
// exists to prevent, and it would look identical to a working node until
// somebody submitted something hostile.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/microvm"
)

var (
	// ErrArbitraryCodeRefused is returned when a submitter sends a program
	// rather than data to a node that has no microVM. Distinct from a failure:
	// the node is working correctly and declining on principle.
	ErrArbitraryCodeRefused = errors.New(
		"computeworker: this node has no microVM, so it runs signed catalogue " +
			"images only — arbitrary programs need hardware isolation")
	ErrGPUUnavailable = errors.New("computeworker: GPU work requires passthrough this node does not have")
)

// Payload is what was submitted.
type Payload struct {
	// Arbitrary is true when the submitter supplied CODE rather than only data
	// for a catalogue image. The distinction is the whole safety question, so
	// it is a field rather than something inferred from whether Files is empty.
	Arbitrary bool
	// CatalogueImage is the signed image to run when Arbitrary is false.
	CatalogueImage string
	Files          map[string]string
	Entrypoint     string
	// NeedsGPU asks for device passthrough, which punches through the isolation
	// every other layer provides — so it is requested explicitly and refused by
	// default.
	NeedsGPU bool
}

// Isolation is what a node can offer.
type Isolation uint8

const (
	IsolationNone      Isolation = iota // nothing — must not run submitted work
	IsolationContainer                  // hardened container: catalogue images only
	IsolationMicroVM                    // hardware virtualisation: arbitrary code defensible
)

func (i Isolation) String() string {
	switch i {
	case IsolationMicroVM:
		return "microvm"
	case IsolationContainer:
		return "container"
	default:
		return "none"
	}
}

// IsolationOf reports the strongest boundary this machine can provide.
//
// Reads the same probe the scheduler matches on, so what a node advertises and
// what it will actually enforce cannot disagree.
func IsolationOf(profile compute.Profile) Isolation {
	if profile.MicroVM.Isolated() {
		return IsolationMicroVM
	}
	return IsolationContainer
}

// Admit decides whether a payload may run under a given isolation.
//
// Separated from execution so a scheduler can ask before dispatching, and so
// the rule lives in one readable place rather than being scattered through the
// runner.
func Admit(payload Payload, iso Isolation, gpuAvailable bool) error {
	if iso == IsolationNone {
		return ErrArbitraryCodeRefused
	}
	if payload.Arbitrary && iso != IsolationMicroVM {
		// The rule. A container is not a boundary for code somebody else wrote.
		return ErrArbitraryCodeRefused
	}
	if !payload.Arbitrary && payload.CatalogueImage == "" {
		return fmt.Errorf("computeworker: non-arbitrary work needs a catalogue image")
	}
	if payload.NeedsGPU && !gpuAvailable {
		return ErrGPUUnavailable
	}
	return nil
}

// MicroVMExecutor runs arbitrary code in a guest.
type MicroVMExecutor struct {
	Runner     *microvm.Runner
	KernelPath string
	RootFSPath string
	// OutputBytes sizes the result drive. Sparse, so a large ceiling costs
	// nothing for a job returning twelve bytes.
	OutputBytes int64
}

// Run boots a guest, runs the payload, and extracts the result.
//
// The output drive carries NO FILESYSTEM (see microvm/output.go): the guest
// writes a length-prefixed blob to a raw block device and the host reads it
// back with an ordinary file read. Mounting a guest-written filesystem would
// need root, and escalating the host to read the answer of a job it deliberately
// confined is a poor trade.
func (e *MicroVMExecutor) Run(ctx context.Context, job Job) (Result, []byte, error) {
	if e.Runner == nil || e.KernelPath == "" || e.RootFSPath == "" {
		return Result{JobID: job.ID}, nil, ErrArbitraryCodeRefused
	}
	dir, err := os.MkdirTemp("", "compute-out-")
	if err != nil {
		return Result{JobID: job.ID}, nil, err
	}
	defer os.RemoveAll(dir)

	size := e.OutputBytes
	if size <= 0 {
		size = 64 << 20
	}
	outPath := filepath.Join(dir, "output.img")
	if err := microvm.CreateOutputImage(outPath, size); err != nil {
		return Result{JobID: job.ID}, nil, err
	}

	timeout := job.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	vmResult, err := e.Runner.Run(ctx, microvm.Job{
		KernelPath: e.KernelPath,
		RootFSPath: e.RootFSPath,
		OutputPath: outPath,
		Limits: microvm.Limits{
			VCPUs: 1, MemMiB: 512, Timeout: timeout,
		},
	})
	result := Result{
		JobID:      job.ID,
		ExitCode:   vmResult.ExitCode,
		Stdout:     string(vmResult.Console),
		RanSeconds: int(vmResult.Duration.Seconds()),
		TimedOut:   vmResult.TimedOut,
	}
	if err != nil {
		result.Error = err.Error()
		return result, nil, err
	}

	// Read the result even on timeout: a job killed at its deadline may have
	// written something, and the console alone rarely explains what.
	output, readErr := microvm.ReadResult(outPath)
	if readErr != nil {
		if !result.TimedOut {
			// A finished job that wrote nothing readable is a failure worth
			// naming, not an empty success.
			result.Error = "no readable result: " + readErr.Error()
		}
		return result, nil, nil
	}
	return result, output, nil
}
