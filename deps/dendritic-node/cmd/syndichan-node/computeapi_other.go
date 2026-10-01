//go:build !linux

package main

// The compute API on platforms that cannot host a microVM.
//
// WHY THIS FILE EXISTS
// --------------------
// Compute runs ARBITRARY submitted code, and the only isolation this project
// will make that claim behind is Firecracker on KVM. KVM is a Linux kernel
// interface, so `internal/computeworker` and `internal/microvm` are Linux-only
// by construction. `computeapi.go` referenced those symbols with no build tag,
// which meant four of the seven release targets could not compile at all.
//
// internal/compute/microvm_other.go already settled what non-Linux should say:
//
//	"microVM isolation requires Linux with KVM; this platform cannot host it"
//
// and, in its own words, reports "not-usable with a reason that says the
// platform rather than implying something is missing that could be installed."
// This file applies that same rule one layer up, at the HTTP boundary.
//
// WHY THE ROUTES STILL EXIST HERE
// -------------------------------
// Dropping them would turn a deliberate platform limit into a 404, which reads
// as a broken node rather than an honest answer. A caller cannot tell "this
// build has no compute" from "this URL is wrong", and a scheduler seeing 404
// learns nothing it can act on. So the routes stay and answer plainly.
//
// WHAT THIS IS NOT
// ----------------
// There is no executor here, fake or otherwise, and no alternative execution
// mode. A request is refused AT ADMISSION — before a job is accepted, before
// any result map is touched — so nothing on this platform can ever reach a
// MicroVMExecutor that does not exist, and nothing can report a workload as
// accepted or executed.

import (
	"log"
	"net/http"

	"github.com/syndichan/maniwani/storage-client/internal/config"
)

// unsupportedPlatform is the one reason this file gives, borrowed verbatim in
// spirit from internal/compute/microvm_other.go so an operator reading a node's
// probe output and a caller reading an HTTP refusal are told the same thing.
const unsupportedPlatform = "microVM isolation requires Linux with KVM; " +
	"this platform cannot host it, so this node cannot run submitted work"

// computeAPI on non-Linux holds nothing, because there is nothing it could do.
//
// It deliberately keeps the same name and method set as the Linux type so that
// computepeer.go, computeimages.go and dcsapi.go — none of which is platform
// specific — compile unchanged. The difference between the platforms is a build
// decision, not a code path anybody can take by accident.
type computeAPI struct{}

// newComputeAPI mirrors the Linux constructor's CONSENT check exactly.
//
// nil when the operator has not offered a device, because a node lending
// nothing should not answer "would you take this?" at all — that is the Linux
// rule (see dcsapi.go) and it is not this file's business to change it.
//
// Non-nil when they HAVE offered one, so the routes mount and refuse honestly.
// Returning nil in that case would unmount them and produce exactly the
// unexplained 404 this file exists to avoid.
func newComputeAPI(cfg config.Config, logger *log.Logger) *computeAPI {
	if !cfg.Compute.Enabled || (!cfg.Compute.OfferCPU && !cfg.Compute.OfferGPU) {
		return nil
	}
	// Said once at startup rather than only per request: an operator who
	// enabled compute on a Mac should learn it from the log, not from a
	// scheduler's refusal counter.
	logger.Printf("compute: %s; compute endpoints will refuse every request",
		unsupportedPlatform)
	return &computeAPI{}
}

// SetComputeCatalogueReady accepts the fact and does nothing with it.
//
// The image loader is platform independent and may well finish; it changes
// nothing here, because holding every image does not make a platform able to
// isolate what runs in them.
func (c *computeAPI) SetComputeCatalogueReady(ready bool) {}

// handleAdmit refuses before anything is accepted.
//
// This is the admission gate, and it is the only place the refusal needs to
// happen: a caller that is told no here never submits.
func (c *computeAPI) handleAdmit(w http.ResponseWriter, r *http.Request) {
	// "admitted": false in the same shape the Linux path uses for its own
	// refusals, so a caller parses one answer rather than two.
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"admitted": false,
		"reason":   unsupportedPlatform,
		// NOT retryable. Waiting will not make this node Linux, and a caller
		// that retried would do so forever.
		"retryable": false,
	})
}

// handleSubmit refuses. Reached only by a caller that ignored handleAdmit.
func (c *computeAPI) handleSubmit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"accepted":  false,
		"reason":    unsupportedPlatform,
		"retryable": false,
	})
}

// handleResult refuses.
//
// It reports no result and no job — not "pending", not "unknown", not an empty
// success. Nothing was ever accepted here, so there is nothing whose outcome
// could be reported.
func (c *computeAPI) handleResult(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"done":      false,
		"reason":    unsupportedPlatform,
		"retryable": false,
	})
}
