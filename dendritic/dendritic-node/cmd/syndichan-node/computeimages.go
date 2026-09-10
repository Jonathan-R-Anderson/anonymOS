package main

// Making "this node lends compute" a claim that is true.
//
// WHEN THIS NODE FETCHES, AND WHY IT IS AT START
// ----------------------------------------------
// Three moments were available and only one of them is honest.
//
// ON FIRST JOB is the tempting one — nothing is downloaded that is never needed
// — and it cannot work here. The node would have to advertise compute BEFORE it
// could perform any, because the advertisement is what causes the first job to
// arrive; the first submitter then pays for a ~190 MB download inside their
// deadline, on a home connection, and a 600-second embed unit spends most of it
// downloading. Worse, it makes the failure this whole change exists to remove
// arrive one step later rather than not at all: a node whose fetch fails has
// already accepted the work.
//
// ON A SWEEP ALONE means a fresh node advertises nothing for up to an interval
// after starting, which is a needless outage on every restart.
//
// AT START, then, with a sweep BEHIND it. The objection to fetching at start is
// that a node pulls images it may never need — and that objection does not apply
// to this system, because an operator who offers compute does not get to choose
// which catalogue workloads they take. Every catalogue image is one this node
// has already agreed to run. There is no "may never need" set to save.
//
// It runs in the background, so storage, the gateway and the DHT are up in the
// usual time; compute simply is not advertised until its images are there. The
// sweep behind it covers the two cases a single attempt cannot: the site was
// down when this node started, and an image that goes away later.

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/computeimage"
	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
)

// catalogueSweepInterval is how often a node re-checks that it still holds
// every catalogue image.
//
// Half an hour rather than minutes: the check is one Docker call per workload
// when everything is present, and the case it exists for — a failed fetch, or an
// operator pruning images — is not a case where a few extra minutes of not
// advertising costs anything. A node that failed its start-up fetch retries on
// this schedule and starts advertising the moment it succeeds, without a
// restart.
const catalogueSweepInterval = 30 * time.Minute

// catalogueReadyReporter is what a completed sweep tells. Two implementations in
// practice — the p2p node, whose heartbeat carries the claim to the network, and
// the compute API, which stops accepting work it cannot do — and an interface so
// this file can be tested without either.
type catalogueReadyReporter interface {
	SetComputeCatalogueReady(ready bool)
}

// startCatalogueImages obtains this node's catalogue images and keeps the
// compute advertisement honest about the result.
//
// Does nothing at all when the operator lends no compute: a node that offers
// nothing has nothing to make true, and downloading 190 MB onto a machine whose
// owner declined to lend it would be an unpleasant surprise.
func startCatalogueImages(ctx context.Context, cfg config.Config,
	logger *log.Logger, report ...catalogueReadyReporter) {

	announce := catalogueAnnouncer(report...)

	if !cfg.Compute.Enabled || (!cfg.Compute.OfferCPU && !cfg.Compute.OfferGPU) {
		return
	}
	workloads := compute.CatalogueWorkloads()
	if len(workloads) == 0 {
		// An empty catalogue is trivially satisfied. Said out loud because a
		// node advertising compute with nothing to run is a build problem, and
		// silence here would make it look like a working node.
		logger.Printf("compute: the workload catalogue is empty; nothing to fetch")
		announce(true)
		return
	}

	docker, err := dcs.NewDockerClient(cfg.DCS.DockerEndpoint)
	if err != nil {
		// A node with no container runtime cannot run a catalogue workload, and
		// until now it advertised compute anyway — NewDockerClient only checks
		// that the endpoint string starts with unix://, so a machine with no
		// daemon passed every check the site makes and failed every job. It now
		// simply does not claim the capability.
		logger.Printf("compute: no container runtime (%v); this node will not "+
			"advertise compute, because it could not run a catalogue image", err)
		announce(false)
		return
	}

	loader := &computeimage.Loader{
		Runtime:    docker,
		BaseURL:    cfg.Compute.ImageBaseURL,
		ScratchDir: computeimage.ScratchDirFor(cfg.DataDir),
		Logger:     logger,
		// Direct, never through the I2P HTTP proxy. This is a fetch from the
		// origin over TLS, the same shape as the heartbeat, and routing ~190 MB
		// through a volunteer's garlic tunnels would be slow enough to look
		// broken while hiding nothing: the request is for a public artifact
		// whose contents everybody running compute has.
		HTTP: &http.Client{Timeout: 30 * time.Minute},
	}

	go sweepCatalogue(ctx, loader, workloads, catalogueSweepInterval, logger, announce)
}

// catalogueAnnouncer collects the parties that need to know, skipping the ones
// that are not there.
//
// A nil *p2p.Node or *computeAPI arrives as a NON-NIL interface holding a nil
// pointer, so this cannot be a plain != nil check: the caller passes both
// freely, and on most nodes at least one of them is nil because compute is off
// or the node is gateway-only. Filtered here, where the concrete types are
// known, rather than at the call site where the reader would have to remember.
func catalogueAnnouncer(report ...catalogueReadyReporter) func(bool) {
	live := make([]catalogueReadyReporter, 0, len(report))
	for _, r := range report {
		switch typed := r.(type) {
		case *p2p.Node:
			if typed == nil {
				continue
			}
		case *computeAPI:
			if typed == nil {
				continue
			}
		case nil:
			continue
		}
		live = append(live, r)
	}
	return func(ready bool) {
		for _, r := range live {
			r.SetComputeCatalogueReady(ready)
		}
	}
}

// sweepCatalogue makes the images present, announces the result, and keeps
// doing so.
//
// The first pass is IMMEDIATE — a node whose operator already ran
// compute-images/build.sh is ready within one Docker round trip and advertises
// on its first heartbeat, with nothing downloaded.
func sweepCatalogue(ctx context.Context, loader *computeimage.Loader,
	workloads []compute.Workload, interval time.Duration,
	logger *log.Logger, announce func(bool)) {

	for {
		err := loader.Ensure(ctx, workloads)
		if err == nil {
			announce(true)
		} else {
			// Both halves are said: what failed, and what it costs. An operator
			// who opted into compute and finds their node lending none deserves
			// to be told that in the same line as the reason, rather than
			// deducing it from a capability missing off a page.
			logger.Printf("compute: %v — NOT advertising compute until every "+
				"catalogue image is present; retrying in %s", err, interval)
			announce(false)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
