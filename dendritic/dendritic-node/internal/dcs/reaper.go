package dcs

import (
	"context"
	"time"
)

// Reaper enforces the auto-spin-down TTL. It periodically asks the admission
// controller which running instances have passed their expiry and destroys
// them, which frees their slot for whoever is next in the queue.
//
// This is what makes "auto spin down after 24 hours" a guarantee rather than a
// hope: a deployer who walks away, or whose client dies, still has their
// instance reclaimed on schedule, and the volunteer's machine is handed back.
type Reaper struct {
	admission *AdmissionController
	destroy   func(ctx context.Context, containerID string) error
	interval  time.Duration
	logf      func(string, ...any)
}

func NewReaper(admission *AdmissionController, destroy func(context.Context, string) error, logf func(string, ...any)) *Reaper {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Reaper{admission: admission, destroy: destroy, interval: time.Minute, logf: logf}
}

// Run reaps on each tick until ctx is cancelled. One sweep runs immediately so
// a restart does not leave an already-expired instance lingering for a full
// interval.
func (r *Reaper) Run(ctx context.Context) {
	r.sweep(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweep(ctx)
		}
	}
}

func (r *Reaper) sweep(ctx context.Context) {
	for _, id := range r.admission.Expired() {
		if err := r.destroy(ctx, id); err != nil {
			r.logf("dcs: reaper could not destroy expired container %s: %v", id, err)
			continue
		}
		r.logf("dcs: auto-spun-down container %s (TTL reached)", id)
	}
}
