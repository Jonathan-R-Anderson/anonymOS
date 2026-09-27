package main

import (
	"bytes"
	"context"
	"log"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/dcs"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/place"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// Blob placement wiring: advertise this node's free space, accept placements
// from peers, and let the local blob store fall back to a peer when full.
//
// Deliberately in main rather than in the packages it connects: internal/place
// knows nothing about I2P or the store, internal/p2p knows nothing about blobs,
// and keeping the seam here is what let both be tested without a network.
//
// The lesson being applied: a capability nothing CALLS does not exist. The
// codeplay DHT publisher on the site side sat behind an admin button for months
// with zero snapshots published, so this starts itself alongside the bridge
// rather than waiting to be invoked.

const advertiseInterval = 5 * time.Minute

// localAdapter lets the store satisfy place.Local without place importing it.
type localAdapter struct{ store *store.Store }

func (l *localAdapter) PutLocal(digest string, data []byte) error {
	_, err := l.store.PutObject(buildContextBucket, digest, "application/x-tar", bytes.NewReader(data))
	return err
}

func (l *localAdapter) HasLocal(digest string) bool {
	// HeadObject reads the manifest without fetching shards, so an idempotent
	// re-placement costs a lookup rather than a full reassembly.
	m, err := l.store.HeadObject(buildContextBucket, digest)
	return err == nil && m != nil
}

func startBlobPlacement(ctx context.Context, node *p2p.Node, storage *store.Store,
	blobs dcs.BlobStore, logger *log.Logger) {
	if node == nil || storage == nil {
		return
	}
	setter, ok := blobs.(interface{ SetPlacer(*place.Placer) })
	if !ok {
		return
	}

	placer := place.NewPlacer(node.Host(), node, logger, node.DialStoragePeer)
	setter.SetPlacer(placer)

	local := &localAdapter{store: storage}
	// The same capacity rule governs an accepted placement and a local write:
	// a node must not accept from a peer what it would refuse from itself.
	server := place.NewServer(node.Host(), local, logger, func(size int64) bool {
		used, err := storage.UsedBytes()
		if err != nil {
			return false
		}
		return used+size <= storage.Capacity()
	})
	server.Start()

	go advertiseCapacity(ctx, node, storage, logger)
	logger.Printf("place: blob placement active; advertising capacity every %s", advertiseInterval)
}

// advertiseCapacity republishes free space so peers can route writes here.
// Re-published rather than set once because free space is a moving number and a
// stale record sends writes at a node that filled up an hour ago.
func advertiseCapacity(ctx context.Context, node *p2p.Node, storage *store.Store, logger *log.Logger) {
	publish := func() {
		used, err := storage.UsedBytes()
		if err != nil {
			logger.Printf("place: cannot measure used bytes: %v", err)
			return
		}
		free := storage.Capacity() - used
		if free < 0 {
			free = 0
		}
		pubCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err := node.PublishStorageCapacity(pubCtx, free, storage.Capacity()); err != nil {
			logger.Printf("place: advertising capacity failed: %v", err)
		}
	}
	publish()
	ticker := time.NewTicker(advertiseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		}
	}
}
