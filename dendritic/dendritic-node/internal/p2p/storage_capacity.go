package p2p

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multihash"

	syndii2p "github.com/syndichan/maniwani/storage-client/internal/i2p"
	"github.com/syndichan/maniwani/storage-client/internal/place"
)

// Storage-capacity advertisement: the half of the DHT that was missing.
//
// Nodes already advertised "I can run containers" at a worker rendezvous. They
// did not advertise "I have room for bytes", so a node whose local store was
// full simply failed a write — there was nothing to ask and nowhere to send it.
// These two functions are the directory that makes placement possible, and they
// deliberately mirror PublishDCSWorker/FindDCSWorkers rather than inventing a
// second discovery mechanism.
//
// Records are NOT signed, unlike worker records, and that is a considered
// difference. A worker record grants the right to be sent somebody's workload;
// a capacity record only invites a write that the receiver revalidates by
// content address. The worst a liar achieves is one wasted attempt before the
// placer moves to the next candidate — see internal/place.

func storageRendezvousCID() (cid.Cid, error) {
	digest := sha256.Sum256([]byte(place.RendezvousSeed))
	mh, err := multihash.Encode(digest[:], multihash.SHA2_256)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, mh), nil
}

func storageCapacityKey(nodeID string) string {
	return "/syndichan-storage/" + nodeID
}

// PublishStorageCapacity announces how much room this node will accept.
//
// Called on the same cadence as the worker advertisement. The record carries a
// timestamp and readers drop anything older than place.RecordTTL, because free
// space is a moving number: a stale record is worse than none, since it routes
// writes at a node that filled up an hour ago.
func (n *Node) PublishStorageCapacity(ctx context.Context, freeBytes, capacity int64) error {
	if n.cacheOnly {
		// A cache-only node hosts nothing for other peers -- the "store" handler
		// refuses every shard with "node is cache-only and does not host
		// shards". Advertising capacity anyway makes it a permanent candidate
		// that permanently refuses: measured on production, every placement
		// round offered it a shard, burned the attempt, and objects stalled one
		// holder short of the durability threshold because a slot was spent on
		// a node that was never going to accept.
		//
		// Silently publishing nothing is right here rather than an error: being
		// cache-only is a legitimate configuration, not a failure, and the
		// caller has nothing to handle.
		return nil
	}
	record := place.Record{
		RecordType:  "storage_capacity",
		NodeID:      n.host.ID().String(),
		Destination: n.I2PDestination(),
		FreeBytes:   freeBytes,
		Capacity:    capacity,
		// A DRAINING node keeps publishing, and keeps publishing HONEST figures.
		//
		// Going silent would be the obvious way to stop receiving writes and it is
		// wrong twice over: this record is the only channel by which owners learn
		// the node wants emptying, so a silent node is one nobody drains; and its
		// occupancy is what tells the fleet how much is about to come back, so
		// zeroing FreeBytes to discourage writers would corrupt the same
		// arithmetic levelling reads. The flag says "do not send" in one field
		// that cannot be confused with a measurement.
		Draining:  n.draining.Load(),
		Published: time.Now().UTC(),
	}
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := n.dht.PutValue(ctx, storageCapacityKey(record.NodeID), value); err != nil {
		return err
	}
	rendezvous, err := storageRendezvousCID()
	if err != nil {
		return err
	}
	return n.dht.Provide(ctx, rendezvous, true)
}

// FindStoragePeers returns peers currently advertising free space.
//
// Self is excluded: a node that could store the blob locally would not be
// asking, so offering itself as a candidate would just fail the same capacity
// check a second time.
func (n *Node) FindStoragePeers(ctx context.Context, limit int) ([]place.Record, error) {
	rendezvous, err := storageRendezvousCID()
	if err != nil {
		return nil, err
	}
	seen := map[peer.ID]struct{}{}
	var out []place.Record
	for provider := range n.dht.FindProvidersAsync(ctx, rendezvous, limit) {
		if provider.ID == n.host.ID() {
			continue
		}
		if _, dup := seen[provider.ID]; dup {
			continue
		}
		seen[provider.ID] = struct{}{}

		value, err := n.dht.GetValue(ctx, storageCapacityKey(provider.ID.String()))
		if err != nil {
			continue
		}
		var record place.Record
		if err := json.Unmarshal(value, &record); err != nil {
			continue
		}
		// The record names its own node id; a record claiming to be somebody
		// else's would let one peer redirect writes at a third party.
		if record.NodeID != provider.ID.String() {
			continue
		}
		out = append(out, record)
	}
	return out, nil
}

// DialStoragePeer teaches the host how to reach a candidate and returns its id.
// Passed to place.NewPlacer so that package needs no I2P knowledge of its own.
func (n *Node) DialStoragePeer(_ context.Context, record place.Record) (peer.ID, error) {
	target, err := peer.Decode(record.NodeID)
	if err != nil {
		return "", fmt.Errorf("storage peer id %q: %w", record.NodeID, err)
	}
	addr, err := syndii2p.Multiaddr(record.Destination)
	if err != nil {
		return "", fmt.Errorf("storage peer destination %q: %w", record.Destination, err)
	}
	n.host.Peerstore().AddAddr(target, addr, place.RecordTTL)
	return target, nil
}
