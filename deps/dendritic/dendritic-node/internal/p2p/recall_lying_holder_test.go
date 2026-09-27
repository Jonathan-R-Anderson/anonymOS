package p2p

import (
	"bufio"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// A holder that ANSWERS "deleted" and keeps the bytes.
//
// This is the case the follow-up `have` exists for, and the case that matters
// most: for a content-removal feature, the party being asked to delete is the
// party with the motive to lie. Before verification the owner recorded
// RecallDeleted on the holder's word alone and then dropped it from the
// placement ledger -- so the owner no longer knew that peer had ever held the
// shard and would never ask again. The lie was permanent and invisible.
//
// The fake handler below answers the delete truthfully-shaped but falsely, and
// answers `have` honestly, because a holder that keeps the shard and hides it
// from `have` is a different (and harder) adversary that only pof-challenge
// would catch. This pins the realistic one.
func TestAHolderThatClaimsDeletionButKeepsTheShardIsNotRecordedDeleted(t *testing.T) {
	h := newRecallHarness(t)
	const objectID = "object-lying-holder"
	shardID := h.plantShard(t, objectID, []byte("bytes the holder wants to keep"))

	// Replace the target's real handler with one that lies about deleting and
	// tells the truth about still having it.
	h.target.host.SetStreamHandler(ProtocolID, func(stream network.Stream) {
		defer stream.Close()
		var header requestHeader
		if err := readJSONFrame(bufio.NewReader(stream), &header); err != nil {
			return
		}
		switch header.Operation {
		case "delete":
			// The lie.
			_ = writeJSONFrame(stream, responseHeader{OK: true, Deleted: true})
		case "have":
			// The truth, which is what convicts it.
			_ = writeJSONFrame(stream, responseHeader{OK: true, Present: true, Size: 30})
		default:
			_ = writeJSONFrame(stream, responseHeader{Error: "unsupported operation"})
		}
	})

	state, detail := h.source.recallFromPeer(h.ctx, h.target.host.ID(), h.token(objectID, shardID))

	if state == store.RecallDeleted {
		t.Fatalf("a lying holder was recorded as having deleted the shard: %s", detail)
	}
	if state != store.RecallRefused {
		t.Fatalf("expected the claim to be rejected as a refusal, got %v (%s)", state, detail)
	}
	t.Logf("caught the lie: %s", detail)
}

// The mirror case: a holder that cannot be re-checked must NOT be credited with
// a deletion. Unknown must not collapse into the outcome we were hoping for --
// that is the same failure as reporting a ledger read error as "no holders".
func TestAnUnverifiableDeletionClaimIsNotRecordedDeleted(t *testing.T) {
	h := newRecallHarness(t)
	const objectID = "object-unverifiable"
	shardID := h.plantShard(t, objectID, []byte("bytes"))

	h.target.host.SetStreamHandler(ProtocolID, func(stream network.Stream) {
		var header requestHeader
		if err := readJSONFrame(bufio.NewReader(stream), &header); err != nil {
			stream.Close()
			return
		}
		if header.Operation == "delete" {
			_ = writeJSONFrame(stream, responseHeader{OK: true, Deleted: true})
			stream.Close()
			return
		}
		// The re-check gets nothing at all: hang up without answering.
		stream.Reset()
	})

	state, detail := h.source.recallFromPeer(h.ctx, h.target.host.ID(), h.token(objectID, shardID))

	if state == store.RecallDeleted {
		t.Fatalf("an unverifiable claim was recorded as deleted: %s", detail)
	}
	t.Logf("unknown stayed unknown: %v (%s)", state, detail)
}
