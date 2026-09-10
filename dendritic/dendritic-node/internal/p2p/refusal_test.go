package p2p

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
)

// A peer that keeps refusing must stop winning candidate slots. Measured on
// production: three refusing peers held every object at "placed 6, failed 3"
// while seven healthy nodes were available, because candidates are ranked by
// ADVERTISED free space and a refusing peer advertises plenty.
func TestAPeerThatKeepsRefusingStopsBeingACandidate(t *testing.T) {
	n := &Node{}
	const peer = "12D3KooWRefusesEverything"

	for i := 1; i < refusalsBeforeSkipping; i++ {
		n.noteRefusal(peer, "storage capacity exceeded")
		if n.refusingPeer(peer) {
			t.Fatalf("skipped after only %d refusals; a peer having one bad round must not be dropped", i)
		}
	}
	n.noteRefusal(peer, "storage capacity exceeded")
	if !n.refusingPeer(peer) {
		t.Fatalf("still a candidate after %d refusals", refusalsBeforeSkipping)
	}

	// Any success means whatever it was refusing over is gone.
	n.noteAccepted(peer)
	if n.refusingPeer(peer) {
		t.Error("a peer that accepted a shard is still being skipped")
	}
}

// The cooldown is what lets a fixed peer back in with nobody intervening -- a
// permanent blacklist would shrink the network every time a volunteer had a bad
// hour. RKLs refused every lease until its binary was replaced, then was fine.
func TestRefusalsExpireSoAFixedPeerReturns(t *testing.T) {
	n := &Node{}
	const peer = "12D3KooWWasBrokenNowFixed"
	for i := 0; i < refusalsBeforeSkipping; i++ {
		n.noteRefusal(peer, "storage capacity exceeded")
	}
	if !n.refusingPeer(peer) {
		t.Fatal("expected the peer to be skipped")
	}
	n.refusalMu.Lock()
	n.refusals[peer].last = time.Now().Add(-refusalCooldown - time.Minute)
	n.refusalMu.Unlock()
	if n.refusingPeer(peer) {
		t.Error("the refusal never expired, so a repaired peer could never rejoin")
	}
}

// Absence is not refusal. A dial that never completed says the network was
// busy, which is not predictive and not the volunteer's fault.
func TestOnlyAnsweredRefusalsCount(t *testing.T) {
	for _, answered := range []string{
		"node is cache-only and does not host shards",
		"storage capacity exceeded",
		"invalid coordinator lease signature",
	} {
		if !answeredNo(errors.New(answered)) {
			t.Errorf("an explicit refusal was not counted: %q", answered)
		}
	}
	for _, absent := range []string{
		"failed to dial: all dials failed",
		"context deadline exceeded",
		"stream reset",
		"i2p stream connect failed: CANT_REACH_PEER",
	} {
		if answeredNo(errors.New(absent)) {
			t.Errorf("an unreachable peer was counted as refusing: %q", absent)
		}
	}
	if answeredNo(nil) {
		t.Error("nil error counted as a refusal")
	}
}

// The filter has to cover BOTH candidate tiers. It was applied only to the
// DHT-record branch, and the peers that refuse are precisely the ones we stay
// connected to -- so every one of them walked back in through the connected-peer
// fallback. Measured on production: four peers still drew ~170 attempts each in
// twenty minutes with the filter "on".
func TestBothCandidateTiersConsultTheRefusalFilter(t *testing.T) {
	source, err := os.ReadFile("disperse.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	// The DHT-record tier and the connected-peer fallback each build a
	// Candidate; both must be guarded.
	guards := strings.Count(text, "n.refusingPeer(")
	if guards < 2 {
		t.Fatalf("refusingPeer is consulted %d time(s); both the DHT-record tier "+
			"and the connected-peer fallback must check it", guards)
	}
}

// Crossing the threshold must drop the cached candidate set, or the peer keeps
// its slot for the rest of the TTL -- which, at nine shards a pass, is most of
// the pass we just decided to stop wasting.
func TestCrossingTheThresholdInvalidatesTheCandidateCache(t *testing.T) {
	n := &Node{}
	n.candidateCache = []placement.Candidate{{PeerID: "someone"}}
	n.candidateAt = time.Now()
	const peer = "12D3KooWJustWentBad"
	for i := 0; i < refusalsBeforeSkipping; i++ {
		n.noteRefusal(peer, "storage capacity exceeded")
	}
	n.candidateMu.Lock()
	cached := len(n.candidateCache)
	n.candidateMu.Unlock()
	if cached != 0 {
		t.Error("the candidate cache still holds a peer we have stopped asking")
	}
}
