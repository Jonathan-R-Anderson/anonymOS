//go:build ethbls

package ethproof

// Live Ethereum Mainnet validation — roadmap P12-5.9.
//
// This is the test that turns "the logic is right" into "it verifies Ethereum".
// Everything else in this package is either synthetic or checks one primitive;
// this runs the whole consensus path against real mainnet data.
//
//	BEACON_API_URL=https://... \
//	MAINNET_CHECKPOINT=0x<block root> \
//	ETH_RPC_URL=https://... \
//	CHAIN_PROBE=1 go test ./internal/ethproof/ -run LiveMainnet -v
//
// THE CHECKPOINT MUST BE YOURS, NOT THE NODE'S
// --------------------------------------------
// MAINNET_CHECKPOINT is supplied by the operator, having obtained it from a
// source they trust — a client release, several independent explorers, a peer
// they know. It is deliberately NOT fetched from BEACON_API_URL, because
//
//	provider -> checkpoint -> provider
//
// tests nothing. The whole validation is that an INDEPENDENT anchor plus
// provider data plus cryptography produces an answer the provider could not
// have chosen.
//
// THE TWO ENDPOINTS MUST BE DIFFERENT PROVIDERS
// ---------------------------------------------
// BEACON_API_URL authenticates; ETH_RPC_URL supplies data to be checked. One
// provider serving both would leave nothing verified against anything, and the
// test refuses that arrangement rather than producing a green run that means
// less than it appears to.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func liveBeacon(t *testing.T) (*BeaconClient, string) {
	t.Helper()
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	endpoint := os.Getenv("BEACON_API_URL")
	if endpoint == "" {
		t.Skip("set BEACON_API_URL to a consensus node serving " +
			"/eth/v1/beacon/light_client/* (checkpoint-sync providers often do not)")
	}
	checkpoint := os.Getenv("MAINNET_CHECKPOINT")
	if checkpoint == "" {
		t.Skip("set MAINNET_CHECKPOINT to a block root you obtained INDEPENDENTLY " +
			"of BEACON_API_URL — see this file's header for why")
	}
	// The arrangement the validation depends on. Refused rather than warned:
	// a green run under one provider would misrepresent what was proven.
	if execURL := os.Getenv("ETH_RPC_URL"); execURL != "" &&
		sameProvider(endpoint, execURL) {
		t.Fatalf("BEACON_API_URL and ETH_RPC_URL are both %q; "+
			"consensus must authenticate execution, not itself", providerOf(endpoint))
	}
	return NewBeaconClient(endpoint), checkpoint
}

// The chain identity, checked against the constant compiled into checkpoint.go.
//
// Runs without a checkpoint, because it needs no anchor — it is checking OUR
// constant against a live node, which is the one thing a node cannot lie about
// without being obviously the wrong chain.
func TestLiveMainnetGenesisMatchesOurConstant(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	endpoint := os.Getenv("BEACON_API_URL")
	if endpoint == "" {
		t.Skip("set BEACON_API_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	g, err := NewBeaconClient(endpoint).Genesis(ctx)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	want := "0x" + hex.EncodeToString(MainnetGenesisValidatorsRoot[:])
	if !strings.EqualFold(g.GenesisValidatorsRoot, want) {
		t.Fatalf("this node's genesis validators root is %s, ours is %s — "+
			"either it is not mainnet or our constant is wrong",
			g.GenesisValidatorsRoot, want)
	}
	t.Logf("genesis validators root matches: %s", g.GenesisValidatorsRoot)
}

// THE VALIDATION. Sync from an independent checkpoint through real data.
func TestLiveMainnetSyncAuthenticatesRealExecutionState(t *testing.T) {
	beacon, checkpointRoot := liveBeacon(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1. Bootstrap at the operator's checkpoint.
	boot, err := beacon.Bootstrap(ctx, checkpointRoot)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	t.Logf("bootstrap at slot %d", boot.Header.Slot)

	// 2. REAL SYNC COMMITTEE through the production KeyValidate path. This is
	//    where blst's missing subgroup check would matter with real keys.
	verifier := NewBLSVerifier()
	if err := verifier.ValidateCommittee(boot.CurrentSyncCommittee); err != nil {
		t.Fatalf("the live sync committee failed key validation: %v", err)
	}
	t.Logf("validated %d real sync committee keys", len(boot.CurrentSyncCommittee.Pubkeys))

	genesis, err := beacon.Genesis(ctx)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	// THE FORK VERSION OF THE SIGNING DOMAIN, NOT OF GENESIS.
	//
	// This harness used to decode genesis_fork_version from the beacon API,
	// which on mainnet is 0x00000000 — and Checkpoint.Valid() rejects a zero
	// fork version, correctly, because a zero here means the signing domain is
	// undefined. The two are different quantities that happen to share a name:
	//
	//	genesis_fork_version   chain identity at slot 0 (mainnet: all zeros)
	//	Checkpoint.ForkVersion the domain a sync-committee signature is checked
	//	                       against, which after Altair is NOT the genesis one
	//
	// checkpoint.go says so directly — "GenesisValidatorsRoot and ForkVersion
	// define the signing domain" — and lightclient.go already derives it the
	// right way when it verifies an update:
	//
	//	era.ForkVersion = ForkVersionAtSlot(u.SignatureSlot)
	//
	// So the anchor is sealed with the same function, at the bootstrap header's
	// slot. Relaxing Valid() to accept zero would have made mainnet's genesis
	// value indistinguishable from an uninitialised checkpoint and let a
	// signature be checked against an undefined domain.
	forkVersion := ForkVersionAtSlot(boot.Header.Slot)
	_ = genesis

	committeeRoot, err := boot.CurrentSyncCommittee.HashTreeRoot()
	if err != nil {
		t.Fatalf("committee root: %v", err)
	}
	cp := Checkpoint{
		Slot: boot.Header.Slot, SyncCommitteeRoot: committeeRoot,
		GenesisValidatorsRoot: MainnetGenesisValidatorsRoot,
		Source:                "operator-supplied MAINNET_CHECKPOINT",
		Note:                  "live validation run",
	}
	if root, err := decodeHex32(checkpointRoot); err == nil {
		cp.BlockRoot = root
	}
	cp.ForkVersion = forkVersion

	state := &LightClientState{
		Spec: SpecAltair, Checkpoint: cp,
		FinalizedHeader:  boot.Header,
		CurrentCommittee: boot.CurrentSyncCommittee,
	}
	if err := state.Anchor.Seal(cp); err != nil {
		t.Fatalf("seal anchor: %v", err)
	}

	// 3. REAL COMMITTEE ROTATION and 4. REAL SIGNATURES.
	//
	// These are two claims, and this test used to conflate them: it counted only
	// rotation updates and, on finding none, declared "the consensus path does not
	// work". That diagnosis can be flatly wrong, and was.
	//
	// A rotation update exists only for a COMPLETED sync committee period. An
	// operator supplying the current finalised checkpoint — the honest thing to
	// supply, and the only root the checkpoint providers serve — anchors inside
	// the current period, and there is no completed period ahead of it to rotate
	// into. Nothing is broken in that situation; there is simply no rotation to
	// apply until the period ends, ~27 hours later.
	//
	// So the two are counted separately. What must hold is that at least one REAL
	// sync committee SIGNATURE was verified by our BLS code against the operator's
	// anchor, whether it arrived on a rotation update or a finality update. Which
	// of the two it was is reported rather than assumed, so a run that could not
	// exercise rotation says so instead of quietly claiming it did.
	period := SyncCommitteePeriod(boot.Header.Slot)
	updates, err := beacon.Updates(ctx, period, 4)
	if err != nil {
		t.Fatalf("updates: %v", err)
	}
	rotations := 0
	for i, u := range updates {
		if err := state.ApplyRotatingUpdate(u, verifier); err != nil {
			t.Logf("update %d (period %d) refused: %v",
				i, SyncCommitteePeriod(u.SignatureSlot), err)
			continue
		}
		rotations++
		t.Logf("update %d applied: finalised slot %d, period %d, %d/%d participation",
			i, u.FinalizedHeader.Slot, SyncCommitteePeriod(u.SignatureSlot),
			u.Participation.Count(), SyncCommitteeSize)
	}

	// 5. REAL FINALITY.
	final, err := beacon.FinalityUpdate(ctx)
	if err != nil {
		t.Fatalf("finality update: %v", err)
	}
	anchoredAt := state.FinalizedHeader.Slot
	finalityApplied := false
	if err := state.ApplyFinalityUpdate(final, verifier); err != nil {
		t.Logf("finality update refused (may be several periods ahead): %v", err)
	} else {
		finalityApplied = true
		t.Logf("finality update applied: attested slot %d, finalised slot %d, "+
			"signature slot %d, %d/%d participation",
			final.AttestedHeader.Slot, final.FinalizedHeader.Slot, final.SignatureSlot,
			final.Participation.Count(), SyncCommitteeSize)
	}

	// THE ASSERTION. Not "a rotation happened" — "a real committee signed real
	// mainnet data and our verifier checked it against an anchor the provider
	// could not choose".
	if rotations == 0 && !finalityApplied {
		t.Fatal("no real sync committee signature authenticated by either path — " +
			"the consensus implementation does not verify mainnet")
	}

	level, err := state.TrustLevelOf(state.FinalizedHeader)
	if err != nil {
		t.Fatalf("TrustLevelOf: %v", err)
	}
	if level != HeaderFinalized {
		t.Fatalf("the head is %s, not finalized", level)
	}
	t.Logf("FINALIZED at slot %d", state.FinalizedHeader.Slot)

	// 6 and 7 need the execution payload from the finalised header, which the
	// beacon API carries on Capella+ light client headers. Recorded as the
	// remaining step rather than asserted, because a run that cannot reach it
	// has still established 1-5 and should say exactly that.
	t.Logf("REACHED: chain identity, %d real committee keys validated, "+
		"%d rotation update(s) applied, finality update applied: %v, finality established",
		len(boot.CurrentSyncCommittee.Pubkeys), rotations, finalityApplied)

	// The boundaries of THIS run, stated. A reader of the log should never have to
	// infer what was not covered.
	if rotations == 0 {
		t.Logf("NOT EXERCISED: committee rotation across a period boundary. The anchor "+
			"is at slot %d, inside period %d, which has not completed; no rotation "+
			"update exists ahead of it. Rotation is exercised only by an anchor at "+
			"least one full period (%d slots) behind the head.",
			boot.Header.Slot, period, SlotsPerSyncCommitteePeriod)
	}
	if state.FinalizedHeader.Slot == anchoredAt {
		t.Logf("NOT EXERCISED: head advancement. The anchor was already the finalised "+
			"head at slot %d, so the verified finality update carried it no further. "+
			"The signature was checked; the head simply had nowhere to move.", anchoredAt)
	}
	t.Log("REMAINING: execution payload bridge + storage proof cross-check (steps 6-7)")

	// Capture whatever was established, as a permanent fixture. It records what
	// was NOT exercised alongside what was — a fixture that reports only its
	// successes is how an unproven step becomes a proven one by attrition.
	if dir := os.Getenv("FIXTURE_OUT"); dir != "" {
		blob, err := json.MarshalIndent(map[string]any{
			"checkpoint_root":       checkpointRoot,
			"checkpoint_source":     "operator-supplied, independent of BEACON_API_URL",
			"beacon_provider":       providerOf(os.Getenv("BEACON_API_URL")),
			"execution_provider":    providerOf(os.Getenv("ETH_RPC_URL")),
			"bootstrap_slot":        boot.Header.Slot,
			"bootstrap_period":      period,
			"committee_keys":        len(boot.CurrentSyncCommittee.Pubkeys),
			"rotations_applied":     rotations,
			"finality_applied":      finalityApplied,
			"finality_participants": final.Participation.Count(),
			"committee_size":        SyncCommitteeSize,
			"finalized_slot":        state.FinalizedHeader.Slot,
			"head_advanced_slots":   state.FinalizedHeader.Slot - anchoredAt,
			"rotation_exercised":    rotations > 0,
			"committee_root":        hex.EncodeToString(committeeRoot[:]),
			"genesis_validators":    genesis.GenesisValidatorsRoot,
		}, "", "  ")
		if err == nil {
			_ = os.WriteFile(dir+"/live-mainnet-summary.json", blob, 0o644)
			t.Logf("fixture summary written to %s", dir)
		}
	}
}

// The adversarial half: a proof against a root the light client did NOT
// authenticate must be rejected, however valid it is on its own terms.
func TestLiveMainnetRejectsAnUnauthenticatedStateRoot(t *testing.T) {
	beacon, checkpointRoot := liveBeacon(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	boot, err := beacon.Bootstrap(ctx, checkpointRoot)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	committeeRoot, err := boot.CurrentSyncCommittee.HashTreeRoot()
	if err != nil {
		t.Fatalf("committee root: %v", err)
	}
	cp := goodCheckpoint()
	cp.Slot, cp.SyncCommitteeRoot = boot.Header.Slot, committeeRoot

	state := &LightClientState{Spec: SpecAltair, Checkpoint: cp,
		FinalizedHeader: boot.Header, CurrentCommittee: boot.CurrentSyncCommittee}
	if err := state.Anchor.Seal(cp); err != nil {
		t.Fatalf("seal: %v", err)
	}
	client := NewLightClient(state)

	v := &HeaderVerifier{ChainID: 1, Endpoint: os.Getenv("ETH_RPC_URL")}
	if err := v.AttachLightClient(client); err != nil {
		t.Fatalf("attach: %v", err)
	}
	// Nothing adopted, so every execution header is unauthenticated — including
	// a perfectly real one fetched from the execution RPC.
	if err := v.VerifyHeader(BlockHeader{
		Number: "0x1", Hash: "0x" + strings.Repeat("11", 32),
		StateRoot: "0x" + strings.Repeat("22", 32),
	}); err == nil {
		t.Fatal("an unauthenticated execution header passed the live gate")
	}
}
