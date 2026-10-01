package main

// Filing the inclusion and repricing runs that were ALREADY MEASURED.
//
// Both were run against Ethereum mainnet, both are recorded in testdata, and
// both are already accepted by Record() — the repository's own tests do exactly
// that and pass. What had never happened is filing them outside a test binary.
//
// SO NOTHING HERE MEASURES ANYTHING. It reads two fixtures and hands them to
// the same AsEvidence/Record path everything else uses. Re-running the
// campaigns would spend mainnet ETH to reproduce numbers that already exist,
// and would replace evidence whose provenance is already recorded.
//
// THE ACCOUNT IS NOT THE TREASURY, and that is not a defect. Record() has no
// sender check: the measuring account travels in the Method string as
// provenance, which is what it is for. Re-running from a different account
// would change who the evidence says measured it, not whether it is true.

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

// inclusionFixture is the on-disk shape of a recorded inclusion run.
type inclusionFixture struct {
	Account string `json:"account"`
	ChainID int64  `json:"chain_id"`
	Samples []struct {
		Hash   string  `json:"tx_hash"`
		Delay  float64 `json:"inclusion_delay_seconds"`
		Blocks uint64  `json:"blocks_waited"`
		MaxFee float64 `json:"max_fee_gwei"`
		Tip    float64 `json:"priority_fee_gwei"`
	} `json:"samples"`
}

// repricingFixture is the on-disk shape of a recorded repricing campaign.
type repricingFixture struct {
	Account      string `json:"account"`
	ChainID      int64  `json:"chain_id"`
	Limitation   string `json:"limitation"`
	ValidSamples []struct {
		OrigHash    string  `json:"original_tx_hash"`
		ReplHash    string  `json:"replacement_tx_hash"`
		Recovery    float64 `json:"recovery_seconds"`
		OrigUnmined bool    `json:"original_remained_unmined"`
		ReplStatus  string  `json:"replacement_status"`
		BaseFee     string  `json:"base_fee_at_submission_wei"`
	} `json:"valid_samples"`
	Discarded []struct {
		Reason string `json:"discard_reason"`
	} `json:"discarded_samples"`
}

// readInclusion rebuilds the observation from its recorded run.
//
// Every recorded sample is Confirmed: the measuring tool only wrote a sample
// once a receipt named a block, and an abandoned transaction aborted the run
// instead of being written down. That is why the fixture cannot contain an
// unconfirmed sample, and why AsEvidence's guard against them is exercised by a
// separate test rather than by this data.
func readInclusion(path string) (channel.InclusionObservation, error) {
	var f inclusionFixture
	if err := readJSON(path, &f); err != nil {
		return channel.InclusionObservation{}, err
	}
	if f.ChainID != mainnet {
		return channel.InclusionObservation{}, fmt.Errorf(
			"inclusion fixture is chain %d, not mainnet", f.ChainID)
	}
	obs := channel.InclusionObservation{Account: f.Account}
	for _, s := range f.Samples {
		obs.Samples = append(obs.Samples, channel.InclusionSample{
			TxHash: s.Hash, Delay: time.Duration(s.Delay) * time.Second,
			BlocksWaited: s.Blocks, Confirmed: true,
			// maxFee was set to 2*base + tip, so base is recoverable.
			BaseFeeGwei: (s.MaxFee - s.Tip) / 2,
		})
	}
	if len(obs.Samples) == 0 {
		return obs, fmt.Errorf("inclusion fixture contains no samples")
	}
	return obs, nil
}

// readRepricing rebuilds the campaign, INCLUDING its discards.
//
// The discard reasons are carried rather than dropped: a campaign that threw
// samples away has to say how many and why, or its worst case is a selection
// rather than a measurement.
func readRepricing(path string) (channel.RepricingObservation, error) {
	var f repricingFixture
	if err := readJSON(path, &f); err != nil {
		return channel.RepricingObservation{}, err
	}
	if f.ChainID != mainnet {
		return channel.RepricingObservation{}, fmt.Errorf(
			"repricing fixture is chain %d, not mainnet", f.ChainID)
	}
	obs := channel.RepricingObservation{
		Account:   f.Account,
		Discarded: map[string]int{},
		// The conditions the campaign ran in. AsEvidence refuses a campaign that
		// does not state them, because a recovery time without a fee market to
		// read it against is not a measurement of anything.
		Conditions: "calm fee market, base fee 0.088-0.139 gwei, blocks not full",
	}
	for _, d := range f.Discarded {
		obs.Discarded[d.Reason]++
	}
	for _, s := range f.ValidSamples {
		base, _ := strconv.ParseFloat(s.BaseFee, 64)
		obs.Samples = append(obs.Samples, channel.RepricingSample{
			OriginalHash: s.OrigHash, ReplacementHash: s.ReplHash,
			Recovery:             time.Duration(s.Recovery) * time.Second,
			OriginalUnmined:      s.OrigUnmined,
			ReplacementSucceeded: s.ReplStatus == "0x1",
			BaseFeeGwei:          base / 1e9,
		})
	}
	if len(obs.Samples) == 0 {
		return obs, fmt.Errorf("repricing fixture contains no valid samples")
	}
	return obs, nil
}

func readJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("malformed fixture %s: %w", path, err)
	}
	return nil
}

// ---- failover and detection --------------------------------------------------

type failoverFixture struct {
	ChainID   int64  `json:"chain_id"`
	Rounds    int    `json:"rounds"`
	Attested  string `json:"attested"`
	Worst     string `json:"worst_failover"`
	AllFailed int    `json:"all_failed"`
	Endpoints []struct {
		Endpoint string `json:"endpoint"`
		Attempts int    `json:"attempts"`
		Failures int    `json:"failures"`
	} `json:"endpoints"`
}

type detectionFixture struct {
	ChainID   int64  `json:"chain_id"`
	Channels  int    `json:"channels_per_watchtower"`
	Worst     string `json:"worst_sweep"`
	Samples   int    `json:"samples"`
	Method    string `json:"method"`
}

// readFailover rebuilds the observation so AsEvidence applies its own guards —
// two endpoints, independent providers, an attestation, no all-failed round,
// and a primary that actually failed. Reconstructing rather than trusting the
// fixture's stored verdict means the refusals still run.
func readFailover(path string) (channel.FailoverObservation, string, error) {
	var f failoverFixture
	if err := readJSON(path, &f); err != nil {
		return channel.FailoverObservation{}, "", err
	}
	if f.ChainID != mainnet {
		return channel.FailoverObservation{}, "", fmt.Errorf(
			"failover fixture is chain %d, not mainnet", f.ChainID)
	}
	worst, err := time.ParseDuration(f.Worst)
	if err != nil {
		return channel.FailoverObservation{}, "", fmt.Errorf("worst failover %q: %w", f.Worst, err)
	}
	obs := channel.FailoverObservation{WorstFailover: worst, AllFailed: f.AllFailed}
	for _, e := range f.Endpoints {
		obs.Endpoints = append(obs.Endpoints, channel.EndpointHealth{
			Endpoint: e.Endpoint, Attempts: e.Attempts, Failures: e.Failures,
		})
	}
	return obs, f.Attested, nil
}

// readDetection builds the evidence directly: there is no DetectionObservation
// type, so the harness records the fields Record() needs and this hands them
// over unchanged. AtChannels is what Record() checks against the envelope.
func readDetection(path string, now int64) (channel.Evidence, error) {
	var f detectionFixture
	if err := readJSON(path, &f); err != nil {
		return channel.Evidence{}, err
	}
	if f.ChainID != mainnet {
		return channel.Evidence{}, fmt.Errorf("detection fixture is chain %d, not mainnet", f.ChainID)
	}
	worst, err := time.ParseDuration(f.Worst)
	if err != nil {
		return channel.Evidence{}, fmt.Errorf("worst sweep %q: %w", f.Worst, err)
	}
	return channel.Evidence{
		Term: "detection", Measured: worst, Samples: f.Samples,
		ChainID: mainnet, Method: f.Method, TakenAt: now,
		AtChannels: f.Channels,
	}, nil
}
