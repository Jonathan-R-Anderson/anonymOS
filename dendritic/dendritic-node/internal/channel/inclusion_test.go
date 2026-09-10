package channel

// P12-8 — the inclusion term, scored from a real Ethereum Mainnet run.
//
// The measurement itself is not here. Thirty transactions were broadcast from a
// dedicated mainnet account and the run was captured to
// testdata/p12-8-inclusion-mainnet.json; this file is what turns that capture
// into a validation record, and what pins the guard that stops a bad capture
// from becoming one.
//
// The fixture holds transaction hashes and a PUBLIC address. It holds no key
// material, and nothing in this package can broadcast.

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// mainnetRun is the shape written by the measurement tool.
type mainnetRun struct {
	Account       string `json:"account"`
	ChainID       int64  `json:"chain_id"`
	Provider      string `json:"endpoint_provider"`
	TotalSpentWei string `json:"total_spent_wei"`
	Samples       []struct {
		Hash     string  `json:"tx_hash"`
		Delay    float64 `json:"inclusion_delay_seconds"`
		Blocks   uint64  `json:"blocks_waited"`
		MaxFee   float64 `json:"max_fee_gwei"`
		TipGwei  float64 `json:"priority_fee_gwei"`
		Included uint64  `json:"included_in_block"`
	} `json:"samples"`
}

func loadMainnetRun(t *testing.T) InclusionObservation {
	t.Helper()
	raw, err := os.ReadFile("testdata/p12-8-inclusion-mainnet.json")
	if err != nil {
		t.Fatalf("reading the mainnet run: %v", err)
	}
	var run mainnetRun
	if err := json.Unmarshal(raw, &run); err != nil {
		t.Fatalf("decoding the mainnet run: %v", err)
	}
	if run.ChainID != 1 {
		t.Fatalf("fixture is chain %d, not mainnet", run.ChainID)
	}
	obs := InclusionObservation{Account: run.Account, Endpoint: run.Provider}
	for _, s := range run.Samples {
		// The tool only writes a sample once a receipt names a block, so every
		// recorded sample is a confirmed one. An abandoned transaction aborts
		// the run instead of being written down, which is why the guard in
		// AsEvidence has to be tested separately, below.
		obs.Samples = append(obs.Samples, InclusionSample{
			TxHash: s.Hash, Delay: time.Duration(s.Delay) * time.Second,
			BlocksWaited: s.Blocks, Confirmed: true,
			BaseFeeGwei: (s.MaxFee - s.TipGwei) / 2, // maxFee = 2*base + tip
		})
	}
	return obs
}

// TestMainnetInclusionFitsItsBudget is the P12-8 result for this term.
func TestMainnetInclusionFitsItsBudget(t *testing.T) {
	obs := loadMainnetRun(t)
	if len(obs.Samples) < MinEvidenceSamples {
		t.Fatalf("run has %d samples, the evidence rules require %d",
			len(obs.Samples), MinEvidenceSamples)
	}

	takenAt := time.Date(2026, 8, 12, 11, 40, 0, 0, time.UTC).Unix()
	ev, err := obs.AsEvidence(1, takenAt)
	if err != nil {
		t.Fatalf("scoring the run: %v", err)
	}

	budget := MainnetChallengeBudget()
	v := NewValidatedBudget(1, budget, OperatingEnvelope{
		Channels: 10000, Watchtowers: 2, SweepInterval: 30 * time.Second,
		OnCallResponse: time.Hour,
		OnCall:         "one hour to acknowledge, four hours maximum outage",
	})
	if err := v.Record(ev); err != nil {
		t.Fatalf("the measured inclusion time does not satisfy the budget: %v", err)
	}

	// The point of the term, stated as an assertion rather than left implicit:
	// the budget is a worst case, so what has to fit is the worst sample.
	if ev.Measured > budget.Inclusion {
		t.Fatalf("worst inclusion %s exceeds the %s term", ev.Measured, budget.Inclusion)
	}
	t.Logf("worst inclusion %s against a %s term (%.1f%% of it), %d samples",
		ev.Measured, budget.Inclusion,
		100*float64(ev.Measured)/float64(budget.Inclusion), ev.Samples)
}

// TestInclusionEvidenceRefusesAnAbandonedTransaction pins the guard.
//
// This is the failure this term is most likely to be validated through: a run
// where one transaction sat unconfirmed, was given up on, and the maximum was
// taken over the twenty-nine that landed. That number is not the worst case —
// the abandoned one is, and its duration is unknown.
func TestInclusionEvidenceRefusesAnAbandonedTransaction(t *testing.T) {
	obs := loadMainnetRun(t)
	obs.Samples = append(obs.Samples, InclusionSample{
		TxHash: "0xabandoned", Confirmed: false, BaseFeeGwei: 0.08,
	})

	if _, err := obs.AsEvidence(1, time.Now().Unix()); err == nil {
		t.Fatal("a run containing an abandoned transaction was accepted as evidence; " +
			"the worst case of such a run is unknown, not the slowest success")
	}
}

// TestInclusionEvidenceIsChainSpecific — a mainnet measurement must not
// validate a budget for anything else.
func TestInclusionEvidenceIsChainSpecific(t *testing.T) {
	obs := loadMainnetRun(t)
	ev, err := obs.AsEvidence(1, time.Now().Unix())
	if err != nil {
		t.Fatalf("scoring: %v", err)
	}
	v := NewValidatedBudget(11155111, MainnetChallengeBudget(), OperatingEnvelope{
		Channels: 10000, Watchtowers: 2, SweepInterval: 30 * time.Second,
		OnCallResponse: time.Hour,
		OnCall:         "one hour to acknowledge, four hours maximum outage",
	})
	if err := v.Record(ev); err == nil {
		t.Fatal("mainnet evidence was accepted for a Sepolia budget")
	}
}
