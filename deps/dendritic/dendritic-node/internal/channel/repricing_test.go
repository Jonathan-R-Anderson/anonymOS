package channel

// P12-8 — the repricing term, scored from a real Ethereum Mainnet campaign.
//
// Thirty full recovery cycles: a transaction made arithmetically unmineable by
// setting maxFeePerGas below the base fee, then replaced at the same nonce one
// block later at a fee priced to confirm. Captured to
// testdata/p12-8-repricing-mainnet.json.
//
// Protocol: doc/p12-8-repricing-protocol.md. The fixture carries transaction
// hashes and a PUBLIC address; no key material, and nothing here can broadcast.

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type mainnetRepricing struct {
	Account      string `json:"account"`
	ChainID      int64  `json:"chain_id"`
	Attempts     int    `json:"attempts"`
	Limitation   string `json:"limitation"`
	ValidSamples []struct {
		OrigHash    string  `json:"original_tx_hash"`
		ReplHash    string  `json:"replacement_tx_hash"`
		Recovery    float64 `json:"recovery_seconds"`
		OrigUnmined bool    `json:"original_remained_unmined"`
		ReplStatus  string  `json:"replacement_status"`
		BaseFee     string  `json:"base_fee_at_submission_wei"`
		OrigMaxFee  string  `json:"original_max_fee_wei"`
	} `json:"valid_samples"`
	Discarded []struct {
		Reason string `json:"discard_reason"`
	} `json:"discarded_samples"`
}

func loadRepricingCampaign(t *testing.T) (RepricingObservation, mainnetRepricing) {
	t.Helper()
	raw, err := os.ReadFile("testdata/p12-8-repricing-mainnet.json")
	if err != nil {
		t.Fatalf("reading the campaign: %v", err)
	}
	var c mainnetRepricing
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decoding the campaign: %v", err)
	}
	if c.ChainID != 1 {
		t.Fatalf("fixture is chain %d, not mainnet", c.ChainID)
	}
	obs := RepricingObservation{
		Account:    c.Account,
		Discarded:  map[string]int{},
		Conditions: "calm fee market, base fee 0.088-0.139 gwei, blocks not full",
	}
	for _, d := range c.Discarded {
		obs.Discarded[d.Reason]++
	}
	for _, s := range c.ValidSamples {
		base, _ := strconv.ParseFloat(s.BaseFee, 64)
		obs.Samples = append(obs.Samples, RepricingSample{
			OriginalHash: s.OrigHash, ReplacementHash: s.ReplHash,
			Recovery:             time.Duration(s.Recovery) * time.Second,
			OriginalUnmined:      s.OrigUnmined,
			ReplacementSucceeded: s.ReplStatus == "0x1",
			BaseFeeGwei:          base / 1e9,
		})
	}
	return obs, c
}

func repricingEnvelope() OperatingEnvelope {
	return OperatingEnvelope{
		Channels: 10000, Watchtowers: 2, SweepInterval: 30 * time.Second,
		OnCallResponse: time.Hour,
		OnCall:         "one hour to acknowledge, four hours maximum outage",
	}
}

// TestMainnetRepricingFitsItsBudget is the P12-8 result for this term.
func TestMainnetRepricingFitsItsBudget(t *testing.T) {
	obs, c := loadRepricingCampaign(t)
	if len(obs.Samples) < MinEvidenceSamples {
		t.Fatalf("campaign has %d valid samples, the rules require %d",
			len(obs.Samples), MinEvidenceSamples)
	}

	takenAt := time.Date(2026, 8, 12, 12, 20, 0, 0, time.UTC).Unix()
	ev, err := obs.AsEvidence(1, takenAt)
	if err != nil {
		t.Fatalf("scoring the campaign: %v", err)
	}

	budget := MainnetChallengeBudget()
	v := NewValidatedBudget(1, budget, repricingEnvelope())
	if err := v.Record(ev); err != nil {
		t.Fatalf("the measured recovery time does not satisfy the budget: %v", err)
	}
	if ev.Measured > budget.Repricing {
		t.Fatalf("worst recovery %s exceeds the %s term", ev.Measured, budget.Repricing)
	}

	// Every valid sample must have exercised the replacement path.
	for i, s := range obs.Samples {
		if !s.OriginalUnmined || !s.ReplacementSucceeded {
			t.Fatalf("sample %d was recorded valid without a completed recovery", i+1)
		}
	}
	if c.Attempts != len(obs.Samples)+len(c.Discarded) {
		t.Fatalf("attempts %d does not equal valid %d + discarded %d — "+
			"samples went unaccounted for", c.Attempts, len(obs.Samples), len(c.Discarded))
	}

	t.Logf("worst recovery %s against a %s term (%.2f%% of it), %d samples, %d discarded",
		ev.Measured, budget.Repricing,
		100*float64(ev.Measured)/float64(budget.Repricing), ev.Samples, len(c.Discarded))
}

// TestRepricingEvidenceRefusesAMinedOriginal pins the primary guard.
//
// If the original was mined, no repricing happened. Such a cycle "completes"
// fast for the one reason that makes it meaningless, and admitting it would
// pull the distribution toward zero with samples where the mechanism under test
// never ran.
func TestRepricingEvidenceRefusesAMinedOriginal(t *testing.T) {
	obs, _ := loadRepricingCampaign(t)
	obs.Samples = append(obs.Samples, RepricingSample{
		OriginalHash: "0xselfresolved", Recovery: time.Second,
		OriginalUnmined: false, ReplacementSucceeded: true, BaseFeeGwei: 0.09,
	})
	if _, err := obs.AsEvidence(1, time.Now().Unix()); err == nil {
		t.Fatal("a sample whose original was mined was accepted; nothing was repriced in it")
	}
}

// TestRepricingEvidenceRefusesAFailedReplacement — a failed recovery is not a
// recovery, however fast the replacement was mined.
func TestRepricingEvidenceRefusesAFailedReplacement(t *testing.T) {
	obs, _ := loadRepricingCampaign(t)
	obs.Samples = append(obs.Samples, RepricingSample{
		OriginalHash: "0xstuck", ReplacementHash: "0xreverted", Recovery: time.Second,
		OriginalUnmined: true, ReplacementSucceeded: false, BaseFeeGwei: 0.09,
	})
	if _, err := obs.AsEvidence(1, time.Now().Unix()); err == nil {
		t.Fatal("a reverted replacement was accepted as a successful recovery")
	}
}

// TestRepricingEvidenceCarriesItsConditions is the congestion limitation, kept
// structural rather than editorial.
//
// The measurement is only meaningful relative to the fee market it ran in. A
// campaign that does not state its conditions cannot produce evidence, and the
// conditions are embedded in Method so the figure cannot travel without them.
func TestRepricingEvidenceCarriesItsConditions(t *testing.T) {
	obs, _ := loadRepricingCampaign(t)

	stripped := obs
	stripped.Conditions = "   "
	if _, err := stripped.AsEvidence(1, time.Now().Unix()); err == nil {
		t.Fatal("a campaign with no stated fee conditions produced evidence")
	}

	ev, err := obs.AsEvidence(1, time.Now().Unix())
	if err != nil {
		t.Fatalf("scoring: %v", err)
	}
	for _, want := range []string{"LIMITATION", "sustained fee-market congestion", "base fee"} {
		if !strings.Contains(ev.Method, want) {
			t.Fatalf("Method does not carry %q; the limitation must travel with the number:\n%s",
				want, ev.Method)
		}
	}
}
