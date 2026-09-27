package channel

// P12-8 detection, re-measured against the real chain — gate evidence.
//
// WHY THE FILED EVIDENCE NEEDED REPLACING
// ---------------------------------------
// doc/deployment-gate.md requires detection to be measured "at the channel count
// this deployment will hold, AGAINST A REAL RPC". The filed 31s figure comes from
// TestDetectionAtProductionEnvelope, which builds its envelope on NewFakeChain()
// — an in-memory map with no latency and, more importantly, NO CONCEPT OF
// FINALITY.
//
// That matters because AuthenticatedStateRoot refuses any header that is not
// FINALIZED (execution.go: `if level != HeaderFinalized`). So the watchtower
// cannot see a channel state change until the block carrying it finalises, and
// the dominant term in real detection is not RPC latency or scan cost at all —
// it is Ethereum's own finality delay.
//
// A zero-latency chain cannot express that, so the 31s figure is not merely
// optimistic; it measures a different quantity.
//
//	P128_FINALITY=1 BEACON_API_URL=... go test ./internal/channel/ \
//	  -run TestP128FinalityLagForDetection -v -timeout 6h
//
// NOTHING IS CHANGED BY THIS FILE. It measures. The 30-minute detection term,
// challengePeriod, every budget term, the watchtower and the gate are untouched.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"
)

// finalitySample is one observation of how far behind finality is.
type finalitySample struct {
	AttestedSlot  int64
	FinalizedSlot int64
	LagSlots      int64
	At            time.Time
}

func (f finalitySample) Lag() time.Duration {
	return time.Duration(f.LagSlots) * 12 * time.Second
}

// fetchFinality reads one finality update from the beacon API.
func fetchFinality(url string) (finalitySample, error) {
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Get(
		url + "/eth/v1/beacon/light_client/finality_update")
	if err != nil {
		return finalitySample{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			AttestedHeader struct {
				Beacon struct {
					Slot string `json:"slot"`
				} `json:"beacon"`
			} `json:"attested_header"`
			FinalizedHeader struct {
				Beacon struct {
					Slot string `json:"slot"`
				} `json:"beacon"`
			} `json:"finalized_header"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return finalitySample{}, err
	}
	var att, fin int64
	fmt.Sscanf(out.Data.AttestedHeader.Beacon.Slot, "%d", &att)
	fmt.Sscanf(out.Data.FinalizedHeader.Beacon.Slot, "%d", &fin)
	if att == 0 || fin == 0 {
		return finalitySample{}, fmt.Errorf("beacon returned slots att=%d fin=%d", att, fin)
	}
	return finalitySample{
		AttestedSlot: att, FinalizedSlot: fin, LagSlots: att - fin, At: time.Now(),
	}, nil
}

// TestP128FinalityLagForDetection gathers the detection term's dominant
// component: how long after a block is produced can an authenticated system
// first act on it.
//
// Samples must be INDEPENDENT. Finality advances once per epoch (32 slots,
// 6.4 min), so polling every 20 seconds yields the same answer a dozen times
// over and would let a 12-sample run masquerade as 30. This waits for the
// finalized slot to CHANGE before counting a new sample.
func TestP128FinalityLagForDetection(t *testing.T) {
	if os.Getenv("P128_FINALITY") == "" {
		t.Skip("set P128_FINALITY=1 — this runs for hours, one sample per epoch")
	}
	beacon := os.Getenv("BEACON_API_URL")
	if beacon == "" {
		t.Skip("set BEACON_API_URL")
	}
	want := 30 // the gate's minimum sample count
	if v := os.Getenv("P128_SAMPLES"); v != "" {
		fmt.Sscanf(v, "%d", &want)
	}

	var samples []finalitySample
	var lastFinalized int64
	deadline := time.Now().Add(5 * time.Hour)

	for len(samples) < want && time.Now().Before(deadline) {
		s, err := fetchFinality(beacon)
		if err != nil {
			t.Logf("  beacon read failed (continuing): %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		if s.FinalizedSlot == lastFinalized {
			// Same epoch. Not a new observation.
			time.Sleep(20 * time.Second)
			continue
		}
		lastFinalized = s.FinalizedSlot
		samples = append(samples, s)
		t.Logf("  sample %2d/%d: attested %d, finalized %d, lag %d slots = %s",
			len(samples), want, s.AttestedSlot, s.FinalizedSlot, s.LagSlots,
			s.Lag().Round(time.Second))
	}

	if len(samples) < want {
		t.Fatalf("only %d independent samples in %s; the gate requires %d and "+
			"this must not be filed short", len(samples), 5*time.Hour, want)
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i].LagSlots < samples[j].LagSlots })
	min := samples[0].Lag()
	median := samples[len(samples)/2].Lag()
	p95 := samples[int(0.95*float64(len(samples)-1))].Lag()
	max := samples[len(samples)-1].Lag()

	t.Logf("")
	t.Logf("FINALITY LAG over %d INDEPENDENT epochs", len(samples))
	t.Logf("  min %s   median %s   p95 %s   MAX %s",
		min.Round(time.Second), median.Round(time.Second),
		p95.Round(time.Second), max.Round(time.Second))

	// The gate takes the WORST sample as the evidence, as it does for inclusion.
	budget := MainnetChallengeBudget().Detection
	sweep := DefaultWatchInterval
	total := max + sweep
	t.Logf("")
	t.Logf("DETECTION, end to end, worst observed:")
	t.Logf("  finality lag        %s   <- Ethereum's, not ours", max.Round(time.Second))
	t.Logf("+ sweep interval      %s", sweep)
	t.Logf("= %s against a %s budget (%.0f%% of it)",
		total.Round(time.Second), budget, 100*total.Seconds()/budget.Seconds())

	if total > budget {
		t.Errorf("DETECTION EXCEEDS ITS BUDGET: %s > %s. The term must be raised "+
			"and challengePeriod re-derived — NOT the measurement adjusted.",
			total.Round(time.Second), budget)
	} else {
		t.Logf("  FITS, with %s of margin", (budget - total).Round(time.Second))
	}

	t.Logf("")
	t.Logf("WHAT THIS REPLACES: the filed 31s came from a NewFakeChain envelope, "+
		"which has no finality and no latency. The dominant term is consensus "+
		"finality — %s of the %s budget — and no RPC tier, local node or "+
		"watchtower optimisation can reduce it.",
		max.Round(time.Second), budget)
	t.Log("NOTHING WAS CHANGED. The 30-minute detection term, challengePeriod, " +
		"every other budget term and the deployment gate are exactly as they were.")
}
