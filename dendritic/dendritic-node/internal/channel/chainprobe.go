package channel

// Measuring the chain terms of the challenge budget — roadmap P12.
//
// validation.go refuses to produce a deployable challengePeriod until every
// term that makes a claim about the world has evidence. This is how two of
// those claims get measured, and — as importantly — it is where the ones that
// CANNOT be measured this way are written down.
//
//	reorg depth   measurable here, read-only, by watching the head
//	rpc failure   measurable here, read-only, by watching the endpoints
//
//	inclusion     Not measurable READ-ONLY. Needs transactions actually sent on
//	repricing     the target chain from a funded account, because the thing
//	              being measured is what the network does with a real
//	              transaction. A read-only probe can observe fee markets and
//	              block times, which is context, not evidence.
//
//	              InclusionObservation below therefore only SCORES a run that
//	              something else performed; it deliberately cannot broadcast.
//	              Keeping the spending out of this file is what stops a probe
//	              from quietly acquiring a funded key.
//
//	detection     measurable, but by running the watchtower at the channel
//	              count this deployment will hold — not by asking the chain.
//	outage        an operational commitment, not a property of any network.
//
// Guessing at the four unmeasurable ones from the two measurable ones would be
// exactly the move the gate exists to stop.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ReorgObservation is what watching the head found.
type ReorgObservation struct {
	// MaxDepth is the deepest reorganisation seen: how many blocks had to be
	// discarded. Zero means none were observed, which is NOT the same as none
	// being possible — see Evidence.
	MaxDepth int
	// Blocks and Reorgs are the sample size and the number of events.
	Blocks, Reorgs int
	// MaxDepthTime is the wall-clock equivalent of MaxDepth at the observed
	// block interval, which is the form the budget wants.
	MaxDepthTime time.Duration
	// BlockInterval is the mean spacing observed.
	BlockInterval time.Duration
}

// ObserveReorgs watches the chain head and reports the deepest reorganisation.
//
// Read-only, so it needs no funds and no deployed contract — it can be pointed
// at the target chain long before anything is deployed to it, which is the
// point: this measurement takes real time to gather and should be started
// early.
//
// The method is to remember the hash seen at each height. When a height comes
// back with a different hash, everything from there to the previous head was
// discarded, and that distance is the depth.
func ObserveReorgs(ctx context.Context, endpoint string, poll time.Duration, want int) (ReorgObservation, error) {
	if poll <= 0 {
		poll = time.Second
	}
	client := &http.Client{Timeout: 15 * time.Second}
	seen := map[uint64]string{}
	out := ReorgObservation{}

	var highest uint64
	var firstAt, lastAt time.Time

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for out.Blocks < want {
		select {
		case <-ctx.Done():
			// A cancelled observation still reports what it saw. Losing an
			// hour's sampling because the window closed would make this
			// unusable for exactly the long runs it needs.
			return finishObservation(out, firstAt, lastAt, highest), ctx.Err()
		case <-ticker.C:
		}

		number, hash, err := headBlock(ctx, client, endpoint)
		if err != nil {
			continue // an endpoint blip is not an observation
		}
		previous, known := seen[number]
		switch {
		case !known:
			seen[number] = hash
			if number > highest {
				if firstAt.IsZero() {
					firstAt = time.Now()
				}
				lastAt = time.Now()
				out.Blocks += int(number - highest)
				if highest == 0 {
					out.Blocks = 1
				}
				highest = number
			}
		case previous != hash:
			// This height has been rewritten. Everything from here to the head
			// we had is gone.
			depth := int(highest-number) + 1
			out.Reorgs++
			if depth > out.MaxDepth {
				out.MaxDepth = depth
			}
			seen[number] = hash
		}
	}
	return finishObservation(out, firstAt, lastAt, highest), nil
}

func finishObservation(out ReorgObservation, firstAt, lastAt time.Time, highest uint64) ReorgObservation {
	if out.Blocks > 1 && !firstAt.IsZero() && lastAt.After(firstAt) {
		out.BlockInterval = lastAt.Sub(firstAt) / time.Duration(out.Blocks-1)
	}
	out.MaxDepthTime = time.Duration(out.MaxDepth) * out.BlockInterval
	return out
}

func headBlock(ctx context.Context, client *http.Client, endpoint string) (uint64, string, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: 1, Method: "eth_getBlockByNumber",
		Params: []any{"latest", false},
	})
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	var parsed struct {
		Result *struct {
			Number string `json:"number"`
			Hash   string `json:"hash"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return 0, "", err
	}
	if parsed.Result == nil {
		return 0, "", fmt.Errorf("chainprobe: no block in the reply")
	}
	var number uint64
	if _, err := fmt.Sscanf(strings.TrimPrefix(parsed.Result.Number, "0x"), "%x", &number); err != nil {
		return 0, "", err
	}
	return number, parsed.Result.Hash, nil
}

// EndpointHealth is one RPC endpoint's behaviour under sampling.
type EndpointHealth struct {
	Endpoint string
	Attempts int
	Failures int
	// WorstLatency is the slowest successful reply. The budget wants a worst
	// case, so a mean would understate it by design.
	WorstLatency time.Duration
}

// FailoverObservation is what a set of endpoints did together.
type FailoverObservation struct {
	Endpoints []EndpointHealth
	// WorstFailover is the longest time taken to get an answer from SOMEBODY,
	// which is what the rpc-failure term actually budgets for.
	WorstFailover time.Duration
	// AllFailed counts rounds where no endpoint answered. Any at all means the
	// rpc-failure term cannot be validated: there is no bound on a wait that
	// nobody ends.
	AllFailed int
}

// ObserveFailover samples every endpoint in order and times how long it takes
// to get an answer from any of them.
//
// The order matters and is the deployment's own: this measures the failover
// path as configured, not an idealised one. An operator running this against a
// single endpoint will find AllFailed climbing the moment that endpoint blinks,
// which is the correct and useful result — the budget's rpc term explicitly
// assumes more than one.
func ObserveFailover(ctx context.Context, endpoints []string, rounds int, gap time.Duration) FailoverObservation {
	out := FailoverObservation{}
	health := make([]EndpointHealth, len(endpoints))
	for i, e := range endpoints {
		health[i].Endpoint = e
	}
	client := &http.Client{Timeout: 15 * time.Second}

	for round := 0; round < rounds; round++ {
		if round > 0 && gap > 0 {
			select {
			case <-ctx.Done():
				out.Endpoints = health
				return out
			case <-time.After(gap):
			}
		}
		started := time.Now()
		answered := false
		for i, endpoint := range endpoints {
			health[i].Attempts++
			at := time.Now()
			if _, _, err := headBlock(ctx, client, endpoint); err != nil {
				health[i].Failures++
				continue
			}
			if latency := time.Since(at); latency > health[i].WorstLatency {
				health[i].WorstLatency = latency
			}
			answered = true
			break // failover stops at the first endpoint that answers
		}
		if !answered {
			out.AllFailed++
			continue
		}
		if took := time.Since(started); took > out.WorstFailover {
			out.WorstFailover = took
		}
	}
	out.Endpoints = health
	return out
}

// AsEvidence turns a reorg observation into a validation record.
//
// Refuses when nothing was observed. "We watched for an hour and saw no
// reorganisation" bounds nothing — the budget term is a worst case, and the
// worst case of an empty sample is unknown, not zero. This is the single
// easiest place to accidentally validate a term with an absence of data.
func (o ReorgObservation) AsEvidence(chainID int64, takenAt int64) (Evidence, error) {
	if o.Reorgs == 0 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: %d blocks with no reorganisation observed; "+
				"an absence of events does not bound the depth of one", o.Blocks)
	}
	return Evidence{
		Term: "reorg depth", Measured: o.MaxDepthTime, Samples: o.Blocks,
		ChainID: chainID, TakenAt: takenAt,
		Method: fmt.Sprintf("head-tracking over %d blocks; %d reorgs, deepest %d blocks at %s spacing",
			o.Blocks, o.Reorgs, o.MaxDepth, o.BlockInterval),
	}, nil
}

// InclusionSample is one broadcast-to-confirmation observation.
//
// BlocksWaited is carried alongside Delay because the two fail differently:
// Delay is measured against the including block's timestamp and so depends on
// the local clock being roughly right, while BlocksWaited is read entirely off
// the chain. When they disagree, the block count is the one to believe.
type InclusionSample struct {
	TxHash       string
	Delay        time.Duration
	BlocksWaited uint64
	// Confirmed is false for a transaction that was broadcast and then gave up
	// waiting. See InclusionObservation.AsEvidence for why this matters.
	Confirmed bool
	// BaseFeeGwei is what the fee market looked like at broadcast, recorded so
	// a later reader can see which regime the number came from.
	BaseFeeGwei float64
}

// InclusionObservation is a run of inclusion samples against a real chain.
type InclusionObservation struct {
	Samples []InclusionSample
	// Endpoint is the provider the transactions were broadcast through, for
	// provenance. Not a security input — inclusion is a property of the chain,
	// and a lying endpoint would show up as a transaction that never confirms.
	Endpoint string
	// Account is the PUBLIC address the measurements were sent from.
	Account string
}

// AsEvidence turns an inclusion run into a validation record.
//
// Refuses when any sample was abandoned unconfirmed. This is the same mistake
// ReorgObservation.AsEvidence guards against, wearing different clothes: taking
// the maximum over the transactions that DID confirm silently discards the ones
// that did not, and those are precisely the observations the worst case is made
// of. A run with one abandoned transaction has an unknown worst case, not a
// worst case equal to its slowest success.
func (o InclusionObservation) AsEvidence(chainID int64, takenAt int64) (Evidence, error) {
	if len(o.Samples) == 0 {
		return Evidence{}, errors.New("chainprobe: no inclusion samples")
	}
	var worst time.Duration
	var worstBlocks, abandoned uint64
	minFee, maxFee := math.Inf(1), math.Inf(-1)
	for _, s := range o.Samples {
		if !s.Confirmed {
			abandoned++
			continue
		}
		if s.Delay > worst {
			worst = s.Delay
		}
		if s.BlocksWaited > worstBlocks {
			worstBlocks = s.BlocksWaited
		}
		minFee = math.Min(minFee, s.BaseFeeGwei)
		maxFee = math.Max(maxFee, s.BaseFeeGwei)
	}
	if abandoned > 0 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: %d of %d transactions were abandoned unconfirmed; "+
				"the worst case of a run with an unconfirmed transaction is unknown, "+
				"not the slowest one that happened to land", abandoned, len(o.Samples))
	}
	return Evidence{
		Term: "inclusion", Measured: worst, Samples: len(o.Samples),
		ChainID: chainID, TakenAt: takenAt,
		Method: fmt.Sprintf(
			"%d EIP-1559 self-transfers from %s, 21000 gas, value 0, sequential nonces; "+
				"broadcast to first containing block; worst %s (%d blocks); "+
				"base fee %.3f–%.3f gwei at broadcast, priority fee 0.1 gwei",
			len(o.Samples), o.Account, worst, worstBlocks, minFee, maxFee),
	}, nil
}

// RepricingSample is one full recovery cycle: a transaction that could not be
// mined, replaced at the same nonce by one that could.
type RepricingSample struct {
	OriginalHash, ReplacementHash string
	// Recovery is original submission to replacement inclusion, from BLOCK
	// timestamps. The local clock is not in this number.
	Recovery time.Duration
	// OriginalUnmined records that the original never obtained a receipt. A
	// sample where it did is not a repricing sample at all — nothing was
	// repriced — which is what the guard below turns on.
	OriginalUnmined bool
	// ReplacementSucceeded is the replacement's receipt status, not merely its
	// presence. A reverted replacement is a failed recovery.
	ReplacementSucceeded bool
	BaseFeeGwei          float64
}

// RepricingObservation is a campaign of recovery cycles against a real chain.
type RepricingObservation struct {
	Samples []RepricingSample
	// Discarded counts samples that did not satisfy the validity rules, by
	// reason. RECORDED, not dropped: a campaign that retries until it has
	// enough survivors is selecting for a favourable answer, and the only
	// defence is that the selection is visible.
	Discarded map[string]int
	Account   string
	// Conditions describes the fee regime this was measured in. Required —
	// see AsEvidence.
	Conditions string
}

// AsEvidence turns a repricing campaign into a validation record.
//
// Two refusals, for two different ways this term gets validated by accident.
//
// FIRST, a sample in which nothing was repriced. If the original was mined, the
// replacement path never ran, and the cycle "completed" quickly for the one
// reason that makes it meaningless. Recording that as a fast sample pulls the
// distribution toward zero using observations where the mechanism under test
// did not execute. Same shape as the abandoned-transaction guard on inclusion.
//
// SECOND, a campaign with no stated conditions. This measurement is only
// meaningful relative to the fee market it ran in, and a number carried without
// that context WILL eventually be read as a general claim about Ethereum. The
// conditions travel inside Method so they cannot be separated from the figure.
func (o RepricingObservation) AsEvidence(chainID int64, takenAt int64) (Evidence, error) {
	if len(o.Samples) == 0 {
		return Evidence{}, errors.New("chainprobe: no repricing samples")
	}
	if strings.TrimSpace(o.Conditions) == "" {
		return Evidence{}, errors.New(
			"chainprobe: a repricing campaign must state the fee conditions it ran in; " +
				"a recovery time without them reads as a claim about all conditions")
	}
	var worst time.Duration
	minFee, maxFee := math.Inf(1), math.Inf(-1)
	for i, s := range o.Samples {
		if !s.OriginalUnmined {
			return Evidence{}, fmt.Errorf(
				"chainprobe: sample %d had its original mined, so nothing was repriced; "+
					"a cycle that skipped the replacement path is not a fast sample", i+1)
		}
		if !s.ReplacementSucceeded {
			return Evidence{}, fmt.Errorf(
				"chainprobe: sample %d's replacement did not succeed; "+
					"a failed recovery is not a recovery", i+1)
		}
		if s.Recovery > worst {
			worst = s.Recovery
		}
		minFee = math.Min(minFee, s.BaseFeeGwei)
		maxFee = math.Max(maxFee, s.BaseFeeGwei)
	}
	var discards int
	for _, n := range o.Discarded {
		discards += n
	}
	return Evidence{
		Term: "repricing", Measured: worst, Samples: len(o.Samples),
		ChainID: chainID, TakenAt: takenAt,
		Method: fmt.Sprintf(
			"%d full recovery cycles from %s: an EIP-1559 transaction with maxFeePerGas "+
				"below the base fee (arithmetically unmineable), replaced at the same nonce "+
				"one block later at a fee priced to confirm; recovery measured from block "+
				"timestamps, original submission to replacement inclusion; worst %s; "+
				"%d discarded; base fee %.3f–%.3f gwei. "+
				"LIMITATION: %s. This does NOT establish replacement behaviour during "+
				"sustained fee-market congestion.",
			len(o.Samples), o.Account, worst, discards, minFee, maxFee, o.Conditions),
	}, nil
}

// providerOf reduces an endpoint URL to the operator it most likely belongs to.
//
// The last two labels of the host: eth-mainnet.g.alchemy.com and
// eth-sepolia.g.alchemy.com both reduce to alchemy.com, which is the point —
// two URLs at one provider fail together, so listing both is not failover.
//
// A HEURISTIC, and it says so where it matters. It cannot see that two
// different companies resell the same upstream, or share a datacentre, or use
// the same DNS. It catches the common mistake and no more, which is why
// AsEvidence asks for an explicit attestation as well.
func providerOf(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return endpoint
	}
	host := strings.ToLower(u.Hostname())
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// IndependentEndpoints reports whether a list looks like genuine failover.
//
// Returns the duplicated provider when it does not.
func IndependentEndpoints(endpoints []string) (bool, string) {
	seen := map[string]bool{}
	for _, e := range endpoints {
		p := providerOf(e)
		if seen[p] {
			return false, p
		}
		seen[p] = true
	}
	return true, ""
}

// AsEvidence turns a failover observation into a validation record.
//
// `attested` is the operator stating that these endpoints are genuinely
// independent — different providers, not two URLs at one. It is required
// because no probe can establish it: two hostnames can resolve into the same
// datacentre, and the measurement would look perfect right up until they failed
// together. The host check below catches the obvious case; the attestation
// covers the one that matters.
func (o FailoverObservation) AsEvidence(chainID int64, takenAt int64, attested string) (Evidence, error) {
	if len(o.Endpoints) < 2 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: %d endpoint(s); the rpc-failure term assumes failover is possible",
			len(o.Endpoints))
	}
	urls := make([]string, 0, len(o.Endpoints))
	for _, e := range o.Endpoints {
		urls = append(urls, e.Endpoint)
	}
	if ok, provider := IndependentEndpoints(urls); !ok {
		return Evidence{}, fmt.Errorf(
			"chainprobe: two endpoints share the provider %q; they fail together, "+
				"so this is not failover evidence", provider)
	}
	if strings.TrimSpace(attested) == "" {
		return Evidence{}, fmt.Errorf(
			"chainprobe: no attestation that these endpoints are independent; " +
				"a probe cannot establish that two providers do not share an upstream")
	}
	if o.AllFailed > 0 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: %d round(s) where no endpoint answered; that is an unbounded wait, not a measured one",
			o.AllFailed)
	}
	// THE FALLBACK MUST ACTUALLY HAVE BEEN EXERCISED.
	//
	// ObserveFailover stops at the first endpoint that answers, so a healthy
	// primary means the secondary is never tried — and the result measures "the
	// primary worked", not failover. Filing that as rpc-failure evidence would
	// validate a term about recovery using a run in which nothing recovered.
	//
	// Found by a real measurement: 60/60 rounds answered by the primary, zero
	// attempts against the secondary, and this function accepted it.
	// AT LEAST ONE fallback must have carried rounds, and the primary must have
	// failed at least once. Requiring EVERY endpoint to be tried would be wrong
	// — a working secondary means the tertiary is legitimately never needed —
	// so what is required is that failover HAPPENED, not that it exhausted the
	// list.
	fallbackUsed := false
	for i, e := range o.Endpoints {
		if i > 0 && e.Attempts > 0 {
			fallbackUsed = true
			break
		}
	}
	if !fallbackUsed || o.Endpoints[0].Failures == 0 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: the primary answered every round (%d attempts, %d failures) "+
				"and no fallback carried any — this measures a healthy primary, not "+
				"failover. Induce a primary failure to measure the recovery path",
			o.Endpoints[0].Attempts, o.Endpoints[0].Failures)
	}
	attempts := 0
	for _, e := range o.Endpoints {
		attempts += e.Attempts
	}
	return Evidence{
		Term: "rpc failure", Measured: o.WorstFailover, Samples: attempts,
		ChainID: chainID, TakenAt: takenAt,
		Method: fmt.Sprintf("failover sampling across %d endpoints; independence attested: %s",
			len(o.Endpoints), attested),
	}, nil
}
