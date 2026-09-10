package aggregator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Epoch randomness before the epoch exists on-chain.
//
// EpochManager.randomnessOf(N) is written by submitEpoch(N), which commits work
// already performed. But witness selection for epoch N has to be decidable
// DURING epoch N, or nobody knows who was entitled to audit whom until it is
// too late to have done it. Reading it from the chain is a chicken and egg:
// nodes ask for a value that by construction does not exist yet, get nothing,
// and do no work.
//
// So a live epoch's randomness is derived from the genesis seed:
//
//	randomness(N) = keccak256(seed || uint64_be(N))
//
// This MUST match backend/services/pof_randomness.py exactly. Two
// implementations in two languages that disagree would give the node one
// witness set and settlement another, and every honest receipt would be
// rejected for attestations from "witnesses the protocol did not select" — the
// worst possible failure, because it looks like fraud. The shared vectors are
// pinned in randomness_test.go and tests/test_pof_randomness.py.
func DeriveEpochRandomness(seed [32]byte, epoch uint64) [32]byte {
	return keccak(seed[:], be64(epoch))
}

type genesisSeedResponse struct {
	Armed bool   `json:"armed"`
	Seed  string `json:"seed"`
	Epoch uint64 `json:"epoch"`
	Error string `json:"error"`
}

// FetchGenesisSeed reads the published genesis seed.
//
// The seed is public by design — witness selection has to be re-derivable by
// anyone auditing a receipt — so reading it over HTTP concedes nothing. What it
// does concede is that a lying server could hand back a different seed; a
// caller that cares compares it against EpochManager.randomnessOf(genesisEpoch)
// once genesis is settled.
func FetchGenesisSeed(ctx context.Context, siteBaseURL string) ([32]byte, uint64, error) {
	var seed [32]byte
	url := strings.TrimSuffix(siteBaseURL, "/") + "/api/v1/pof/genesis-seed"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return seed, 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return seed, 0, fmt.Errorf("aggregator: genesis seed unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out genesisSeedResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 || !out.Armed {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return seed, 0, fmt.Errorf("aggregator: no genesis seed: %s", msg)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(out.Seed, "0x"))
	if err != nil || len(raw) != 32 {
		return seed, 0, fmt.Errorf("aggregator: genesis seed %q is not 32 bytes", out.Seed)
	}
	copy(seed[:], raw)
	return seed, out.Epoch, nil
}

// EpochRandomness returns the randomness to settle an epoch with: the on-chain
// value once it exists, otherwise the derived one.
//
// Preferring the chain is not redundant. Once an epoch is submitted, what is on
// it is what disputes are judged against, and a derived value that disagreed
// would be the aggregator quietly overruling the record.
func EpochRandomness(ctx context.Context, chain *ChainClient, siteBaseURL string,
	epoch uint64) ([32]byte, string, error) {
	var zero [32]byte
	if chain != nil {
		onChain, err := chain.RandomnessOf(ctx, epoch)
		if err == nil && onChain != zero {
			return onChain, "on-chain", nil
		}
	}
	seed, genesisEpoch, err := FetchGenesisSeed(ctx, siteBaseURL)
	if err != nil {
		return zero, "", err
	}
	if epoch < genesisEpoch {
		return zero, "", fmt.Errorf(
			"aggregator: epoch %d is before genesis (epoch %d)", epoch, genesisEpoch)
	}
	if epoch == genesisEpoch {
		// The genesis epoch's randomness IS the seed: that is what was
		// submitted on-chain, so the derivation must agree with the record
		// rather than with itself.
		return seed, "the genesis seed itself", nil
	}
	return DeriveEpochRandomness(seed, epoch), "derived from the genesis seed", nil
}
