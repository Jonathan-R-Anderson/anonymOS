// Command pof-settle computes one epoch's settlement.
//
// Read-only against the chain and the relay: it fetches, computes, and prints.
// Posting the roots on-chain is a separate, wallet-signed step in the admin
// console, so running this can never move money — which means anyone can run it
// to check the aggregator's arithmetic, and that is the whole basis of the
// optimistic model.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/syndichan/maniwani/proof-of-facilitation/aggregator"
)

func main() {
	site := flag.String("site", "https://syndichan.org", "website base URL")
	rpc := flag.String("rpc", "https://mainnet.era.ethereum.io", "Ethereum RPC")
	epochManager := flag.String("epoch-manager", "0xbEE083af6b96AAa29285a9753DB56483Fcf3269f", "EpochManager address")
	nodeRegistry := flag.String("node-registry", "0x34B7B3Db8A7600cc58938c5391c7297E5B060124", "NodeRegistry address")
	stakeVault := flag.String("stake-vault", "0x401b1dBA06ca2B3A4B17540AD297A1B2564b61f2", "StakeVault address")
	epoch := flag.Uint64("epoch", 0, "epoch to settle")
	budget := flag.String("budget", "1000000000000000000000", "epoch budget in wei")
	flag.Parse()

	em, err := aggregator.ParseAddress(*epochManager)
	exitOn(err)
	nr, err := aggregator.ParseAddress(*nodeRegistry)
	exitOn(err)
	sv, err := aggregator.ParseAddress(*stakeVault)
	exitOn(err)

	budgetWei, ok := new(big.Int).SetString(*budget, 10)
	if !ok {
		exitOn(fmt.Errorf("budget %q is not a decimal number", *budget))
	}

	// Split evenly across the services that exist today. The real split comes
	// from ServicePolicyRegistry once policy is on-chain; until then this is
	// stated here rather than hidden, so a challenger knows what was applied.
	var split [7]uint16
	split[aggregator.ServiceStorage] = 10000

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := aggregator.SettleEpochFromRelay(ctx, aggregator.SettlementInputs{
		SiteBaseURL: *site,
		Chain:       aggregator.NewChainClient(*rpc, em, nr, sv),
		Epoch:       *epoch,
		Policy: aggregator.Policy{
			EpochBudget: budgetWei, SplitBps: split, PerNodeCapBps: 2000,
		},
	})
	exitOn(err)

	encoded, err := json.MarshalIndent(result, "", "  ")
	exitOn(err)
	fmt.Println(string(encoded))

	if !result.WithinBudget {
		// Refuse to look successful: an over-budget epoch is currency inflation
		// and must not be submitted.
		fmt.Fprintln(os.Stderr, "REFUSING: total rewards exceed the epoch budget")
		os.Exit(2)
	}
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pof-settle:", err)
		os.Exit(1)
	}
}
