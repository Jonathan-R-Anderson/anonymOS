package main

// The rpc-failure measurement — roadmap P12.
//
// WHAT THE TERM ACTUALLY BUDGETS
// ------------------------------
// "time lost to an endpoint that is down or lying, before a fallback succeeds."
// Not "are my endpoints up". The number that matters is how long a caller waits
// when the first one does not answer.
//
// SO THE PRIMARY HAS TO FAIL
// --------------------------
// AsEvidence refuses a run in which the primary answered every round, and says
// why: that measures a healthy primary, not failover. Its comment records a
// real 60/60 run that was nearly filed as recovery evidence. The instruction it
// gives is to induce a primary failure, and this does exactly that — the first
// endpoint is an unroutable address from TEST-NET-1 (RFC 5737), reserved for
// documentation and guaranteed not to route anywhere.
//
// WHY UNROUTABLE RATHER THAN A CLOSED PORT
// ----------------------------------------
// A closed port refuses instantly; an unroutable address hangs until the
// client's timeout. Both are real failure modes, but they measure opposite
// ends: a refused connection would record a recovery far FASTER than reality
// and under-budget the term. The budget is a worst case, so the failure induced
// here is the slow one.
//
// This is stated in the attestation and printed in the report, because a reader
// must be able to tell an induced failure from an observed one.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

const mainnet = 1

// deadPrimary is RFC 5737 TEST-NET-1: reserved for documentation, guaranteed
// unroutable. It is the induced failure, and it is deliberately obvious.
const deadPrimary = "http://192.0.2.1:8545"

func main() {
	rounds := flag.Int("rounds", 30, "measurement rounds")
	gap := flag.Duration("gap", 0, "pause between rounds")
	out := flag.String("out", "", "write the observation as a fixture for p12-evidence")
	flag.Parse()

	// Genuinely distinct registrable domains. providerOf() takes the last two
	// labels, so these are four different providers by the repository's own
	// rule, not merely four different URLs.
	endpoints := []string{
		deadPrimary,
		"https://ethereum-rpc.publicnode.com",
		"https://eth.drpc.org",
		"https://eth1.lava.build",
	}
	if ok, dup := channel.IndependentEndpoints(endpoints); !ok {
		fmt.Fprintf(os.Stderr, "endpoints share the provider %q\n", dup)
		os.Exit(1)
	}

	attested := "The selected RPC providers are intended to be operationally " +
		"independent and are not known to share a common upstream provider. " +
		"The primary is an unroutable RFC 5737 address, used deliberately to " +
		"induce the failure this term measures; the fallbacks are live public " +
		"mainnet providers on distinct registrable domains."

	fmt.Println("== endpoints, in failover order")
	for i, e := range endpoints {
		role := "fallback"
		if i == 0 {
			role = "PRIMARY (induced failure)"
		}
		fmt.Printf("  %-42s %s\n", e, role)
	}
	fmt.Printf("\nrunning %d rounds...\n", *rounds)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	start := time.Now()
	obs := channel.ObserveFailover(ctx, endpoints, *rounds, *gap)

	fmt.Printf("\n== observed in %s\n", time.Since(start).Round(time.Second))
	for _, e := range obs.Endpoints {
		fmt.Printf("  %-42s attempts=%-4d failures=%d\n", e.Endpoint, e.Attempts, e.Failures)
	}
	fmt.Printf("  worst failover   %v\n", obs.WorstFailover)
	fmt.Printf("  rounds nobody answered  %d\n", obs.AllFailed)

	ev, err := obs.AsEvidence(mainnet, time.Now().Unix(), attested)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nREFUSED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n== evidence\n  measured %v (budget %v)\n  samples  %d\n  method   %s\n",
		ev.Measured, channel.MainnetChallengeBudget().RPCFailure, ev.Samples,
		strings.TrimSpace(ev.Method))

	if *out == "" {
		fmt.Println("\nREPORT ONLY — no fixture written. Pass -out to record the run.")
		return
	}
	// Written as a fixture rather than filed here, because ValidatedBudget is
	// in-memory: one process has to assemble every term to ask the gate a
	// question. p12-evidence is that process.
	fixture := map[string]any{
		"chain_id": mainnet, "rounds": *rounds,
		"attested":       attested,
		"worst_failover": obs.WorstFailover.String(),
		"all_failed":     obs.AllFailed,
		"endpoints":      endpointRows(obs),
	}
	blob, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("\nwrote %s\n", *out)
}

// endpointRows records what each endpoint did, in order. The ORDER is part of
// the evidence: failover is a property of the list as configured.
func endpointRows(o channel.FailoverObservation) []map[string]any {
	rows := make([]map[string]any, 0, len(o.Endpoints))
	for _, e := range o.Endpoints {
		rows = append(rows, map[string]any{
			"endpoint": e.Endpoint, "attempts": e.Attempts, "failures": e.Failures,
		})
	}
	return rows
}
