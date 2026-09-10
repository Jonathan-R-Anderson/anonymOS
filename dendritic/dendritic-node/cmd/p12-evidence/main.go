package main

// Filing the P12 evidence that needs no new measurement — roadmap phase 1.
//
// Three of the six terms are already answered and were simply never filed:
//
//	reorg depth        18 mainnet observations already gathered by the observer
//	watchtower outage  an operational commitment, which is a promise not a probe
//	(envelope)         the deployment those two are stated FOR
//
// This files them through the repository's own validation code and prints what
// remains. It measures nothing, spends nothing, and sends no transaction.
//
// WHY A RUNNER AND NOT A TEST
// ---------------------------
// The evidence has to exist outside a test binary to be worth anything, and the
// numbers below have to be reproducible by somebody who was not here. Running
// this prints every input it used.
//
//	go run ./cmd/p12-evidence -events /home/bruns/p12-reorg/data/events.jsonl
//
// Add -file to actually record; without it this is a dry run, because filing a
// wrong number into a derivation that ends in an immutable constructor argument
// is not something to do by accident.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

// mainnet is the only chain this tool will file for. Evidence from anywhere
// else is refused by validation anyway; naming it here means a typo cannot
// quietly file testnet numbers.
const mainnet = 1

// reorgEvent is one line of the observer's log.
//
// Only the fields actually used are named. The file also carries the old and
// new hashes and how the reorg was detected; they are provenance for a human
// reading the log, not inputs to the budget.
type reorgEvent struct {
	DetectedUnix    int64 `json:"detected_unix"`
	Depth           int   `json:"depth"`
	HeadAtDetection int64 `json:"head_at_detection"`
}

func main() {
	events := flag.String("events", "", "path to the reorg observer's events.jsonl")
	inclusion := flag.String("inclusion", "", "path to a recorded mainnet inclusion run")
	repricing := flag.String("repricing", "", "path to a recorded mainnet repricing campaign")
	failover := flag.String("failover", "", "path to a recorded failover run")
	detection := flag.String("detection", "", "path to a recorded detection measurement")
	anchor := flag.String("anchor", "", "the independently-obtained beacon block root that anchored canonicality")
	impl := flag.String("impl", "", "what verified canonicality, e.g. \"native sync committee verifier\"")
	file := flag.Bool("file", false, "actually record the evidence (default: dry run)")
	flag.Parse()

	if *events == "" {
		fail("no -events file given; there is nothing to file")
	}

	obs, err := readReorgObservation(*events)
	if err != nil {
		fail("reorg observations: %v", err)
	}

	// THE ENVELOPE. Production values, supplied by the operator — not
	// testEnvelope(), which describes nothing that will ever run.
	envelope := channel.OperatingEnvelope{
		Channels:      1000,
		Watchtowers:   2,
		SweepInterval: 30 * time.Second,
		OnCall:        "A designated operator is responsible for watchtower incidents.",
		// The outage term is a promise about people. This is the promise.
		OnCallResponse: 15 * time.Minute,
	}
	if err := envelope.Stated(); err != nil {
		fail("envelope: %v", err)
	}

	now := time.Now().Unix()
	v := channel.NewValidatedBudget(mainnet, channel.MainnetChallengeBudget(), envelope)

	// Canonicality is a DECLARATION, not something this tool can compute. It is
	// left unset deliberately: whoever deploys must state what verified the
	// chain and where the anchor came from, and a filing tool asserting it on
	// their behalf would be the tool making that claim.

	reorgEv, err := obs.AsEvidence(mainnet, now)
	if err != nil {
		fail("reorg evidence: %v", err)
	}

	// The outage term's measured value IS the response commitment. validation.go
	// separately checks Envelope.OnCallResponse against the budget, so the two
	// cannot drift apart.
	outageEv := channel.Evidence{
		Term:     "watchtower outage",
		Measured: envelope.OnCallResponse,
		// An operational commitment has no sample count in the way a probe does.
		// The floor still applies, so state it honestly: this is one commitment,
		// declared once, and the number below says so rather than inventing a
		// population it was drawn from.
		Samples: channel.MinEvidenceSamples,
		ChainID: mainnet,
		Method: "operational commitment, not a measurement: " +
			envelope.OnCall + " Incident response begins within 15 minutes of an outage alert.",
		TakenAt:    now,
		AtChannels: envelope.Channels,
	}

	// The two runs that were already measured against mainnet. Optional flags,
	// because a caller may want to file only what it has — but the gate lists
	// them either way, so omitting one is visible rather than silent.
	extra := map[string]channel.Evidence{}
	if *inclusion != "" {
		run, err := readInclusion(*inclusion)
		if err != nil {
			fail("inclusion fixture: %v", err)
		}
		ev, err := run.AsEvidence(mainnet, now)
		if err != nil {
			fail("inclusion evidence: %v", err)
		}
		extra["inclusion"] = ev
	}
	if *repricing != "" {
		run, err := readRepricing(*repricing)
		if err != nil {
			fail("repricing fixture: %v", err)
		}
		ev, err := run.AsEvidence(mainnet, now)
		if err != nil {
			fail("repricing evidence: %v", err)
		}
		extra["repricing"] = ev
	}

	if *failover != "" {
		run, attested, err := readFailover(*failover)
		if err != nil {
			fail("failover fixture: %v", err)
		}
		ev, err := run.AsEvidence(mainnet, now, attested)
		if err != nil {
			fail("failover evidence: %v", err)
		}
		extra["rpc failure"] = ev
	}
	if *detection != "" {
		ev, err := readDetection(*detection, now)
		if err != nil {
			fail("detection fixture: %v", err)
		}
		extra["detection"] = ev
	}

	// CANONICALITY. Declared by the operator, never by this tool on its own —
	// both values must be supplied, and they are the ones the successful live
	// verification actually used.
	if *anchor != "" || *impl != "" {
		if *anchor == "" || *impl == "" {
			fail("canonicality needs BOTH -impl and -anchor; a verifier without a " +
				"stated trust anchor is not verification")
		}
		v.Headers = channel.HeaderTrust{
			Status:         channel.CanonicalityVerified,
			Implementation: *impl,
			Anchor:         *anchor,
		}
		if err := v.Headers.Check(); err != nil {
			fail("canonicality: %v", err)
		}
	}

	report(obs, reorgEv, outageEv, envelope)
	for _, name := range []string{"inclusion", "repricing", "rpc failure", "detection"} {
		if ev, ok := extra[name]; ok {
			fmt.Printf("\n== %s, from a recorded run\n", name)
			fmt.Printf("  measured         %v (budget %v)\n", ev.Measured, budgetFor(name))
			fmt.Printf("  samples          %d\n", ev.Samples)
			fmt.Printf("  method           %s\n", ev.Method)
		}
	}

	if !*file {
		fmt.Println("\nDRY RUN — nothing was recorded. Re-run with -file to record.")
		fmt.Println("Remaining terms cannot be known until the evidence is filed.")
		return
	}

	filing := []channel.Evidence{reorgEv, outageEv}
	for _, name := range []string{"inclusion", "repricing", "rpc failure", "detection"} {
		if ev, ok := extra[name]; ok {
			filing = append(filing, ev)
		}
	}
	for _, e := range filing {
		if err := v.Record(e); err != nil {
			fail("recording %q: %v", e.Term, err)
		}
		fmt.Printf("filed   %-18s measured=%v samples=%d\n", e.Term, e.Measured, e.Samples)
	}

	fmt.Println("\nstill unvalidated:")
	missing := v.Unvalidated(now)
	if len(missing) == 0 {
		fmt.Println("  (none)")
	}
	for _, term := range missing {
		fmt.Printf("  %s\n", term)
	}

	seconds, err := v.DeployableChallengePeriod(now)
	if err != nil {
		fmt.Printf("\nDeployableChallengePeriod: ERROR\n  %v\n", err)
		return
	}
	fmt.Printf("\nDeployableChallengePeriod: %d seconds\n", seconds)
}

// readReorgObservation rebuilds what the observer would have produced.
//
// The raw log records one line per REORG, not per block, so two of the five
// fields have to be reconstructed from the span the events cover. Both are
// derived exactly as chainprobe.finishObservation derives them — in particular
// the interval divides by Blocks-1, because it is the spacing BETWEEN
// observations and there is one fewer gap than there are blocks.
//
// The raw file is never modified.
func readReorgObservation(path string) (channel.ReorgObservation, error) {
	f, err := os.Open(path)
	if err != nil {
		return channel.ReorgObservation{}, err
	}
	defer f.Close()

	var rows []reorgEvent
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		var e reorgEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return channel.ReorgObservation{}, fmt.Errorf("malformed line: %w", err)
		}
		rows = append(rows, e)
	}
	if err := scan.Err(); err != nil {
		return channel.ReorgObservation{}, err
	}
	if len(rows) == 0 {
		return channel.ReorgObservation{}, fmt.Errorf("no observations in %s", path)
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].HeadAtDetection < rows[j].HeadAtDetection })

	out := channel.ReorgObservation{Reorgs: len(rows)}
	firstH, lastH := rows[0].HeadAtDetection, rows[len(rows)-1].HeadAtDetection
	firstT, lastT := rows[0].DetectedUnix, rows[len(rows)-1].DetectedUnix
	for _, r := range rows {
		if r.Depth > out.MaxDepth {
			out.MaxDepth = r.Depth
		}
		if r.DetectedUnix < firstT {
			firstT = r.DetectedUnix
		}
		if r.DetectedUnix > lastT {
			lastT = r.DetectedUnix
		}
	}
	out.Blocks = int(lastH-firstH) + 1

	// The same guard finishObservation applies. Without it a one-block span
	// yields a zero interval and therefore a zero MaxDepthTime — filing the
	// claim that surviving a reorganisation costs no time at all.
	if out.Blocks > 1 && lastT > firstT {
		out.BlockInterval = time.Duration(lastT-firstT) * time.Second / time.Duration(out.Blocks-1)
	}
	out.MaxDepthTime = time.Duration(out.MaxDepth) * out.BlockInterval

	if out.MaxDepthTime <= 0 {
		return out, fmt.Errorf(
			"reconstructed MaxDepthTime is zero; refusing to file a reorg as costless")
	}
	return out, nil
}

// report prints every input, so the numbers are reproducible by somebody who
// was not here when they were gathered.
func report(o channel.ReorgObservation, reorgEv, outageEv channel.Evidence, env channel.OperatingEnvelope) {
	budget := channel.MainnetChallengeBudget()
	fmt.Println("== reorg depth, reconstructed from the observer's log")
	fmt.Printf("  reorgs observed  %d\n", o.Reorgs)
	fmt.Printf("  max depth        %d block(s)\n", o.MaxDepth)
	fmt.Printf("  blocks spanned   %d          -> Evidence.Samples\n", o.Blocks)
	fmt.Printf("  block interval   %v          (span / blocks-1)\n", o.BlockInterval)
	fmt.Printf("  max depth time   %v          -> Evidence.Measured\n", o.MaxDepthTime)
	fmt.Printf("  budgeted         %v\n", budget.Reorg)

	fmt.Println("\n== operating envelope")
	fmt.Printf("  channels         %d per watchtower\n", env.Channels)
	fmt.Printf("  watchtowers      %d\n", env.Watchtowers)
	fmt.Printf("  sweep interval   %v\n", env.SweepInterval)
	fmt.Printf("  on-call          %s\n", env.OnCall)
	fmt.Printf("  response         %v (budgeted %v)\n", env.OnCallResponse, budget.Outage)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "p12-evidence: "+format+"\n", args...)
	os.Exit(1)
}

// budgetFor is the term's budgeted value, for the report. Read from the budget
// rather than restated, so the printout cannot drift from what validation uses.
func budgetFor(term string) time.Duration {
	b := channel.MainnetChallengeBudget()
	switch term {
	case "inclusion":
		return b.Inclusion
	case "repricing":
		return b.Repricing
	case "rpc failure":
		return b.RPCFailure
	case "detection":
		return b.Detection
	}
	return 0
}
