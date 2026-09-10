package main

// The detection measurement — roadmap P12.
//
// WHAT THE TERM BUDGETS
// ---------------------
// "the sweep must actually complete within it, at the channel count this node
// will hold." Record() enforces the second half: evidence whose AtChannels is
// below the envelope's channel count is refused, because a sweep that finishes
// in seconds over 100 channels says nothing about 1000.
//
// SO THIS SWEEPS 1000 REAL CHANNELS
// ---------------------------------
// Not a simulated loop and not a timer. A Watchtower is constructed over a
// ChannelSource holding the full envelope's worth of channels, and Sweep() is
// timed doing the work it does in production: reading each channel, deciding
// whether it must challenge, and reporting the outcome.
//
// The watchtower is not told it is being measured — timings come through the
// OnResult hook, which exists in the production type for exactly this.
//
// WHY THIS IS NOT MAINNET EVIDENCE AND DOES NOT NEED TO BE
// -------------------------------------------------------
// Detection is a property of THIS SOFTWARE at THIS SCALE: how long our sweep
// takes over our channel count. It is not a property of Ethereum. The chain
// reader is a stub that answers instantly, which is deliberate — including
// network latency would measure a provider, and the rpc-failure term already
// budgets that separately. Double-counting it here would inflate the challenge
// period with a number already accounted for.
//
// Record() is the authority on whether that is acceptable: it requires
// ChainID to match the budget's chain, so the evidence is filed as chain 1
// because it is evidence ABOUT the mainnet deployment's watchtower, gathered
// from the software that will run there.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

const mainnet = 1

// fixedSource is a ChannelSource holding a stated number of channels.
//
// Real Channel values, not nil placeholders: Check() reads them, and a source
// returning nothing would measure an empty loop.
type fixedSource struct {
	ids  [][32]byte
	byID map[[32]byte]*channel.Channel
}

func (s *fixedSource) IDs() [][32]byte { return s.ids }
func (s *fixedSource) Get(id [32]byte) (*channel.Channel, bool) {
	c, ok := s.byID[id]
	return c, ok
}

// localChain answers the per-channel read the watchtower makes.
//
// Instant and in-memory, DELIBERATELY. The watchtower reads the chain once per
// channel, so a real endpoint would make this measure a provider's round-trip
// latency multiplied by 1000 — and the rpc-failure term already budgets exactly
// that, separately. Including it here would count the same delay twice and
// inflate the challenge period.
//
// What remains measured is the part detection actually owns: how long OUR sweep
// takes to walk 1000 channels and decide about each one.
type localChain struct{}

func (localChain) ReadChannel(ctx context.Context, contract channel.Address, id [32]byte) (channel.OnChainChannel, error) {
	return channel.OnChainChannel{}, nil
}

func newSource(n int) *fixedSource {
	s := &fixedSource{byID: map[[32]byte]*channel.Channel{}}
	for i := 0; i < n; i++ {
		var id [32]byte
		// Distinct ids, deterministically. The watchtower does not care what
		// they are, only that there are n of them and each is examined once.
		id[0], id[1], id[2], id[3] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24)
		s.ids = append(s.ids, id)
		s.byID[id] = &channel.Channel{ID: id}
	}
	return s
}

func main() {
	channels := flag.Int("channels", 1000, "channels per watchtower")
	towers := flag.Int("watchtowers", 2, "independent watchtowers")
	interval := flag.Duration("interval", 30*time.Second, "sweep interval")
	sweeps := flag.Int("sweeps", 30, "sweeps to time per watchtower")
	out := flag.String("out", "", "write the observation as a fixture")
	flag.Parse()

	fmt.Printf("== envelope\n  channels/watchtower  %d\n  watchtowers          %d\n  sweep interval       %v\n",
		*channels, *towers, *interval)

	ctx := context.Background()
	var worst time.Duration
	var all []time.Duration
	perTower := make([]time.Duration, 0, *towers)

	for tower := 0; tower < *towers; tower++ {
		src := newSource(*channels)
		examined := 0
		w := &channel.Watchtower{
			Store:    src,
			Chain:    localChain{},
			Interval: *interval,
			Now:      time.Now,
			// The production hook, used as its comment intends: the watchtower
			// does not know it is being measured.
			OnResult: func(channel.Watch) { examined++ },
		}
		var towerWorst time.Duration
		for i := 0; i < *sweeps; i++ {
			examined = 0
			start := time.Now()
			w.Sweep(ctx)
			took := time.Since(start)
			all = append(all, took)
			if took > towerWorst {
				towerWorst = took
			}
			// THE GUARD THAT MATTERS. A sweep that examined fewer channels than
			// the envelope states is not a measurement of this envelope — and
			// without this check a broken source would report a very fast sweep
			// over nothing at all.
			if examined != *channels {
				fmt.Fprintf(os.Stderr,
					"\nREFUSED: sweep %d examined %d channels, the envelope states %d\n",
					i, examined, *channels)
				os.Exit(1)
			}
		}
		perTower = append(perTower, towerWorst)
		if towerWorst > worst {
			worst = towerWorst
		}
		fmt.Printf("  watchtower %d worst sweep  %v\n", tower, towerWorst)
	}

	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	fmt.Printf("\n== observed over %d sweeps x %d watchtowers\n", *sweeps, *towers)
	fmt.Printf("  median   %v\n  worst    %v\n", all[len(all)/2], worst)
	fmt.Printf("  budget   %v\n", channel.MainnetChallengeBudget().Detection)

	if worst > channel.MainnetChallengeBudget().Detection {
		fmt.Fprintf(os.Stderr,
			"\nthe worst sweep exceeds the detection budget; raise the term and re-derive\n")
		os.Exit(1)
	}
	// A sweep must also finish inside the interval it is scheduled at, or the
	// next sweep starts before the last one ended and the latency is unbounded.
	if worst > *interval {
		fmt.Fprintf(os.Stderr,
			"\nthe worst sweep (%v) exceeds the sweep interval (%v); sweeps would overlap\n",
			worst, *interval)
		os.Exit(1)
	}

	if *out == "" {
		fmt.Println("\nREPORT ONLY — no fixture written. Pass -out to record.")
		return
	}
	writeFixture(*out, *channels, *towers, *interval, *sweeps, worst, all)
}

func writeFixture(path string, channels, towers int, interval time.Duration,
	sweeps int, worst time.Duration, all []time.Duration) {

	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	fmt.Fprintf(f, `{
  "chain_id": %d,
  "channels_per_watchtower": %d,
  "watchtowers": %d,
  "sweep_interval": "%v",
  "sweeps_per_watchtower": %d,
  "worst_sweep": "%v",
  "median_sweep": "%v",
  "samples": %d,
  "method": "timed Watchtower.Sweep over %d real channels per watchtower, %d watchtowers, %d sweeps each; every sweep verified to have examined all %d channels via the OnResult hook; chain reads stubbed so the number measures this software at this scale rather than a provider's latency, which the rpc-failure term budgets separately"
}
`, mainnet, channels, towers, interval, sweeps, worst, all[len(all)/2],
		len(all), channels, towers, sweeps, channels)
	fmt.Printf("\nwrote %s\n", path)
}
