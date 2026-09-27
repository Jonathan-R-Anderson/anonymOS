// Package params is the single home for every tunable protocol constant.
//
// P0 test T0.2 is the reason this package exists: the cell size, guard count,
// tunnel lifetime and DHT k/alpha/d must appear here and nowhere else, so that
// a parameter change is one edit and a divergent literal elsewhere in the tree
// is a build failure rather than a silent second opinion.
//
// Values come from the roadmap's Constitution section 5. Where a value is not
// yet settled the constant is present with the agreed default and the comment
// says what would change it.
package params

import "time"

// ---------------------------------------------------------------------------
// Naming (Constitution section 1, as amended by the naming addendum)
// ---------------------------------------------------------------------------

// RootSuffix is the one compile-time naming constant in the system. Namespace
// labels are NOT constants: they are read from the root registry at runtime,
// and a client that hardcodes the namespace set is non-conformant, because the
// set changes by vote.
const RootSuffix = "axon"

// AddressNamespace is the permanently reserved namespace label under which
// self-certifying Layer 1 addresses live, e.g. <56 base32>.key.axon. No vote
// can allocate it, which is what stops Layer 3 shadowing Layer 1.
const AddressNamespace = "key"

// ---------------------------------------------------------------------------
// Cells and circuits (sections 8.1, 8.5)
// ---------------------------------------------------------------------------

const (
	// CellSize is the fixed on-link size of every cell, on every link,
	// regardless of how many hops remain. Padding to a constant size is the
	// property; changing this changes the wire format.
	CellSize = 1024

	// CellHeaderSize is circuit id (8) + cmd (1) + flags (1) + len (2) + reserved (4).
	CellHeaderSize = 16

	// AEADTagSize is reserved at EVERY hop position, not only the ones in use,
	// so that the on-wire size does not reveal the hop count.
	AEADTagSize = 16

	// MaxHops bounds the tag reservation and therefore the payload capacity.
	MaxHops = 4

	// DefaultHops is the standard circuit length: guard, middle, terminal.
	DefaultHops = 3

	// MinHops is permitted only for explicitly non-anonymous performance
	// contexts and is never a default.
	MinHops = 2

	// RelayBuildBudget caps RELAY_BUILD cells per circuit (T5.8, PAR-08).
	//
	// THE NUMBER, derived rather than chosen: MaxHops (4) extension requests,
	// plus section 8.4's two permitted redraws, plus two spare = 8. Tor arrived
	// at the same figure for RELAY_EARLY by the same reasoning.
	//
	// It exists because an unbounded extension budget is an unbounded circuit,
	// and because the early/normal distinction has been used as a signalling
	// side channel between a hostile entry and a hostile directory node.
	RelayBuildBudget = 8

	// DropCellThreshold is how many structurally valid but impossible cells a
	// circuit may attract before it is torn down (T5.9, PAR-28).
	//
	// A SENDME for a closed stream, a DATA cell for a stream that never opened,
	// a TRUNCATED for a hop already gone: each is droppable, and a droppable
	// event nobody counts is a signalling channel.
	DropCellThreshold = 10

	// CircuitIDQuarantine is how long a freed circuit id is withheld from reuse
	// (section 8.4's C_DEAD state). Reusing an id immediately would let a late
	// cell from a dead circuit land on a live one.
	CircuitIDQuarantine = 60 * time.Second

	// --- E5.2 throughput floors (item 4.4b) ------------------------------
	//
	// E5.2 asks a 3-hop circuit to "sustain a STATED THROUGHPUT FLOOR for 10
	// minutes". No floor was ever stated, so the soak could only REPORT its
	// rate, never assert one. These two constants state it -- but first they
	// separate two questions the criterion conflates.
	//
	// A DEPLOYMENT throughput SLA is NOT among these and stays open (4.4b):
	// it needs a network, an RTT and a target application, and §5.1 already
	// shows the §8.6 window binds before the cipher at any RTT a 3-hop circuit
	// actually sees, so a crypto-path number is not even the right floor for a
	// deployment. What the IN-PROCESS soak can honestly guard is different and
	// narrower: that the crypto-and-framing path has not REGRESSED. That is
	// what these are, and calling them anything grander would overclaim.
	//
	// Both are TRIPWIRES far below the measured rate (135.0 Mbit/s single-
	// threaded, in-process, on the 2026 dev machine), not targets. They are
	// deliberately loose because a floor that fails on hardware variance
	// teaches people to ignore failures -- the pathology this codebase keeps
	// finding -- so each is sized to survive realistic slowness and trip only
	// on a gross algorithmic regression. IF ONE EVER TRIPS ON HARDWARE THAT IS
	// MERELY SLOW, lower the constant WITH A NOTE saying so; do not delete the
	// assertion.

	// CircuitThroughputSmokeFloorMbps guards EVERY run, including the 2-second
	// default and runs under `-race`.
	//
	// 2 Mbit/s: the measured 135 leaves ~67x of headroom, which survives the
	// race detector's ~10x slowdown AND a heavily loaded CI runner on top of
	// it. Tripping this means the path is catastrophically broken -- a
	// deadlock-adjacent stall or an O(n^2) blow-up -- not that a machine was
	// slow. It is the floor a smoke test can assert without ever flaking.
	CircuitThroughputSmokeFloorMbps = 2.0

	// CircuitThroughputRegressionFloorMbps guards the FULL 10-minute soak
	// (`-soak-minutes=10`), a deliberate performance run that is never done
	// under `-race`.
	//
	// 20 Mbit/s: ~6.75x below the measured 135. It catches an algorithmic
	// regression that made the crypto path more than ~6x slower -- a serious
	// defect worth failing on -- while surviving CI hardware up to ~6x slower
	// than the dev machine. It is asserted only on the full soak because the
	// 10-minute average is stable where a 2-second sample is not.
	CircuitThroughputRegressionFloorMbps = 20.0

	// MaxStreamsPerCircuit caps concurrent streams on one circuit (§8.6), the
	// same for both traffic classes. A per-class cap would make the class
	// inferable from the stream count.
	MaxStreamsPerCircuit = 64

	// MaxCircuitsPerRelay is the global admission cap (P24, PAR-21). It is the
	// bound MaxCircuitsPerLink is not: that one is per link, so an attacker
	// opens more links.
	MaxCircuitsPerRelay = 65536
)

// Circuit lifecycle budgets (section 8.4's state machine). Specified defaults,
// NOT measurements.
const (
	LinkTimeout      = 5 * time.Second
	CreateTimeout    = 10 * time.Second
	ExtendTimeout    = 10 * time.Second
	OpenIdleTimeout  = 60 * time.Second
	ClosingTimeout   = 5 * time.Second
	MaxExtendRedraws = 2
)

// MaxPayload is the usable cell body: everything after the fixed header.
//
// It was CellSize - CellHeaderSize - (AEADTagSize * MaxHops), reserving 64 bytes
// for a per-hop tag stack so that payload capacity could not leak path length.
// PAR-01 found that tag stack to be a cross-hop tagging channel and section 81.1
// withdrew it; P5a replaced it with a wide-block permutation over the whole
// body, which needs no tags and therefore no reservation.
//
// The reservation's PURPOSE survives and is now structural: the body is one
// fixed-size permuted block whatever the path length, so capacity still cannot
// leak it. AEADTagSize and MaxHops are retained -- MaxHops still bounds path
// length, and AEADTagSize is still the end-to-end authenticator's size.
const MaxPayload = CellSize - CellHeaderSize

// ---------------------------------------------------------------------------
// Guards (section 8.5)
// ---------------------------------------------------------------------------
//
// Workstream 1 of the hard-problems programme found these parameters sit at a
// poor point on the exposure curve: at 2 guards on a 45-day rotation a client
// passes through a hostile guard within a year with probability 0.56 against a
// 5% adversary. They are kept here as the current agreed values, and P17 is the
// phase that is expected to change them.

const (
	PrimaryGuards     = 2
	GuardRotation     = 45 * 24 * time.Hour
	GuardListLifetime = 90 * 24 * time.Hour

	// SampledGuardSize bounds how much of the relay population a client will
	// EVER have tried (PAR-05).
	//
	// This is the property Tor's sampled set buys and §8.5 lacked: without a
	// bound, a long-running adversary who can make guards fail walks the client
	// through the population one guard at a time and enumerates it by attrition.
	// The sampled set is persisted, and a client never connects to a guard
	// outside it.
	SampledGuardSize = 20

	// PoolMinReady is the floor below which the pool raises DEGRADED and the
	// session layer stops opening new streams -- concentrating a destination's
	// whole traffic onto one survivor is worse than refusing to grow.
	PoolMinReady = 2

	// TunnelProbeInterval and TunnelProbeMisses drive ACTIVE -> SUSPECT.
	TunnelProbeInterval = 30 * time.Second
	TunnelProbeMisses   = 3

	// TunnelBuildTries and TunnelBuildTimeout bound one slot's attempts.
	TunnelBuildTries   = 5
	TunnelBuildTimeout = 10 * time.Second
	VanguardLayer2Size = 4
	VanguardLayer3Size = 8
)

// ---------------------------------------------------------------------------
// Tunnels and pools (section 9.2)
// ---------------------------------------------------------------------------

const (
	TunnelLifetime = 10 * time.Minute
	// TunnelRebuildAt is the fraction of a tunnel's life at which its
	// replacement is planned. The 180 s it leaves is NOT about build latency --
	// a build is sub-second -- it absorbs FAILURES: under the 1-2-4-8-16 s
	// backoff the window permits five attempts, so a slot is empty at expiry
	// with probability (1-p)^5. Sized for the degraded case, not the good one.
	TunnelRebuildAt     = 0.70
	InboundPoolSize     = 3
	OutboundPoolSize    = 3
	PoolSpares          = 1
	DescriptorLifetime  = 3 * time.Hour
	DescriptorRepublish = 1 * time.Hour
)

// ---------------------------------------------------------------------------
// Epochs and time periods (sections 5.4, 7.2)
// ---------------------------------------------------------------------------

const (
	// EpochLength is the rotation period for the shared random value and
	// therefore for KadID placement.
	EpochLength = 24 * time.Hour

	// PeriodLength is the blinded-descriptor-key rotation period. It is a
	// separate constant from EpochLength on purpose: they rotate different
	// things and there is no requirement that they stay equal.
	PeriodLength = 24 * time.Hour

	// PeriodLengthSeconds is PeriodLength as the u64 that enters the blinding
	// KDF context. Kept explicit because the KDF hashes the number, so a unit
	// mistake here silently changes every blinded key.
	PeriodLengthSeconds = uint64(86400)

	// PeriodOverlap is how long the previous period's descriptor stays valid,
	// so a client with a slightly stale clock still resolves.
	PeriodOverlap = 12 * time.Hour
)

// ---------------------------------------------------------------------------
// DHT (section 7)
// ---------------------------------------------------------------------------

const (
	KademliaK         = 20 // bucket size
	KademliaAlpha     = 3  // lookup concurrency
	KademliaDisjoint  = 3  // disjoint lookup paths, S/Kademlia style
	ReplicationFactor = 8  // r, across distinct /24, /48 and ASN
	IPv4DiversityBits = 24
	IPv6DiversityBits = 48
)

// ---------------------------------------------------------------------------
// Storage (section 10)
// ---------------------------------------------------------------------------
//
// Read from the existing node's config defaults rather than invented: the
// deployed default is 6 data + 3 parity over 1 MiB chunks.

const (
	DataShards   = 6
	ParityShards = 3
	ChunkBytes   = 1 << 20
)

// ---------------------------------------------------------------------------
// Local peer profiling (P12a, PAR-03)
// ---------------------------------------------------------------------------
//
// The STRUCTURE is I2P's, which has run for two decades without a measurement
// authority; the VALUES are ours and are not measurements. R14 forbids the
// authority, so every figure here is a local policy choice, and none of it ever
// leaves the node.

const (
	// ProfileHalfLife is the exponential decay applied to every metric. A relay
	// that was fast yesterday does not coast on it.
	ProfileHalfLife = 1 * time.Hour

	// ProfileMinSamples is the floor below which a peer is UNTIERED and
	// selection falls back to uniform. It is applied twice -- per peer, and
	// across the whole profile store -- because a node that has barely observed
	// anything must not act on the little it has (E12a.3).
	//
	// It is a floor on DECAYED samples, not on raw ones, so N observations never
	// quite reach N: ten observations a second apart weigh 9.99, and a peer
	// needs slightly more than ProfileMinSamples of them to tier. That is the
	// intended reading -- the floor asks "how much do I currently know about
	// this peer", and the answer to that decays like everything else here.
	ProfileMinSamples = 10

	// TierFastFraction and TierHighCapacityFraction are I2P's 10 % / 25 %.
	// They are FRACTIONS, not thresholds, on purpose: an absolute threshold
	// would put the whole network in one tier on a fast day and none of it in
	// that tier on a slow one, and the tier population would then depend on
	// conditions rather than on relative standing.
	TierFastFraction         = 0.10
	TierHighCapacityFraction = 0.25

	// ProfileFailingStreak is how many CONSECUTIVE failures exclude a peer.
	ProfileFailingStreak = 3

	// ProfileRepromoteInterval is how long an excluded peer stays excluded
	// before it is eligible again. Permanent exclusion would let an adversary
	// who can cause three failures remove a peer from this node's view for
	// good, which is a cheaper attack than it should be.
	ProfileRepromoteInterval = 30 * time.Minute
)

// Selection weights by tier. The RATIO is what matters and it is deliberately
// small: 2:1 between the best tier and the ordinary one.
//
// The failure mode being priced is the feedback loop P12a names -- fast peers
// get more traffic, therefore more samples, therefore look faster still. A
// large ratio makes that loop converge on a handful of relays and undoes P3's
// diversity work. A ratio of 2 tilts selection without collapsing it.
const (
	WeightUntiered     = 1.0
	WeightStandard     = 1.0
	WeightHighCapacity = 1.5
	WeightFast         = 2.0
	WeightFailing      = 0.0
)

// ---------------------------------------------------------------------------
// Sybil resistance (P14)
// ---------------------------------------------------------------------------
//
// EVERY CONSTANT IN THIS BLOCK IS PROVISIONAL, and each one says so in its own
// comment with the derivation it does or does not have. That is E14.3, and the
// reason is P14's honest centre: nobody can state what bond makes 20 % of
// relays infeasible, because the answer depends on a token price, an
// adversary's budget and a deployed population, and §18.22 records that none of
// those exists. A number shipped without that caveat implies a claim the number
// does not support.

const (
	// BondFloorRelay is the minimum bonded stake, in whole tokens, for a node to
	// be admitted as a RELAY.
	//
	// PROVISIONAL. Derivation: none available. It is a placeholder chosen so the
	// mechanism has something to compare against, and §25(c)'s capital gate cuts
	// both ways -- high enough to deter a fleet is high enough to exclude
	// volunteers. What P14 delivers is the MECHANISM; calibration is P15's and
	// is [UNSOLVED].
	BondFloorRelay = 100

	// BondFloorStorage, BondFloorDHT, BondFloorExit are the same, per role.
	//
	// PROVISIONAL. Derivation: ordered by what the role can do to somebody else,
	// not by what it costs to run. EXIT is highest because an exit's misbehaviour
	// is attributed to its operator by third parties; STORAGE is next because it
	// accepts other people's data; DHT is lowest because a bad DHT node is
	// routed around by the d=3 disjoint lookup. The ORDER is derived; the VALUES
	// are not.
	BondFloorStorage = 250
	BondFloorDHT     = 50
	BondFloorExit    = 1000

	// AdmissionPoWBits is the leading-zero-bit difficulty for the cheap-role
	// admission puzzle.
	//
	// PROVISIONAL. Derivation: T14.5 requires the cost be MEASURED on low-end
	// hardware and recorded, so the exclusion it causes is a known quantity
	// rather than an assumption. The measurement lives in the package's tests
	// and the value is set from it; see pow.go.
	AdmissionPoWBits = 18

	// MaxPerPrefixPerBucket and MaxPerASNPerBucket restate §7.2's DHT caps here
	// so that P14's composition test reads ONE policy rather than four
	// independent ones.
	//
	// PROVISIONAL as figures; NOT provisional as a rule. E14.4 is the rule: an
	// adversary with 100 identities in one /24 occupies at most one slot per
	// bucket and one hop per path.
	MaxPerPrefixPerBucket = 2
	MaxPerASNPerBucket    = 8

	// MaxPerPrefixPerPath and MaxPerASNPerPath are 1 by construction, not by
	// choice: §8.7's diversity constraint is "no two hops share a domain", and
	// any value above 1 would not be that constraint.
	MaxPerPrefixPerPath = 1
	MaxPerASNPerPath    = 1

	// MaxPerPrefixPerReplicaSet and MaxPerASNPerReplicaSet are §7.2's
	// replica-set rule, and they are also the DHT sibling-list caps -- the
	// sibling list is what decides replica-set membership, so they are the same
	// rule seen from two sides and must not be two constants.
	//
	// PROVISIONAL as figures, though barely: 1 is derived from what a replica
	// set is for. A replica set that admits two members of one /24 has bought
	// erasure coding and paid for it with a single failure domain.
	MaxPerPrefixPerReplicaSet = 1
	MaxPerASNPerReplicaSet    = 1
)

// ---------------------------------------------------------------------------
// Traffic-analysis defences (P13, section 16.3's MVP set)
// ---------------------------------------------------------------------------
//
// EVERY CONSTANT BELOW APPEARS EXACTLY ONCE, HERE. That is E13.4, and it is not
// hygiene: §16.8's last row makes ONE CANONICAL WIRE PROFILE normative, so a
// second definition anywhere is a second profile, and configuration diversity
// is itself the node fingerprint the profile exists to remove.
//
// None of these figures is measured. They are §16.3's arithmetic from the §5
// parameters, and §16's own closing note says so in as many words.

const (
	// DatagramSize is M2: every overlay QUIC packet is padded to a constant, so
	// the cell boundary is not visible in packet lengths.
	//
	// 1200 B is the conservative IPv6 minimum-MTU-derived figure that avoids
	// fragmentation on essentially every path. §16.8 prices it at +30.1 % over
	// payload including IPv4/UDP headers.
	DatagramSize = 1200

	// KeepaliveMin and KeepaliveMax are M6a: on an idle link, one PADDING cell
	// after U(KeepaliveMin, KeepaliveMax), reset on any real cell.
	//
	// The interval is RANDOM, not fixed. A fixed keepalive is a metronome, and a
	// metronome's phase is a per-link identifier that survives for as long as
	// the link does -- the same defect §16.3 identifies in unjittered rotation.
	KeepaliveMin = 1500 * time.Millisecond
	KeepaliveMax = 9500 * time.Millisecond

	// FloorRateCellsPerSec is M6b's R_floor: the minimum cell rate per direction
	// on a client<->guard link. Real cells count toward it.
	//
	// 0.5 costs 6.4 GB/month across two guards in both directions. §16.8 records
	// the risk that this is simply unaffordable for some users and that a
	// network where only the careful pad gives the careful a SMALLER anonymity
	// set. That is unresolved, not solved by this constant.
	FloorRateCellsPerSec = 0.5

	// FloorTailMin and FloorTailMax are how long the floor continues after the
	// last REAL cell, so the instant activity stops is not visible.
	//
	// The tail is extended by real cells only. A padding cell that extended it
	// would make the floor self-sustaining and the cost unbounded.
	FloorTailMin = 5 * time.Second
	FloorTailMax = 30 * time.Second

	// RotationJitter is M5's ± U(0, 15 %) on the rebuild trigger.
	//
	// Without it every client rebuilds on a phase-locked 420 s cadence and the
	// phase offset becomes a stable per-client identifier at the guard. §16.3:
	// unjittered, M5 ADDS a fingerprint while claiming to reduce one.
	RotationJitter = 0.15
)

// PaddingEnabledByDefault is T13.3's single bit.
//
// Padding is on unless a node is explicitly, visibly built without it. It is a
// constant and not a config key on purpose: §16.8 makes the wire profile
// normative, and a tunable padding rate would let each operator emit a
// distinguishable profile -- which is the attack, not the defence.
const PaddingEnabledByDefault = true

// ---------------------------------------------------------------------------
// Path selection (P12)
// ---------------------------------------------------------------------------

const (
	// PathPrefixBitsV4 and PathPrefixBitsV6 are the failure-domain widths for a
	// PATH, and they are deliberately COARSER than the /24 and /48 used for
	// shard placement.
	//
	// §7.5 (replication) says /24 and /48. §8.7 (path selection) says /16 and
	// /32. Both are in the roadmap and they were read as one number for a while;
	// they are not. The asymmetry is correct, because the two defend against
	// different things:
	//
	//	placement  loses an object when several holders fail together, which is
	//	           a correlated-outage question -- a rack, a host, a /24
	//	path       loses ANONYMITY when one observer sees two hops, which is a
	//	           vantage-point question -- and an ISP or a hosting provider
	//	           routinely sees a whole /16
	//
	// So the path constraint is 256x coarser. It costs candidate diversity on a
	// small network, and that is the correct cost: the alternative is a path
	// whose first and last hop sit in one provider's address space.
	PathPrefixBitsV4 = 16
	PathPrefixBitsV6 = 32

	// PathMinCandidates is the candidate-pool floor below which selection
	// raises a partition warning (T12.5).
	//
	// DERIVED, not chosen: a 3-hop path under distinct-/24 needs 3 domains, and
	// a pool that offers no more than the minimum offers no choice at all -- an
	// adversary who supplies the view controls every hop. Four times the path
	// length is the point at which a hostile view has to include real relays to
	// stay plausible. On a network this size the warning will fire often; that
	// is the correct output, not a reason to lower it.
	PathMinCandidates = DefaultHops * 4

	// PathMinDistinctPrefixes is the same floor expressed in failure domains,
	// which is the number that actually matters: 40 candidates in 3 /24s is a
	// partitioned view wearing a large pool as a disguise.
	PathMinDistinctPrefixes = DefaultHops * 3

	// BondBytesPerSecondPerToken converts bonded stake into the most bandwidth
	// a self-report may claim (T12.3).
	//
	// [NEEDS RESEARCH] -- NOT A MEASUREMENT. It is a policy exchange rate and
	// the roadmap has no basis for it yet. What the constant buys regardless of
	// its value is the SHAPE: a claim above the cap is worth exactly the cap, so
	// the marginal return on lying is zero and inflating a self-report costs the
	// same bond as telling the truth about the same capacity.
	BondBytesPerSecondPerToken = 1 << 20 // 1 MiB/s per whole token bonded

	// WeightClaimSpread bounds the ratio between the largest and smallest
	// claim-derived weight, exactly as the tier weights are bounded.
	//
	// Without it the bond cap alone is not a bound: a wealthy adversary bonds
	// enough to claim a legitimate 10 Gb/s and takes a proportional share of
	// every path. Capping the SPREAD makes bonded capacity buy a tilt rather
	// than the network.
	WeightClaimSpread = 2.0
)

// ---------------------------------------------------------------------------
// Multipath (Part VI)
// ---------------------------------------------------------------------------

const (
	// MultipathDefaultPaths is deliberately 2, not 8: two paths capture most
	// of the latency and resilience gain at the smallest increase in the
	// number of relays that observe some of the stream.
	MultipathDefaultPaths = 2
	MultipathMaxPaths     = 8
)
