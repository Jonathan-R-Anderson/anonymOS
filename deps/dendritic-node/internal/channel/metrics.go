package channel

// P14 — aggregate-only instrumentation.
//
// THE QUESTION THIS ANSWERS, AND THE ONE IT MUST NOT
// ---------------------------------------------------
//	answers   "how economically and operationally viable is the channel system?"
//	must not  "who paid whom, when, over which channel?"
//
// Those are close enough that the second is the natural accident of building the
// first. Every payment metric wants an id to group by, and the moment one is
// stored the metrics layer IS the metadata chokepoint the privacy layer exists
// to avoid — sitting inside the privacy layer, wearing the word "analytics".
//
// hub.go already refused this once, and for the same reason:
//
//	"Delivered and Failed are aggregate. No per-payment history: a hub that
//	 logged which reader paid which streamer would be the metadata chokepoint
//	 the privacy layer exists to avoid, sitting inside the privacy layer."
//
// STRUCTURAL, NOT POLICY
// ----------------------
// The guarantee here is not that nobody will query it that way. It is that the
// TYPES CANNOT CARRY THE DATA. Every method below takes amounts, counts,
// durations and small enums. None takes a channel id, a payment id, an address,
// a hash, a nonce, a preimage, a route id — or a string, which could carry any
// of them.
//
// TestMetricsAPICannotAcceptIdentifiers enforces that by reflection over the
// method set, so adding an identifying parameter fails the build's tests rather
// than requiring review to catch it.
//
// WHAT IS DELIBERATELY ABSENT
// ---------------------------
// There is no event list. Not a ring buffer, not a capped log, not a "last N
// payments" for debugging. A sequence of individual records is a payment history
// however short it is, and a short one is still enough to correlate a tip with a
// stream that was live at that moment. Counters and histograms cannot be
// replayed into an ordering.

// NIL IS A WORKING COLLECTOR. Every method tolerates a nil receiver and does
// nothing, so a production path can hold a *Metrics that was never set and needs
// no guard at the call site. Instrumentation that requires an `if m != nil`
// around it gets forgotten in exactly one place.

import (
	"encoding/json"
	"math/big"
	"sync"
	"time"
)

// CloseKind distinguishes how a channel ended. An enum, not a string: a string
// parameter is a place an identifier can be smuggled.
type CloseKind uint8

const (
	CloseCooperative CloseKind = iota
	CloseDisputed
)

// DHTOp is an evidence-store operation.
type DHTOp uint8

const (
	DHTRead DHTOp = iota
	DHTWrite
)

// Bucket boundaries. Fixed and coarse on purpose: fine buckets over a small
// population are a fingerprint, and "exactly 37 tips" identifies a channel in a
// way "between 32 and 63" does not.
var (
	tipCountBuckets = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
	// Settlement intervals, seconds.
	intervalBuckets = []int64{60, 300, 900, 3600, 21600, 86400, 604800}
)

// Histogram is a bucketed count. It holds counts, never samples — a sample list
// is an event log with extra steps.
type Histogram struct {
	Bounds []int64  `json:"bounds"`
	Counts []uint64 `json:"counts"`
	Over   uint64   `json:"over"`
	Total  uint64   `json:"total"`
	Sum    int64    `json:"sum"`
}

func newHistogram(bounds []int64) *Histogram {
	return &Histogram{Bounds: bounds, Counts: make([]uint64, len(bounds))}
}

func (h *Histogram) observe(v int64) {
	h.Total++
	h.Sum += v
	for i, b := range h.Bounds {
		if v <= b {
			h.Counts[i]++
			return
		}
	}
	h.Over++
}

// Mean is the arithmetic mean of everything observed, or 0 for nothing.
func (h *Histogram) Mean() float64 {
	if h.Total == 0 {
		return 0
	}
	return float64(h.Sum) / float64(h.Total)
}

// Metrics is the whole instrumentation surface. Safe for concurrent use: it is
// written from every payment path at once.
type Metrics struct {
	mu sync.Mutex

	// Payment lifecycle.
	tipsAttempted uint64
	tipsCompleted uint64
	tipsFailed    uint64
	tipsRefunded  uint64
	tipValue      *big.Int
	refundedValue *big.Int

	// Channels.
	channelOpens      uint64
	channelCloses     uint64
	cooperativeCloses uint64
	disputedCloses    uint64
	channelValue      *big.Int
	// channelsOpen is a GAUGE, and it is what makes mean lifetime derivable
	// without any per-channel timestamp — see Snapshot.MeanChannelLifetime.
	channelsOpen int64

	// HTLCs.
	htlcsCreated  uint64
	htlcsSettled  uint64
	htlcsRefunded uint64

	// Routing and multipath.
	routedPayments    uint64
	multipathPayments uint64
	multipathLegs     uint64
	executorFailures  uint64

	// Watchtower and verification.
	watchtowerObservations uint64
	watchtowerRecoveries   uint64

	// The authenticated-chain path (P14.5). Counts only — a block number is not
	// an identifier of anybody, but a per-block series aligned against payment
	// counters would time them, so these are totals like everything else here.
	chainBlocksAuthenticated uint64
	chainBlocksSkipped       uint64
	chainReceiptsVerified    uint64
	chainRateLimited         uint64
	proofsVerified           uint64
	proofsRejected           uint64

	// Evidence store.
	dhtReads      uint64
	dhtWrites     uint64
	dhtFailures   uint64
	dhtBytesRead  uint64
	dhtBytesWrite uint64

	// RPC.
	rpcCalls uint64

	// Resources — last sample plus peaks. Not a time series: a series of
	// resource samples timestamped alongside payment counters would let an
	// observer align load spikes with individual payments.
	cpuPercent  float64
	rssBytes    uint64
	diskBytes   uint64
	peakRSS     uint64
	peakCPU     float64
	resourceObs uint64

	// Distributions.
	tipsAtClose        *Histogram
	settlementInterval *Histogram
}

// NewMetrics builds an empty collector.
func NewMetrics() *Metrics {
	return &Metrics{
		tipValue:           new(big.Int),
		refundedValue:      new(big.Int),
		channelValue:       new(big.Int),
		tipsAtClose:        newHistogram(intsToInt64(tipCountBuckets)),
		settlementInterval: newHistogram(intervalBuckets),
	}
}

func intsToInt64(in []int) []int64 {
	out := make([]int64, len(in))
	for i, v := range in {
		out[i] = int64(v)
	}
	return out
}

// ---- payment lifecycle ------------------------------------------------------
//
// Note the shapes. A completed tip carries its AMOUNT and nothing else — not
// which channel it crossed, not who sent it. A failed tip carries nothing at
// all, because the interesting fact is that one failed, and any detail that
// would explain WHICH one is the detail that identifies it.

// NIL SAFETY LIVES IN EACH METHOD, NOT IN bump.
//
// `m.bump(&m.counter)` evaluates &m.counter BEFORE bump is entered, and taking
// the address of a field on a nil pointer panics — so a guard inside bump is
// unreachable. An earlier version had exactly that, and every un-instrumented
// deployment would have panicked on its first payment. A real-path test found
// it, because a node without a collector is the ordinary case there.
func (m *Metrics) TipAttempted() {
	if m == nil {
		return
	}
	m.bump(&m.tipsAttempted)
}
func (m *Metrics) TipFailed() {
	if m == nil {
		return
	}
	m.bump(&m.tipsFailed)
}

func (m *Metrics) TipCompleted(amount *big.Int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tipsCompleted++
	m.tipValue.Add(m.tipValue, orZero(amount))
}

func (m *Metrics) TipRefunded(amount *big.Int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tipsRefunded++
	m.refundedValue.Add(m.refundedValue, orZero(amount))
}

// ---- channels ---------------------------------------------------------------

func (m *Metrics) ChannelOpened(deposit *big.Int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channelOpens++
	m.channelsOpen++
	m.channelValue.Add(m.channelValue, orZero(deposit))
}

// ChannelClosed records an ending. `tips` is how many payments the channel
// carried over its life — a COUNT, passed at the moment of closing, so nothing
// has to be retained per channel to produce it.
func (m *Metrics) ChannelClosed(kind CloseKind, tips int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channelCloses++
	if m.channelsOpen > 0 {
		m.channelsOpen--
	}
	switch kind {
	case CloseDisputed:
		m.disputedCloses++
	default:
		m.cooperativeCloses++
	}
	if tips >= 0 {
		m.tipsAtClose.observe(int64(tips))
	}
}

// ObserveSettlementInterval records how long passed between two settlements.
// A duration, computed by the caller at the moment it settles; nothing here
// remembers when anything happened.
func (m *Metrics) ObserveSettlementInterval(d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settlementInterval.observe(int64(d / time.Second))
}

// ---- HTLCs, routing, executor ----------------------------------------------

func (m *Metrics) HTLCCreated() {
	if m == nil {
		return
	}
	m.bump(&m.htlcsCreated)
}
func (m *Metrics) HTLCSettled() {
	if m == nil {
		return
	}
	m.bump(&m.htlcsSettled)
}
func (m *Metrics) HTLCRefunded() {
	if m == nil {
		return
	}
	m.bump(&m.htlcsRefunded)
}
func (m *Metrics) RoutedPayment() {
	if m == nil {
		return
	}
	m.bump(&m.routedPayments)
}
func (m *Metrics) ExecutorFailure() {
	if m == nil {
		return
	}
	m.bump(&m.executorFailures)
}

// MultipathPayment records one split payment and how many legs it used. The leg
// COUNT is a load figure; which channels carried them is not recorded.
func (m *Metrics) MultipathPayment(legs int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.multipathPayments++
	if legs > 0 {
		m.multipathLegs += uint64(legs)
	}
}

// ---- watchtower and verification -------------------------------------------

func (m *Metrics) WatchtowerObservation() {
	if m == nil {
		return
	}
	m.bump(&m.watchtowerObservations)
}
func (m *Metrics) WatchtowerRecovery() {
	if m == nil {
		return
	}
	m.bump(&m.watchtowerRecoveries)
}

// ChainBlockAuthenticated counts a finalised block whose identity and
// commitments were established. One per block examined, however cheap.
func (m *Metrics) ChainBlockAuthenticated() {
	if m == nil {
		return
	}
	m.bump(&m.chainBlocksAuthenticated)
}

// ChainBlockSkippedByBloom counts a block the AUTHENTICATED bloom excluded, so
// no receipts were fetched. The gap between this and ChainBlockAuthenticated is
// the workload the design exists to remove.
func (m *Metrics) ChainBlockSkippedByBloom() {
	if m == nil {
		return
	}
	m.bump(&m.chainBlocksSkipped)
}

// ChainReceiptsVerified counts receipts rebuilt into a trie whose root matched
// the authenticated receiptsRoot. The count, never which block.
func (m *Metrics) ChainReceiptsVerified(count int) {
	if m == nil || count <= 0 {
		return
	}
	m.mu.Lock()
	m.chainReceiptsVerified += uint64(count)
	m.mu.Unlock()
}

// ChainRateLimited counts provider refusals for capacity.
//
// SEPARATE on purpose. Folded into a latency figure a rate limit disappears; on
// its own it is a number that climbs before the watchtower stops working.
func (m *Metrics) ChainRateLimited() {
	if m == nil {
		return
	}
	m.bump(&m.chainRateLimited)
}

// ProofVerified records a verification outcome. A bool, not a reason string —
// a reason is free text and free text is where identifiers end up.
func (m *Metrics) ProofVerified(ok bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.proofsVerified++
		return
	}
	m.proofsRejected++
}

// ---- evidence store and RPC -------------------------------------------------

// DHTEvidence records one evidence-store operation and its size. Size is a load
// figure; a size alone does not identify a record, and no key is accepted.
func (m *Metrics) DHTEvidence(op DHTOp, bytes int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if bytes < 0 {
		bytes = 0
	}
	switch op {
	case DHTWrite:
		m.dhtWrites++
		m.dhtBytesWrite += uint64(bytes)
	default:
		m.dhtReads++
		m.dhtBytesRead += uint64(bytes)
	}
}

func (m *Metrics) RPCCall() {
	if m == nil {
		return
	}
	m.bump(&m.rpcCalls)
}

// EvidenceRead, EvidenceWrite and EvidenceFailure implement
// ethproof.EvidenceMetrics, so the evidence store can report without importing
// this package. Byte counts only — the interface has no way to name a record.
func (m *Metrics) EvidenceRead(bytes int)  { m.DHTEvidence(DHTRead, bytes) }
func (m *Metrics) EvidenceWrite(bytes int) { m.DHTEvidence(DHTWrite, bytes) }
func (m *Metrics) EvidenceFailure() {
	if m == nil {
		return
	}
	m.bump(&m.dhtFailures)
}

// ObserveResources records one sample of this process's usage.
//
// Last value and peak only. A time series of samples, stored beside payment
// counters, would let somebody align a load spike with the moment a payment
// happened — which is a timing side channel built out of otherwise harmless
// numbers.
func (m *Metrics) ObserveResources(cpuPercent float64, rssBytes, diskBytes uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resourceObs++
	m.cpuPercent, m.rssBytes, m.diskBytes = cpuPercent, rssBytes, diskBytes
	if rssBytes > m.peakRSS {
		m.peakRSS = rssBytes
	}
	if cpuPercent > m.peakCPU {
		m.peakCPU = cpuPercent
	}
}

// bump increments under the lock. Callers MUST check nil themselves — see
// below.
func (m *Metrics) bump(p *uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*p++
}

// ---- reading it back --------------------------------------------------------

// Snapshot is the whole state, as plain numbers.
type Snapshot struct {
	TipsAttempted uint64 `json:"tips_attempted"`
	TipsCompleted uint64 `json:"tips_completed"`
	TipsFailed    uint64 `json:"tips_failed"`
	TipsRefunded  uint64 `json:"tips_refunded"`
	TipValue      string `json:"tip_value"`
	RefundedValue string `json:"refunded_value"`

	ChannelOpens      uint64 `json:"channel_opens"`
	ChannelCloses     uint64 `json:"channel_closes"`
	CooperativeCloses uint64 `json:"cooperative_closes"`
	DisputedCloses    uint64 `json:"disputed_closes"`
	ChannelsOpen      int64  `json:"channels_open"`
	ChannelValue      string `json:"channel_value"`

	HTLCsCreated  uint64 `json:"htlcs_created"`
	HTLCsSettled  uint64 `json:"htlcs_settled"`
	HTLCsRefunded uint64 `json:"htlcs_refunded"`

	RoutedPayments    uint64 `json:"routed_payments"`
	MultipathPayments uint64 `json:"multipath_payments"`
	MultipathLegs     uint64 `json:"multipath_legs"`
	ExecutorFailures  uint64 `json:"executor_failures"`

	WatchtowerObservations uint64 `json:"watchtower_observations"`

	// The authenticated-chain path. ChainRateLimited is its own field rather
	// than an error total, because "the provider refused us" is operationally
	// different from "the provider was wrong".
	ChainBlocksAuthenticated uint64 `json:"chain_blocks_authenticated"`
	ChainBlocksSkipped       uint64 `json:"chain_blocks_skipped_by_bloom"`
	ChainReceiptsVerified    uint64 `json:"chain_receipts_verified"`
	ChainRateLimited         uint64 `json:"chain_rate_limited"`
	WatchtowerRecoveries     uint64 `json:"watchtower_recoveries"`
	ProofsVerified           uint64 `json:"proofs_verified"`
	ProofsRejected           uint64 `json:"proofs_rejected"`

	DHTFailures   uint64 `json:"dht_failures"`
	DHTReads      uint64 `json:"dht_reads"`
	DHTWrites     uint64 `json:"dht_writes"`
	DHTBytesRead  uint64 `json:"dht_bytes_read"`
	DHTBytesWrite uint64 `json:"dht_bytes_written"`
	RPCCalls      uint64 `json:"rpc_calls"`

	CPUPercent float64 `json:"cpu_percent"`
	RSSBytes   uint64  `json:"rss_bytes"`
	DiskBytes  uint64  `json:"disk_bytes"`
	PeakRSS    uint64  `json:"peak_rss_bytes"`
	PeakCPU    float64 `json:"peak_cpu_percent"`

	TipsAtClose        *Histogram `json:"tips_at_close"`
	SettlementInterval *Histogram `json:"settlement_interval_seconds"`
}

// Snapshot copies the current values.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		TipsAttempted: m.tipsAttempted, TipsCompleted: m.tipsCompleted,
		TipsFailed: m.tipsFailed, TipsRefunded: m.tipsRefunded,
		TipValue: m.tipValue.String(), RefundedValue: m.refundedValue.String(),

		ChannelOpens: m.channelOpens, ChannelCloses: m.channelCloses,
		CooperativeCloses: m.cooperativeCloses, DisputedCloses: m.disputedCloses,
		ChannelsOpen: m.channelsOpen, ChannelValue: m.channelValue.String(),

		HTLCsCreated: m.htlcsCreated, HTLCsSettled: m.htlcsSettled,
		HTLCsRefunded: m.htlcsRefunded,

		RoutedPayments: m.routedPayments, MultipathPayments: m.multipathPayments,
		MultipathLegs: m.multipathLegs, ExecutorFailures: m.executorFailures,

		WatchtowerObservations: m.watchtowerObservations,
		WatchtowerRecoveries:   m.watchtowerRecoveries,

		ChainBlocksAuthenticated: m.chainBlocksAuthenticated,
		ChainBlocksSkipped:       m.chainBlocksSkipped,
		ChainReceiptsVerified:    m.chainReceiptsVerified,
		ChainRateLimited:         m.chainRateLimited,
		ProofsVerified:           m.proofsVerified, ProofsRejected: m.proofsRejected,

		DHTReads: m.dhtReads, DHTWrites: m.dhtWrites, DHTFailures: m.dhtFailures,
		DHTBytesRead: m.dhtBytesRead, DHTBytesWrite: m.dhtBytesWrite,
		RPCCalls: m.rpcCalls,

		CPUPercent: m.cpuPercent, RSSBytes: m.rssBytes, DiskBytes: m.diskBytes,
		PeakRSS: m.peakRSS, PeakCPU: m.peakCPU,

		TipsAtClose:        cloneHistogram(m.tipsAtClose),
		SettlementInterval: cloneHistogram(m.settlementInterval),
	}
}

func cloneHistogram(h *Histogram) *Histogram {
	if h == nil {
		return nil
	}
	out := &Histogram{Bounds: append([]int64(nil), h.Bounds...),
		Counts: append([]uint64(nil), h.Counts...),
		Over:   h.Over, Total: h.Total, Sum: h.Sum}
	return out
}

// MeanChannelLifetime derives the average time a channel stays open, WITHOUT
// any per-channel timestamp.
//
// Little's Law: for a system in steady state, mean time in system = mean number
// in system / arrival rate. Here that is
//
//	mean lifetime = channels currently open / closes per second
//
// so two counters and a gauge give the mean, and nothing has to remember when
// any particular channel opened. `elapsed` is how long this process has been
// collecting, which the caller knows and this type deliberately does not.
//
// A MEAN ONLY. The distribution of lifetimes is not recoverable this way, and
// producing one would require dating individual channels — see
// doc/fixtures/p14-metrics.md, where it is recorded as NOT MEASURABLE under the
// privacy constraint rather than quietly approximated.
func (s Snapshot) MeanChannelLifetime(elapsed time.Duration) time.Duration {
	if s.ChannelCloses == 0 || elapsed <= 0 {
		return 0
	}
	closeRate := float64(s.ChannelCloses) / elapsed.Seconds()
	if closeRate == 0 {
		return 0
	}
	return time.Duration(float64(s.ChannelsOpen)/closeRate) * time.Second
}

// MeanTipsPerChannel is the cohort figure: total completed tips over channels
// closed. Aggregate by construction — it never groups by anything.
func (s Snapshot) MeanTipsPerChannel() float64 {
	if s.ChannelCloses == 0 {
		return 0
	}
	return float64(s.TipsCompleted) / float64(s.ChannelCloses)
}

// ChannelUtilisation is the share of committed channel value that actually
// moved: total tip value over total channel value.
//
// The economic question underneath P14 — capital sitting idle in a channel is a
// cost, and a channel that carried a tenth of its deposit was over-funded.
func (s Snapshot) ChannelUtilisation() float64 {
	value, ok := new(big.Int).SetString(s.ChannelValue, 10)
	if !ok || value.Sign() == 0 {
		return 0
	}
	tipped, ok := new(big.Int).SetString(s.TipValue, 10)
	if !ok {
		return 0
	}
	ratio := new(big.Float).Quo(new(big.Float).SetInt(tipped), new(big.Float).SetInt(value))
	f, _ := ratio.Float64()
	return f
}

// HTLCUtilisation is the share of created HTLCs that settled rather than being
// refunded — the routing layer's success rate, in aggregate.
func (s Snapshot) HTLCUtilisation() float64 {
	if s.HTLCsCreated == 0 {
		return 0
	}
	return float64(s.HTLCsSettled) / float64(s.HTLCsCreated)
}

// RoutingSuccessRate is completed tips over attempted, across every path.
func (s Snapshot) RoutingSuccessRate() float64 {
	if s.TipsAttempted == 0 {
		return 0
	}
	return float64(s.TipsCompleted) / float64(s.TipsAttempted)
}

// JSON renders the snapshot. Kept here so there is exactly one serialisation and
// the privacy test has one thing to check.
func (s Snapshot) JSON() ([]byte, error) { return json.MarshalIndent(s, "", "  ") }
