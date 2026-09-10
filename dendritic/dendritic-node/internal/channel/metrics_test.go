package channel

// P14 — proving the metrics layer cannot become a metadata store.
//
// The correctness tests matter, but they are the easy half. The half that has to
// hold under future edits is the privacy boundary, and "we won't query it that
// way" is not a boundary — so these check the TYPES and the SERIALISATION,
// mechanically, rather than checking that today's callers happen to behave.
//
// The failure being guarded against is specific and ordinary: somebody adds
// `channelID` to a metric "just for debugging", and nothing objects.

import (
	"encoding/json"
	"io"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- the structural boundary -----------------------------------------------

// No metrics method may accept a type capable of identifying a payment.
//
// This is the load-bearing test of the whole layer. It is an allowlist rather
// than a blocklist on purpose: a blocklist has to predict what somebody will add
// next, and it will eventually be wrong. An allowlist makes anything new fail
// until a human decides it is safe.
//
// `string` is excluded deliberately even though it is not an identifier type.
// A string parameter is where a channel id, an address or a hash arrives in
// practice, hex-encoded and looking innocuous.
func TestMetricsAPICannotAcceptIdentifiers(t *testing.T) {
	allowed := map[string]bool{
		"int": true, "int64": true, "uint64": true, "float64": true, "bool": true,
		"*big.Int": true, "time.Duration": true,
		"channel.CloseKind": true, "channel.DHTOp": true,
	}

	mt := reflect.TypeOf(NewMetrics())
	for i := 0; i < mt.NumMethod(); i++ {
		method := mt.Method(i)
		ft := method.Type
		// Field 0 is the receiver.
		for a := 1; a < ft.NumIn(); a++ {
			in := ft.In(a)
			name := in.String()
			if allowed[name] {
				continue
			}
			t.Errorf("Metrics.%s accepts %s.\n\n"+
				"Only amounts, counts, durations and small enums may enter the metrics\n"+
				"layer. If this parameter is genuinely needed, it must arrive as an\n"+
				"AGGREGATE (a count, a duration, a bucket) rather than as the value\n"+
				"itself — see the header of metrics.go. Adding a string is how a channel\n"+
				"id gets in wearing a disguise.", method.Name, name)
		}
	}
}

// The snapshot must not carry identifying fields either — reading is as much a
// leak as writing.
func TestSnapshotCarriesNoIdentifyingFields(t *testing.T) {
	banned := []string{
		"channel", "payment", "payer", "recipient", "route", "tx", "hash",
		"nonce", "preimage", "address", "id", "peer", "node", "intent", "lock",
	}
	// Field names that legitimately contain a banned substring because they are
	// aggregate COUNTS of a thing, not the thing.
	permitted := map[string]bool{
		"TipsAttempted": true, "TipsCompleted": true, "TipsFailed": true,
		"TipsRefunded": true, "TipValue": true, "RefundedValue": true,
		"ChannelOpens": true, "ChannelCloses": true, "CooperativeCloses": true,
		"DisputedCloses": true, "ChannelsOpen": true, "ChannelValue": true,
		"HTLCsCreated": true, "HTLCsSettled": true, "HTLCsRefunded": true,
		"RoutedPayments": true, "MultipathPayments": true, "MultipathLegs": true,
		"ExecutorFailures": true, "TipsAtClose": true,
		// P14.5 chain-follower counters. Each is a COUNT of blocks or receipts
		// examined, never a height, hash or identifier — "Blocks" trips the
		// "lock" substring and "ChainReceiptsVerified" is a total, not a list.
		"ChainBlocksAuthenticated": true, "ChainBlocksSkipped": true,
		"ChainReceiptsVerified": true, "ChainRateLimited": true,
	}

	st := reflect.TypeOf(Snapshot{})
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if permitted[f.Name] {
			continue
		}
		lower := strings.ToLower(f.Name)
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("Snapshot.%s looks like it carries %q. If it is an aggregate "+
					"count, add it to the permitted list with a reason; if it is an "+
					"identifier, it must not be here at all.", f.Name, b)
			}
		}
	}
}

// Serialised output must contain nothing that looks like an identifier.
//
// Checks the bytes, not the struct: a field could carry an identifier inside a
// string without its NAME giving it away.
func TestSerialisedMetricsContainNoIdentifiers(t *testing.T) {
	m := NewMetrics()
	// Drive every recording path, so anything that leaked would be present.
	m.TipAttempted()
	m.TipCompleted(anon(5))
	m.TipFailed()
	m.TipRefunded(anon(2))
	m.ChannelOpened(anon(500))
	m.ChannelClosed(CloseCooperative, 12)
	m.ChannelClosed(CloseDisputed, 3)
	m.HTLCCreated()
	m.HTLCSettled()
	m.HTLCRefunded()
	m.RoutedPayment()
	m.MultipathPayment(3)
	m.ExecutorFailure()
	m.WatchtowerObservation()
	m.WatchtowerRecovery()
	m.ProofVerified(true)
	m.ProofVerified(false)
	m.DHTEvidence(DHTRead, 1024)
	m.DHTEvidence(DHTWrite, 2048)
	m.RPCCall()
	m.ObserveSettlementInterval(90 * time.Second)
	m.ObserveResources(12.5, 1<<20, 1<<30)

	raw, err := m.Snapshot().JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	out := string(raw)

	// A 40-hex run is an address; 64 is a hash, channel id or preimage.
	for _, n := range []int{40, 64} {
		if hasHexRun(out, n) {
			t.Fatalf("serialised metrics contain a %d-character hex run — that is the "+
				"shape of an identifier:\n%s", n, out)
		}
	}
	if strings.Contains(out, "0x") {
		t.Fatalf("serialised metrics contain a 0x-prefixed value:\n%s", out)
	}
	// Every value must be a number, a decimal string, or a histogram. Nothing
	// should be a long opaque token.
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k, v := range parsed {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if len(s) > 40 {
			t.Fatalf("field %s is a %d-character string; metrics carry numbers, not tokens", k, len(s))
		}
		for _, r := range s {
			if r < '0' || r > '9' {
				t.Fatalf("field %s = %q is not a decimal value", k, s)
			}
		}
	}
}

func hasHexRun(s string, n int) bool {
	run := 0
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if isHex {
			run++
			if run >= n {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

// The collector must hold no per-event storage at all.
//
// A slice or map of events is a payment log however it is labelled, and a capped
// one is still enough to correlate a tip with whatever was happening then.
func TestMetricsHoldsNoPerEventStorage(t *testing.T) {
	mt := reflect.TypeOf(Metrics{})
	for i := 0; i < mt.NumField(); i++ {
		f := mt.Field(i)
		switch f.Type.Kind() {
		case reflect.Map:
			t.Errorf("Metrics.%s is a map (%s). A map keyed by anything per-payment "+
				"is a metadata store; aggregate into a counter or a histogram instead.",
				f.Name, f.Type)
		case reflect.Slice:
			// Histograms own fixed-size slices of counts; those are fine. A slice
			// directly on Metrics is not.
			t.Errorf("Metrics.%s is a slice (%s). A sequence of records is an event "+
				"log; aggregate it.", f.Name, f.Type)
		}
	}
}

// Restarting must not resurrect anything: a fresh collector is empty.
//
// The layer deliberately has no persistence. If one is added later, this fails
// and whoever adds it has to state what is retained and why.
func TestRestartingMetricsCreatesNoHiddenHistory(t *testing.T) {
	m := NewMetrics()
	for i := 0; i < 25; i++ {
		m.TipCompleted(anon(1))
		m.ChannelOpened(anon(10))
	}
	if got := m.Snapshot().TipsCompleted; got != 25 {
		t.Fatalf("recorded %d tips", got)
	}

	fresh := NewMetrics()
	s := fresh.Snapshot()
	if s.TipsCompleted != 0 || s.ChannelOpens != 0 || s.ChannelsOpen != 0 {
		t.Fatalf("a new collector started with state: %+v", s)
	}
	if s.TipValue != "0" || s.ChannelValue != "0" {
		t.Fatalf("a new collector started with value: %s / %s", s.TipValue, s.ChannelValue)
	}
	// And nothing here can write anywhere. Checked by TYPE rather than by field
	// name: a first attempt matched on the substring "path" and flagged
	// multipathPayments, which proves the point about name matching.
	//
	// A persistence path would be a string, a file handle or a writer, so the
	// absence of all three is the mechanical statement of "this cannot persist".
	mt := reflect.TypeOf(Metrics{})
	writer := reflect.TypeOf((*io.Writer)(nil)).Elem()
	for i := 0; i < mt.NumField(); i++ {
		f := mt.Field(i)
		if f.Type.Kind() == reflect.String {
			t.Errorf("Metrics.%s is a string; a path or a name is how persistence "+
				"and identifiers both arrive", f.Name)
		}
		if f.Type.Implements(writer) {
			t.Errorf("Metrics.%s can be written to; a persisted metrics stream is a "+
				"history", f.Name)
		}
	}
}

// Aggregation must not permit reconstructing a sequence.
//
// Two different orderings of the same events must produce byte-identical
// snapshots. If ordering were recoverable, the layer would encode a payment
// sequence — which is the thing it exists not to do.
func TestAggregationCannotReconstructOrdering(t *testing.T) {
	forward := NewMetrics()
	forward.TipCompleted(anon(1))
	forward.TipCompleted(anon(2))
	forward.TipCompleted(anon(3))
	forward.TipFailed()

	backward := NewMetrics()
	backward.TipFailed()
	backward.TipCompleted(anon(3))
	backward.TipCompleted(anon(2))
	backward.TipCompleted(anon(1))

	a, err := forward.Snapshot().JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	b, err := backward.Snapshot().JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("two orderings of the same events produced different snapshots; "+
			"the ordering is recoverable\n--- forward ---\n%s\n--- backward ---\n%s", a, b)
	}
}

// ---- correctness under load -------------------------------------------------

// Totals must be right with many goroutines recording at once.
func TestTotalsAreCorrectUnderConcurrency(t *testing.T) {
	m := NewMetrics()
	const workers, each = 16, 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				m.TipAttempted()
				m.TipCompleted(anon(1))
				m.HTLCCreated()
				m.HTLCSettled()
			}
		}()
	}
	wg.Wait()

	s := m.Snapshot()
	want := uint64(workers * each)
	if s.TipsAttempted != want || s.TipsCompleted != want {
		t.Fatalf("attempted %d completed %d, want %d each", s.TipsAttempted, s.TipsCompleted, want)
	}
	if s.TipValue != new(big.Int).Mul(anon(1), big.NewInt(int64(want))).String() {
		t.Fatalf("tip value %s", s.TipValue)
	}
	if s.HTLCsCreated != want || s.HTLCsSettled != want {
		t.Fatalf("htlcs created %d settled %d", s.HTLCsCreated, s.HTLCsSettled)
	}
}

// Mixed outcomes across many channels and recipients must still add up.
func TestTotalsAcrossMixedOutcomes(t *testing.T) {
	m := NewMetrics()
	// Five channels, each carrying a different mix.
	for c := 0; c < 5; c++ {
		m.ChannelOpened(anon(100))
		for i := 0; i < 10; i++ {
			m.TipAttempted()
			switch i % 5 {
			case 0:
				m.TipFailed()
			case 1:
				m.TipRefunded(anon(1))
			default:
				m.TipCompleted(anon(2))
			}
		}
		if c%2 == 0 {
			m.ChannelClosed(CloseCooperative, 6)
		} else {
			m.ChannelClosed(CloseDisputed, 6)
		}
	}

	s := m.Snapshot()
	if s.TipsAttempted != 50 {
		t.Fatalf("attempted %d, want 50", s.TipsAttempted)
	}
	if s.TipsFailed != 10 || s.TipsRefunded != 10 || s.TipsCompleted != 30 {
		t.Fatalf("failed %d refunded %d completed %d", s.TipsFailed, s.TipsRefunded, s.TipsCompleted)
	}
	// Every attempt reached exactly one terminal state.
	if s.TipsFailed+s.TipsRefunded+s.TipsCompleted != s.TipsAttempted {
		t.Fatal("terminal outcomes do not account for every attempt")
	}
	if s.ChannelOpens != 5 || s.ChannelCloses != 5 || s.ChannelsOpen != 0 {
		t.Fatalf("opens %d closes %d open-now %d", s.ChannelOpens, s.ChannelCloses, s.ChannelsOpen)
	}
	if s.CooperativeCloses+s.DisputedCloses != s.ChannelCloses {
		t.Fatal("close kinds do not sum to closes")
	}
}

// Routed and multi-path activity must be counted without leaking structure.
func TestRoutedAndMultipathTotals(t *testing.T) {
	m := NewMetrics()
	for i := 0; i < 4; i++ {
		m.RoutedPayment()
	}
	m.MultipathPayment(3)
	m.MultipathPayment(2)
	m.ExecutorFailure()

	s := m.Snapshot()
	if s.RoutedPayments != 4 {
		t.Fatalf("routed %d", s.RoutedPayments)
	}
	if s.MultipathPayments != 2 || s.MultipathLegs != 5 {
		t.Fatalf("multipath %d legs %d", s.MultipathPayments, s.MultipathLegs)
	}
	if s.ExecutorFailures != 1 {
		t.Fatalf("executor failures %d", s.ExecutorFailures)
	}
}

// ---- the derived economics --------------------------------------------------

// Mean channel lifetime comes from Little's Law, not from timestamps.
func TestMeanChannelLifetimeNeedsNoTimestamps(t *testing.T) {
	m := NewMetrics()
	// Steady state: 10 channels open, 20 closed over an hour.
	for i := 0; i < 30; i++ {
		m.ChannelOpened(anon(100))
	}
	for i := 0; i < 20; i++ {
		m.ChannelClosed(CloseCooperative, 5)
	}
	s := m.Snapshot()
	if s.ChannelsOpen != 10 {
		t.Fatalf("channels open %d, want 10", s.ChannelsOpen)
	}
	// closes/sec = 20/3600; lifetime = 10 / (20/3600) = 1800s.
	got := s.MeanChannelLifetime(time.Hour)
	if got != 1800*time.Second {
		t.Fatalf("mean lifetime %s, want 30m", got)
	}
	// With nothing closed the answer is unknown, not zero-by-accident.
	empty := NewMetrics().Snapshot()
	if empty.MeanChannelLifetime(time.Hour) != 0 {
		t.Fatal("a lifetime was reported with no closes to derive it from")
	}
}

func TestDerivedEconomics(t *testing.T) {
	m := NewMetrics()
	m.ChannelOpened(anon(1000))
	for i := 0; i < 10; i++ {
		m.TipAttempted()
		m.TipCompleted(anon(10))
	}
	for i := 0; i < 2; i++ {
		m.TipAttempted()
		m.TipFailed()
	}
	m.ChannelClosed(CloseCooperative, 10)
	for i := 0; i < 8; i++ {
		m.HTLCCreated()
	}
	for i := 0; i < 6; i++ {
		m.HTLCSettled()
	}
	s := m.Snapshot()

	if got := s.MeanTipsPerChannel(); got != 10 {
		t.Fatalf("mean tips per channel %v, want 10", got)
	}
	// 100 tipped out of 1000 committed.
	if got := s.ChannelUtilisation(); got < 0.099 || got > 0.101 {
		t.Fatalf("channel utilisation %v, want ~0.1", got)
	}
	if got := s.HTLCUtilisation(); got != 0.75 {
		t.Fatalf("htlc utilisation %v, want 0.75", got)
	}
	// 10 completed of 12 attempted.
	if got := s.RoutingSuccessRate(); got < 0.83 || got > 0.834 {
		t.Fatalf("routing success rate %v, want ~0.833", got)
	}
}

// Histogram buckets are coarse on purpose, and must not reveal an exact count.
func TestHistogramBucketsAreCoarse(t *testing.T) {
	m := NewMetrics()
	m.ChannelClosed(CloseCooperative, 37)
	h := m.Snapshot().TipsAtClose
	if h.Total != 1 {
		t.Fatalf("observations %d", h.Total)
	}
	// 37 lands in the (32,64] bucket. No bucket may hold exactly one value.
	for i, b := range h.Bounds {
		if h.Counts[i] == 0 {
			continue
		}
		lower := int64(0)
		if i > 0 {
			lower = h.Bounds[i-1]
		}
		if b-lower < 2 {
			t.Fatalf("bucket (%d,%d] is narrow enough to pin an exact count", lower, b)
		}
	}
}
