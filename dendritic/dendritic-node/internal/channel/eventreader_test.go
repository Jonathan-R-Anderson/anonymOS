package channel

// P14.5 — the event-driven reader, against a synthetic but REAL chain.
//
// "Synthetic" here means the blocks are ours; it does not mean the cryptography
// is faked. Every header is RLP-encoded and hashed by the production encoder,
// every receipts root is built by the production trie builder, and every bloom
// is derived by the production bloom code. A test chain that computed its roots
// some other way would be testing the test.
//
// The adversarial cases are the point. Each one is a thing a hostile or broken
// provider can actually do, and each must produce a REFUSAL rather than a
// plausible answer.

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

// pragueTime is safely inside the recorded Prague/Osaka layout window.
const pragueTime uint64 = 1_760_000_000

// synthBlock is one block of the test chain, with everything needed to serve it
// as both an untrusted header and an authenticated payload.
type synthBlock struct {
	number   uint64
	hash     [32]byte
	parent   [32]byte
	header   ethproof.ExecutionHeader
	receipts []ethproof.Receipt
	bloom    ethproof.Bloom2048
	rroot    ethproof.Root
}

// synthChain builds a chain whose roots and hashes are computed by production
// code, so a bug in that code fails these tests rather than hiding in them.
type synthChain struct {
	blocks []synthBlock
}

func newSynthChain(t *testing.T, start uint64, count int,
	logsFor func(n uint64) []ethproof.Log) *synthChain {
	t.Helper()

	c := &synthChain{}
	var parent [32]byte
	parent[0] = 0xAA
	for i := 0; i < count; i++ {
		n := start + uint64(i)
		logs := logsFor(n)

		// One receipt carrying the logs, plus a filler receipt so the trie has
		// more than a single leaf and the branch/extension paths are exercised.
		receipts := []ethproof.Receipt{
			{TxIndex: 0, Type: 2, Status: 1, CumulativeGasUsed: 21000},
			{TxIndex: 1, Type: 0, Status: 1, CumulativeGasUsed: 42000, Logs: logs},
		}
		for i := range receipts {
			receipts[i].Bloom = ethproof.BloomFromLogs(receipts[i].Logs)
		}
		root, err := ethproof.ReceiptsRoot(receipts)
		if err != nil {
			t.Fatalf("receipts root: %v", err)
		}
		var bloom ethproof.Bloom2048
		for _, r := range receipts {
			for j := range bloom {
				bloom[j] |= r.Bloom[j]
			}
		}

		h := prageHeader(parent, n, root, bloom)
		encoded, err := ethproof.EncodeExecutionHeader(h, ethproof.ForkPrague)
		if err != nil {
			t.Fatalf("encode header: %v", err)
		}
		var hash [32]byte
		copy(hash[:], ethproof.Keccak256(encoded))

		var rroot ethproof.Root
		copy(rroot[:], root)
		c.blocks = append(c.blocks, synthBlock{
			number: n, hash: hash, parent: parent, header: h,
			receipts: receipts, bloom: bloom, rroot: rroot,
		})
		parent = hash
	}
	return c
}

func prageHeader(parent [32]byte, n uint64, receiptsRoot []byte,
	bloom ethproof.Bloom2048) ethproof.ExecutionHeader {

	var wr, pbr, rh [32]byte
	wr[0], pbr[0], rh[0] = 0x11, 0x22, 0x33
	zero := uint64(0)
	h := ethproof.ExecutionHeader{
		ParentHash: parent,
		Difficulty: new(big.Int),
		Number:     new(big.Int).SetUint64(n),
		GasLimit:   30_000_000,
		GasUsed:    100_000,
		Time:       pragueTime + n,
		Extra:      []byte("p145"),
		Bloom:      bloom,
		BaseFee:    big.NewInt(1_000_000_000),

		WithdrawalsRoot:       &wr,
		BlobGasUsed:           &zero,
		ExcessBlobGas:         &zero,
		ParentBeaconBlockRoot: &pbr,
		RequestsHash:          &rh,
	}
	copy(h.ReceiptRoot[:], receiptsRoot)
	return h
}

func (c *synthChain) at(n uint64) *synthBlock {
	for i := range c.blocks {
		if c.blocks[i].number == n {
			return &c.blocks[i]
		}
	}
	return nil
}

func (c *synthChain) head() synthBlock { return c.blocks[len(c.blocks)-1] }

// ---- the sources, with knobs for every adversarial case --------------------

type synthSource struct {
	chain *synthChain

	// Provider misbehaviour, one knob per attack in the matrix.
	omitReceiptAt    uint64 // drop a receipt from this block
	reorderAt        uint64 // return receipts in reverse array order
	modifyReceiptAt  uint64 // alter cumulativeGasUsed
	modifyLogAt      uint64 // alter a log's address
	modifyTopicAt    uint64 // alter a log's topic
	fabricateEventAt uint64 // invent an extra log
	wrongHeaderAt    uint64 // serve a header with a corrupted receiptsRoot
	modifyBloomAt    uint64 // alter a receipt's stored logsBloom
	zeroHeaderBloom  uint64 // serve a header whose bloom hides the contract

	mu    sync.Mutex
	calls int
}

func (s *synthSource) ReceiptsByNumber(ctx context.Context, n uint64) ([]ethproof.Receipt, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()

	b := s.chain.at(n)
	if b == nil {
		return nil, fmt.Errorf("no block %d", n)
	}
	out := deepCopyReceipts(b.receipts)

	switch {
	case s.omitReceiptAt == n:
		out = out[:1]
	case s.reorderAt == n:
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	case s.modifyReceiptAt == n:
		out[0].CumulativeGasUsed++
	case s.modifyLogAt == n && len(out[1].Logs) > 0:
		out[1].Logs[0].Address[0] ^= 0xFF
	case s.modifyTopicAt == n && len(out[1].Logs) > 0 && len(out[1].Logs[0].Topics) > 1:
		out[1].Logs[0].Topics[1][31] ^= 0x01
	case s.modifyBloomAt == n:
		out[1].Bloom[7] ^= 0x08
	case s.fabricateEventAt == n:
		out[1].Logs = append(out[1].Logs, closeStartedLog(managerAddr, [32]byte{9, 9, 9}, 99, 0))
	}
	return out, nil
}

func (s *synthSource) HeadersDescending(ctx context.Context, from uint64, count int) ([]ethproof.ExecutionHeader, error) {
	var out []ethproof.ExecutionHeader
	for i := 0; i < count; i++ {
		b := s.chain.at(from - uint64(i))
		if b == nil {
			return nil, fmt.Errorf("no block %d", from-uint64(i))
		}
		h := b.header
		if s.wrongHeaderAt == b.number {
			h.ReceiptRoot[0] ^= 0xFF
		}
		if s.zeroHeaderBloom == b.number {
			h.Bloom = ethproof.Bloom2048{}
		}
		out = append(out, h)
	}
	return out, nil
}

func deepCopyReceipts(in []ethproof.Receipt) []ethproof.Receipt {
	out := make([]ethproof.Receipt, len(in))
	for i, r := range in {
		c := r
		c.Logs = make([]ethproof.Log, len(r.Logs))
		for j, l := range r.Logs {
			nl := l
			nl.Data = append([]byte(nil), l.Data...)
			// Topics copied INDIVIDUALLY. Copying the outer slice alone shares
			// every topic's bytes, and a mutation case would then corrupt the
			// chain it is measured against.
			nl.Topics = make([][32]byte, len(l.Topics))
			copy(nl.Topics, l.Topics)
			c.Logs[j] = nl
		}
		out[i] = c
	}
	return out
}

// synthFinal serves a chosen block as the authenticated finalised head.
type synthFinal struct {
	chain *synthChain
	head  uint64

	// forgeHashAt makes the "authenticated" head claim a hash the chain does not
	// have — the reorg-at-finality case.
	forgeHash bool
}

func (f *synthFinal) FinalizedBlock(ctx context.Context) (ethproof.AuthenticatedBlock, error) {
	b := f.chain.at(f.head)
	if b == nil {
		return ethproof.AuthenticatedBlock{}, fmt.Errorf("no head %d", f.head)
	}
	p := ethproof.ExecutionPayloadHeader{
		ParentHash:   b.parent,
		ReceiptsRoot: b.rroot,
		LogsBloom:    b.bloom,
		BlockNumber:  b.number,
		BlockHash:    b.hash,
		Timestamp:    b.header.Time,
	}
	if f.forgeHash {
		p.BlockHash[0] ^= 0xFF
	}
	return ethproof.BlockFromFinalizedPayload(p), nil
}

// memCheckpoints is an in-memory CheckpointStore that survives a "restart"
// because the test holds it, exactly as a file would.
type memCheckpoints struct {
	mu  sync.Mutex
	cp  ethproof.FollowerCheckpoint
	set bool
}

func (m *memCheckpoints) LoadCheckpoint() (ethproof.FollowerCheckpoint, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cp, m.set, nil
}
func (m *memCheckpoints) SaveCheckpoint(cp ethproof.FollowerCheckpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cp, m.set = cp, true
	return nil
}

// ---- fixtures ---------------------------------------------------------------

var managerAddr = [20]byte{
	0xae, 0x70, 0x52, 0x69, 0x31, 0xFF, 0x46, 0x08, 0x94, 0x13,
	0x32, 0x01, 0xf6, 0xC8, 0xcA, 0x91, 0xbb, 0xA0, 0xE1, 0x77,
}

func topicOf(sig string) [32]byte {
	var t [32]byte
	copy(t[:], keccak([]byte(sig)))
	return t
}

func closeStartedLog(addr [20]byte, id [32]byte, nonce uint64, ends int64) ethproof.Log {
	data := make([]byte, 64)
	for i := 0; i < 8; i++ {
		data[31-i] = byte(nonce >> (8 * i))
		data[63-i] = byte(ends >> (8 * i))
	}
	var by [32]byte
	by[31] = 0x01
	return ethproof.Log{
		Address: addr,
		Topics: [][32]byte{
			topicOf("CloseStarted(bytes32,address,uint64,uint256)"), id, by,
		},
		Data: data,
	}
}

// countingReader records how often the chain was actually consulted, which is
// the whole quantity this design changes.
type countingReader struct {
	mu    sync.Mutex
	reads map[[32]byte]int
	occ   func(id [32]byte) OnChainChannel
	err   error
}

func (c *countingReader) ReadChannel(ctx context.Context, contract Address, id [32]byte) (OnChainChannel, error) {
	c.mu.Lock()
	if c.reads == nil {
		c.reads = map[[32]byte]int{}
	}
	c.reads[id]++
	c.mu.Unlock()
	if c.err != nil {
		return OnChainChannel{}, c.err
	}
	if c.occ != nil {
		return c.occ(id), nil
	}
	return OnChainChannel{ID: id}, nil
}

func (c *countingReader) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.reads {
		n += v
	}
	return n
}

func (c *countingReader) forID(id [32]byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads[id]
}

// harness wires a follower and reader over a synthetic chain.
type harness struct {
	chain  *synthChain
	src    *synthSource
	final  *synthFinal
	store  *memCheckpoints
	inner  *countingReader
	reader *EventChainReader
}

func newHarness(t *testing.T, chain *synthChain, tweak func(*synthSource)) *harness {
	t.Helper()
	src := &synthSource{chain: chain}
	if tweak != nil {
		tweak(src)
	}
	final := &synthFinal{chain: chain, head: chain.head().number}
	store := &memCheckpoints{}
	inner := &countingReader{}

	f := &ethproof.ChainFollower{
		ChainID: 1, Contract: managerAddr,
		Headers: src, Finalized: final, Store: store, BatchSize: 8,
	}
	// Start at the first block, so everything after it must be caught up.
	if err := f.InitializeAt(ethproof.FollowerCheckpoint{
		BlockNumber: chain.blocks[0].number, BlockHash: chain.blocks[0].hash,
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	return &harness{
		chain: chain, src: src, final: final, store: store, inner: inner,
		reader: &EventChainReader{
			Inner: inner, Follower: f, Contract: Address{},
			RefreshInterval: time.Nanosecond,
		},
	}
}

var chanA = [32]byte{1}
var chanB = [32]byte{2}

// quietChain has no channel events at all — the common case.
func quietChain(t *testing.T) *synthChain {
	return newSynthChain(t, 1000, 12, func(n uint64) []ethproof.Log { return nil })
}

// ---- the matrix -------------------------------------------------------------

func TestP145ReaderAnswersFromAuthenticatedStateWithoutReading(t *testing.T) {
	h := newHarness(t, quietChain(t), nil)
	ctx := context.Background()

	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatalf("first read: %v", err)
	}
	first := h.inner.total()
	if first != 1 {
		t.Fatalf("first read consulted the chain %d times, want 1", first)
	}
	// Every later sweep must be free: no event named this channel, so its state
	// is PROVEN unchanged.
	for i := 0; i < 50; i++ {
		if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if got := h.inner.total(); got != 1 {
		t.Fatalf("50 further sweeps cost %d chain reads, want 0 beyond the first", got-1)
	}
}

func TestP145EventInvalidatesOnlyItsOwnChannel(t *testing.T) {
	// Blocks 1000..1011; block 1005 closes channel A.
	chain := newSynthChain(t, 1000, 12, func(n uint64) []ethproof.Log {
		if n == 1005 {
			return []ethproof.Log{closeStartedLog(managerAddr, chanA, 7, 1234)}
		}
		return nil
	})
	h := newHarness(t, chain, nil)
	ctx := context.Background()

	// Prime both channels while the follower is still at block 1000.
	h.final.head = 1000
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanB); err != nil {
		t.Fatal(err)
	}
	beforeA, beforeB := h.inner.forID(chanA), h.inner.forID(chanB)

	// Advance past the close.
	h.final.head = 1011
	var seen []ChannelEvent
	h.reader.OnEvent = func(ev ChannelEvent) { seen = append(seen, ev) }
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanB); err != nil {
		t.Fatal(err)
	}

	if h.inner.forID(chanA) != beforeA+1 {
		t.Errorf("channel A was not re-read after its own CloseStarted")
	}
	if h.inner.forID(chanB) != beforeB {
		t.Errorf("channel B was re-read (%d -> %d) although no event named it",
			beforeB, h.inner.forID(chanB))
	}
	if len(seen) != 1 || seen[0].Kind != EventCloseStarted {
		t.Fatalf("expected one CloseStarted, got %+v", seen)
	}
	// E: the deadline arrives WITH the event, so nothing has to poll for it.
	if seen[0].Nonce != 7 || seen[0].ChallengeEnds != 1234 {
		t.Errorf("CloseStarted carried nonce=%d challengeEnds=%d, want 7 and 1234",
			seen[0].Nonce, seen[0].ChallengeEnds)
	}
}

func TestP145ProviderTamperingIsRefused(t *testing.T) {
	// Every case here is a real thing a provider can do. Each must REFUSE.
	cases := []struct {
		name  string
		tweak func(*synthSource)
	}{
		{"omitted receipt", func(s *synthSource) { s.omitReceiptAt = 1005 }},
		{"modified receipt", func(s *synthSource) { s.modifyReceiptAt = 1005 }},
		{"modified log", func(s *synthSource) { s.modifyLogAt = 1005 }},
		{"modified topic", func(s *synthSource) { s.modifyTopicAt = 1005 }},
		{"fabricated event", func(s *synthSource) { s.fabricateEventAt = 1005 }},
		{"wrong receipts root in header", func(s *synthSource) { s.wrongHeaderAt = 1005 }},
		{"wrong logs bloom on a receipt", func(s *synthSource) { s.modifyBloomAt = 1005 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := newSynthChain(t, 1000, 12, func(n uint64) []ethproof.Log {
				if n == 1005 {
					return []ethproof.Log{closeStartedLog(managerAddr, chanA, 7, 1234)}
				}
				return nil
			})
			h := newHarness(t, chain, tc.tweak)
			_, err := h.reader.ReadChannel(context.Background(), Address{}, chanA)
			if err == nil {
				t.Fatalf("%s was ACCEPTED — the reader served an answer built on it", tc.name)
			}
			if !errors.Is(err, ErrFollowerNotReady) {
				t.Fatalf("%s produced %v, which is not a fail-closed refusal", tc.name, err)
			}
		})
	}
}

// The attack that needs the header hash check specifically.
//
// A forged bloom is worse than a forged receipt: a wrong receipt is CAUGHT by
// the root comparison, but a bloom with the contract's bits cleared makes the
// follower SKIP the block, and a skipped block is never fetched, so nothing
// downstream ever gets the chance to notice. Only re-hashing the header stops
// it.
func TestP145ForgedHeaderBloomCannotHideAnEvent(t *testing.T) {
	chain := newSynthChain(t, 1000, 8, func(n uint64) []ethproof.Log {
		if n == 1004 {
			return []ethproof.Log{closeStartedLog(managerAddr, chanA, 7, 1234)}
		}
		return nil
	})
	// The honest block really does admit our contract, so a skip could only come
	// from the forgery.
	if !ethproof.MayContain(chain.at(1004).bloom, managerAddr[:]) {
		t.Fatal("fixture is wrong: block 1004 should be bloom-positive")
	}

	h := newHarness(t, chain, func(s *synthSource) { s.zeroHeaderBloom = 1004 })
	var seen []ChannelEvent
	h.reader.OnEvent = func(ev ChannelEvent) { seen = append(seen, ev) }

	_, err := h.reader.ReadChannel(context.Background(), Address{}, chanA)
	if err == nil {
		t.Fatalf("a header with a cleared logsBloom was accepted; the CloseStarted "+
			"was skipped and the watchtower saw %d events", len(seen))
	}
	if !errors.Is(err, ErrFollowerNotReady) {
		t.Fatalf("want a fail-closed refusal, got %v", err)
	}
}

func TestP145ReorderedReceiptsAreFine(t *testing.T) {
	// The one alteration that must NOT be refused: a trie is a set, and the key
	// is the declared transactionIndex. Refusing here would make the watchtower
	// hostage to a provider's array order.
	chain := newSynthChain(t, 1000, 6, func(n uint64) []ethproof.Log {
		if n == 1003 {
			return []ethproof.Log{closeStartedLog(managerAddr, chanA, 3, 99)}
		}
		return nil
	})
	h := newHarness(t, chain, func(s *synthSource) { s.reorderAt = 1003 })
	var seen []ChannelEvent
	h.reader.OnEvent = func(ev ChannelEvent) { seen = append(seen, ev) }
	if _, err := h.reader.ReadChannel(context.Background(), Address{}, chanA); err != nil {
		t.Fatalf("reordered receipts were refused: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("expected the event to survive reordering, saw %d", len(seen))
	}
}

// bloomPositionsOf recomputes the three bits an item sets, independently of
// bloom.go. A test that reused the production helper could not tell a correct
// filter from a consistently wrong one.
func bloomPositionsOf(item []byte) [3]uint {
	h := ethproof.Keccak256(item)
	var out [3]uint
	for i := 0; i < 3; i++ {
		out[i] = (uint(h[2*i])<<8 | uint(h[2*i+1])) & 0x7FF
	}
	return out
}

// logsForcingBloomPositive returns logs from `from` — a DIFFERENT contract —
// whose topics happen to set exactly the bits `target` sets.
//
// This manufactures a genuine bloom false positive, which is the only way to
// test the address filter at all: a block whose bloom excludes our contract is
// skipped before any log is looked at, so a foreign-contract test without this
// would pass while proving nothing.
func logsForcingBloomPositive(t *testing.T, from [20]byte, target [20]byte) []ethproof.Log {
	t.Helper()
	want := bloomPositionsOf(target[:])
	var have ethproof.Bloom2048
	set := func(bit uint) bool { return have[255-bit/8]&(1<<(bit%8)) != 0 }

	topics := [][32]byte{}
	for _, bit := range want {
		if set(bit) {
			continue
		}
		found := false
		for n := uint64(0); n < 2_000_000 && !found; n++ {
			var cand [32]byte
			for i := 0; i < 8; i++ {
				cand[31-i] = byte(n >> (8 * i))
			}
			for _, p := range bloomPositionsOf(cand[:]) {
				if p == bit {
					topics = append(topics, cand)
					ethproof.AddToBloom(&have, cand[:])
					found = true
					break
				}
			}
		}
		if !found {
			t.Fatalf("could not find a topic setting bloom bit %d", bit)
		}
	}
	if !ethproof.MayContain(have, target[:]) {
		t.Fatalf("failed to manufacture a bloom false positive")
	}
	out := []ethproof.Log{}
	for _, tp := range topics {
		out = append(out, ethproof.Log{Address: from, Topics: [][32]byte{tp}})
	}
	return out
}

func TestP145WrongContractAddressIsIgnored(t *testing.T) {
	// A different contract, in a block whose bloom DOES admit our address. The
	// bloom lets the block through, the receipts authenticate, and the address
	// filter is the thing that has to save us.
	other := managerAddr
	other[0] ^= 0xFF

	var forced []ethproof.Log
	chain := newSynthChain(t, 1000, 8, func(n uint64) []ethproof.Log {
		if n == 1004 {
			if forced == nil {
				forced = append(logsForcingBloomPositive(t, other, managerAddr),
					closeStartedLog(other, chanA, 7, 1234))
			}
			return forced
		}
		return nil
	})

	// The test is only meaningful if the bloom really is positive for us.
	if !ethproof.MayContain(chain.at(1004).bloom, managerAddr[:]) {
		t.Fatal("block 1004's bloom excludes our contract, so the address filter " +
			"is never reached and this test would prove nothing")
	}

	h := newHarness(t, chain, nil)
	ctx := context.Background()

	h.final.head = 1000
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	before := h.inner.forID(chanA)

	h.final.head = 1007
	var seen []ChannelEvent
	h.reader.OnEvent = func(ev ChannelEvent) { seen = append(seen, ev) }
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	// The receipts WERE fetched — that is the false positive costing work.
	h.src.mu.Lock()
	fetched := h.src.calls
	h.src.mu.Unlock()
	if fetched == 0 {
		t.Fatal("the bloom-positive block was never fetched; the filter path did not run")
	}
	if len(seen) != 0 {
		t.Errorf("an event from another contract was decoded as ours: %+v", seen)
	}
	if h.inner.forID(chanA) != before {
		t.Errorf("another contract's event invalidated our channel's cache")
	}
}

func TestP145WrongChannelIDDoesNotInvalidate(t *testing.T) {
	chain := newSynthChain(t, 1000, 8, func(n uint64) []ethproof.Log {
		if n == 1004 {
			return []ethproof.Log{closeStartedLog(managerAddr, chanB, 7, 1234)}
		}
		return nil
	})
	h := newHarness(t, chain, nil)
	ctx := context.Background()

	h.final.head = 1000
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	before := h.inner.forID(chanA)

	h.final.head = 1007
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	if h.inner.forID(chanA) != before {
		t.Errorf("an event for channel B forced a re-read of channel A")
	}
}

func TestP145MissingEventMeansTheChannelLooksQuiet(t *testing.T) {
	// The attack eth_getLogs cannot survive: the provider simply does not
	// mention the CloseStarted. Here the receipt carrying it is dropped, so the
	// trie no longer matches and the whole block is REFUSED — the watchtower
	// stops rather than concluding the channel is quiet.
	chain := newSynthChain(t, 1000, 8, func(n uint64) []ethproof.Log {
		if n == 1004 {
			return []ethproof.Log{closeStartedLog(managerAddr, chanA, 7, 1234)}
		}
		return nil
	})
	h := newHarness(t, chain, func(s *synthSource) { s.omitReceiptAt = 1004 })

	_, err := h.reader.ReadChannel(context.Background(), Address{}, chanA)
	if err == nil {
		t.Fatal("a suppressed CloseStarted produced a quiet answer — the exact " +
			"failure this design exists to prevent")
	}
	if !errors.Is(err, ErrFollowerNotReady) {
		t.Fatalf("want a fail-closed refusal, got %v", err)
	}
}

func TestP145RestartWithoutACheckpointRefuses(t *testing.T) {
	chain := quietChain(t)
	src := &synthSource{chain: chain}
	f := &ethproof.ChainFollower{
		ChainID: 1, Contract: managerAddr, Headers: src,
		Finalized: &synthFinal{chain: chain, head: chain.head().number},
		Store:     &memCheckpoints{}, // EMPTY: a fresh process with no memory
	}
	r := &EventChainReader{Inner: &countingReader{}, Follower: f, RefreshInterval: time.Nanosecond}

	_, err := r.ReadChannel(context.Background(), Address{}, chanA)
	if err == nil {
		t.Fatal("a watchtower with no checkpoint served an answer; it cannot " +
			"distinguish a quiet chain from having been switched off")
	}
	if !errors.Is(err, ErrFollowerNotReady) {
		t.Fatalf("want ErrFollowerNotReady, got %v", err)
	}
}

func TestP145RestartAfterDowntimeSeesWhatItMissed(t *testing.T) {
	// The close happens while the process is DOWN. On restart it must find it.
	chain := newSynthChain(t, 1000, 30, func(n uint64) []ethproof.Log {
		if n == 1015 {
			return []ethproof.Log{closeStartedLog(managerAddr, chanA, 11, 555)}
		}
		return nil
	})
	src := &synthSource{chain: chain}
	store := &memCheckpoints{}
	final := &synthFinal{chain: chain, head: 1010}

	newFollower := func() *ethproof.ChainFollower {
		return &ethproof.ChainFollower{
			ChainID: 1, Contract: managerAddr, Headers: src,
			Finalized: final, Store: store, BatchSize: 7,
		}
	}
	f := newFollower()
	if err := f.InitializeAt(ethproof.FollowerCheckpoint{
		BlockNumber: 1000, BlockHash: chain.at(1000).hash,
	}); err != nil {
		t.Fatal(err)
	}
	r1 := &EventChainReader{Inner: &countingReader{}, Follower: f, RefreshInterval: time.Nanosecond}
	if _, err := r1.ReadChannel(context.Background(), Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	if r1.Head() != 1010 {
		t.Fatalf("head is %d, want 1010", r1.Head())
	}

	// ---- the process dies here. The chain moves on past the close. ----
	final.head = 1029

	// A brand-new reader and follower, sharing only the persisted checkpoint.
	r2 := &EventChainReader{
		Inner: &countingReader{}, Follower: newFollower(), RefreshInterval: time.Nanosecond,
	}
	var seen []ChannelEvent
	r2.OnEvent = func(ev ChannelEvent) { seen = append(seen, ev) }
	if _, err := r2.ReadChannel(context.Background(), Address{}, chanA); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if len(seen) != 1 || seen[0].Kind != EventCloseStarted || seen[0].Block != 1015 {
		t.Fatalf("the restarted watchtower did not see the close it slept through: %+v", seen)
	}
	if r2.Head() != 1029 {
		t.Fatalf("head after catch-up is %d, want 1029", r2.Head())
	}
}

func TestP145ReorgAtFinalityIsRefused(t *testing.T) {
	chain := quietChain(t)
	h := newHarness(t, chain, nil)
	ctx := context.Background()
	if _, err := h.reader.ReadChannel(ctx, Address{}, chanA); err != nil {
		t.Fatal(err)
	}

	// The "finalised" head now claims a hash the chain does not contain at that
	// height. Never silently accepted: that is history being rewritten.
	h.final.forgeHash = true
	h.final.head = chain.head().number
	_, err := h.reader.ReadChannel(ctx, Address{}, chanA)
	if err == nil {
		t.Fatal("a finalised head inconsistent with our checkpoint was accepted")
	}
	if !errors.Is(err, ErrFollowerNotReady) {
		t.Fatalf("want a fail-closed refusal, got %v", err)
	}
}

func TestP145ReorgOffOurCheckpointIsRefused(t *testing.T) {
	// A competing branch: same heights, different blocks. The backwards walk
	// must fail to link back to the recorded checkpoint.
	original := newSynthChain(t, 2000, 10, func(n uint64) []ethproof.Log { return nil })
	competing := newSynthChain(t, 2000, 10, func(n uint64) []ethproof.Log {
		if n == 2001 {
			return []ethproof.Log{closeStartedLog(managerAddr, chanB, 1, 1)}
		}
		return nil
	})

	store := &memCheckpoints{}
	// Recorded on the ORIGINAL branch...
	if err := store.SaveCheckpoint(ethproof.FollowerCheckpoint{
		BlockNumber: 2002, BlockHash: original.at(2002).hash,
	}); err != nil {
		t.Fatal(err)
	}
	// ...but the chain now served is the competing one.
	f := &ethproof.ChainFollower{
		ChainID: 1, Contract: managerAddr,
		Headers:   &synthSource{chain: competing},
		Finalized: &synthFinal{chain: competing, head: competing.head().number},
		Store:     store, BatchSize: 4,
	}
	_, err := f.Advance(context.Background(), func(ethproof.AuthenticatedBlock, []ethproof.Log) error {
		return nil
	})
	if err == nil {
		t.Fatal("the follower walked onto a competing branch without noticing")
	}
	if !errors.Is(err, ethproof.ErrReorgBeyondCheckpoint) &&
		!errors.Is(err, ethproof.ErrHeaderHashMismatch) {
		t.Fatalf("want a reorg refusal, got %v", err)
	}
}

func TestP145InterruptedCatchUpResumes(t *testing.T) {
	// A handler that fails partway must leave the checkpoint at the last block
	// actually processed — not at the head, which would skip everything after
	// the failure, and not at the start, which would redo work.
	chain := newSynthChain(t, 3000, 20, func(n uint64) []ethproof.Log { return nil })
	src := &synthSource{chain: chain}
	store := &memCheckpoints{}
	f := &ethproof.ChainFollower{
		ChainID: 1, Contract: managerAddr, Headers: src,
		Finalized: &synthFinal{chain: chain, head: 3019}, Store: store, BatchSize: 5,
	}
	if err := f.InitializeAt(ethproof.FollowerCheckpoint{
		BlockNumber: 3000, BlockHash: chain.at(3000).hash,
	}); err != nil {
		t.Fatal(err)
	}

	boom := errors.New("handler failed")
	seen := 0
	_, err := f.Advance(context.Background(), func(b ethproof.AuthenticatedBlock, _ []ethproof.Log) error {
		seen++
		if b.Number == 3005 {
			return boom
		}
		return nil
	})
	if err == nil {
		t.Fatal("a failing handler did not stop the advance")
	}
	cp, ok, _ := store.LoadCheckpoint()
	if !ok || cp.BlockNumber != 3004 {
		t.Fatalf("checkpoint is %d, want 3004 — the last block fully processed", cp.BlockNumber)
	}

	// Resuming picks up exactly at the failure.
	resumed := []uint64{}
	if _, err := f.Advance(context.Background(), func(b ethproof.AuthenticatedBlock, _ []ethproof.Log) error {
		resumed = append(resumed, b.Number)
		return nil
	}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if len(resumed) == 0 || resumed[0] != 3005 {
		t.Fatalf("resumed at %v, want it to start at 3005", resumed[:min(3, len(resumed))])
	}
}

func TestP145CatchUpBoundIsRefusalNotTruncation(t *testing.T) {
	chain := newSynthChain(t, 4000, 40, func(n uint64) []ethproof.Log { return nil })
	store := &memCheckpoints{}
	f := &ethproof.ChainFollower{
		ChainID: 1, Contract: managerAddr,
		Headers:   &synthSource{chain: chain},
		Finalized: &synthFinal{chain: chain, head: 4039},
		Store:     store, BatchSize: 5, MaxCatchUp: 10,
	}
	if err := f.InitializeAt(ethproof.FollowerCheckpoint{
		BlockNumber: 4000, BlockHash: chain.at(4000).hash,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.Advance(context.Background(), func(ethproof.AuthenticatedBlock, []ethproof.Log) error {
		return nil
	})
	if !errors.Is(err, ethproof.ErrCatchUpTooLarge) {
		t.Fatalf("a gap beyond the bound gave %v; it must REFUSE rather than "+
			"quietly process the last 10 blocks and call itself current", err)
	}
	// And the checkpoint must not have moved.
	cp, _, _ := store.LoadCheckpoint()
	if cp.BlockNumber != 4000 {
		t.Fatalf("the refused advance still moved the checkpoint to %d", cp.BlockNumber)
	}
}

func TestP145BloomNegativeSkipsWithoutFetching(t *testing.T) {
	// The 82% case. A block whose authenticated bloom excludes the contract must
	// cost ZERO receipt fetches.
	chain := quietChain(t)
	h := newHarness(t, chain, nil)
	if _, err := h.reader.ReadChannel(context.Background(), Address{}, chanA); err != nil {
		t.Fatal(err)
	}
	h.src.mu.Lock()
	fetches := h.src.calls
	h.src.mu.Unlock()
	if fetches != 0 {
		t.Fatalf("a chain with no contract logs still cost %d receipt fetches", fetches)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
