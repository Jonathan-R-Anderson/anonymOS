package ethproof

// Real proofs from Ethereum mainnet — roadmap P12-2.
//
// Read-only. Needs no funds, no deployment and no disk, which is why it is the
// right next step: it tests the architecture we already have rather than one we
// would have to buy.
//
//	CHAIN_PROBE=1 ETH_RPC_URL=... go test ./internal/ethproof/ -run Live -v
//
// WHAT THIS PROVES AND WHAT IT DOES NOT
// -------------------------------------
// It proves the SHAPE and the ECONOMICS: that a storage slot can be recovered
// from a block header's state root without believing the provider's answer, and
// what that costs in bytes and milliseconds.
//
// It does NOT prove independence. The header still comes from the same provider
// serving the proof, so a provider willing to fabricate a whole consistent
// history is not caught here. Narrowing that to the header alone is real
// progress; removing it is P12-5.

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// The deployed V1 ChannelManager. ChannelManagerV2 is not on mainnet, so this
// stands in: same mapping-of-struct shape, real storage, real trie depth.
const deployedChannelManager = "0xae70526931FF460894133201f6C8cA91bbA0E177"

func liveClient(t *testing.T) *Client {
	t.Helper()
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1 to measure against a real chain")
	}
	endpoint := os.Getenv("ETH_RPC_URL")
	if endpoint == "" {
		t.Skip("set ETH_RPC_URL")
	}
	return NewClient(endpoint)
}

// The whole chain, end to end, against mainnet.
func TestLiveVerifiedReadFromMainnet(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The eleven slots of one channel, laid out as ChannelManagerV2 would:
	// `channels` at position 0, so a channel begins at keccak256(id ‖ 0).
	var id [32]byte
	id[31] = 1
	base := StorageSlotKey(id, 0)
	slots := make([][32]byte, 11)
	for i := range slots {
		slots[i] = SlotAt(base, uint64(i))
	}

	m, err := VerifiedRead(ctx, c, deployedChannelManager, slots, "latest")
	if err != nil {
		t.Fatalf("VerifiedRead: %v", err)
	}

	if !m.AccountVerified {
		t.Fatal("the account proof did not verify against the header's stateRoot")
	}
	// The storage root we RECOVERED must match the one the provider claimed. A
	// mismatch would mean the provider's own fields disagree with its proof.
	if !m.StorageRootAgree {
		t.Errorf("recovered storageRoot %x but the RPC claimed %x",
			m.StorageRoot[:8], m.ClaimedStorage[:8])
	}
	for i, s := range m.Slots {
		if !s.Agrees {
			t.Errorf("slot %d: proof commits to %x, RPC claimed %x",
				i, s.Value[:8], s.Claimed[:8])
		}
	}

	t.Logf("block %d  stateRoot %s", m.BlockNumber, m.StateRoot[:18])
	t.Logf("account proof: %d nodes, %d bytes", m.AccountNodes, m.AccountProofLen)
	total := 0
	for i, s := range m.Slots {
		total += s.ProofLen
		t.Logf("  slot %2d: %d nodes, %5d bytes, absent=%v", i, s.Nodes, s.ProofLen, s.Absent)
	}
	t.Logf("TOTAL for an 11-slot channel: %d bytes in %s", m.TotalBytes(), m.Elapsed)

	// The figures doc/ethereum-data-layer.md costed the architecture on.
	t.Logf("assumed in the doc: account 5120 B, per-slot 3072 B, channel ~38 KB")
	t.Logf("measured:           account %d B, per-slot ~%d B, channel %d B",
		m.AccountProofLen, total/len(m.Slots), m.TotalBytes())
}

// A proof must not verify against the wrong root. Without this the verifier
// could be returning the provider's value for any input at all.
func TestLiveAProofDoesNotVerifyAgainstAnotherRoot(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	header, err := c.Header(ctx, "latest")
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	var id [32]byte
	id[31] = 1
	slots := [][32]byte{StorageSlotKey(id, 0)}

	proof, err := c.GetProof(ctx, deployedChannelManager, slots, header.Number)
	if err != nil {
		t.Fatalf("getProof: %v", err)
	}
	nodes, _, err := decodeNodes(proof.AccountProof)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	addr, _ := decodeHexBytes(deployedChannelManager)

	// A root that is not this block's.
	var wrong [32]byte
	for i := range wrong {
		wrong[i] = 0xAB
	}
	if _, err := VerifyProof(wrong[:], addr, nodes); err == nil {
		t.Fatal("a mainnet proof verified against a fabricated state root")
	}
}

// A single altered byte anywhere in the proof must break it.
func TestLiveATamperedProofIsRejected(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	header, err := c.Header(ctx, "latest")
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	var id [32]byte
	id[31] = 1
	proof, err := c.GetProof(ctx, deployedChannelManager,
		[][32]byte{StorageSlotKey(id, 0)}, header.Number)
	if err != nil {
		t.Fatalf("getProof: %v", err)
	}
	stateRoot, _ := decodeHex32(header.StateRoot)
	addr, _ := decodeHexBytes(deployedChannelManager)
	nodes, _, _ := decodeNodes(proof.AccountProof)

	// Flip a bit in the last node — the one nearest the value, where a lie
	// would be most useful.
	victim := len(nodes) - 1
	original := append([]byte(nil), nodes[victim]...)
	nodes[victim][len(nodes[victim])/2] ^= 0x01

	if _, err := VerifyProof(stateRoot[:], addr, nodes); err == nil {
		t.Fatal("a proof with a flipped bit still verified")
	}
	nodes[victim] = original
	if _, err := VerifyProof(stateRoot[:], addr, nodes); err != nil {
		t.Fatalf("restoring the byte did not restore the proof: %v", err)
	}
}

// Absence is an answer. An unwritten channel proves absent rather than failing,
// and the caller must be able to tell that from a broken proof.
func TestLiveAnUnwrittenSlotProvesAbsent(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A channel id nobody has ever opened.
	var id [32]byte
	for i := range id {
		id[i] = 0xDE
	}
	m, err := VerifiedRead(ctx, c, deployedChannelManager,
		[][32]byte{StorageSlotKey(id, 0)}, "latest")
	if err != nil {
		t.Fatalf("VerifiedRead: %v", err)
	}
	if !m.Slots[0].Absent {
		t.Errorf("an unwritten slot did not prove absent (value %x)", m.Slots[0].Value)
	}
	var zero [32]byte
	if m.Slots[0].Value != zero {
		t.Errorf("an absent slot returned %x, want zero", m.Slots[0].Value)
	}
	t.Logf("proof of absence: %d nodes, %d bytes", m.Slots[0].Nodes, m.Slots[0].ProofLen)
}

// What a header costs, since Strategy B fetches one per block forever.
func TestLiveHeaderCost(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const samples = 5
	var worst time.Duration
	for i := 0; i < samples; i++ {
		started := time.Now()
		h, err := c.Header(ctx, "latest")
		if err != nil {
			t.Fatalf("header %d: %v", i, err)
		}
		if took := time.Since(started); took > worst {
			worst = took
		}
		if len(h.LogsBloom) != 2+512 {
			t.Errorf("logsBloom is %d hex chars, want 512", len(h.LogsBloom)-2)
		}
	}
	t.Logf("header fetch worst of %d: %s", samples, worst)
	t.Logf("logsBloom is 256 bytes — the per-block cost of asking "+
		"'could this block contain our contract's logs'")
}

func TestSlotArithmetic(t *testing.T) {
	// keccak256(id ‖ uint256(0)) for a mapping at position 0, then consecutive
	// slots for the struct's members.
	var id [32]byte
	id[31] = 1
	base := StorageSlotKey(id, 0)

	if SlotAt(base, 0) != base {
		t.Error("slot 0 of a struct is not its base")
	}
	// Carrying across a byte boundary is where a hand-rolled adder breaks.
	var edge [32]byte
	edge[31] = 0xFF
	next := SlotAt(edge, 1)
	if next[31] != 0x00 || next[30] != 0x01 {
		t.Errorf("carry failed: %x", next[28:])
	}
	t.Logf("channels[0x..01] begins at slot %s", hex.EncodeToString(base[:]))
}

// A populated slot, which is the number the architecture actually rests on.
//
// The channel measurement above reads a contract where those slots have never
// been written, so every proof is a proof of ABSENCE — and absence proofs
// terminate early, at the first node that diverges. Costing the design on them
// would understate every real read.
//
// WETH is the stand-in: a huge, deeply populated storage trie, so a proof into
// it is a realistic worst case for a contract with many channels.
func TestLiveAPopulatedSlotCostsMore(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
	// balanceOf is a mapping at position 3. The holder is WETH's own largest
	// counterparty class; any address with a balance would do.
	holders := []string{
		"0x2f0b23f53734fa66ab551a3d5b9c2b0c1f5d8f3b",
		"0x8EB8a3b98659Cce290402893d0123abb75E3ab28",
		"0x28C6c06298d514Db089934071355E5743bf21d60",
	}
	var slots [][32]byte
	for _, h := range holders {
		var key [32]byte
		raw, err := decodeHexBytes(h)
		if err != nil {
			t.Fatalf("holder: %v", err)
		}
		copy(key[32-len(raw):], raw)
		slots = append(slots, StorageSlotKey(key, 3))
	}

	m, err := VerifiedRead(ctx, c, weth, slots, "latest")
	if err != nil {
		t.Fatalf("VerifiedRead: %v", err)
	}
	if !m.AccountVerified {
		t.Fatal("WETH's account proof did not verify")
	}

	present, absent := 0, 0
	presentBytes, absentBytes := 0, 0
	for i, s := range m.Slots {
		if s.Absent {
			absent++
			absentBytes += s.ProofLen
		} else {
			present++
			presentBytes += s.ProofLen
		}
		if !s.Agrees {
			t.Errorf("slot %d: proof commits to %x, RPC claimed %x", i, s.Value[:8], s.Claimed[:8])
		}
		t.Logf("  slot %d: %d nodes, %d bytes, absent=%v", i, s.Nodes, s.ProofLen, s.Absent)
	}
	t.Logf("account proof: %d nodes, %d bytes", m.AccountNodes, m.AccountProofLen)
	if present > 0 {
		t.Logf("PRESENT slots: %d, mean %d bytes each", present, presentBytes/present)
	}
	if absent > 0 {
		t.Logf("absent slots:  %d, mean %d bytes each", absent, absentBytes/absent)
	}
	t.Logf("verified read in %s", m.Elapsed)
}
