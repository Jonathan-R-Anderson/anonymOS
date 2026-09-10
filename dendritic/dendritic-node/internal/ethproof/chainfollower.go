package ethproof

// Following the authenticated chain across restarts — roadmap P14.5.
//
// THE FAILURE THIS FILE EXISTS TO PREVENT
// ---------------------------------------
// An event-driven watchtower is STATEFUL where a polling one is stateless. A
// polling watchtower that restarts asks the chain about every channel and is
// immediately correct again. An event-driven one that restarts knows only what
// it wrote down, and if it writes down nothing it has exactly three options:
//
//	scan back to the last authenticated point   correct, costs the gap
//	refuse to run until caught up               correct, fail-closed
//	start fresh from the current head           SILENTLY BLIND
//
// The third is the dangerous one, because it works. Everything downstream keeps
// functioning, no error is raised, and the only symptom is that a CloseStarted
// which fired during the outage is never seen — the precise event the watchtower
// exists to catch. So there is no code path here that begins at the current
// finalised head without an operator saying so in as many words.
//
// WALKING BACKWARDS BINDS BY HASH
// -------------------------------
// Catch-up never uses a height to decide which block is which. It starts at a
// finalised block the beacon chain authenticated and follows parentHash links,
// each one verified by re-encoding the header and hashing it. A reorg cannot
// move the walk onto a competing branch, because a competing branch's blocks do
// not hash to the parentHash values on this one.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	// ErrNoAuthenticatedCheckpoint means this follower has no recorded progress.
	// It must not run: it cannot tell a quiet chain from an outage.
	ErrNoAuthenticatedCheckpoint = errors.New(
		"ethproof: no authenticated checkpoint — the follower cannot distinguish " +
			"'nothing happened' from 'we were not watching', and must catch up or refuse")
	// ErrReorgBeyondCheckpoint means the finalised chain no longer contains the
	// block this follower had recorded as authenticated. Fail closed.
	ErrReorgBeyondCheckpoint = errors.New(
		"ethproof: the authenticated checkpoint is not an ancestor of the finalised head")
	// ErrCatchUpTooLarge means the gap exceeds the configured bound. Refused
	// rather than truncated: a truncated catch-up is silent blindness with extra
	// steps.
	ErrCatchUpTooLarge = errors.New("ethproof: catch-up gap exceeds the configured bound")
)

// FollowerCheckpoint is the follower's durable progress: the last block whose logs were
// fully processed, identified by HASH as well as height.
//
// The hash is what makes restart safe. A height alone would let a reorged-away
// block be mistaken for the one that was processed.
type FollowerCheckpoint struct {
	BlockNumber uint64   `json:"block_number"`
	BlockHash   [32]byte `json:"-"`
	BlockHashV  string   `json:"block_hash"`
}

// CheckpointStore persists follower progress.
type CheckpointStore interface {
	LoadCheckpoint() (FollowerCheckpoint, bool, error)
	SaveCheckpoint(FollowerCheckpoint) error
}

// HeaderSource supplies UNTRUSTED headers and receipts. Everything it returns is
// verified before use; it is named for what it is so that no call site mistakes
// it for an authority.
type HeaderSource interface {
	// HeadersDescending returns headers for [from, from-count+1], newest first.
	// Implementations should batch: the parentHash chain is serial to VERIFY but
	// not to FETCH, and that difference is most of the catch-up cost.
	HeadersDescending(ctx context.Context, from uint64, count int) ([]ExecutionHeader, error)
	// ReceiptsByNumber returns a block's receipts, unverified.
	ReceiptsByNumber(ctx context.Context, number uint64) ([]Receipt, error)
}

// FinalizedSource supplies an AUTHENTICATED finalised block. The implementation
// is responsible for having verified the SSZ execution branch.
type FinalizedSource interface {
	FinalizedBlock(ctx context.Context) (AuthenticatedBlock, error)
}

// FollowerMetrics is aggregate-only, like the rest of the metrics layer: counts
// and sizes, never an identifier.
//
// RateLimited is separate on purpose. A rate-limit event folded into a latency
// average disappears; kept apart it is a number an operator can watch, and the
// measurement work found the provider refusing this exact workload.
type FollowerMetrics interface {
	BlockAuthenticated()
	BlockSkippedByBloom()
	ReceiptsAuthenticated(count int)
	RateLimited()
}

// ChainFollower advances over finalised blocks, producing authenticated logs.
type ChainFollower struct {
	ChainID   uint64
	Contract  [20]byte
	Headers   HeaderSource
	Finalized FinalizedSource
	Store     CheckpointStore
	Metrics   FollowerMetrics

	// MaxCatchUp bounds a single Advance. Zero means unbounded. Exceeding it is
	// an ERROR, never a silent truncation.
	MaxCatchUp int
	// BatchSize is how many headers to request at once during catch-up.
	BatchSize int

	mu sync.Mutex
}

// Progress reports what one Advance did.
type Progress struct {
	From, To       uint64
	BlocksExamined int
	BlocksSkipped  int // the authenticated bloom proved the contract absent
	BlocksFetched  int // the bloom was positive, so receipts were authenticated
	LogsFound      int
}

// Initialize records the current finalised head as the starting point.
//
// THIS ACCEPTS BLINDNESS to everything before now, and is therefore an explicit
// operator action with a name that says so — never something Advance does for
// itself when it finds no checkpoint. For a watchtower already holding channels,
// this is the wrong call: it must catch up from when those channels were
// adopted, not from now.
func (f *ChainFollower) Initialize(ctx context.Context) (FollowerCheckpoint, error) {
	head, err := f.Finalized.FinalizedBlock(ctx)
	if err != nil {
		return FollowerCheckpoint{}, err
	}
	if !head.Authenticated() {
		return FollowerCheckpoint{}, ErrBlockNotAuthenticated
	}
	cp := FollowerCheckpoint{BlockNumber: head.Number, BlockHash: head.Hash}
	if err := f.Store.SaveCheckpoint(cp); err != nil {
		return FollowerCheckpoint{}, err
	}
	return cp, nil
}

// InitializeAt records a specific block as the starting point, for a watchtower
// that knows when its channels were adopted.
func (f *ChainFollower) InitializeAt(cp FollowerCheckpoint) error {
	if cp.BlockNumber == 0 || cp.BlockHash == ([32]byte{}) {
		return fmt.Errorf("%w: a checkpoint needs both a height and a hash",
			ErrNoAuthenticatedCheckpoint)
	}
	return f.Store.SaveCheckpoint(cp)
}

// Advance processes every finalised block after the checkpoint.
//
// handle is called once per block that the authenticated bloom did not exclude,
// with the logs that block's authenticated receipts contain for the contract.
// It may be called with an empty slice: a bloom false positive is an ordinary
// event, and "the bloom said maybe and the receipts said no" is a real answer.
//
// The checkpoint advances after EACH block, so an interrupted catch-up resumes
// where it stopped rather than starting over. A handler that returns an error
// stops the advance without moving past the block that failed.
func (f *ChainFollower) Advance(ctx context.Context,
	handle func(AuthenticatedBlock, []Log) error) (Progress, error) {

	f.mu.Lock()
	defer f.mu.Unlock()

	var prog Progress
	cp, ok, err := f.Store.LoadCheckpoint()
	if err != nil {
		return prog, err
	}
	if !ok {
		return prog, ErrNoAuthenticatedCheckpoint
	}

	head, err := f.Finalized.FinalizedBlock(ctx)
	if err != nil {
		return prog, err
	}
	if !head.Authenticated() {
		return prog, ErrBlockNotAuthenticated
	}
	prog.From, prog.To = cp.BlockNumber, head.Number

	switch {
	case head.Number == cp.BlockNumber:
		if head.Hash != cp.BlockHash {
			// Same height, different block, both claimed final. Never treat the
			// new one as simply superseding: that is exactly the silent
			// rewriting of history this must refuse.
			return prog, fmt.Errorf("%w: finalised head %d is %x, checkpoint is %x",
				ErrReorgBeyondCheckpoint, head.Number, head.Hash[:8], cp.BlockHash[:8])
		}
		return prog, nil
	case head.Number < cp.BlockNumber:
		// The finalised head went BACKWARDS past our checkpoint. Either the
		// beacon source is behind or finality was reverted; neither is something
		// to paper over.
		return prog, fmt.Errorf("%w: finalised head is %d, checkpoint is %d",
			ErrReorgBeyondCheckpoint, head.Number, cp.BlockNumber)
	}

	gap := int(head.Number - cp.BlockNumber)
	if f.MaxCatchUp > 0 && gap > f.MaxCatchUp {
		return prog, fmt.Errorf("%w: %d blocks behind, bound is %d",
			ErrCatchUpTooLarge, gap, f.MaxCatchUp)
	}

	// Walk backwards from the authenticated head to the checkpoint, binding each
	// step by hash. Collected newest-first, then processed oldest-first.
	chain, err := f.walkBack(ctx, head, cp)
	if err != nil {
		return prog, err
	}

	for i := len(chain) - 1; i >= 0; i-- {
		b := chain[i]
		prog.BlocksExamined++
		f.metricBlockAuthenticated()

		var logs []Log
		if !b.MayContainAddress(f.Contract) {
			// A bloom NEGATIVE is authoritative — no false negatives — so the
			// block is skipped with no further request. This is the 82% case.
			prog.BlocksSkipped++
			f.metricBlockSkipped()
		} else {
			receipts, err := f.Headers.ReceiptsByNumber(ctx, b.Number)
			if err != nil {
				return prog, fmt.Errorf("block %d receipts: %w", b.Number, err)
			}
			logs, err = b.AuthenticatedLogsFrom(f.Contract, receipts)
			if err != nil {
				return prog, err
			}
			prog.BlocksFetched++
			prog.LogsFound += len(logs)
			f.metricReceipts(len(receipts))
		}

		if err := handle(b, logs); err != nil {
			return prog, fmt.Errorf("block %d: %w", b.Number, err)
		}
		if err := f.Store.SaveCheckpoint(FollowerCheckpoint{
			BlockNumber: b.Number, BlockHash: b.Hash,
		}); err != nil {
			return prog, err
		}
	}
	return prog, nil
}

// walkBack returns the authenticated chain from head down to (but excluding) the
// checkpoint, newest first.
func (f *ChainFollower) walkBack(ctx context.Context,
	head AuthenticatedBlock, cp FollowerCheckpoint) ([]AuthenticatedBlock, error) {

	batch := f.BatchSize
	if batch <= 0 {
		batch = 100
	}

	chain := []AuthenticatedBlock{head}
	expected := head.ParentHash
	next := head.Number - 1

	for next > cp.BlockNumber {
		count := batch
		if remaining := int(next - cp.BlockNumber); remaining < count {
			count = remaining
		}
		headers, err := f.Headers.HeadersDescending(ctx, next, count)
		if err != nil {
			return nil, err
		}
		if len(headers) != count {
			return nil, fmt.Errorf("ethproof: asked for %d headers from %d, got %d",
				count, next, len(headers))
		}
		for _, h := range headers {
			fork, err := ExecutionForkAt(f.ChainID, h.Time)
			if err != nil {
				return nil, err
			}
			b, err := BlockFromParentLink(h, fork, expected)
			if err != nil {
				return nil, fmt.Errorf("walking back to %d: %w", next, err)
			}
			if b.Number != next {
				return nil, fmt.Errorf("%w: header at %d claims number %d",
					ErrHeaderHashMismatch, next, b.Number)
			}
			chain = append(chain, b)
			expected = b.ParentHash
			next--
		}
	}

	// The last link: the oldest block collected must name the checkpoint as its
	// parent. If it does not, the checkpoint is not on this chain.
	if expected != cp.BlockHash {
		return nil, fmt.Errorf("%w: block %d's parent is %x, checkpoint is %x",
			ErrReorgBeyondCheckpoint, cp.BlockNumber+1, expected[:8], cp.BlockHash[:8])
	}
	return chain, nil
}

func (f *ChainFollower) metricBlockAuthenticated() {
	if f.Metrics != nil {
		f.Metrics.BlockAuthenticated()
	}
}
func (f *ChainFollower) metricBlockSkipped() {
	if f.Metrics != nil {
		f.Metrics.BlockSkippedByBloom()
	}
}
func (f *ChainFollower) metricReceipts(n int) {
	if f.Metrics != nil {
		f.Metrics.ReceiptsAuthenticated(n)
	}
}

// ---- a file-backed checkpoint store ----------------------------------------

// FileCheckpointStore keeps the checkpoint in one small JSON file.
type FileCheckpointStore struct {
	Path string
	mu   sync.Mutex
}

// LoadCheckpoint reads the recorded progress. Absent is not an error: it is the
// answer that makes a follower refuse to run.
func (s *FileCheckpointStore) LoadCheckpoint() (FollowerCheckpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return FollowerCheckpoint{}, false, nil
	}
	if err != nil {
		return FollowerCheckpoint{}, false, err
	}
	var cp FollowerCheckpoint
	if err := json.Unmarshal(blob, &cp); err != nil {
		return FollowerCheckpoint{}, false, err
	}
	raw, err := hex.DecodeString(trim0x(cp.BlockHashV))
	if err != nil || len(raw) != 32 {
		return FollowerCheckpoint{}, false, fmt.Errorf(
			"ethproof: checkpoint file %s has an unusable block hash", s.Path)
	}
	copy(cp.BlockHash[:], raw)
	return cp, true, nil
}

// SaveCheckpoint writes through a temporary file and renames.
//
// A checkpoint torn by a crash mid-write would be worse than none: it would name
// a height with a corrupt hash, and the follower would refuse to run until
// somebody deleted it by hand.
func (s *FileCheckpointStore) SaveCheckpoint(cp FollowerCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp.BlockHashV = "0x" + hex.EncodeToString(cp.BlockHash[:])
	blob, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
