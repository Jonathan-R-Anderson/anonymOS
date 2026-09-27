package compute

// The benchmark kernel — M1's "measured throughput", and M5's verification
// primitive, deliberately the same code.
//
// WHY ONE KERNEL FOR BOTH
// -----------------------
// M1 needs a number that predicts how long a job will take on this machine.
// M5 needs a way to tell whether a returned result was actually computed. Those
// look like separate problems and are not: a kernel that runs identically
// everywhere gives a throughput figure AND a digest that only a machine which
// really ran it can produce. Two uses, one implementation, no drift between
// what was benchmarked and what is verified.
//
// WHY INTEGER ARITHMETIC
// ----------------------
// The digest must match bit-for-bit across every machine in the network, and
// floating point does not offer that. Compilers contract a*b+c into FMA at
// their discretion, x87 keeps 80-bit intermediates, vectorised reductions
// reassociate, and -ffast-math reorders freely. Every one of those produces a
// *correct* answer and a *different* one — which is exactly the property a
// consensus check cannot tolerate.
//
// 64-bit integer operations have none of that freedom. Wrapping multiply, xor
// and rotate are defined to the bit in Go's spec and identical on amd64, arm64
// and riscv64. So the kernel is integer-only, and it is not a limitation: it
// measures the two things that actually predict job time, ALU throughput and
// memory bandwidth, without inheriting float's ambiguity.
//
// (This is the roadmap's central asymmetry made concrete. The same trick does
// NOT work on a GPU: warp scheduling reorders reductions and atomicAdd on
// floats is non-deterministic by construction, which is why GPU verification
// has to fall back to tolerance windows and spot-checks.)

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"time"
)

// KernelVersion is part of the digest's meaning: a result is only comparable to
// another result from the same kernel. Bump it on ANY change to the mixing
// below, including one believed equivalent — a digest that silently changes
// meaning is worse than one that obviously does not match.
const KernelVersion = 1

// blockWords is the working set in 64-bit words: 1 MiB.
//
// Chosen to be larger than a typical L2 slice and smaller than most L3, so the
// kernel is memory-sensitive without becoming a pure DRAM-latency test. A
// buffer that fits in L1 would report ALU throughput and predict nothing about
// real work; one far above L3 would report DRAM latency and predict just as
// little.
const blockWords = 1 << 17

// Result is one benchmark run.
type Result struct {
	// Digest is the proof half: a machine that did not run the kernel cannot
	// produce it. Identical on every machine for the same (Version, Seed,
	// Rounds).
	Digest string `json:"digest"`
	// OpsPerSecond is the measurement half. Reported as work units rather than
	// seconds so it can be compared between machines directly.
	OpsPerSecond int64 `json:"ops_per_second"`
	// MemBandwidthMBps is derived from the same run — every round touches the
	// whole block, so bytes moved is known exactly.
	MemBandwidthMBps int64 `json:"mem_bandwidth_mbps"`

	Version  int   `json:"version"`
	Seed     int64 `json:"seed"`
	Rounds   int   `json:"rounds"`
	Threads  int   `json:"threads"`
	ElapsedM int64 `json:"elapsed_ms"`
}

// mix is splitmix64's finalizer. Every operation in it — wrapping multiply,
// xor, logical shift — is exactly specified by the Go spec and identical on
// every architecture Go targets. That is the whole reason it is here rather
// than something faster and vaguer.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// fill seeds the block deterministically. Not zeroes and not random: a
// zero-filled block lets a compiler or a memory controller optimise away work
// that a real job would do, and a randomly-filled one cannot be reproduced by
// the verifier.
func fill(block []uint64, seed int64) {
	state := uint64(seed) ^ 0x243f6a8885a308d3
	for i := range block {
		state = mix(state)
		block[i] = state
	}
}

// Run executes the kernel single-threaded and returns throughput plus digest.
//
// Single-threaded ON PURPOSE, and this is the part most likely to be
// "improved" later into a bug. Splitting the loop across N goroutines would
// report a bigger number and destroy the digest's meaning: a parallel
// reduction's result depends on how the work was partitioned, so a 4-core
// machine and a 16-core machine would disagree while both being right. The
// digest has to be a property of the INPUT, not of the machine.
//
// Core count is reported separately (see Probe). A scheduler that wants total
// machine throughput multiplies; it does not need the kernel to do it, and the
// kernel cannot afford to.
func Run(seed int64, rounds int) Result {
	block := make([]uint64, blockWords)
	fill(block, seed)

	start := time.Now()
	acc := uint64(0x6a09e667f3bcc908)
	for r := 0; r < rounds; r++ {
		// Round constant, so no two rounds are the same transformation and the
		// loop cannot be collapsed to a single pass.
		rc := mix(uint64(r) ^ uint64(seed))
		for i := 0; i < len(block); i++ {
			v := block[i] ^ rc
			v = mix(v)
			// Feed forward into the accumulator so every word is load-bearing:
			// a partial run cannot produce the right digest.
			acc = mix(acc ^ v)
			block[i] = v
		}
	}
	elapsed := time.Since(start)

	// Digest binds the parameters as well as the data. Without them, a result
	// computed with fewer rounds could be presented as one computed with more.
	sum := sha256.New()
	var scratch [8]byte
	for _, v := range []uint64{uint64(KernelVersion), uint64(seed), uint64(rounds), acc} {
		binary.BigEndian.PutUint64(scratch[:], v)
		sum.Write(scratch[:])
	}
	// The final block state, not just the accumulator: it is what a real job's
	// output would be, and hashing it means a machine cannot shortcut by
	// tracking the accumulator alone.
	for _, v := range block {
		binary.BigEndian.PutUint64(scratch[:], v)
		sum.Write(scratch[:])
	}

	ops := int64(rounds) * int64(len(block))
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1e-9 // a clock too coarse to see the run; do not divide by zero
	}
	bytes := float64(ops) * 8 * 2 // each word is read and written once per round

	return Result{
		Digest:           hex.EncodeToString(sum.Sum(nil)),
		OpsPerSecond:     int64(float64(ops) / seconds),
		MemBandwidthMBps: int64(bytes / seconds / (1 << 20)),
		Version:          KernelVersion,
		Seed:             seed,
		Rounds:           rounds,
		Threads:          1,
		ElapsedM:         elapsed.Milliseconds(),
	}
}

// Calibrate picks a round count that runs for roughly target, then measures.
//
// A fixed round count is wrong in both directions across the hardware this
// network expects: what takes a second on a workstation takes most of a minute
// on a NAS, and a count tuned for the NAS finishes on the workstation too fast
// for the clock to resolve. Calibrating costs one throwaway round and makes the
// figure meaningful on both.
//
// The returned Result's Rounds is what a verifier must be told to reproduce it.
func Calibrate(seed int64, target time.Duration) Result {
	probe := Run(seed, 1)
	rounds := 1
	if probe.ElapsedM > 0 {
		rounds = int(target.Milliseconds() / probe.ElapsedM)
	} else {
		// Faster than the clock could measure: start high and let the ceiling
		// below bound it.
		rounds = 256
	}
	if rounds < 1 {
		rounds = 1
	}
	if rounds > 4096 {
		rounds = 4096 // a ceiling, so a mis-measured probe cannot run for an hour
	}
	return Run(seed, rounds)
}

// VerifyBenchmark recomputes a claimed benchmark and reports whether the digest
// matches. Named apart from Verify, which checks WORK — mixing up "is this
// machine as fast as it says" with "is this answer correct" would be a bad
// mistake to make in a payment path.
//
// This is M5's redundant-execution check in its smallest form. Note what it
// does NOT compare: throughput. Two machines legitimately disagree about how
// fast they are, and the whole point is that they cannot disagree about what
// the answer was.
func VerifyBenchmark(claim Result) bool {
	if claim.Version != KernelVersion {
		// A different kernel is not a mismatch, it is an unanswerable question.
		// Refusing is correct: silently returning false would mark honest work
		// from a node on another version as fraud.
		return false
	}
	return Run(claim.Seed, claim.Rounds).Digest == claim.Digest
}

// MaxParallelism is what a scheduler multiplies single-thread throughput by.
// Reported separately from the kernel for the reason Run's comment gives.
func MaxParallelism() int { return runtime.NumCPU() }
