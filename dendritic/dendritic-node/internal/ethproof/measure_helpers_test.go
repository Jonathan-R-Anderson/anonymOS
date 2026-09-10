package ethproof

// Timing helpers shared by the measurement tests.
//
// Here rather than in p14_baseline_test.go because that file is now
// `//go:build ethbls` — it exercises real BLS against the consensus-spec
// vectors — while p146_localnode_test.go measures the local-node path and
// touches no cryptography at all. Leaving these behind a BLS tag would have
// made an unrelated measurement test vanish from the ordinary build.

import "time"

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	i := int(p * float64(len(d)-1))
	return d[i]
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}
