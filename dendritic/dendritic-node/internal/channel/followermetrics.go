package channel

// Bridging the aggregate-only metrics to the chain follower — roadmap P14.5.
//
// ethproof must not import channel, so ChainFollower states what it needs as an
// interface of four methods taking nothing and an int. Like ethproof's
// EvidenceMetrics, the interface CANNOT EXPRESS a block hash, a channel id or an
// address — the privacy boundary is enforced by the shape of the types rather
// than by everyone remembering.

// FollowerMetrics adapts the aggregate collector to ethproof.FollowerMetrics.
//
// A nil *Metrics is the ordinary case for an uninstrumented node, and every
// method below tolerates it — the collector's own methods each guard, because a
// guard inside a shared helper is unreachable when the caller takes a field
// address on a nil pointer.
type FollowerMetrics struct{ M *Metrics }

func (f FollowerMetrics) BlockAuthenticated()         { f.M.ChainBlockAuthenticated() }
func (f FollowerMetrics) BlockSkippedByBloom()        { f.M.ChainBlockSkippedByBloom() }
func (f FollowerMetrics) ReceiptsAuthenticated(n int) { f.M.ChainReceiptsVerified(n) }
func (f FollowerMetrics) RateLimited()                { f.M.ChainRateLimited() }
