package intro

import "sort"

// The admission queue — §23.6's "queue that orders admitted clients by effort".
//
// T6a.6: a client that solves at higher effort is admitted ahead of one that
// solves at lower effort. This is the part of P6a that turns the puzzle from a
// gate into a PRIORITY: under a flood, everybody who solved gets in eventually,
// but the order is by what they spent.
//
// §23.6 NAMES ITS OWN FAILURE MODE -- "effort-ordered queueing that a well-funded
// attacker simply wins" -- and that failure is REAL AND UNMITIGATED here. An
// adversary with more CPU than the honest population outbids it, and no ordering
// rule fixes that; what the ordering buys is that the adversary must keep paying
// for every introduction, continuously, at a cost that rises with the pressure
// it applies. That is the whole claim. It is not a claim that the attacker loses.

// Admission is one client waiting to be introduced.
type Admission struct {
	// Effort is the VERIFIED effort, from Verify. Never the claimed value: a
	// queue ordered by an unverified claim is ordered by whoever lies hardest,
	// and lying is free.
	Effort uint64
	// Seq is arrival order, used to break ties.
	Seq uint64
	// Payload is the opaque INTRODUCE1 body.
	Payload []byte
}

// Queue orders pending introductions by verified effort, highest first.
type Queue struct {
	items []Admission
	next  uint64
	// Cap bounds the queue. Zero means unbounded, which is a denial of service
	// with extra steps: a queue that grows without limit under a flood is the
	// memory exhaustion the puzzle was meant to prevent.
	Cap int
}

// NewQueue returns a queue bounded at cap entries.
func NewQueue(cap int) *Queue { return &Queue{Cap: cap} }

// Push adds a VERIFIED admission. It returns false if the queue is full and the
// entry did not displace anything.
//
// When full, the LOWEST-effort entry is displaced -- and only if the newcomer
// beat it. Dropping the newest instead would make the queue a first-come lock,
// so an attacker who filled it once would hold it for as long as the flood
// lasted and no honest client could ever buy in at any price.
func (q *Queue) Push(a Admission) bool {
	a.Seq = q.next
	q.next++
	if q.Cap <= 0 || len(q.items) < q.Cap {
		q.items = append(q.items, a)
		q.sortItems()
		return true
	}
	last := len(q.items) - 1
	if q.items[last].Effort >= a.Effort {
		return false
	}
	q.items[last] = a
	q.sortItems()
	return true
}

// Pop removes and returns the highest-effort admission.
func (q *Queue) Pop() (Admission, bool) {
	if len(q.items) == 0 {
		return Admission{}, false
	}
	a := q.items[0]
	q.items = q.items[1:]
	return a, true
}

// Len is the current depth — the input to the difficulty controller.
func (q *Queue) Len() int { return len(q.items) }

// sortItems orders by effort descending, then by arrival.
//
// Arrival breaks ties so that at difficulty 0, where every effort is 1, the
// queue is plain FIFO and behaves exactly as it did before P6a existed. That is
// T6a.1's shape: with no attack in progress, the puzzle machinery must not
// change what an honest client experiences.
func (q *Queue) sortItems() {
	sort.SliceStable(q.items, func(i, j int) bool {
		if q.items[i].Effort != q.items[j].Effort {
			return q.items[i].Effort > q.items[j].Effort
		}
		return q.items[i].Seq < q.items[j].Seq
	})
}
