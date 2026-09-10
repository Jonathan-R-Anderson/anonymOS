package channel

// Keeping a hub able to pay.
//
// THE PROBLEM, WHICH IS PERMANENT RATHER THAN OCCASIONAL
// ------------------------------------------------------
// Every payment a hub routes moves capacity one way: reader→hub grows, hub→
// provider shrinks. Nothing pushes it back. So a hub that starts perfectly
// funded ends up holding plenty of VALUE and unable to pay ANYONE — the money
// is all on the wrong side of its channels.
//
// This is not a failure mode to recover from, it is the steady-state behaviour
// of a working hub, and it arrives faster the more successful the hub is.
//
// THE THREE REMEDIES, CHEAPEST FIRST
// ----------------------------------
//	1. Providers spending their earnings back into the network. Free, and the
//	   only one that costs nothing at all — a streamer who buys storage with
//	   what they were tipped has rebalanced the hub for it.
//	2. Circular routing: send value hub→A→…→hub so outbound toward A is
//	   restored without an on-chain transaction. Costs routing fees only.
//	3. On-chain rebalancing: close and reopen, or deposit more. Always works,
//	   always costs gas, and is the last resort rather than the reflex.
//
// A rebalancer that reached for (3) first would work perfectly and burn money
// doing it, which is why the plan below reports what each option would cost
// rather than just what to do.

import "sort"

// StarvationThreshold is the fraction of original funding below which a
// recipient is considered starved.
//
// A fifth, not a half: waiting until capacity is nearly gone means the first
// payment to fail is a real one somebody was watching. Acting early costs a
// rebalance that was not strictly necessary; acting late costs a failed tip.
const StarvationThreshold = 0.2

// RebalanceAction is one suggested move.
type RebalanceAction struct {
	Recipient NodeID
	// Need is how much outbound capacity to restore.
	Need Amount
	// Method names the cheapest remedy that could work here.
	Method string
	// OnChain says whether this costs a transaction. Surfaced because the
	// difference between "free" and "costs gas" is the whole decision.
	OnChain bool
	Why     string
}

// Funding records what a recipient was originally given, so drain is measurable
// against something. Without it "low capacity" is unknowable — 5 ANON might be
// nearly full or nearly empty.
type Funding map[NodeID]Amount

// PlanRebalance inspects a hub and proposes moves, cheapest first.
//
// Returns a PLAN rather than performing anything. Rebalancing spends money, and
// an operator who has not opted in should never discover it happening — which
// is why RouterConfig.AutoRebalance defaults to off.
func PlanRebalance(h *Hub, original Funding, circularAvailable bool) []RebalanceAction {
	type starved struct {
		id    NodeID
		have  Amount
		want  Amount
		ratio float64
	}
	var found []starved

	h.mu.Lock()
	for id, r := range h.recipients {
		funded, known := original[id]
		if !known || funded <= 0 {
			continue
		}
		ratio := float64(r.Outbound) / float64(funded)
		if ratio < StarvationThreshold {
			found = append(found, starved{id: id, have: r.Outbound, want: funded, ratio: ratio})
		}
	}
	h.mu.Unlock()

	// Worst-starved first, then by id so a plan is reproducible — an operator
	// comparing two runs should not see the same situation described two ways.
	sort.Slice(found, func(i, j int) bool {
		if found[i].ratio != found[j].ratio {
			return found[i].ratio < found[j].ratio
		}
		return found[i].id < found[j].id
	})

	actions := make([]RebalanceAction, 0, len(found))
	for _, s := range found {
		need := s.want - s.have
		if circularAvailable {
			actions = append(actions, RebalanceAction{
				Recipient: s.id, Need: need,
				Method: "circular", OnChain: false,
				Why: "route value back around the network — costs routing fees, no gas",
			})
			continue
		}
		actions = append(actions, RebalanceAction{
			Recipient: s.id, Need: need,
			Method: "on-chain", OnChain: true,
			Why: "no circular path available; deposit or reopen the channel",
		})
	}
	return actions
}

// CanStillPay reports the largest payment a hub could route to a recipient.
//
// The number an interface should show BEFORE someone tries to tip, so a viewer
// learns a payment is impossible before committing to it rather than after.
func CanStillPay(h *Hub, recipient NodeID) Amount {
	return h.OutboundTo(recipient)
}

// HealthSummary is what an operator needs at a glance.
type HealthSummary struct {
	Recipients int
	Starved    int
	// TotalOutbound is capacity available to pay with. Deliberately reported
	// separately from inbound: a hub with vast inbound and no outbound is
	// FULL and BROKE at the same time, and one number cannot say that.
	TotalOutbound Amount
	TotalInbound  Amount
	InFlight      Amount
}

// Health summarises a hub.
func Health(h *Hub, original Funding) HealthSummary {
	out := HealthSummary{InFlight: h.InFlight()}
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, r := range h.recipients {
		out.Recipients++
		out.TotalOutbound += r.Outbound
		if funded, known := original[id]; known && funded > 0 &&
			float64(r.Outbound)/float64(funded) < StarvationThreshold {
			out.Starved++
		}
	}
	for _, bal := range h.readers {
		out.TotalInbound += bal
	}
	return out
}
