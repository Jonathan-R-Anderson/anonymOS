package aggregator

import "math/big"

// Policy is the subset of ServicePolicyRegistry the scorer needs: the epoch
// budget, the per-service split (basis points, indexed by ServiceType), and a
// per-node cap (basis points of the epoch) that bounds how much any one node can
// take — a defense against a single identity dominating an epoch.
type Policy struct {
	EpochBudget   *big.Int
	SplitBps      [7]uint16
	PerNodeCapBps uint16
}

// Score turns validated receipts into per-node reward rows. Within each service,
// a node's share of that service's budget slice is proportional to its
// quality-weighted quantity; a node's total is summed across services and capped.
// `recipients` maps a nodeId to its payout wallet (from NodeRegistry).
func Score(receipts []ServiceReceipt, policy Policy, recipients map[[32]byte][20]byte) []RewardRow {
	points := make([]map[[32]byte]*big.Int, 7)
	svcTotal := make([]*big.Int, 7)
	for i := 0; i < 7; i++ {
		points[i] = make(map[[32]byte]*big.Int)
		svcTotal[i] = big.NewInt(0)
	}

	for _, r := range receipts {
		s := int(r.ServiceType)
		if s < 0 || s > 6 {
			continue
		}
		q := big.NewInt(int64(r.Quantity))
		p := new(big.Int).Mul(q, big.NewInt(int64(r.Quality)))
		if p.Sign() == 0 {
			p = q // quality unset => weight purely by quantity
		}
		if points[s][r.ProviderNodeID] == nil {
			points[s][r.ProviderNodeID] = big.NewInt(0)
		}
		points[s][r.ProviderNodeID].Add(points[s][r.ProviderNodeID], p)
		svcTotal[s].Add(svcTotal[s], p)
	}

	perNode := make(map[[32]byte]*big.Int)
	for s := 0; s < 7; s++ {
		if svcTotal[s].Sign() == 0 {
			continue
		}
		svcBudget := new(big.Int).Div(
			new(big.Int).Mul(policy.EpochBudget, big.NewInt(int64(policy.SplitBps[s]))),
			big.NewInt(10000),
		)
		for node, pts := range points[s] {
			reward := new(big.Int).Div(new(big.Int).Mul(svcBudget, pts), svcTotal[s])
			if perNode[node] == nil {
				perNode[node] = big.NewInt(0)
			}
			perNode[node].Add(perNode[node], reward)
		}
	}

	var cap *big.Int
	if policy.PerNodeCapBps > 0 {
		cap = new(big.Int).Div(
			new(big.Int).Mul(policy.EpochBudget, big.NewInt(int64(policy.PerNodeCapBps))),
			big.NewInt(10000),
		)
	}

	rows := make([]RewardRow, 0, len(perNode))
	for node, amt := range perNode {
		if cap != nil && amt.Cmp(cap) > 0 {
			amt = new(big.Int).Set(cap)
		}
		if amt.Sign() == 0 {
			continue
		}
		rows = append(rows, RewardRow{NodeID: node, Recipient: recipients[node], Amount: amt})
	}
	return rows
}
