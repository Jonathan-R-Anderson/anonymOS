package sybil

import "github.com/syndichan/maniwani/storage-client/internal/axon/params"

// The bond floors, re-exported from params so this package reads one name per
// value. They are NOT redefined here: params is the single home (T0.2), and a
// second literal would be a second opinion.
//
// Every one of them is PROVISIONAL. See params.BondFloorRelay for what that
// means and why the calibration is [UNSOLVED] rather than pending.
const (
	bondFloorRelay   = params.BondFloorRelay
	bondFloorStorage = params.BondFloorStorage
	bondFloorDHT     = params.BondFloorDHT
	bondFloorExit    = params.BondFloorExit
)
