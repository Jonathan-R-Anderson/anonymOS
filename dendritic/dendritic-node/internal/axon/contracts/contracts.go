// Package contracts is the single source of truth for the deployed
// Proof-of-Facilitation contract addresses.
//
// WHY THIS EXISTS. The Go node reads chain state through injected seams --
// resolver.ChainSource, sybil.ProofSource, BondRef.Contract -- so no address is
// hardcoded at a call site, which is correct. But something has to SUPPLY those
// seams the real addresses, and until 2026-08-21 nothing did, because nothing
// was deployed. The 11 contracts are now live on Ethereum mainnet, and their
// addresses lived only in the backend's Postgres (the `pof_contracts` setting).
// This package is the Go-side record, so the resolver/operator/sybil wiring has
// one place to read from rather than each inventing its own.
//
// ONE PLACE, STATED ONCE -- the same discipline §11.3 applies to ROOT_SUFFIX.
// An address that appears in two files eventually disagrees with itself, and a
// disagreement about a mainnet money contract is a payment sent to the wrong
// place. A test (contracts_test.go) validates every address as EIP-55, because
// a mis-typed checksum in THIS file is exactly the failure that record exists
// to prevent.
//
// NOT A TRUST ROOT. These addresses being correct does not make the chain state
// at them trustworthy: that is what the light client and eth_getProof are for
// (T14.2). This package answers only "which address", never "is the state true".
package contracts

// ChainID is the deployment chain. 1 is Ethereum mainnet.
//
// Carried alongside the addresses because an address is meaningless without the
// chain it lives on, and a state signed for one chain replayed against another
// is a real attack the ChainID guards against (see channel config's own note).
const ChainID int64 = 1

// Set is the address of every PoF contract in one deployment.
type Set struct {
	AxonToken             string
	NodeRegistry          string
	StakeVault            string
	EpochManager          string
	RewardDistributor     string
	Treasury              string
	AxonRegistry          string
	DisputeManager        string
	ServicePolicyRegistry string
	SettlementKeeper      string
	AxonGovernance        string
	// Channels is the contract tipping runs on. The deployed contract is
	// ChannelManagerV2, the pre-rename predecessor of the source's AxonChannels;
	// the address is what is on chain, not what the source now calls the type.
	// Displayed lowercase by the console but a valid address.
	Channels string
}

// Mainnet is the live deployment (chainId 1), deployed 2026-08-21, owner wallet
// 0xB2b36AaD18d7be5d4016267BC4cCec2f12a64b6e.
//
// DEPLOYED IS NOT WIRED. As recorded here these contracts exist but the seed
// and role transactions have not been sent: AxonToken.setTreasury and
// mintGenesis (supply is 0), AxonRegistry.setGovernor (governance reverts
// NoGovernor), and the EpochManager/StakeVault role wiring. A caller reading a
// bond from StakeVault will correctly get zero until nodes stake, and a
// resolver reading AxonRegistry state will find names ACTIVE-by-absence until
// the governor is set. Those are honest answers about an unwired deployment,
// not bugs in the reader.
var Mainnet = Set{
	AxonToken:             "0x8196c59E3B796EaD4B3ffE8e48039588ca1B5e88",
	NodeRegistry:          "0x23B2EafB32055AFFbDfA8c0FD8904C264eCBDe1A",
	StakeVault:            "0x41988C3Ef915DD27f57DD2cDCeC1bf034F6064a7",
	EpochManager:          "0x8F35889D936CE4D16c48d6e8Bec0E3969066A921",
	RewardDistributor:     "0x344Fd1A274ed43b4e9e47Cea26d18D2Fe95bf610",
	Treasury:              "0x9e110FC6cCaC218a4A601eaF1E476fF4DEBf9588",
	AxonRegistry:          "0x5B2D1cd4AB437e1d4a0adC1416FEe2ff517ef0DB",
	DisputeManager:        "0x7866aCD0e3076EE44d239CA57aF6fEe060F7abe1",
	ServicePolicyRegistry: "0xEA1059F4Ad57715FC0de18Bbe34E76c633da208B",
	SettlementKeeper:      "0x38BDFB8657ca94d53D47dF2F2C35EE1D8d98461b",
	AxonGovernance:        "0xaBA3b4543FcCd6a2c6C867E6b70C69d11C6a436a",
	Channels:              "0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c",
}

// All returns the (name, address) pairs, for enumeration and validation.
func (s Set) All() []struct{ Name, Address string } {
	return []struct{ Name, Address string }{
		{"AxonToken", s.AxonToken},
		{"NodeRegistry", s.NodeRegistry},
		{"StakeVault", s.StakeVault},
		{"EpochManager", s.EpochManager},
		{"RewardDistributor", s.RewardDistributor},
		{"Treasury", s.Treasury},
		{"AxonRegistry", s.AxonRegistry},
		{"DisputeManager", s.DisputeManager},
		{"ServicePolicyRegistry", s.ServicePolicyRegistry},
		{"SettlementKeeper", s.SettlementKeeper},
		{"AxonGovernance", s.AxonGovernance},
		{"Channels", s.Channels},
	}
}
