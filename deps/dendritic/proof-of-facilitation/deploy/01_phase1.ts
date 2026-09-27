import { ethers } from "hardhat";

// Phase 1: deploy the optimistic service-ledger contracts and wire the
// contract-to-contract roles. Requires CREDIT_TOKEN_ADDRESS from Phase 0.
//   CREDIT_TOKEN_ADDRESS=0x... npx hardhat run deploy/01_phase1.ts --network sepolia
export default async function main() {
  const creditAddr = process.env.CREDIT_TOKEN_ADDRESS;
  if (!creditAddr) throw new Error("Set CREDIT_TOKEN_ADDRESS (run deploy/00_phase0.ts first)");

  const [wallet] = await ethers.getSigners();
  const owner = process.env.INITIAL_OWNER || wallet.address;
  const deploy = async (name: string, args: any[]) => {
    const c = await (await ethers.getContractFactory(name)).deploy(...args);
    await c.waitForDeployment();
    return c;
  };

  const CHALLENGE_WINDOW = 24 * 60 * 60; // 24h optimistic window
  const WITHDRAW_DELAY = 24 * 60 * 60; // bonds can't be pulled instantly
  const CHALLENGER_BOND = ethers.parseEther("100");

  const epoch = await deploy("EpochManager", [owner, CHALLENGE_WINDOW]);
  const vault = await deploy("StakeVault", [owner, creditAddr, WITHDRAW_DELAY]);
  const dist = await deploy("RewardDistributor", [owner, creditAddr, await epoch.getAddress()]);
  const disputes = await deploy("DisputeManager", [owner, creditAddr, await epoch.getAddress(), await vault.getAddress(), CHALLENGER_BOND]);
  const policy = await deploy("ServicePolicyRegistry", [owner]);

  console.log("EpochManager:          ", await epoch.getAddress());
  console.log("StakeVault:            ", await vault.getAddress());
  console.log("RewardDistributor:     ", await dist.getAddress());
  console.log("DisputeManager:        ", await disputes.getAddress());
  console.log("ServicePolicyRegistry: ", await policy.getAddress());

  // Wire the contract-to-contract roles when the deployer is the owner.
  if (owner.toLowerCase() === wallet.address.toLowerCase()) {
    await (await epoch.setDisputeManager(await disputes.getAddress(), true)).wait();
    await (await vault.setSlasher(await disputes.getAddress(), true)).wait();
    console.log("\nWired: EpochManager.disputeManager + StakeVault.slasher = DisputeManager");
    console.log("Next (operational): epoch.setAggregator(<aggregator>, true); fund RewardDistributor with the epoch budget; set an initial ServicePolicyRegistry policy.");
  } else {
    console.log("\nINITIAL_OWNER differs from deployer; run these as owner:");
    console.log("  epoch.setDisputeManager(disputes, true); vault.setSlasher(disputes, true)");
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
