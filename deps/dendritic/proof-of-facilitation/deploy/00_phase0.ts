import { ethers } from "hardhat";

// Phase 0 deploy: AxonToken + NodeRegistry.
//   npx hardhat run deploy/00_phase0.ts --network sepolia
//
// Plain hardhat + ethers. An earlier version used an L2 plugin's Deployer; the
// contracts use no chain-specific features, so the standard toolbox is enough.
export default async function main() {
  const [deployer] = await ethers.getSigners();
  const owner = process.env.INITIAL_OWNER || deployer.address;

  const token = await (await ethers.getContractFactory("AxonToken")).deploy(owner);
  await token.waitForDeployment();
  console.log("AxonToken (AXON):", await token.getAddress());

  const registry = await (await ethers.getContractFactory("NodeRegistry")).deploy(owner);
  await registry.waitForDeployment();
  console.log("NodeRegistry:", await registry.getAddress());

  console.log("\nPhase 0 deployed. Owner:", owner);
  console.log("Next: RewardDistributor, then Treasury, then AxonToken.setTreasury(treasury).");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
