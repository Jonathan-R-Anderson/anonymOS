import { ethers } from "hardhat";

// Deploys AxonChannels against an already-deployed AxonToken.
//
// This script deployed `ChannelManager` -- V1 -- right up until V1 was removed
// from the tree. It had been stale for as long as V2 existed: running it would
// have deployed the contract WITHOUT hash locks, so routed tipping would have
// failed at the first hop with no obvious reason why. Deploying the wrong
// contract is not a build error, and nothing here would have caught it.
//   ANON_TOKEN=0x… CHALLENGE_PERIOD=86400 npx hardhat run deploy/02_channels.ts --network sepolia
//
// The challenge period is the safety margin every channel opened under this
// deployment inherits, and it is immutable in the contract. Too short and an
// offline party cannot answer a stale close; too long and closing is an ordeal.
// A day is a reasonable default and is stated here rather than hidden in a
// constant, because it is the number an operator should actually think about.
export default async function main() {
  const token = process.env.ANON_TOKEN;
  if (!token) throw new Error("Set ANON_TOKEN to the deployed AxonToken address");
  const period = Number(process.env.CHALLENGE_PERIOD || 86400);

  const cm = await (await ethers.getContractFactory("AxonChannels")).deploy(token, period);
  await cm.waitForDeployment();
  const addr = await cm.getAddress();

  console.log("AxonChannels:", addr);
  console.log("  token:            ", token);
  console.log("  challenge period: ", period, "seconds");
  console.log("\nAdd to backend/static/pof/contracts.json so the admin console shows it.");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
