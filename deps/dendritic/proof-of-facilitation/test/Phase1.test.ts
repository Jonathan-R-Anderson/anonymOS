import { expect } from "chai";
import { ethers } from "hardhat";

const coder = ethers.AbiCoder.defaultAbiCoder();

// leaf = keccak256(bytes.concat(keccak256(abi.encode(nodeId,recipient,amount,svc))))
function rewardLeaf(nodeId: string, recipient: string, amount: bigint, svc: string): string {
  const inner = ethers.keccak256(
    coder.encode(["bytes32", "address", "uint256", "bytes32"], [nodeId, recipient, amount, svc]),
  );
  return ethers.keccak256(inner);
}
// OpenZeppelin commutative (sorted-pair) hashing.
function hashPair(a: string, b: string): string {
  const [x, y] = BigInt(a) < BigInt(b) ? [a, b] : [b, a];
  return ethers.keccak256(ethers.concat([x, y]));
}

async function increaseTime(seconds: number) {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

describe("Proof-of-Facilitation Phase 1", function () {
  const WINDOW = 100;
  const ZERO = ethers.ZeroHash;

  async function deployAll() {
    const [owner, treasury, aggregator, challenger, r0, r1] = await ethers.getSigners();

    const token = await (await ethers.getContractFactory("AxonToken")).deploy(owner.address);
    await token.setTreasury(treasury.address);

    const epoch = await (await ethers.getContractFactory("EpochManager")).deploy(owner.address, WINDOW);
    const dist = await (await ethers.getContractFactory("RewardDistributor")).deploy(
      owner.address, await token.getAddress(), await epoch.getAddress(),
    );
    const vault = await (await ethers.getContractFactory("StakeVault")).deploy(
      owner.address, await token.getAddress(), WINDOW,
    );
    const disputes = await (await ethers.getContractFactory("DisputeManager")).deploy(
      owner.address, await token.getAddress(), await epoch.getAddress(),
      await vault.getAddress(), ethers.parseEther("10"),
    );

    await epoch.setAggregator(aggregator.address, true);
    await epoch.setDisputeManager(await disputes.getAddress(), true);
    await vault.setSlasher(await disputes.getAddress(), true);

    return { owner, treasury, aggregator, challenger, r0, r1, token, epoch, dist, vault, disputes };
  }

  it("runs a reward epoch: submit -> window -> finalize -> Merkle claim (once)", async function () {
    const { treasury, aggregator, r0, r1, token, epoch, dist } = await deployAll();
    const nodeId0 = ethers.keccak256(ethers.toUtf8Bytes("node0"));
    const nodeId1 = ethers.keccak256(ethers.toUtf8Bytes("node1"));
    const a0 = ethers.parseEther("60"), a1 = ethers.parseEther("40");
    const l0 = rewardLeaf(nodeId0, r0.address, a0, ZERO);
    const l1 = rewardLeaf(nodeId1, r1.address, a1, ZERO);
    const root = hashPair(l0, l1);

    // Fund the distributor with the epoch budget (Treasury mints).
    await token.connect(treasury).mint(await dist.getAddress(), ethers.parseEther("100"));
    await epoch.connect(aggregator).submitEpoch(1, ZERO, root, ZERO, ethers.id("rand"), ethers.parseEther("100"));

    // Cannot claim before finalization.
    await expect(dist.claim(1, nodeId0, r0.address, a0, ZERO, [l1])).to.be.revertedWithCustomError(dist, "NotFinalized");
    // Cannot finalize before the window passes.
    await expect(epoch.finalize(1)).to.be.revertedWithCustomError(epoch, "WindowNotPassed");

    await increaseTime(WINDOW + 1);
    await epoch.finalize(1);

    await dist.claim(1, nodeId0, r0.address, a0, ZERO, [l1]);
    expect(await token.balanceOf(r0.address)).to.equal(a0);
    // Double claim rejected; tampered amount fails the proof.
    await expect(dist.claim(1, nodeId0, r0.address, a0, ZERO, [l1])).to.be.revertedWithCustomError(dist, "AlreadyClaimed");
    await expect(dist.claim(1, nodeId1, r1.address, a1 + 1n, ZERO, [l0])).to.be.revertedWithCustomError(dist, "BadProof");
    // The other node can still claim its correct amount.
    await dist.claim(1, nodeId1, r1.address, a1, ZERO, [l0]);
    expect(await token.balanceOf(r1.address)).to.equal(a1);
  });

  it("stakes and slashes a bond", async function () {
    const { owner, treasury, aggregator, challenger, token, vault } = await deployAll();
    await token.connect(treasury).mint(aggregator.address, ethers.parseEther("100"));
    await token.connect(aggregator).approve(await vault.getAddress(), ethers.parseEther("100"));
    await vault.connect(aggregator).bond(ethers.parseEther("50"));
    expect(await vault.bonded(aggregator.address)).to.equal(ethers.parseEther("50"));

    // A non-slasher cannot slash.
    await expect(vault.connect(owner).slash(aggregator.address, 1n, challenger.address))
      .to.be.revertedWithCustomError(vault, "NotSlasher");
    // Authorize the owner as a slasher for this unit check, then slash to a beneficiary.
    await vault.setSlasher(owner.address, true);
    await vault.connect(owner).slash(aggregator.address, ethers.parseEther("20"), challenger.address);
    expect(await vault.bonded(aggregator.address)).to.equal(ethers.parseEther("30"));
    expect(await token.balanceOf(challenger.address)).to.equal(ethers.parseEther("20"));
  });

  it("freezes a disputed epoch and slashes the aggregator when upheld", async function () {
    const { treasury, aggregator, challenger, token, epoch, vault, disputes } = await deployAll();
    // Aggregator bonds so there is something to slash.
    await token.connect(treasury).mint(aggregator.address, ethers.parseEther("100"));
    await token.connect(aggregator).approve(await vault.getAddress(), ethers.parseEther("100"));
    await vault.connect(aggregator).bond(ethers.parseEther("100"));
    // Challenger funds its bond.
    await token.connect(treasury).mint(challenger.address, ethers.parseEther("10"));
    await token.connect(challenger).approve(await disputes.getAddress(), ethers.parseEther("10"));

    await epoch.connect(aggregator).submitEpoch(2, ZERO, ethers.id("reward"), ZERO, ethers.id("rand2"), 0);
    await disputes.connect(challenger).challenge(2, aggregator.address, ethers.id("badReceipt"));

    // Frozen: cannot finalize even after the window.
    await increaseTime(WINDOW + 1);
    await expect(epoch.finalize(2)).to.be.revertedWithCustomError(epoch, "DisputesOpen");

    // Uphold: invalidate epoch, slash aggregator to the challenger, refund the bond.
    await disputes.resolve(0, true, ethers.parseEther("30"));
    expect(await epoch.isFinalized(2)).to.equal(true);
    expect(await epoch.rewardRootOf(2)).to.equal(ZERO); // no claims possible
    expect(await vault.bonded(aggregator.address)).to.equal(ethers.parseEther("70"));
    // challenger got the 30 slash + its 10 bond back = 40
    expect(await token.balanceOf(challenger.address)).to.equal(ethers.parseEther("40"));
  });

  it("lifts the freeze and lets an epoch finalize when a dispute is rejected", async function () {
    const { treasury, aggregator, challenger, token, epoch, disputes } = await deployAll();
    await token.connect(treasury).mint(challenger.address, ethers.parseEther("10"));
    await token.connect(challenger).approve(await disputes.getAddress(), ethers.parseEther("10"));

    await epoch.connect(aggregator).submitEpoch(3, ZERO, ethers.id("reward3"), ZERO, ethers.id("rand3"), 0);
    await disputes.connect(challenger).challenge(3, aggregator.address, ethers.id("receipt3"));
    await increaseTime(WINDOW + 1);

    await disputes.resolve(0, false, 0); // rejected -> freeze lifted, challenger bond forfeited
    await epoch.finalize(3);
    expect(await epoch.isFinalized(3)).to.equal(true);
    expect(await epoch.rewardRootOf(3)).to.equal(ethers.id("reward3"));
  });
});
