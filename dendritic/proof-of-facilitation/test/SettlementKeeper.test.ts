import { expect } from "chai";
import { ethers } from "hardhat";

// A keeper pays real money for a call anyone could make for free. So the tests
// are about the ways it could pay for nothing: a no-op finalize, an epoch
// already closed, a repeat call, an epoch that pays nobody.

const ZERO = ethers.ZeroHash;

async function increaseTime(seconds: number) {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

describe("SettlementKeeper", function () {
  const WINDOW = 100;
  const BOUNTY = ethers.parseEther("0.002");

  async function deploy() {
    const [owner, aggregator, keeper, other] = await ethers.getSigners();

    const EpochManager = await ethers.getContractFactory("EpochManager");
    const epochs = await EpochManager.deploy(owner.address, WINDOW);
    await epochs.setAggregator(aggregator.address, true);

    const Keeper = await ethers.getContractFactory("SettlementKeeper");
    const bounty = await Keeper.deploy(owner.address, await epochs.getAddress(), BOUNTY);

    await owner.sendTransaction({
      to: await bounty.getAddress(),
      value: ethers.parseEther("1"),
    });
    return { owner, aggregator, keeper, other, epochs, bounty };
  }

  async function submit(epochs: any, aggregator: any, epoch: number, totalRewards: bigint) {
    await epochs.connect(aggregator).submitEpoch(epoch, ZERO, ZERO, ZERO, ZERO, totalRewards);
  }

  it("pays whoever finalizes an epoch worth settling", async () => {
    const { aggregator, keeper, epochs, bounty } = await deploy();
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    await increaseTime(WINDOW + 1);

    const before = await ethers.provider.getBalance(keeper.address);
    const tx = await bounty.connect(keeper).finalizeAndClaim(1);
    const receipt = await tx.wait();
    const gas = receipt!.gasUsed * receipt!.gasPrice;
    const after = await ethers.provider.getBalance(keeper.address);

    expect(after - before + gas).to.equal(BOUNTY);
    expect((await epochs.epochs(1)).finalized).to.equal(true);
  });

  it("pays the same flat bounty regardless of how large the epoch is", async () => {
    // THE REGRESSION TEST. An earlier version paid a basis-point share of
    // `totalRewards`, which is denominated in CREDIT — an ERC-20 — while the
    // bounty is native ETH. Multiplying a CREDIT amount by a rate and sending
    // that many wei crosses an exchange rate that exists nowhere in the
    // contract: an epoch of 1,000 CREDIT would have computed a 50 ETH bounty.
    //
    // What the bounty compensates is gas, and finalizing a huge epoch costs the
    // same gas as finalizing a small one. So they pay the same.
    const { aggregator, epochs, bounty } = await deploy();
    await submit(epochs, aggregator, 1, ethers.parseEther("0.1"));      // small
    await submit(epochs, aggregator, 2, ethers.parseEther("1000"));     // enormous
    await increaseTime(WINDOW + 1);

    expect(await bounty.bountyFor(1)).to.equal(BOUNTY);
    expect(await bounty.bountyFor(2)).to.equal(BOUNTY);
  });

  it("never pays more than it holds", async () => {
    const { owner, aggregator, keeper, epochs, bounty } = await deploy();
    const address = await bounty.getAddress();
    const balance = await ethers.provider.getBalance(address);
    // Leave it holding less than one bounty.
    await bounty.withdraw(owner.address, balance - ethers.parseEther("0.0005"));
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    await increaseTime(WINDOW + 1);

    expect(await bounty.bountyFor(1)).to.equal(ethers.parseEther("0.0005"));
    await bounty.connect(keeper).finalizeAndClaim(1);
    expect(await ethers.provider.getBalance(address)).to.equal(0n);
    expect((await epochs.epochs(1)).finalized).to.equal(true);
  });

  it("refuses an epoch that is already finalized", async () => {
    // The drain: without this, calling finalizeAndClaim on a settled epoch pays
    // a bounty for doing nothing, over and over, until the balance is gone.
    const { aggregator, keeper, epochs, bounty } = await deploy();
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    await increaseTime(WINDOW + 1);
    await bounty.connect(keeper).finalizeAndClaim(1);

    await expect(bounty.connect(keeper).finalizeAndClaim(1))
      .to.be.revertedWithCustomError(bounty, "NothingToFinalize");
  });

  it("refuses an epoch somebody else already finalized directly", async () => {
    // finalize() stays permissionless, so this is a normal race, not an attack.
    // The keeper must not pay for a call whose work was already done.
    const { aggregator, keeper, other, epochs, bounty } = await deploy();
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    await increaseTime(WINDOW + 1);
    await epochs.connect(other).finalize(1);

    await expect(bounty.connect(keeper).finalizeAndClaim(1))
      .to.be.revertedWithCustomError(bounty, "NothingToFinalize");
  });

  it("cannot finalize before the window closes", async () => {
    const { aggregator, keeper, epochs, bounty } = await deploy();
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    await expect(bounty.connect(keeper).finalizeAndClaim(1))
      .to.be.revertedWithCustomError(epochs, "WindowNotPassed");
  });

  it("cannot finalize an unknown epoch", async () => {
    const { keeper, epochs, bounty } = await deploy();
    await expect(bounty.connect(keeper).finalizeAndClaim(99))
      .to.be.revertedWithCustomError(epochs, "UnknownEpoch");
  });

  it("finalizes an empty epoch but pays nothing for it", async () => {
    // Every epoch on this network today is empty. The epoch still closes —
    // that is worth doing — but paying for it would turn a harmless no-op into
    // a standing invitation to spend the balance.
    const { aggregator, keeper, epochs, bounty } = await deploy();
    await submit(epochs, aggregator, 1, 0n);
    await increaseTime(WINDOW + 1);

    expect(await bounty.bountyFor(1)).to.equal(0n);
    const before = await ethers.provider.getBalance(keeper.address);
    const tx = await bounty.connect(keeper).finalizeAndClaim(1);
    const receipt = await tx.wait();
    const gas = receipt!.gasUsed * receipt!.gasPrice;
    const after = await ethers.provider.getBalance(keeper.address);

    expect((await epochs.epochs(1)).finalized).to.equal(true);
    expect(before - after).to.equal(gas);   // paid gas, received nothing
  });

  it("lets a keeper check the bounty before spending gas", async () => {
    // Without a view, competing keepers discover an empty bounty by paying for
    // a transaction that pays them nothing.
    const { aggregator, epochs, bounty } = await deploy();
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    expect(await bounty.isClaimable(1)).to.equal(false);
    await increaseTime(WINDOW + 1);
    expect(await bounty.isClaimable(1)).to.equal(true);
    expect(await bounty.bountyFor(1)).to.equal(BOUNTY);
  });

  it("still finalizes when it cannot pay", async () => {
    // Reverting would undo a settlement the network needs because this contract
    // happens to be empty. The epoch closing matters more than the bounty.
    const { owner, aggregator, keeper, epochs, bounty } = await deploy();
    await bounty.withdraw(owner.address, await ethers.provider.getBalance(await bounty.getAddress()));
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    await increaseTime(WINDOW + 1);

    await expect(bounty.connect(keeper).finalizeAndClaim(1))
      .to.emit(bounty, "BountyUnavailable");
    expect((await epochs.epochs(1)).finalized).to.equal(true);
  });

  it("refuses a bounty above the typo ceiling", async () => {
    const { owner, bounty } = await deploy();
    const ceiling = await bounty.MAX_BOUNTY_WEI();
    await expect(bounty.connect(owner).setBounty(ceiling + 1n))
      .to.be.revertedWithCustomError(bounty, "BountyTooLarge");
    await bounty.connect(owner).setBounty(ceiling);
  });

  it("only the owner can change the bounty or withdraw", async () => {
    const { keeper, bounty } = await deploy();
    await expect(bounty.connect(keeper).setBounty(1n)).to.be.reverted;
    await expect(bounty.connect(keeper).withdraw(keeper.address, 1n)).to.be.reverted;
  });

  it("leaves finalize() permissionless", async () => {
    // The keeper must never become the ONLY route: that would reintroduce the
    // withholding the permissionless design exists to prevent, with this
    // contract doing the withholding instead of an operator.
    const { aggregator, other, epochs } = await deploy();
    await submit(epochs, aggregator, 1, ethers.parseEther("1"));
    await increaseTime(WINDOW + 1);
    await epochs.connect(other).finalize(1);
    expect((await epochs.epochs(1)).finalized).to.equal(true);
  });
});
