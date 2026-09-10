import { expect } from "chai";
import { ethers } from "hardhat";

// The Treasury is the only thing that can create AXON, so these tests are
// mostly about refusing to. The two powers are deliberately asymmetric:
// minting is permissionless but bounded by the epoch, spending is owner-only
// but cannot mint.

const ZERO = ethers.ZeroHash;
const ROOT = "0x" + "11".repeat(32);

async function increaseTime(seconds: number) {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

describe("Treasury", function () {
  const WINDOW = 100;
  const BUDGET = ethers.parseEther("1000");
  const CAP = ethers.parseEther("1000000");

  async function deploy() {
    const [owner, aggregator, caller, alice] = await ethers.getSigners();

    const token = await (await ethers.getContractFactory("AxonToken")).deploy(owner.address);
    const epochs = await (await ethers.getContractFactory("EpochManager")).deploy(owner.address, WINDOW);
    await epochs.setAggregator(aggregator.address, true);
    const distributor = await (await ethers.getContractFactory("RewardDistributor")).deploy(
      owner.address, await token.getAddress(), await epochs.getAddress()
    );
    const treasury = await (await ethers.getContractFactory("Treasury")).deploy(
      owner.address,
      await token.getAddress(),
      await epochs.getAddress(),
      await distributor.getAddress(),
      BUDGET,
      CAP
    );
    await token.setTreasury(await treasury.getAddress());

    return { owner, aggregator, caller, alice, token, epochs, distributor, treasury };
  }

  async function settled(epochs: any, aggregator: any, epoch: number, total: bigint, root = ROOT) {
    await epochs.connect(aggregator).submitEpoch(epoch, ZERO, root, ZERO, ZERO, total);
    await increaseTime(WINDOW + 1);
    await epochs.finalize(epoch);
  }

  // --- minting: permissionless, bounded ------------------------------------

  it("lets anyone fund a settled epoch, minting to the distributor", async () => {
    // Permissionless for the same reason finalize() is: a payment only the
    // operator can release is a payment the operator can withhold.
    const { aggregator, caller, token, epochs, distributor, treasury } = await deploy();
    const total = ethers.parseEther("40");
    await settled(epochs, aggregator, 1, total);

    expect(await treasury.fundableAmount(1)).to.equal(total);
    await expect(treasury.connect(caller).fundEpoch(1))
      .to.emit(treasury, "EpochFunded").withArgs(1, total, caller.address);

    expect(await token.balanceOf(await distributor.getAddress())).to.equal(total);
    expect(await token.totalSupply()).to.equal(total);
    expect(await treasury.fundedAmount(1)).to.equal(total);
  });

  it("refuses to fund the same epoch twice", async () => {
    const { aggregator, caller, epochs, treasury } = await deploy();
    await settled(epochs, aggregator, 1, ethers.parseEther("40"));
    await treasury.connect(caller).fundEpoch(1);

    expect(await treasury.fundableAmount(1)).to.equal(0n);
    await expect(treasury.connect(caller).fundEpoch(1))
      .to.be.revertedWithCustomError(treasury, "AlreadyFunded");
  });

  it("refuses an epoch that is not finalized yet", async () => {
    // It could still be disputed. Minting now would create tokens against
    // rewards that may be about to be invalidated.
    const { aggregator, caller, epochs, treasury } = await deploy();
    await epochs.connect(aggregator).submitEpoch(1, ZERO, ROOT, ZERO, ZERO, ethers.parseEther("40"));

    expect(await treasury.fundableAmount(1)).to.equal(0n);
    await expect(treasury.connect(caller).fundEpoch(1))
      .to.be.revertedWithCustomError(treasury, "NotFinalized");
  });

  it("refuses an invalidated epoch, whose reward root was zeroed", async () => {
    // invalidateEpoch marks it finalized but wipes the root, so nothing is
    // claimable. Minting for it would strand the tokens in the distributor.
    const { owner, aggregator, caller, epochs, treasury } = await deploy();
    await epochs.connect(aggregator).submitEpoch(1, ZERO, ROOT, ZERO, ZERO, ethers.parseEther("40"));
    await epochs.setDisputeManager(owner.address, true);
    await epochs.invalidateEpoch(1);

    expect(await treasury.fundableAmount(1)).to.equal(0n);
    await expect(treasury.connect(caller).fundEpoch(1))
      .to.be.revertedWithCustomError(treasury, "NothingToFund");
  });

  it("refuses an epoch that owes nobody anything", async () => {
    const { aggregator, caller, epochs, treasury } = await deploy();
    await settled(epochs, aggregator, 1, 0n);

    expect(await treasury.fundableAmount(1)).to.equal(0n);
    await expect(treasury.connect(caller).fundEpoch(1))
      .to.be.revertedWithCustomError(treasury, "NothingToFund");
  });

  it("refuses an over-budget epoch loudly rather than minting part of it", async () => {
    // Minting less than the reward tree promises would pay early claimants in
    // full and leave the last one hitting a bare "transfer exceeds balance".
    const { aggregator, caller, epochs, treasury, token, distributor } = await deploy();
    const total = BUDGET + 1n;
    await settled(epochs, aggregator, 1, total);

    expect(await treasury.fundableAmount(1)).to.equal(0n);
    await expect(treasury.connect(caller).fundEpoch(1))
      .to.be.revertedWithCustomError(treasury, "BudgetExceeded").withArgs(total, BUDGET);
    expect(await token.balanceOf(await distributor.getAddress())).to.equal(0n);

    // And the fix is available: raise the budget, call again.
    await treasury.setEpochBudget(total);
    await treasury.connect(caller).fundEpoch(1);
    expect(await token.balanceOf(await distributor.getAddress())).to.equal(total);
  });

  it("will not mint past the supply cap", async () => {
    const { owner, aggregator, caller, epochs, token, treasury } = await deploy();
    // Genesis-mint almost the entire cap, leaving less than one epoch's rewards.
    await token.connect(owner).mintGenesis(owner.address, CAP - ethers.parseEther("10"));
    await settled(epochs, aggregator, 1, ethers.parseEther("40"));

    expect(await treasury.fundableAmount(1)).to.equal(0n);
    await expect(treasury.connect(caller).fundEpoch(1))
      .to.be.revertedWithCustomError(treasury, "CapExceeded");
  });

  it("reports an unknown epoch as unfundable instead of reverting", async () => {
    // A keeper polling many epochs should not have to catch reverts to find
    // the one that needs funding.
    const { treasury } = await deploy();
    expect(await treasury.fundableAmount(999)).to.equal(0n);
  });

  // --- spending: owner-only, and never mints -------------------------------

  it("releases only tokens it already holds, and cannot mint to do it", async () => {
    // This is the path a card purchase or a grant is delivered through. It
    // spends a pre-allocated balance; if it could mint, the supply cap would
    // constrain only the issuance nobody was tempted to exceed.
    const { owner, alice, token, treasury } = await deploy();
    const allocation = ethers.parseEther("500");
    await token.connect(owner).mintGenesis(await treasury.getAddress(), allocation);

    await treasury.release(alice.address, ethers.parseEther("100"));
    expect(await token.balanceOf(alice.address)).to.equal(ethers.parseEther("100"));
    expect(await token.totalSupply()).to.equal(allocation);   // nothing created

    await expect(treasury.release(alice.address, allocation)).to.be.reverted;  // beyond its balance
  });

  it("burns only its own balance", async () => {
    const { owner, alice, token, treasury } = await deploy();
    await token.connect(owner).mintGenesis(await treasury.getAddress(), ethers.parseEther("500"));
    await token.connect(owner).mintGenesis(alice.address, ethers.parseEther("50"));

    await treasury.burn(ethers.parseEther("200"));
    expect(await token.balanceOf(await treasury.getAddress())).to.equal(ethers.parseEther("300"));
    expect(await token.balanceOf(alice.address)).to.equal(ethers.parseEther("50"));
    expect(await token.totalSupply()).to.equal(ethers.parseEther("350"));
  });

  it("keeps spending powers to the owner", async () => {
    const { alice, treasury } = await deploy();
    await expect(treasury.connect(alice).release(alice.address, 1n)).to.be.reverted;
    await expect(treasury.connect(alice).burn(1n)).to.be.reverted;
    await expect(treasury.connect(alice).setEpochBudget(1n)).to.be.reverted;
  });

  it("cannot rescue AXON out from under its own accounting", async () => {
    const { owner, token, treasury } = await deploy();
    await token.connect(owner).mintGenesis(await treasury.getAddress(), ethers.parseEther("10"));
    await expect(treasury.rescue(await token.getAddress(), owner.address, 1n))
      .to.be.revertedWithCustomError(treasury, "ZeroAddress");
  });

  it("is the only thing that can mint, once wired", async () => {
    const { owner, alice, token } = await deploy();
    await expect(token.connect(owner).mint(alice.address, 1n))
      .to.be.revertedWithCustomError(token, "NotTreasury");
  });

  // --- purchase orders ------------------------------------------------------
  //
  // `release` served three different intents — a purchase, a grant, seeding
  // liquidity — and emitted one event for all of them, so nothing on chain
  // could tell a sale from a gift. `releaseOrder` is the purchase path, and it
  // is idempotent because the thing calling it is a payment webhook.

  describe("releaseOrder", function () {
    const ORDER = ethers.keccak256(ethers.toUtf8Bytes("cs_live_example_session"));

    async function funded() {
      const context = await deploy();
      // Seed the treasury with an allocation to sell from.
      await context.token.mintGenesis(await context.treasury.getAddress(),
                                      ethers.parseEther("1000"));
      return context;
    }

    it("delivers the purchase and records the order", async () => {
      const { treasury, token, alice } = await funded();
      const amount = ethers.parseEther("60");

      await expect(treasury.releaseOrder(alice.address, amount, ORDER, ethers.ZeroHash))
        .to.emit(treasury, "PurchaseDelivered");

      expect(await token.balanceOf(alice.address)).to.equal(amount);
      const order = await treasury.orders(ORDER);
      expect(order.buyer).to.equal(alice.address);
      expect(order.amount).to.equal(amount);
      expect(order.filledAt).to.be.greaterThan(0);
      expect(await treasury.orderFilled(ORDER)).to.equal(true);
    });

    it("refuses to fill the same order twice", async () => {
      // THE reason the mapping exists rather than an event alone. Stripe
      // retries a webhook on any non-2xx or timeout, so "deliver order X" WILL
      // arrive more than once in normal operation, and the difference between
      // a retry and a genuine second purchase is not visible from inside the
      // transaction. The chain refuses it, so the delivery path is safe to
      // retry blindly — which is what a payment integration needs.
      const { treasury, token, alice } = await funded();
      const amount = ethers.parseEther("60");

      await treasury.releaseOrder(alice.address, amount, ORDER, ethers.ZeroHash);
      await expect(treasury.releaseOrder(alice.address, amount, ORDER, ethers.ZeroHash))
        .to.be.revertedWithCustomError(treasury, "OrderAlreadyFilled");

      // And the retry moved nothing.
      expect(await token.balanceOf(alice.address)).to.equal(amount);
    });

    it("refuses a zero order id", async () => {
      // A zero id is what an uninitialised variable looks like, and every
      // caller who forgot to set one would collide on it — turning the
      // idempotency guard into a lock on all future orders.
      const { treasury, alice } = await funded();
      await expect(treasury.releaseOrder(alice.address, 1n, ethers.ZeroHash, ethers.ZeroHash))
        .to.be.revertedWithCustomError(treasury, "ZeroOrderId");
    });

    it("is owner-only, like every other spending path", async () => {
      const { treasury, alice } = await funded();
      await expect(treasury.connect(alice).releaseOrder(alice.address, 1n, ORDER, ethers.ZeroHash))
        .to.be.revertedWithCustomError(treasury, "OwnableUnauthorizedAccount");
    });

    it("cannot mint — a purchase comes out of the existing allocation", async () => {
      const { treasury, token, alice } = await funded();
      const before = await token.totalSupply();
      await treasury.releaseOrder(alice.address, ethers.parseEther("10"), ORDER, ethers.ZeroHash);
      expect(await token.totalSupply()).to.equal(before);
    });

    it("carries a timestamp, because eth_getLogs cannot filter by date", async () => {
      // The EVM has no notion of dates and eth_getLogs takes block numbers
      // only. Emitting the timestamp means a reader answering "everything
      // between these dates" resolves the block range once and then reads each
      // log directly, instead of fetching a block header per log.
      const { treasury, alice } = await funded();
      const tx = await treasury.releaseOrder(alice.address, 1n, ORDER, ethers.ZeroHash);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt!.blockNumber);

      const parsed = receipt!.logs
        .map((log) => { try { return treasury.interface.parseLog(log as any); } catch { return null; } })
        .find((log) => log && log.name === "PurchaseDelivered");
      expect(parsed!.args.filledAt).to.equal(BigInt(block!.timestamp));
    });

    it("buckets by day, so a date RANGE is one filtered call", async () => {
      // The only way eth_getLogs does dates. Topics match by exact equality —
      // there is no >= or <= — so a raw timestamp is unfilterable as a range.
      // But each topic position accepts an ARRAY meaning OR, so a coarse
      // bucket turns "these two dates" into a list of day numbers.
      const { treasury, alice } = await funded();
      await treasury.releaseOrder(alice.address, 1n, ORDER, ethers.ZeroHash);

      const receipt = await (await ethers.provider.getBlock("latest"))!;
      const today = Math.floor(receipt.timestamp / 86400);
      expect(await treasury.dayOf(receipt.timestamp)).to.equal(today);

      // A range query: OR the day values in topic position 3, the way a caller
      // actually would. Topics are built explicitly rather than through the
      // filters helper, because that is exactly the shape a backend sends to
      // eth_getLogs and it is the thing worth proving works.
      const sig = treasury.interface.getEvent("PurchaseDelivered")!.topicHash;
      const asTopic = (day: number) => ethers.zeroPadValue(ethers.toBeHex(day), 32);
      const address = await treasury.getAddress();

      const inRange = await ethers.provider.getLogs({
        address,
        fromBlock: 0,
        topics: [sig, null, null, [today - 1, today, today + 1].map(asTopic)],
      });
      expect(inRange.length).to.equal(1);

      // A range that excludes today finds nothing — the filter really filters
      // rather than returning everything.
      const missed = await ethers.provider.getLogs({
        address,
        fromBlock: 0,
        topics: [sig, null, null, [asTopic(today + 5)]],
      });
      expect(missed.length).to.equal(0);
    });

    it("computes the same day bucket the backend will", async () => {
      // dayOf is exposed so there is ONE definition of "which day is this".
      // Two implementations drift the moment somebody thinks about timezones.
      const { treasury } = await funded();
      expect(await treasury.dayOf(0)).to.equal(0);
      expect(await treasury.dayOf(86399)).to.equal(0);
      expect(await treasury.dayOf(86400)).to.equal(1);
      expect(await treasury.dayOf(1785721824)).to.equal(Math.floor(1785721824 / 86400));
    });

    it("is searchable by every field, including the exact second", async () => {
      // Four searchable dimensions across two events, because one event gets
      // three indexed slots. Each of these is a real eth_getLogs filter, built
      // the way a backend would build it.
      const { treasury, alice } = await funded();
      await treasury.releaseOrder(alice.address, ethers.parseEther("5"), ORDER, ethers.ZeroHash);

      const address = await treasury.getAddress();
      const delivered = treasury.interface.getEvent("PurchaseDelivered")!.topicHash;
      const at = treasury.interface.getEvent("PurchaseAt")!.topicHash;
      const pad = (v: any) => ethers.zeroPadValue(ethers.toBeHex(v), 32);

      const block = (await ethers.provider.getBlock("latest"))!;
      const second = block.timestamp;
      const day = Math.floor(second / 86400);

      // 1. by buyer
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [delivered, ethers.zeroPadValue(alice.address, 32)] })).length).to.equal(1);

      // 2. by order id
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [delivered, null, ORDER] })).length).to.equal(1);

      // 3. by day, and by a RANGE of days
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [delivered, null, null, [day - 2, day, day + 2].map(pad)] })).length).to.equal(1);

      // 4. by the exact unix second, via the companion event
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [at, pad(second)] })).length).to.equal(1);

      // ...and the wrong second finds nothing, so it is really filtering.
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [at, pad(second + 1)] })).length).to.equal(0);
    });

    it("joins the two events on orderId", async () => {
      // The companion event carries no data, so a caller that found a purchase
      // by its second has to get back to the full record. orderId is indexed on
      // both, which is what makes that one more filtered call rather than a
      // scan.
      const { treasury, alice } = await funded();
      await treasury.releaseOrder(alice.address, ethers.parseEther("7"), ORDER, ethers.ZeroHash);

      const address = await treasury.getAddress();
      const at = treasury.interface.getEvent("PurchaseAt")!.topicHash;
      const delivered = treasury.interface.getEvent("PurchaseDelivered")!.topicHash;

      const found = await ethers.provider.getLogs({ address, fromBlock: 0, topics: [at] });
      const orderId = found[0].topics[2];

      const full = await ethers.provider.getLogs({
        address, fromBlock: 0, topics: [delivered, null, orderId] });
      const parsed = treasury.interface.parseLog(full[0] as any)!;
      expect(parsed.args.amount).to.equal(ethers.parseEther("7"));
    });

    it("records where a purchase came from, as a hash and never an address", async () => {
      // The search works identically either way — a topic matches by equality,
      // so you hash the address you are looking for. The raw value would buy
      // no extra capability and would publish somebody's connection forever.
      const { treasury, alice } = await funded();
      const PEPPER = ethers.toUtf8Bytes("server-side-secret");
      const originOf = (ip: string) =>
        ethers.keccak256(ethers.concat([PEPPER, ethers.toUtf8Bytes(ip)]));

      const origin = originOf("203.0.113.7");
      await treasury.releaseOrder(alice.address, 1n, ORDER, origin);

      const address = await treasury.getAddress();
      const topic = treasury.interface.getEvent("PurchaseOrigin")!.topicHash;

      // Found by hashing the address being searched for.
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [topic, origin] })).length).to.equal(1);

      // A different address finds nothing.
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [topic, originOf("198.51.100.4")] })).length).to.equal(0);

      // And the address itself never appears anywhere in the log.
      const logs = await ethers.provider.getLogs({ address, fromBlock: 0 });
      const raw = JSON.stringify(logs);
      expect(raw).to.not.contain(Buffer.from("203.0.113.7").toString("hex"));
    });

    it("omits the origin event entirely when none was captured", async () => {
      // Rather than logging zero. A zero topic is a value somebody can filter
      // FOR, and it would gather every purchase whose origin was never
      // recorded into one bucket that looks like a finding.
      const { treasury, alice } = await funded();
      await treasury.releaseOrder(alice.address, 1n, ORDER, ethers.ZeroHash);

      const address = await treasury.getAddress();
      const topic = treasury.interface.getEvent("PurchaseOrigin")!.topicHash;
      expect((await ethers.provider.getLogs({ address, fromBlock: 0,
        topics: [topic] })).length).to.equal(0);
    });

    it("distinguishes a purchase from a grant on chain", async () => {
      // The whole point. `release` still exists for grants and liquidity, and
      // emits a different event, so a log reader can tell them apart.
      const { treasury, alice } = await funded();
      await expect(treasury.release(alice.address, 1n))
        .to.emit(treasury, "Released")
        .and.not.to.emit(treasury, "PurchaseDelivered");
    });
  });
});
