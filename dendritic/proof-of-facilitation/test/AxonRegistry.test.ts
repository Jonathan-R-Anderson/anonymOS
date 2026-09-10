import { expect } from "chai";
import { ethers } from "hardhat";

// §12.4a's acquisition rules, exercised against the compiled contract.
//
// internal/axon/registry models the same rules in Go so they can be tested
// without a chain. THIS is the authority: where the two disagree, the contract
// wins and the Go copy is the thing that is wrong.

const DAY = 86400n;
const YEAR = 365n * DAY;

async function deploy() {
  const [owner, treasury, alice, bob, carol] = await ethers.getSigners();

  const Token = await ethers.getContractFactory("AxonToken");
  const token = await Token.deploy(owner.address);
  await token.waitForDeployment();
  await token.setTreasury(owner.address);

  const Reg = await ethers.getContractFactory("AxonRegistry");
  const reg = await Reg.deploy(
    owner.address,
    await token.getAddress(),
    treasury.address,
    ethers.keccak256(ethers.toUtf8Bytes("axon")),
    // grace, commitMin, commitMax, term, epoch, seizeQuarantine (§93, R-93.3)
    [30n * DAY, 60n, DAY, YEAR, DAY, 90n * DAY],
    [1000n, 500n],                      // basePrice, bondPerName
    [5000, 1, 2],                       // levyBps(50%), burstFree, revealsPerBlock
    180n * DAY                          // levy half-life
  );
  await reg.waitForDeployment();

  for (const who of [alice, bob, carol]) {
    await token.mintGenesis(who.address, ethers.parseEther("1"));
    await token.connect(who).approve(await reg.getAddress(), ethers.MaxUint256);
  }
  return { owner, treasury, alice, bob, carol, token, reg };
}

function hashes(label: string) {
  return {
    nameHash: ethers.keccak256(ethers.toUtf8Bytes(label)),
    skeleton: ethers.keccak256(ethers.toUtf8Bytes(label + ":skel")),
  };
}

async function register(reg: any, who: any, label: string, skelLabel = label) {
  const nameHash = ethers.keccak256(ethers.toUtf8Bytes(label));
  const skeleton = ethers.keccak256(ethers.toUtf8Bytes(skelLabel + ":skel"));
  const secret = ethers.keccak256(ethers.toUtf8Bytes("s:" + label));
  const domainKey = ethers.keccak256(ethers.toUtf8Bytes("k:" + label));
  const commitment = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "bytes32", "bytes32"],
      [nameHash, who.address, secret, domainKey]
    )
  );
  await reg.connect(who).commit(commitment);
  await ethers.provider.send("evm_increaseTime", [120]);
  await ethers.provider.send("evm_mine", []);
  const tx = await reg.connect(who).register(
    nameHash, skeleton, label.length, secret, domainKey);
  return { tx, nameHash, skeleton };
}

describe("AxonRegistry", function () {
  it("takes a name through commit -> reveal and locks the bond", async function () {
    const { reg, token, alice } = await deploy();
    const before = await token.balanceOf(alice.address);

    const { nameHash } = await register(reg, alice, "alicename");
    const n = await reg.nameOf(nameHash);
    expect(n.owner).to.equal(alice.address);
    expect(n.bond).to.equal(500n);
    expect(n.version).to.equal(1);

    // price (base 1000, 9 chars) + bond 500 left the account.
    expect(before - (await token.balanceOf(alice.address))).to.equal(1500n);
    // The bond is HELD BY THE CONTRACT, not spent to the treasury.
    expect(await token.balanceOf(await reg.getAddress())).to.equal(1500n);
  });

  it("refuses a reveal with no commitment, one too young, and one too old", async function () {
    const { reg, alice } = await deploy();
    const { nameHash, skeleton } = hashes("alicename");
    const secret = ethers.ZeroHash;

    await expect(reg.connect(alice).register(nameHash, skeleton, 9, secret, ethers.ZeroHash))
      .to.be.revertedWithCustomError(reg, "NoCommit");

    const commitment = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "bytes32", "bytes32"],
        [nameHash, alice.address, secret, ethers.ZeroHash]));
    await reg.connect(alice).commit(commitment);
    await expect(reg.connect(alice).register(nameHash, skeleton, 9, secret, ethers.ZeroHash))
      .to.be.revertedWithCustomError(reg, "CommitTooNew");

    await ethers.provider.send("evm_increaseTime", [2 * 86400]);
    await ethers.provider.send("evm_mine", []);
    await expect(reg.connect(alice).register(nameHash, skeleton, 9, secret, ethers.ZeroHash))
      .to.be.revertedWithCustomError(reg, "CommitTooOld");
  });

  it("refuses a confusable skeleton held by ANOTHER owner, but not by the same one",
    async function () {
      const { reg, alice, bob } = await deploy();
      await register(reg, alice, "paypal", "paypal");
      // bob wants a different label that folds onto the same skeleton
      await expect(register(reg, bob, "paypa1", "paypal"))
        .to.be.revertedWithCustomError(reg, "ClassHeld");
      // alice may take her own variant: defensive registration has to be
      // affordable for the party the rule protects.
      await expect(register(reg, alice, "paypa1", "paypal")).to.not.be.reverted;
    });

  it("rate-limits reveals per block, turning a dictionary into a queue",
    async function () {
      const { reg, alice } = await deploy();
      // Commit a dictionary up front -- commit-reveal does NOT stop that.
      const items = [];
      for (let i = 0; i < 5; i++) {
        const label = "sweep" + i;
        const nameHash = ethers.keccak256(ethers.toUtf8Bytes(label));
        const skeleton = ethers.keccak256(ethers.toUtf8Bytes(label + ":skel"));
        const secret = ethers.keccak256(ethers.toUtf8Bytes("s:" + label));
        await reg.connect(alice).commit(ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "address", "bytes32", "bytes32"],
            [nameHash, alice.address, secret, ethers.ZeroHash])));
        items.push({ nameHash, skeleton, secret, label });
      }
      await ethers.provider.send("evm_increaseTime", [120]);

      // All in ONE block, so the per-block cap bites.
      await ethers.provider.send("evm_setAutomine", [false]);
      // AWAIT SUBMISSION before mining. The first version pushed un-awaited
      // promises and mined immediately, so nothing was in the mempool yet and
      // all five auto-mined individually afterwards -- one per block, which is
      // exactly the case the cap does not apply to. The test passed the
      // contract and failed itself.
      //
      // Explicit gasLimit skips estimation, so a tx that will revert still
      // reaches the block rather than being rejected client-side.
      for (const it of items) {
        await reg.connect(alice).register(
          it.nameHash, it.skeleton, it.label.length, it.secret, ethers.ZeroHash,
          { gasLimit: 500_000 });
      }
      await ethers.provider.send("evm_mine", []);
      await ethers.provider.send("evm_setAutomine", [true]);

      let taken = 0;
      for (const it of items) {
        const n = await reg.nameOf(it.nameHash);
        if (n.owner !== ethers.ZeroAddress) taken++;
      }
      expect(taken).to.be.lessThanOrEqual(2);   // REVEALS_PER_BLOCK
    });

  it("levies the DAO on a secondary sale, decaying with holding time", async function () {
    const { reg, token, treasury, alice, bob } = await deploy();
    const { nameHash } = await register(reg, alice, "flipname");

    const sale = 100_000n;
    const before = await token.balanceOf(treasury.address);
    await reg.connect(alice).transfer(nameHash, bob.address, sale);
    const levied = (await token.balanceOf(treasury.address)) - before;

    // Same-day flip forfeits half.
    expect(levied).to.equal(sale / 2n);
    expect((await reg.nameOf(nameHash)).owner).to.equal(bob.address);

    // The decay is real: after one half-life it is a quarter.
    expect(await reg.levyFor(sale, 180n * DAY)).to.equal(sale / 4n);
    // And a genuine holder selling years later pays ~nothing.
    expect(await reg.levyFor(sale, 10n * YEAR)).to.equal(0n);
  });

  it("resets the levy clock on transfer, so a self-sale cannot launder the decay",
    async function () {
      const { reg, alice, bob } = await deploy();
      const { nameHash } = await register(reg, alice, "launder");

      await ethers.provider.send("evm_increaseTime", [Number(300n * DAY)]);
      await ethers.provider.send("evm_mine", []);
      // Held a long time -> levy has decayed away.
      await reg.connect(alice).transfer(nameHash, bob.address, 100_000n);

      // bob's clock starts NOW, so his immediate resale is levied in full.
      expect(await reg.levyFor(100_000n, 0n)).to.equal(50_000n);
      const n = await reg.nameOf(nameHash);
      const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
      expect(now - n.acquiredAt).to.be.lessThan(10n);
    });

  it("surcharges a burst within one epoch, and does NOT stop an account split",
    async function () {
      const { reg, alice, bob, carol } = await deploy();
      // Same account, same epoch: superlinear.
      expect(await reg.burstSurcharge(1000n, 1)).to.equal(1000n);
      expect(await reg.burstSurcharge(1000n, 2)).to.equal(2000n);
      expect(await reg.burstSurcharge(1000n, 3)).to.equal(5000n);

      // §12.4a.1's negative result, asserted: three accounts each take one name
      // and every one pays base price. This is why the levy exists and the
      // surcharge is not the guard.
      for (const [who, label] of [[alice, "splitaa"], [bob, "splitbb"], [carol, "splitcc"]] as const) {
        const { tx } = await register(reg, who, label);
        await expect(tx).to.emit(reg, "Registered");
      }
      expect(await reg.feePool()).to.equal(3000n);   // 3 x base, not escalating
    });

  it("refuses a second registration while the name is held", async function () {
    const { reg, alice, bob } = await deploy();
    const { nameHash } = await register(reg, alice, "takenname");
    await expect(register(reg, bob, "takenname", "othersk"))
      .to.be.revertedWithCustomError(reg, "NotAvailable");
    expect((await reg.nameOf(nameHash)).owner).to.equal(alice.address);
  });

  it("prices short labels higher", async function () {
    const { reg } = await deploy();
    expect(await reg.priceOf(3)).to.equal(100_000n);
    expect(await reg.priceOf(4)).to.equal(20_000n);
    expect(await reg.priceOf(5)).to.equal(5_000n);
    expect(await reg.priceOf(9)).to.equal(1_000n);
  });

  it("returns the bond on release", async function () {
    const { reg, token, alice } = await deploy();
    const { nameHash } = await register(reg, alice, "givenback");
    const before = await token.balanceOf(alice.address);
    await reg.connect(alice).release(nameHash);
    expect((await token.balanceOf(alice.address)) - before).to.equal(500n);
    // A RELEASED name is immediately available, unlike an EXPIRED one. Grace
    // exists to protect an owner who forgot to renew; release is that owner
    // choosing to let go, and holding their name hostage for 30 days afterwards
    // would protect nobody. The re-registration still needs an aged commitment,
    // so this is the same race as expiry rather than a new one.
    expect(await reg.available(nameHash)).to.equal(true);
  });
});

// ---------------------------------------------------------------------------
// Part X §93 — seizure by key rotation
// ---------------------------------------------------------------------------
describe("AxonRegistry — governance state (Part X §93)", function () {
  // Reuses the module's own `register` helper rather than a second copy of the
  // commit/reveal dance -- a duplicate would drift from the real one and start
  // testing itself.
  async function take(reg: any, _token: any, who: any, label: string) {
    const { nameHash } = await register(reg, who, label);
    return nameHash;
  }

  it("refuses every governance path until a governor is set (F-94.1)", async function () {
    const { reg, token, owner, alice } = await deploy();
    const nameHash = await take(reg, token, alice, "sequencing");

    // This is the sequencing ruling as code. The DAO's voting weight is defined
    // but three of its four inputs are unmeasurable and there is NO Governance
    // contract on chain; writing seizure state before one exists would make
    // "the blockchain is authoritative" mean "whatever one server writes is".
    expect(await reg.governor()).to.equal(ethers.ZeroAddress);
    await expect(reg.connect(owner).prune(nameHash, 1)).to.be.revertedWithCustomError(reg, "NoGovernor");
    await expect(reg.connect(owner).seize(nameHash, 1)).to.be.revertedWithCustomError(reg, "NoGovernor");

    // And once set, only the governor — not even the contract owner.
    const [, , , , , gov] = await ethers.getSigners();
    await reg.connect(owner).setGovernor(gov.address);
    await expect(reg.connect(owner).prune(nameHash, 1)).to.be.revertedWithCustomError(reg, "NotGovernor");
    await expect(reg.connect(alice).seize(nameHash, 1)).to.be.revertedWithCustomError(reg, "NotGovernor");
  });

  it("refuses a zero quarantine at deployment (R-93.3)", async function () {
    const [owner, treasury] = await ethers.getSigners();
    const Token = await ethers.getContractFactory("AxonToken");
    const token = await Token.deploy(owner.address);
    const Reg = await ethers.getContractFactory("AxonRegistry");
    // A zero quarantine makes every seizure a no-op: the name is re-registered
    // by the seized party from a fresh wallet in the next block. It has to fail
    // at deployment, because a deployment carrying it would look correct.
    await expect(Reg.deploy(
      owner.address, await token.getAddress(), treasury.address,
      ethers.keccak256(ethers.toUtf8Bytes("axon")),
      [30n * DAY, 60n, DAY, YEAR, DAY, 0n],
      [1000n, 500n], [5000, 1, 2], 180n * DAY,
    )).to.be.revertedWithCustomError(Reg, "ZeroQuarantine");
  });

  it("PRUNE zeroes the domain key and leaves the name with its owner (R-93.2)", async function () {
    const { reg, token, owner, alice } = await deploy();
    const [, , , , , gov] = await ethers.getSigners();
    await reg.connect(owner).setGovernor(gov.address);
    const nameHash = await take(reg, token, alice, "pruneme");

    const before = await reg.nameOf(nameHash);
    expect(before.domainKey).to.not.equal(ethers.ZeroHash);

    await expect(reg.connect(gov).prune(nameHash, 42)).to.emit(reg, "Pruned");

    const after = await reg.nameOf(nameHash);
    // A prune does NOT take the name — that is what distinguishes it from a
    // seizure — so the owner, bond and expiry are all untouched.
    expect(after.owner).to.equal(alice.address);
    expect(after.bond).to.equal(before.bond);
    expect(after.expiresAt).to.equal(before.expiresAt);
    // But the key is gone, which is what makes it bite: no descriptor validates,
    // so a node that ignores the prune state ENTIRELY still cannot resolve it.
    expect(after.domainKey).to.equal(ethers.ZeroHash);
    expect(after.version).to.equal(before.version + 1n);  // §11.7 anti-rollback
    expect(await reg.stateOf(nameHash)).to.equal(1);       // PRUNED
    // And it is not available to anybody else while it is pruned.
    expect(await reg.available(nameHash)).to.equal(false);
  });

  it("SEIZE takes the name, forfeits the bond, and never hands over a key (R-93.4)", async function () {
    const { reg, token, owner, alice } = await deploy();
    const [, , , , , gov] = await ethers.getSigners();
    await reg.connect(owner).setGovernor(gov.address);
    const nameHash = await take(reg, token, alice, "seizeme");

    const before = await reg.nameOf(nameHash);
    await expect(reg.connect(gov).seize(nameHash, 7))
      .to.emit(reg, "Seized").withArgs(nameHash, 7, alice.address, before.version + 1n);

    const after = await reg.nameOf(nameHash);
    expect(after.owner).to.equal(ethers.ZeroAddress);   // the network holds it
    expect(after.domainKey).to.equal(ethers.ZeroHash);  // rotated to nothing
    expect(after.bond).to.equal(0n);                    // forfeited
    expect(await reg.stateOf(nameHash)).to.equal(2);    // SEIZED

    // THE PROPERTY THAT MATTERS: the contract has no function that returns a
    // domain key to anybody, because it never holds one. Escrow would put a
    // single compromise between an attacker and every domain in the network.
    const names = reg.interface.fragments
      .map((f: any) => f.name).filter(Boolean).map((n: string) => n.toLowerCase());
    expect(names.filter((n: string) => /escrow|revealkey|exportkey|privkey/.test(n)))
      .to.deep.equal([]);
  });

  it("a seized name cannot be re-registered until the quarantine expires (E-G10b)", async function () {
    const { reg, token, owner, alice, bob } = await deploy();
    const [, , , , , gov] = await ethers.getSigners();
    await reg.connect(owner).setGovernor(gov.address);
    const nameHash = await take(reg, token, alice, "quarantined");
    await reg.connect(gov).seize(nameHash, 9);

    // THE ATTACK: seizure sets owner to zero, so a naive availability test
    // ("is owner zero?") calls the name available in the very block it was
    // taken, and the seized party re-registers it from a fresh wallet.
    expect(await reg.available(nameHash)).to.equal(false);
    await expect(take(reg, token, bob, "quarantined"))
      .to.be.revertedWithCustomError(reg, "NotAvailable");
    // Nor can it be promoted early.
    await expect(reg.makeRecyclable(nameHash)).to.be.revertedWithCustomError(reg, "Quarantined");

    await ethers.provider.send("evm_increaseTime", [Number(90n * DAY) + 1]);
    await ethers.provider.send("evm_mine", []);
    // Permissionless: inaction must not be able to extend a seizure for ever.
    await expect(reg.connect(bob).makeRecyclable(nameHash)).to.emit(reg, "Recyclable");
    expect(await reg.available(nameHash)).to.equal(true);
  });

  it("recycles to a new owner and never rewrites the history (E-G10c)", async function () {
    const { reg, token, owner, alice, bob } = await deploy();
    const [, , , , , gov] = await ethers.getSigners();
    await reg.connect(owner).setGovernor(gov.address);
    const nameHash = await take(reg, token, alice, "recycled");
    await reg.connect(gov).seize(nameHash, 11);
    await ethers.provider.send("evm_increaseTime", [Number(90n * DAY) + 1]);
    await ethers.provider.send("evm_mine", []);
    await reg.makeRecyclable(nameHash);

    await take(reg, token, bob, "recycled");
    const after = await reg.nameOf(nameHash);
    expect(after.owner).to.equal(bob.address);
    expect(after.domainKey).to.not.equal(ethers.ZeroHash);  // bob set his own
    expect(await reg.stateOf(nameHash)).to.equal(0);         // ACTIVE again

    // The seizure is still in the record. A new owner must be judged on their
    // own content, and a history a new owner could erase would let a seized
    // party launder a name by re-registering it.
    const history = await reg.historyOf(nameHash);
    expect(history.length).to.equal(3);                      // SEIZED, RECYCLABLE, ACTIVE
    expect(history[0].state).to.equal(2);
    expect(history[0].previousOwner).to.equal(alice.address);
    expect(history[0].proposalId).to.equal(11n);
  });

  it("a pruned owner cannot escape through release() (R-93.6)", async function () {
    const { reg, token, owner, alice } = await deploy();
    const [, , , , , gov] = await ethers.getSigners();
    await reg.connect(owner).setGovernor(gov.address);
    const nameHash = await take(reg, token, alice, "escapee");
    await reg.connect(gov).prune(nameHash, 3);

    // release() makes a name available IMMEDIATELY, which is right for a
    // voluntary release and inverts under a prune: the owner would hand the
    // name back to the pool and re-register it from a fresh wallet next block,
    // converting a prune into a rename.
    await expect(reg.connect(alice).release(nameHash))
      .to.be.revertedWithCustomError(reg, "BadState");
    // Nor can they transfer out of it.
    expect(await reg.available(nameHash)).to.equal(false);
  });

  it("an appeal restores a PRUNED name but not the key (§93)", async function () {
    const { reg, token, owner, alice } = await deploy();
    const [, , , , , gov] = await ethers.getSigners();
    await reg.connect(owner).setGovernor(gov.address);
    const nameHash = await take(reg, token, alice, "appealed");
    await reg.connect(gov).prune(nameHash, 5);

    await expect(reg.connect(gov).restore(nameHash, 6)).to.emit(reg, "Restored");
    expect(await reg.stateOf(nameHash)).to.equal(0);
    const after = await reg.nameOf(nameHash);
    expect(after.owner).to.equal(alice.address);
    // The key stays zero. The contract never held it, so it cannot give it
    // back — and a key that was public knowledge as "the key of a pruned
    // domain" should not return to service anyway. The owner publishes a fresh
    // one, which is an ordinary owner action.
    expect(after.domainKey).to.equal(ethers.ZeroHash);
    // A seized name cannot be restored this way: its owner is deliberately
    // zero, so there is nobody to restore it to.
    const other = await take(reg, token, alice, "seized2");
    await reg.connect(gov).seize(other, 8);
    await expect(reg.connect(gov).restore(other, 9)).to.be.revertedWithCustomError(reg, "BadState");
  });
});
