import { expect } from "chai";
import { ethers, network } from "hardhat";

// TLDRegistry -- the AXON root zone (§12.0, §12.0a), exercised against the
// compiled contract. Two kinds of test live here:
//
//   * the powers §12.0a ENUMERATES, each behind its timelock, and the ones it
//     makes ABSENT BY CONSTRUCTION, held true by enumerating the ABI;
//   * the test vector internal/axon/registrar's Go tests are pinned to
//     (labelHash, nameHash, commitment, calldata, raw return data), produced
//     HERE by the contracts, so the Go encoder is checked against the chain's
//     own arithmetic rather than against a second hand-written copy.

const DAY = 86400n;
const coder = ethers.AbiCoder.defaultAbiCoder();
const lh = (s: string) => ethers.keccak256(ethers.toUtf8Bytes(s));

const NS = { NONE: 0n, PROPOSED: 1n, ACTIVE: 2n, FROZEN: 3n, RETIRING: 4n, RETIRED: 5n };
const CLS = { IMMUTABLE: 0, UPGRADEABLE: 1, STEWARDED: 2 };
const WHY = {
  NONE: 0, LENGTH: 1, CHARSET: 2, HYPHEN: 3, IDNA_PREFIX: 4, ROOT_SUFFIX: 5,
  SPECIAL_USE: 6, AXON_RESERVED: 7, IANA_DELEGATED: 8, RESERVED_LIST: 9,
};
const ACT = { NONE: 0n, QUEUED: 1n, EXECUTED: 2n, CANCELLED: 3n };

const BOND = 1000n;
const CHARTER = lh("charter: first come, first served, flat fee");
const SCHEMA1 = lh("recordSchema 1: the section 11.6 DomainRecord set");

async function now(): Promise<bigint> {
  return BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
}
async function increase(s: bigint) {
  await ethers.provider.send("evm_increaseTime", [Number(s)]);
  await ethers.provider.send("evm_mine", []);
}

// Mainnet AxonRegistry immutables, read by eth_call from
// 0x5B2D1cd4AB437e1d4a0adC1416FEe2ff517ef0DB on 2026-09-30, so the vector below
// prices a name the way the live registrar would.
const MAINNET_REG = {
  times: [90n * DAY, 60n, DAY, 365n * DAY, 7n * DAY, 30n * DAY], // grace, commitMin, commitMax, term, epoch, seizeQuarantine
  money: [10n * 10n ** 18n, 100n * 10n ** 18n],                  // basePrice, bondPerName
  limits: [500, 3, 8],                                            // levyBps, burstFree, revealsPerBlock
  levyHalfLife: 30n * DAY,
};

async function deployAxonRegistry(signer: any, token: any, treasury: string, tldNode: string) {
  const Reg = await ethers.getContractFactory("AxonRegistry", signer);
  const reg = await Reg.deploy(signer.address, await token.getAddress(), treasury, tldNode,
    MAINNET_REG.times, MAINNET_REG.money, MAINNET_REG.limits, MAINNET_REG.levyHalfLife);
  await reg.waitForDeployment();
  return reg;
}

async function deploy() {
  const [governor, guardian, proposer, alice, stranger, treasury, newGov] = await ethers.getSigners();

  const token = await (await ethers.getContractFactory("AxonToken")).deploy(governor.address);
  await token.waitForDeployment();

  const Root = await ethers.getContractFactory("TLDRegistry");
  const root = await Root.deploy(governor.address, guardian.address, (await now()) + 180n * DAY,
    await token.getAddress(), treasury.address, BOND, SCHEMA1);
  await root.waitForDeployment();
  const rootAddr = await root.getAddress();

  // Genesis: a slice of the IANA snapshot and one reserved label, then seal.
  await root.genesisSeed(["com", "net", "org", "dev", "app"], ["badlabel"], 2026093000);
  await root.sealGenesis();

  for (const who of [proposer, alice, stranger]) {
    await token.mintGenesis(who.address, ethers.parseEther("10000"));
    await token.connect(who).approve(rootAddr, ethers.MaxUint256);
  }

  const labReg = await deployAxonRegistry(governor, token, treasury.address,
    await root.namespaceNode(lh("lab")));

  return { governor, guardian, proposer, alice, stranger, treasury, newGov, token, root, rootAddr, labReg };
}

async function propose(root: any, who: any, label: string, registrar: string,
                       o: { cls?: number; steward?: string; charter?: string; schema?: number } = {}) {
  return root.connect(who).proposeNamespace(label, registrar, o.cls ?? CLS.IMMUTABLE,
    o.steward ?? ethers.ZeroAddress, o.charter ?? CHARTER, o.schema ?? 1);
}

/** The ActionQueued event of a tx: id, eta and the exact payload to execute with. */
async function queued(root: any, txp: Promise<any>) {
  const rc = await (await txp).wait();
  for (const log of rc.logs) {
    let ev;
    try { ev = root.interface.parseLog(log); } catch { continue; }
    if (ev && ev.name === "ActionQueued") {
      return { id: ev.args.id as bigint, eta: ev.args.eta as bigint, payload: ev.args.payload as string };
    }
  }
  throw new Error("no ActionQueued");
}

/** propose -> queueCreate -> 14 days -> execute. */
async function create(ctx: any, label: string, registrar: string, o: any = {}) {
  await propose(ctx.root, ctx.proposer, label, registrar, o);
  const q = await queued(ctx.root, ctx.root.connect(ctx.governor).queueCreate(label));
  await increase(14n * DAY);
  await ctx.root.connect(ctx.stranger).execute(q.id, q.payload);
  return q;
}

describe("TLDRegistry — namespaces", function () {
  it("creates a namespace: propose -> queue -> refused before 14 days -> executed after, with an AxonRegistry as registrar",
    async function () {
      const ctx = await deploy();
      const { root, token, proposer, governor, stranger, labReg } = ctx;
      const h = lh("lab");
      const regAddr = await labReg.getAddress();

      const before = await token.balanceOf(proposer.address);
      await expect(propose(root, proposer, "lab", regAddr))
        .to.emit(root, "NamespaceProposed");
      let ns = await root.namespaceOf(h);
      expect(ns.status).to.equal(NS.PROPOSED);
      expect(ns.bond).to.equal(BOND);
      expect(before - (await token.balanceOf(proposer.address))).to.equal(BOND);

      // Only the governor queues.
      await expect(root.connect(stranger).queueCreate("lab"))
        .to.be.revertedWithCustomError(root, "NotGovernor");
      const q = await queued(root, root.connect(governor).queueCreate("lab"));
      expect(q.eta).to.equal((await now()) + 14n * DAY);
      // Not twice.
      await expect(root.connect(governor).queueCreate("lab"))
        .to.be.revertedWithCustomError(root, "CreatePending");

      // A day short of the timelock: refused.
      await increase(13n * DAY);
      await expect(root.connect(stranger).execute(q.id, q.payload))
        .to.be.revertedWithCustomError(root, "TooEarly");
      // Payload must be the queued one, byte for byte.
      await increase(DAY);
      await expect(root.connect(stranger).execute(q.id, coder.encode(["string"], ["lbb"])))
        .to.be.revertedWithCustomError(root, "BadPayload");
      // After 14 days, ANYONE executes it.
      await expect(root.connect(stranger).execute(q.id, q.payload))
        .to.emit(root, "NamespaceActivated");

      ns = await root.namespaceOf(h);
      expect(ns.registrar).to.equal(regAddr);
      expect(ns.registrarClass).to.equal(CLS.IMMUTABLE);
      expect(ns.status).to.equal(NS.ACTIVE);
      expect(ns.recordSchema).to.equal(1);
      expect(ns.activatedAt).to.equal(await now());
      expect(ns.retiresAt).to.equal(0);
      expect(ns.frozenAt).to.equal(0);
      expect(ns.bond).to.equal(0);                       // returned on activation
      expect(await token.balanceOf(proposer.address)).to.equal(before);
      expect(await root.registrarNamespace(regAddr)).to.equal(h);
      expect((await root.actionOf(q.id)).state).to.equal(ACT.EXECUTED);
      // Executed once.
      await expect(root.execute(q.id, q.payload)).to.be.revertedWithCustomError(root, "NotQueued");

      // The registrar's TLD_NODE is the root's namespace node, and the root's
      // nameHash is the ENS-style chain through it (§11.3.2).
      expect(await labReg.TLD_NODE()).to.equal(await root.namespaceNode(h));
      const rootNode = ethers.keccak256(ethers.concat([ethers.ZeroHash, lh("axon")]));
      expect(await root.ROOT_NODE()).to.equal(rootNode);
      const nsNode = ethers.keccak256(ethers.concat([rootNode, h]));
      expect(await root.nameHashOf(h, lh("alice")))
        .to.equal(ethers.keccak256(ethers.concat([nsNode, lh("alice")])));
    });

  it("refuses ineligible labels: length, charset, hyphens, IDNA prefix, the root, special-use, AXON-reserved, IANA, reserved list",
    async function () {
      const { root, proposer, labReg } = await deploy();
      const reg = await labReg.getAddress();
      const cases: [string, number][] = [
        ["", WHY.LENGTH],
        ["ab", WHY.LENGTH],                           // one/two chars: ccTLD space
        ["a".repeat(25), WHY.LENGTH],
        ["Lab", WHY.CHARSET],                         // uppercase is refused, not folded
        ["la_b", WHY.CHARSET],
        ["_lab", WHY.CHARSET],
        ["la.b", WHY.CHARSET],
        ["lab ", WHY.CHARSET],
        ["lаb", WHY.CHARSET],                         // Cyrillic а: non-ASCII
        ["-lab", WHY.HYPHEN],
        ["lab-", WHY.HYPHEN],
        ["xn--lab", WHY.IDNA_PREFIX],
        ["ab--c", WHY.IDNA_PREFIX],
        ["axon", WHY.ROOT_SUFFIX],
        ["localhost", WHY.SPECIAL_USE],
        ["onion", WHY.SPECIAL_USE],
        ["alt", WHY.SPECIAL_USE],
        ["test", WHY.SPECIAL_USE],
        ["example", WHY.SPECIAL_USE],
        ["invalid", WHY.SPECIAL_USE],
        ["local", WHY.SPECIAL_USE],
        ["arpa", WHY.SPECIAL_USE],
        ["internal", WHY.SPECIAL_USE],
        ["key", WHY.AXON_RESERVED],                   // Layer 1 addresses live here (§11.9)
        ["srv", WHY.AXON_RESERVED],
        ["com", WHY.IANA_DELEGATED],
        ["dev", WHY.IANA_DELEGATED],
        ["badlabel", WHY.RESERVED_LIST],
      ];
      for (const [label, why] of cases) {
        expect(await root.isEligible(label), label).to.equal(false);
        expect(await root.eligibility(label), label).to.equal(why);
        await expect(propose(root, proposer, label, reg), label)
          .to.be.revertedWithCustomError(root, "Ineligible").withArgs(why);
      }
      for (const label of ["anonymous", "lab", "a-b", "123", "a1-b2-c3", "z".repeat(24), "corp"]) {
        expect(await root.isEligible(label), label).to.equal(true);
        expect(await root.eligibility(label), label).to.equal(WHY.NONE);
      }
    });

  it("re-checks eligibility at creation: an IANA update that lands during the timelock blocks it",
    async function () {
      const ctx = await deploy();
      const { root, governor, proposer, stranger, labReg } = ctx;
      const iana = await queued(root, root.connect(governor).queueSetIana(["newgtld"], true, 2026110100));
      await increase(16n * DAY);
      await propose(root, proposer, "newgtld", await labReg.getAddress());
      const create = await queued(root, root.connect(governor).queueCreate("newgtld"));
      await increase(14n * DAY);
      await root.connect(stranger).execute(iana.id, iana.payload);
      expect(await root.ianaSnapshotAt()).to.equal(2026110100);
      await expect(root.connect(stranger).execute(create.id, create.payload))
        .to.be.revertedWithCustomError(root, "Ineligible").withArgs(WHY.IANA_DELEGATED);
      // The stuck proposal is resolved by veto, then rejection.
      await root.connect(governor).cancel(create.id);
      await root.connect(governor).rejectProposal(lh("newgtld"), false);
      expect((await root.namespaceOf(lh("newgtld"))).status).to.equal(NS.NONE);
    });

  it("refuses a second proposal for a taken label, a reused registrar, and a class/steward mismatch",
    async function () {
      const ctx = await deploy();
      const { root, proposer, stranger, labReg } = ctx;
      const reg = await labReg.getAddress();
      await create(ctx, "lab", reg);
      await expect(propose(root, stranger, "lab", reg))
        .to.be.revertedWithCustomError(root, "BadStatus").withArgs(NS.ACTIVE);
      // One registrar, one namespace (§11.0.3 rule 1).
      await expect(propose(root, stranger, "corp", reg))
        .to.be.revertedWithCustomError(root, "RegistrarInUse");
      const other = await (await ethers.getContractFactory("TrapRegistrar")).deploy();
      const o = await other.getAddress();
      await expect(propose(root, proposer, "corp", stranger.address))
        .to.be.revertedWithCustomError(root, "NotAContract");
      await expect(propose(root, proposer, "corp", o, { cls: CLS.IMMUTABLE, steward: stranger.address }))
        .to.be.revertedWithCustomError(root, "StewardMismatch");
      await expect(propose(root, proposer, "corp", o, { cls: CLS.STEWARDED }))
        .to.be.revertedWithCustomError(root, "StewardMismatch");
      await expect(propose(root, proposer, "corp", o, { charter: ethers.ZeroHash }))
        .to.be.revertedWithCustomError(root, "NoCharter");
      await expect(propose(root, proposer, "corp", o, { schema: 2 }))
        .to.be.revertedWithCustomError(root, "UnknownSchema");
      await expect(propose(root, proposer, "corp", o, { cls: CLS.STEWARDED, steward: stranger.address }))
        .to.not.be.reverted;
    });
});

describe("TLDRegistry — the proposer's bond", function () {
  it("is slashed to the treasury, or returned, on rejection; frees the label either way", async function () {
    const ctx = await deploy();
    const { root, token, proposer, governor, treasury, stranger } = ctx;
    const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();

    await propose(root, proposer, "spam", trap);
    await expect(root.connect(stranger).rejectProposal(lh("spam"), true))
      .to.be.revertedWithCustomError(root, "NotGovernor");
    await expect(root.connect(governor).rejectProposal(lh("spam"), true))
      .to.emit(root, "ProposalClosed").withArgs(lh("spam"), proposer.address, BOND, true, true);
    expect(await token.balanceOf(treasury.address)).to.equal(BOND);
    expect((await root.namespaceOf(lh("spam"))).status).to.equal(NS.NONE);

    const before = await token.balanceOf(proposer.address);
    await propose(root, proposer, "spam", trap);
    await root.connect(governor).rejectProposal(lh("spam"), false);
    expect(await token.balanceOf(proposer.address)).to.equal(before);
  });

  it("can be withdrawn by the proposer only once stale, and never while a creation is queued",
    async function () {
      const ctx = await deploy();
      const { root, token, proposer, governor, guardian, stranger } = ctx;
      const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();
      const h = lh("slow");
      const before = await token.balanceOf(proposer.address);
      await propose(root, proposer, "slow", trap);

      await expect(root.connect(proposer).withdrawProposal(h)).to.be.revertedWithCustomError(root, "NotStale");
      const q = await queued(root, root.connect(governor).queueCreate("slow"));
      await increase(61n * DAY);
      await expect(root.connect(proposer).withdrawProposal(h)).to.be.revertedWithCustomError(root, "CreatePending");
      await expect(root.connect(governor).rejectProposal(h, true)).to.be.revertedWithCustomError(root, "CreatePending");
      // The guardian's veto does not move money: the bond stays held.
      await root.connect(guardian).cancel(q.id);
      expect((await root.namespaceOf(h)).bond).to.equal(BOND);
      await expect(root.connect(stranger).withdrawProposal(h)).to.be.revertedWithCustomError(root, "NotProposer");
      await root.connect(proposer).withdrawProposal(h);
      expect(await token.balanceOf(proposer.address)).to.equal(before);
      expect((await root.namespaceOf(h)).status).to.equal(NS.NONE);
    });
});

describe("TLDRegistry — the guardian", function () {
  it("can cancel queued actions and freeze immediately, but cannot enact anything", async function () {
    const ctx = await deploy();
    const { root, governor, guardian, proposer, labReg } = ctx;
    const reg = await labReg.getAddress();
    const h = lh("lab");

    await propose(root, proposer, "lab", reg);
    const q = await queued(root, root.connect(governor).queueCreate("lab"));
    // Cannot execute ahead of the timelock any more than anyone else can.
    await expect(root.connect(guardian).execute(q.id, q.payload)).to.be.revertedWithCustomError(root, "TooEarly");
    // Veto.
    await expect(root.connect(guardian).cancel(q.id)).to.emit(root, "ActionCancelled").withArgs(q.id, guardian.address);
    expect((await root.actionOf(q.id)).state).to.equal(ACT.CANCELLED);
    expect(await root.pendingCreate(h)).to.equal(0);
    expect((await root.namespaceOf(h)).status).to.equal(NS.PROPOSED);
    await increase(14n * DAY);
    await expect(root.execute(q.id, q.payload)).to.be.revertedWithCustomError(root, "NotQueued");

    // Every enacting power is refused to the guardian.
    const g = root.connect(guardian);
    const P = await root.params();
    const params = [P.proposalBond, P.createDelay, P.freezeDelay, P.retireNotice, P.listDelay, P.paramsDelay, P.schemaDelay];
    for (const [what, call] of [
      ["queueCreate", () => g.queueCreate("lab")],
      ["rejectProposal", () => g.rejectProposal(h, true)],
      ["queueFreeze", () => g.queueFreeze(h)],
      ["queueUnfreeze", () => g.queueUnfreeze(h)],
      ["beginRetirement", () => g.beginRetirement(h, 90n * DAY)],
      ["queueSetReserved", () => g.queueSetReserved(["x"], true)],
      ["queueSetIana", () => g.queueSetIana(["x"], true, 0)],
      ["queueSetParams", () => g.queueSetParams(params)],
      ["queueAddSchema", () => g.queueAddSchema(2, lh("s2"))],
      ["queueAdoptSchema", () => g.queueAdoptSchema(h, 2)],
      ["queueSetGuardian", () => g.queueSetGuardian(guardian.address, 0)],
      ["queueGovernorHandover", () => g.queueGovernorHandover(guardian.address)],
      ["genesisSeed", () => g.genesisSeed(["x"], [], 0)],
      ["sealGenesis", () => g.sealGenesis()],
    ] as [string, () => Promise<any>][]) {
      await expect(call(), what).to.be.revertedWithCustomError(root, "NotGovernor");
    }
    await expect(g.acceptGovernor()).to.be.revertedWithCustomError(root, "NotPendingGovernor");

    // Re-queue and activate, then the guardian freezes -- immediately.
    const q2 = await queued(root, root.connect(governor).queueCreate("lab"));
    await increase(14n * DAY);
    await root.execute(q2.id, q2.payload);
    await expect(g.guardianFreeze(h)).to.emit(root, "NamespaceFrozen");
    expect((await root.namespaceOf(h)).status).to.equal(NS.FROZEN);
    expect((await root.namespaceOf(h)).frozenAt).to.equal(await now());
    // ... but cannot unfreeze: that is the vote's (7 days).
    await expect(g.queueUnfreeze(h)).to.be.revertedWithCustomError(root, "NotGovernor");
    await expect(g.guardianFreeze(h)).to.be.revertedWithCustomError(root, "BadStatus");
  });

  it("expires, may resign, and is re-authorised only by the governor through the timelock", async function () {
    const ctx = await deploy();
    const { root, governor, guardian, stranger, labReg } = ctx;
    const reg = await labReg.getAddress();
    await create(ctx, "lab", reg);
    const h = lh("lab");
    const q = await queued(root, root.connect(governor).queueFreeze(h));

    await expect(root.connect(stranger).cancel(q.id)).to.be.revertedWithCustomError(root, "NotGuardian");
    await expect(root.connect(stranger).guardianFreeze(h)).to.be.revertedWithCustomError(root, "NotGuardian");

    // Past its expiry, the guardian is nobody.
    await increase(181n * DAY);
    expect(await root.guardianActive()).to.equal(false);
    await expect(root.connect(guardian).cancel(q.id)).to.be.revertedWithCustomError(root, "NotGuardian");
    await expect(root.connect(guardian).guardianFreeze(h)).to.be.revertedWithCustomError(root, "NotGuardian");

    // Re-authorised: 30 days, and a term no longer than MAX_GUARDIAN_TERM.
    const tooLong = (await now()) + 30n * DAY + 400n * DAY;
    const bad = await queued(root, root.connect(governor).queueSetGuardian(stranger.address, tooLong));
    await increase(30n * DAY);
    await expect(root.execute(bad.id, bad.payload)).to.be.revertedWithCustomError(root, "BadGuardianTerm");
    const term = (await now()) + 30n * DAY + 300n * DAY;
    const good = await queued(root, root.connect(governor).queueSetGuardian(stranger.address, term));
    await increase(29n * DAY);
    await expect(root.execute(good.id, good.payload)).to.be.revertedWithCustomError(root, "TooEarly");
    await increase(DAY);
    await root.execute(good.id, good.payload);
    expect(await root.guardian()).to.equal(stranger.address);
    expect(await root.guardianActive()).to.equal(true);

    await root.connect(stranger).resignGuardian();
    expect(await root.guardian()).to.equal(ethers.ZeroAddress);
    expect(await root.guardianActive()).to.equal(false);
  });
});

describe("TLDRegistry — freeze", function () {
  it("is a status change only: the registrar is untouched and existing names keep their records",
    async function () {
      const ctx = await deploy();
      const { root, governor, guardian, alice, token, labReg } = ctx;
      const reg = await labReg.getAddress();
      await create(ctx, "lab", reg);
      const h = lh("lab");

      // alice.lab.axon, registered before the freeze.
      await token.connect(alice).approve(reg, ethers.MaxUint256);
      const aliceHash = await registerName(root, labReg, alice, "alice");
      const nameBefore = await labReg.nameOf(aliceHash);
      const nsBefore = await root.namespaceOf(h);

      await root.connect(guardian).guardianFreeze(h);
      const frozenAt = await now();
      const ns = await root.namespaceOf(h);
      expect(ns.status).to.equal(NS.FROZEN);
      expect(ns.frozenAt).to.equal(frozenAt);
      expect(ns.registrar).to.equal(nsBefore.registrar);
      expect(ns.registrarClass).to.equal(nsBefore.registrarClass);
      expect(ns.activatedAt).to.equal(nsBefore.activatedAt);
      // The existing name is byte-for-byte unchanged: version included.
      expect(await labReg.nameOf(aliceHash)).to.deep.equal(nameBefore);

      // The root did not touch the registrar, so an IMMUTABLE registrar that does
      // not read the root still ACCEPTS a registration. What blocks it is the
      // resolver rule: in a FROZEN namespace a name with registeredAt >= frozenAt
      // does not resolve. This test documents that, rather than pretending the
      // root can stop a contract it never calls.
      const bobHash = await registerName(root, labReg, alice, "bobbybob");
      expect((await labReg.nameOf(bobHash)).registeredAt).to.be.gte(frozenAt);

      // Unfreeze is the vote's, 7 days.
      const q = await queued(root, root.connect(governor).queueUnfreeze(h));
      await increase(7n * DAY - 10n);
      await expect(root.execute(q.id, q.payload)).to.be.revertedWithCustomError(root, "TooEarly");
      await increase(10n);
      await expect(root.execute(q.id, q.payload)).to.emit(root, "NamespaceUnfrozen").withArgs(h);
      const after = await root.namespaceOf(h);
      expect(after.status).to.equal(NS.ACTIVE);
      expect(after.frozenAt).to.equal(0);

      // Freeze by vote: 7 days.
      const f = await queued(root, root.connect(governor).queueFreeze(h));
      await increase(6n * DAY);
      await expect(root.execute(f.id, f.payload)).to.be.revertedWithCustomError(root, "TooEarly");
      await increase(DAY);
      await expect(root.execute(f.id, f.payload)).to.emit(root, "NamespaceFrozen");
      expect((await root.namespaceOf(h)).status).to.equal(NS.FROZEN);
      expect(await labReg.nameOf(aliceHash)).to.deep.equal(nameBefore);
    });
});

describe("TLDRegistry — retirement", function () {
  it("needs >= 90 days notice, keeps names resolving through it, cannot be shortened, and is final at retiresAt",
    async function () {
      const ctx = await deploy();
      const { root, governor, guardian, stranger, proposer, alice, token, labReg } = ctx;
      const reg = await labReg.getAddress();
      await create(ctx, "lab", reg);
      const h = lh("lab");
      await token.connect(alice).approve(reg, ethers.MaxUint256);
      const aliceHash = await registerName(root, labReg, alice, "alice");
      const nameBefore = await labReg.nameOf(aliceHash);

      await expect(root.connect(governor).beginRetirement(h, 89n * DAY))
        .to.be.revertedWithCustomError(root, "DelayOutOfRange");
      await expect(root.connect(stranger).beginRetirement(h, 90n * DAY))
        .to.be.revertedWithCustomError(root, "NotGovernor");

      const q = await queued(root, root.connect(governor).beginRetirement(h, 90n * DAY));
      const t0 = await now();
      let ns = await root.namespaceOf(h);
      expect(ns.status).to.equal(NS.RETIRING);
      expect(ns.retiresAt).to.equal(t0 + 90n * DAY);
      expect(q.eta).to.equal(ns.retiresAt);
      expect(ns.registrar).to.equal(reg);

      // No path shortens the notice: not a second begin, not a parameter change.
      await expect(root.connect(governor).beginRetirement(h, 90n * DAY))
        .to.be.revertedWithCustomError(root, "BadStatus").withArgs(NS.RETIRING);
      const P = await root.params();
      await expect(root.connect(governor).queueSetParams(
        [P.proposalBond, P.createDelay, P.freezeDelay, 30n * DAY, P.listDelay, P.paramsDelay, P.schemaDelay]))
        .to.be.revertedWithCustomError(root, "DelayOutOfRange");

      // A veto during the notice restores the namespace; a re-begin starts a
      // FULL notice again, so cancel + re-begin cannot shorten anything.
      await increase(60n * DAY);
      await root.connect(guardian).cancel(q.id);
      ns = await root.namespaceOf(h);
      expect(ns.status).to.equal(NS.ACTIVE);
      expect(ns.retiresAt).to.equal(0);
      const q2 = await queued(root, root.connect(governor).beginRetirement(h, 90n * DAY));
      expect((await root.namespaceOf(h)).retiresAt).to.equal((await now()) + 90n * DAY);

      // Names resolve throughout: the registrar record is untouched.
      await increase(89n * DAY);
      expect(await labReg.nameOf(aliceHash)).to.deep.equal(nameBefore);
      await expect(root.execute(q2.id, q2.payload)).to.be.revertedWithCustomError(root, "TooEarly");
      await increase(DAY);

      // Past retiresAt: final by time alone -- nobody may revive it.
      await expect(root.connect(guardian).cancel(q2.id)).to.be.revertedWithCustomError(root, "RetirementFinal");
      await expect(root.connect(governor).cancel(q2.id)).to.be.revertedWithCustomError(root, "RetirementFinal");
      await expect(root.connect(stranger).execute(q2.id, q2.payload))
        .to.emit(root, "NamespaceRetired").withArgs(h);
      expect((await root.namespaceOf(h)).status).to.equal(NS.RETIRED);
      // Retirement does not confiscate: the registrar record still exists; the
      // service behind it is reachable at Layer 1 (§11.9).
      expect(await labReg.nameOf(aliceHash)).to.deep.equal(nameBefore);
      // A retired label is never re-created.
      const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();
      await expect(propose(root, proposer, "lab", trap))
        .to.be.revertedWithCustomError(root, "BadStatus").withArgs(NS.RETIRED);
    });

  it("retiring a FROZEN namespace and cancelling restores FROZEN", async function () {
    const ctx = await deploy();
    const { root, governor, guardian, labReg } = ctx;
    await create(ctx, "lab", await labReg.getAddress());
    const h = lh("lab");
    await root.connect(guardian).guardianFreeze(h);
    const frozenAt = (await root.namespaceOf(h)).frozenAt;
    const q = await queued(root, root.connect(governor).beginRetirement(h, 120n * DAY));
    expect((await root.namespaceOf(h)).frozenAt).to.equal(frozenAt);
    await root.connect(governor).cancel(q.id);
    const ns = await root.namespaceOf(h);
    expect(ns.status).to.equal(NS.FROZEN);
    expect(ns.frozenAt).to.equal(frozenAt);
  });
});

describe("TLDRegistry — what governance may NOT do (§12.0a, absent by construction)", function () {
  it("exposes exactly the enumerated mutating functions, none of which acts on a name", async function () {
    const { root } = await deploy();
    const fns = root.interface.fragments.filter((f: any) => f.type === "function") as any[];
    const mutating = fns.filter((f) => f.stateMutability !== "view" && f.stateMutability !== "pure")
      .map((f) => f.name).sort();
    // ADDING A MUTATING FUNCTION FAILS THIS TEST ON PURPOSE. Justify it against
    // §12.0a's table before extending the list.
    expect(mutating).to.deep.equal([
      "acceptGovernor", "beginRetirement", "cancel", "execute", "genesisSeed",
      "guardianFreeze", "proposeNamespace", "queueAddSchema", "queueAdoptSchema",
      "queueCreate", "queueFreeze", "queueGovernorHandover", "queueSetGuardian",
      "queueSetIana", "queueSetParams", "queueSetReserved", "queueUnfreeze",
      "rejectProposal", "resignGuardian", "sealGenesis", "withdrawProposal",
    ]);
    // Transfer, revoke, mint, seize/prune/restore, alter a DomainIdentity,
    // redirect a resolver, upgrade or repoint a registrar, shorten a notice.
    const forbidden = /transfer|revoke|mint|seize|prune|restore|domainkey|resolver|upgrade|setregistrar|setclass|setsteward|shorten|burn|reassign|setowner|register|renew|release|recycl/i;
    for (const f of fns) expect(f.name, f.name).to.not.match(forbidden);
    // No mutating function takes a name-level argument.
    for (const f of fns.filter((f) => f.stateMutability !== "view" && f.stateMutability !== "pure")) {
      for (const input of f.inputs) {
        expect(input.name, `${f.name}(${input.name})`).to.not.match(/namehash|domainkey|owner|^key$|resolver/i);
      }
    }
    // None of AxonRegistry's name-level selectors exist on the root.
    for (const sig of ["transfer(bytes32,address,uint256)", "release(bytes32)", "prune(bytes32,uint256)",
                       "seize(bytes32,uint256)", "restore(bytes32,uint256)", "setGovernor(address)",
                       "register(bytes32,bytes32,uint8,bytes32,bytes32)", "commit(bytes32)"]) {
      expect(root.interface.getFunction(sig), sig).to.equal(null);
    }
  });

  it("never calls a registrar: a namespace whose registrar reverts on every call survives its whole lifecycle",
    async function () {
      const ctx = await deploy();
      const { root, governor, guardian, stranger } = ctx;
      const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();
      await create(ctx, "trapped", trap);
      const h = lh("trapped");
      await root.connect(guardian).guardianFreeze(h);
      const u = await queued(root, root.connect(governor).queueUnfreeze(h));
      await increase(7n * DAY);
      await root.execute(u.id, u.payload);
      const add = await queued(root, root.connect(governor).queueAddSchema(2, lh("schema 2")));
      await increase(30n * DAY);
      await root.execute(add.id, add.payload);
      const adopt = await queued(root, root.connect(governor).queueAdoptSchema(h, 2));
      await increase(30n * DAY);
      await root.execute(adopt.id, adopt.payload);
      const r1 = await queued(root, root.connect(governor).beginRetirement(h, 90n * DAY));
      await root.connect(guardian).cancel(r1.id);
      const r2 = await queued(root, root.connect(governor).beginRetirement(h, 90n * DAY));
      await increase(90n * DAY);
      await root.connect(stranger).execute(r2.id, r2.payload);
      const ns = await root.namespaceOf(h);
      expect(ns.status).to.equal(NS.RETIRED);
      // IMMUTABLE stays IMMUTABLE, and the registrar stays the registrar,
      // through every transition there is.
      expect(ns.registrar).to.equal(trap);
      expect(ns.registrarClass).to.equal(CLS.IMMUTABLE);
      expect(ns.recordSchema).to.equal(2);
    });

  it("schemas are additive: never overwritten, and a namespace only moves forward", async function () {
    const ctx = await deploy();
    const { root, governor, labReg } = ctx;
    await create(ctx, "lab", await labReg.getAddress());
    const h = lh("lab");
    await expect(root.connect(governor).queueAddSchema(1, lh("other"))).to.be.revertedWithCustomError(root, "SchemaExists");
    await expect(root.connect(governor).queueAdoptSchema(h, 1)).to.be.revertedWithCustomError(root, "SchemaNotNewer");
    await expect(root.connect(governor).queueAdoptSchema(h, 3)).to.be.revertedWithCustomError(root, "UnknownSchema");
    const a = await queued(root, root.connect(governor).queueAddSchema(3, lh("schema 3")));
    const b = await queued(root, root.connect(governor).queueAddSchema(3, lh("schema 3, again")));
    await increase(30n * DAY);
    await root.execute(a.id, a.payload);
    await expect(root.execute(b.id, b.payload)).to.be.revertedWithCustomError(root, "SchemaExists");
    expect(await root.schemaSpec(3)).to.equal(lh("schema 3"));
    const up = await queued(root, root.connect(governor).queueAdoptSchema(h, 3));
    await increase(30n * DAY);
    await root.execute(up.id, up.payload);
    expect((await root.namespaceOf(h)).recordSchema).to.equal(3);
    await expect(root.connect(governor).queueAdoptSchema(h, 1))
      .to.be.revertedWithCustomError(root, "SchemaNotNewer");
  });

  it("root parameters: 30-day timelock, floors at the §12.0a table, a ceiling, and no retroactive effect",
    async function () {
      const ctx = await deploy();
      const { root, governor } = ctx;
      const P = await root.params();
      expect(P.createDelay).to.equal(14n * DAY);
      expect(P.freezeDelay).to.equal(7n * DAY);
      expect(P.retireNotice).to.equal(90n * DAY);
      expect(P.listDelay).to.equal(30n * DAY);
      expect(P.paramsDelay).to.equal(30n * DAY);
      expect(P.schemaDelay).to.equal(30n * DAY);
      const base = [P.proposalBond, P.createDelay, P.freezeDelay, P.retireNotice, P.listDelay, P.paramsDelay, P.schemaDelay];
      for (const [i, low] of [[1, 13n], [2, 6n], [3, 89n], [4, 29n], [5, 29n], [6, 29n]] as [number, bigint][]) {
        const p = [...base]; p[i] = low * DAY;
        await expect(root.connect(governor).queueSetParams(p), `field ${i}`)
          .to.be.revertedWithCustomError(root, "DelayOutOfRange");
        p[i] = 731n * DAY;
        await expect(root.connect(governor).queueSetParams(p), `field ${i} ceiling`)
          .to.be.revertedWithCustomError(root, "DelayOutOfRange");
      }
      // A create queued BEFORE a delay change keeps its eta.
      const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();
      await propose(root, ctx.proposer, "early", trap);
      const longer = [...base]; longer[0] = 5000n; longer[1] = 60n * DAY;
      const q = await queued(root, root.connect(governor).queueSetParams(longer));
      await increase(29n * DAY);
      await expect(root.execute(q.id, q.payload)).to.be.revertedWithCustomError(root, "TooEarly");
      const c = await queued(root, root.connect(governor).queueCreate("early"));
      await increase(DAY);
      await root.execute(q.id, q.payload);
      expect((await root.params()).createDelay).to.equal(60n * DAY);
      expect((await root.params()).proposalBond).to.equal(5000n);
      await increase(14n * DAY);
      await root.execute(c.id, c.payload);
      expect((await root.namespaceOf(lh("early"))).status).to.equal(NS.ACTIVE);
    });

  it("reserved-list updates take 30 days and never touch an existing namespace", async function () {
    const ctx = await deploy();
    const { root, governor, proposer, labReg } = ctx;
    await create(ctx, "lab", await labReg.getAddress());
    const q = await queued(root, root.connect(governor).queueSetReserved(["lab", "squat"], true));
    await increase(30n * DAY);
    await expect(root.execute(q.id, q.payload)).to.emit(root, "ReservedSet").withArgs(lh("lab"), "lab", true);
    expect(await root.reservedLabel(lh("squat"))).to.equal(true);
    expect((await root.namespaceOf(lh("lab"))).status).to.equal(NS.ACTIVE);  // not retroactive
    const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();
    await expect(propose(root, proposer, "squat", trap))
      .to.be.revertedWithCustomError(root, "Ineligible").withArgs(WHY.RESERVED_LIST);
    const un = await queued(root, root.connect(governor).queueSetReserved(["squat"], false));
    await increase(30n * DAY);
    await root.execute(un.id, un.payload);
    expect(await root.isEligible("squat")).to.equal(true);
  });
});

describe("TLDRegistry — governor handover", function () {
  it("is two-step and timelocked, and the guardian can veto it", async function () {
    const ctx = await deploy();
    const { root, governor, guardian, stranger, newGov } = ctx;
    await expect(root.connect(governor).queueGovernorHandover(governor.address))
      .to.be.revertedWithCustomError(root, "SameGovernor");
    await expect(root.connect(governor).queueGovernorHandover(ethers.ZeroAddress))
      .to.be.revertedWithCustomError(root, "ZeroAddress");

    // A vetoed handover.
    const v = await queued(root, root.connect(governor).queueGovernorHandover(stranger.address));
    await root.connect(guardian).cancel(v.id);

    const q = await queued(root, root.connect(governor).queueGovernorHandover(newGov.address));
    await increase(30n * DAY - 5n);
    await expect(root.execute(q.id, q.payload)).to.be.revertedWithCustomError(root, "TooEarly");
    await increase(5n);
    await expect(root.connect(stranger).execute(q.id, q.payload))
      .to.emit(root, "GovernorPending").withArgs(newGov.address);
    // Step one moved nothing.
    expect(await root.governor()).to.equal(governor.address);
    expect(await root.pendingGovernor()).to.equal(newGov.address);
    await expect(root.connect(stranger).acceptGovernor()).to.be.revertedWithCustomError(root, "NotPendingGovernor");
    await expect(root.connect(governor).acceptGovernor()).to.be.revertedWithCustomError(root, "NotPendingGovernor");
    // Step two.
    await expect(root.connect(newGov).acceptGovernor())
      .to.emit(root, "GovernorAccepted").withArgs(governor.address, newGov.address);
    expect(await root.governor()).to.equal(newGov.address);
    expect(await root.pendingGovernor()).to.equal(ethers.ZeroAddress);
    await expect(root.connect(governor).queueFreeze(lh("lab"))).to.be.revertedWithCustomError(root, "NotGovernor");
  });
});

describe("TLDRegistry — genesis", function () {
  it("refuses proposals until sealed; seeding is governor-only, additive, and ends at the seal", async function () {
    const [governor, guardian, proposer, , , treasury] = await ethers.getSigners();
    const token = await (await ethers.getContractFactory("AxonToken")).deploy(governor.address);
    const Root = await ethers.getContractFactory("TLDRegistry");
    await expect(Root.deploy(ethers.ZeroAddress, guardian.address, (await now()) + DAY,
      await token.getAddress(), treasury.address, 0, SCHEMA1)).to.be.revertedWithCustomError(Root, "ZeroAddress");
    await expect(Root.deploy(governor.address, guardian.address, (await now()) + 400n * DAY,
      await token.getAddress(), treasury.address, 0, SCHEMA1)).to.be.revertedWithCustomError(Root, "BadGuardianTerm");
    const root = await Root.deploy(governor.address, ethers.ZeroAddress, 0,
      await token.getAddress(), treasury.address, 0, SCHEMA1);
    const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();

    await expect(propose(root, proposer, "early", trap)).to.be.revertedWithCustomError(root, "GenesisOpen");
    await expect(root.connect(governor).queueSetParams([0, 14n * DAY, 7n * DAY, 90n * DAY, 30n * DAY, 30n * DAY, 30n * DAY]))
      .to.be.revertedWithCustomError(root, "GenesisOpen");
    await expect(root.connect(proposer).genesisSeed(["com"], [], 1)).to.be.revertedWithCustomError(root, "NotGovernor");
    await expect(root.connect(governor).genesisSeed(["com", "net"], ["nope"], 2026093000))
      .to.emit(root, "IanaSet").withArgs(lh("com"), "com", true);
    expect(await root.ianaDelegated(lh("net"))).to.equal(true);
    expect(await root.reservedLabel(lh("nope"))).to.equal(true);
    expect(await root.ianaSnapshotAt()).to.equal(2026093000);
    await root.connect(governor).sealGenesis();
    await expect(root.connect(governor).genesisSeed(["org"], [], 0)).to.be.revertedWithCustomError(root, "GenesisClosed");
    await expect(root.connect(governor).sealGenesis()).to.be.revertedWithCustomError(root, "GenesisClosed");
    // A zero bond is allowed, and is what a deployment must use while the token
    // supply is zero.
    await expect(propose(root, proposer, "early", trap)).to.emit(root, "NamespaceProposed");
    expect((await root.namespaceOf(lh("early"))).bond).to.equal(0);
  });
});

describe("TLDRegistry — storage layout (§12.5: the interface resolvers prove against)", function () {
  it("puts registrar|class|status|schema|activatedAt in nsBase+0 and the timestamps in nsBase+1", async function () {
    const ctx = await deploy();
    const { root, rootAddr, governor, guardian, stranger } = ctx;
    const trap = await (await (await ethers.getContractFactory("TrapRegistrar")).deploy()).getAddress();
    await create(ctx, "stewarded", trap, { cls: CLS.STEWARDED, steward: stranger.address });
    const h = lh("stewarded");
    await root.connect(guardian).guardianFreeze(h);
    await root.connect(governor).beginRetirement(h, 100n * DAY);
    const ns = await root.namespaceOf(h);

    const nsBase = BigInt(ethers.solidityPackedKeccak256(["bytes32", "uint256"], [h, 0]));
    const word = async (n: bigint) => ethers.getBytes(await ethers.provider.getStorage(rootAddr, nsBase + n));
    const be = (w: Uint8Array, a: number, b: number) => BigInt(ethers.hexlify(w.slice(a, b)));

    const w0 = await word(0n);
    expect(ethers.getAddress(ethers.hexlify(w0.slice(12, 32)))).to.equal(trap);
    expect(w0[11]).to.equal(CLS.STEWARDED);
    expect(BigInt(w0[10])).to.equal(NS.RETIRING);
    expect(be(w0, 8, 10)).to.equal(1n);
    expect(be(w0, 0, 8)).to.equal(ns.activatedAt);

    const w1 = await word(1n);
    expect(be(w1, 24, 32)).to.equal(ns.retiresAt);
    expect(be(w1, 16, 24)).to.equal(ns.frozenAt);
    expect(be(w1, 0, 16)).to.equal(0n);

    expect(ethers.getAddress(ethers.hexlify((await word(2n)).slice(12, 32)))).to.equal(stranger.address);
    expect(ethers.hexlify(await word(3n))).to.equal(CHARTER);
    expect(be(await word(4n), 0, 32)).to.equal(0n);   // bond returned on activation
    // The top-level slots the NatSpec states.
    const slot3 = ethers.getBytes(await ethers.provider.getStorage(rootAddr, 3));
    expect(ethers.getAddress(ethers.hexlify(slot3.slice(12, 32)))).to.equal(governor.address);
    expect(be(slot3, 4, 12)).to.equal(2026093000n);   // ianaSnapshotAt
    expect(slot3[3]).to.equal(1);                     // genesisSealed
    expect(await ethers.provider.getStorage(rootAddr,
      ethers.solidityPackedKeccak256(["bytes32", "uint256"], [lh("com"), 1]))).to.equal(ethers.toBeHex(1, 32));
  });
});

// ---------------------------------------------------------------- helpers

/** commit -> 120 s -> register, for `label`.lab.axon, as `who`. */
async function registerName(root: any, reg: any, who: any, label: string) {
  const nsHash = lh("lab");
  const nameHash = await root.nameHashOf(nsHash, lh(label));
  const skeleton = await root.nameHashOf(nsHash, lh("skel:" + label));
  const secret = lh("secret:" + label);
  const domainKey = lh("key:" + label);
  const commitment = ethers.keccak256(coder.encode(
    ["bytes32", "address", "bytes32", "bytes32"], [nameHash, who.address, secret, domainKey]));
  await reg.connect(who).commit(commitment);
  await increase(120n);
  await reg.connect(who).register(nameHash, skeleton, label.length, secret, domainKey);
  return nameHash;
}

// ---------------------------------------------------------------- the Go vector

// THE VECTOR internal/axon/registrar/registrar_test.go IS PINNED TO.
//
// Every value is PRODUCED BY THE CONTRACTS here and asserted against the same
// constants the Go test asserts its own encoder against. The two halves together
// are the cross-check: if either the Solidity or the Go side changes, one of
// them fails. Addresses are deterministic because the vector runs from fresh,
// fixed-key wallets inside an evm_snapshot (so their nonces start at 0 whatever
// ran before), and timestamps are pinned with evm_setNextBlockTimestamp.
const V = {
  t0: 4_000_000_000n,
  name: "alice.lab.axon",
  secret: lh("axon-vector-secret"),
  domainKey: lh("axon-vector-domainkey"),
};

describe("TLDRegistry — test vector for the Go registrar client", function () {
  it("produces the labelHash / nameHash / commitment / calldata / return data the Go test pins", async function () {
    const snap = await network.provider.send("evm_snapshot", []);
    const setNext = (t: bigint) => network.provider.send("evm_setNextBlockTimestamp", [Number(t)]);
    try {
      const [funder] = await ethers.getSigners();
      const deployer = new ethers.Wallet(lh("axon-vector-deployer"), ethers.provider);
      const alice = new ethers.Wallet(lh("axon-vector-alice"), ethers.provider);
      await funder.sendTransaction({ to: deployer.address, value: ethers.parseEther("100") });
      await funder.sendTransaction({ to: alice.address, value: ethers.parseEther("100") });

      const token = await (await ethers.getContractFactory("AxonToken", deployer)).deploy(deployer.address);
      await token.waitForDeployment();
      const root = await (await ethers.getContractFactory("TLDRegistry", deployer)).deploy(
        deployer.address, ethers.ZeroAddress, 0, await token.getAddress(), deployer.address, 0, SCHEMA1);
      await root.waitForDeployment();
      await root.sealGenesis();
      const nsHash = lh("lab");
      const reg = await deployAxonRegistry(deployer, token, deployer.address, await root.namespaceNode(nsHash));
      const regAddr = await reg.getAddress();
      await root.proposeNamespace("lab", regAddr, CLS.IMMUTABLE, ethers.ZeroAddress, CHARTER, 1);
      await setNext(V.t0);
      const q = await queued(root, root.queueCreate("lab"));
      await setNext(V.t0 + 14n * DAY);
      await root.execute(q.id, q.payload);

      const nsCall = root.interface.encodeFunctionData("namespaceOf", [nsHash]);
      const nsRet = await ethers.provider.call({ to: await root.getAddress(), data: nsCall });

      const nameHash = await root.nameHashOf(nsHash, lh("alice"));
      // Skeleton("alice") = "a11ce" (§11.3.3: l->1, i->1), hashed as a name in
      // the same namespace -- registry.ClaimFor's construction.
      const skeleton = await root.nameHashOf(nsHash, lh("a11ce"));
      const commitment = ethers.keccak256(coder.encode(
        ["bytes32", "address", "bytes32", "bytes32"], [nameHash, alice.address, V.secret, V.domainKey]));
      const price = await reg.priceOf(5);
      const approveAmount = price + (await reg.BOND_PER_NAME());

      const commitData = reg.interface.encodeFunctionData("commit", [commitment]);
      const approveData = token.interface.encodeFunctionData("approve", [regAddr, approveAmount]);
      const registerData = reg.interface.encodeFunctionData("register",
        [nameHash, skeleton, 5, V.secret, V.domainKey]);

      await token.mintGenesis(alice.address, ethers.parseEther("1000"));
      // Sent RAW, exactly as a wallet would send the Go plan's bytes.
      await setNext(V.t0 + 15n * DAY);
      await (await alice.sendTransaction({ to: regAddr, data: commitData })).wait();
      await (await alice.sendTransaction({ to: await token.getAddress(), data: approveData })).wait();
      await setNext(V.t0 + 15n * DAY + 120n);
      await (await alice.sendTransaction({ to: regAddr, data: registerData })).wait();

      const nameCall = reg.interface.encodeFunctionData("nameOf", [nameHash]);
      const nameRet = await ethers.provider.call({ to: regAddr, data: nameCall });
      const n = await reg.nameOf(nameHash);
      expect(n.owner).to.equal(alice.address);
      expect(n.domainKey).to.equal(V.domainKey);
      expect(n.skeleton).to.equal(skeleton);

      const out = {
        deployer: deployer.address, owner: alice.address,
        token: await token.getAddress(), root: await root.getAddress(), registrar: regAddr,
        labelHash: nsHash, nameHash, skeleton, commitment, approveAmount: approveAmount.toString(),
        nsCall, nsRet, commitData, approveData, registerData, nameCall, nameRet,
      };
      if (process.env.PRINT_VECTOR) console.log(JSON.stringify(out, null, 2));
      expect(out).to.deep.equal(PINNED);
    } finally {
      await network.provider.send("evm_revert", [snap]);
    }
  });
});

const PINNED: any = {
  deployer: "0x12A551584b6189423BfF2F9CEB6bCA40B287175A",
  owner: "0xbD7aaE000C9212685b5361bda4Bcb1e655E744B3",
  token: "0xf18CE4D86a3e46537b7A48B335d1F195F00010b2",
  root: "0x569d8b2257baF8dd0228c43106a89606491cB937",
  registrar: "0x7D870D21A6fc01Cde5168b4b4874cfe78779413d",
  labelHash: "0x4305b11146ee91a5c46324d0d0911ab1fd5275c19fedf8d14c2f2af4b3cc68f4",
  nameHash: "0xa11de4e35ea4c76cbcf6d85a6c86f84520bf08e925add96f72d7111aedfb49d6",
  skeleton: "0x73b30c5c06a3a9d1befc1225711e37b0e4288d93d840e920595cb1d3c11c4a7f",
  commitment: "0xe8899313c26f10d88f8aea6f139677ec4aee27a2530990fc2728f9c1ee5a4bfd",
  approveAmount: "150000000000000000000",
  nsCall: "0x7c8fab2c4305b11146ee91a5c46324d0d0911ab1fd5275c19fedf8d14c2f2af4b3cc68f4",
  nsRet: "0x" +
    "0000000000000000000000007d870d21a6fc01cde5168b4b4874cfe78779413d" +
    "0000000000000000000000000000000000000000000000000000000000000000" +
    "0000000000000000000000000000000000000000000000000000000000000002" +
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "00000000000000000000000000000000000000000000000000000000ee7d9d00" +
    "0000000000000000000000000000000000000000000000000000000000000000" +
    "0000000000000000000000000000000000000000000000000000000000000000" +
    "0000000000000000000000000000000000000000000000000000000000000000" +
    "6764716f3fd790044888adb27f32b1ddbcb94d3f558f4a5a7974105e53d96b26" +
    "0000000000000000000000000000000000000000000000000000000000000000",
  commitData: "0xf14fcbc8e8899313c26f10d88f8aea6f139677ec4aee27a2530990fc2728f9c1ee5a4bfd",
  approveData: "0x095ea7b3" +
    "0000000000000000000000007d870d21a6fc01cde5168b4b4874cfe78779413d" +
    "00000000000000000000000000000000000000000000000821ab0d4414980000",
  registerData: "0x2245eb1c" +
    "a11de4e35ea4c76cbcf6d85a6c86f84520bf08e925add96f72d7111aedfb49d6" +
    "73b30c5c06a3a9d1befc1225711e37b0e4288d93d840e920595cb1d3c11c4a7f" +
    "0000000000000000000000000000000000000000000000000000000000000005" +
    "e43074e2436e8b6878c49b6c6284b7226b7196a3fa1c2c04090aaae46f47e0fd" +
    "196ac4be5b2a1715d869d41b6bbd00656db4adc71a4340980f0ddc88d5e742dc",
  nameCall: "0xe532a034a11de4e35ea4c76cbcf6d85a6c86f84520bf08e925add96f72d7111aedfb49d6",
  nameRet: "0x" +
    "000000000000000000000000bd7aae000c9212685b5361bda4bcb1e655e744b3" +
    "00000000000000000000000000000000000000000000000000000000f0602278" +
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "196ac4be5b2a1715d869d41b6bbd00656db4adc71a4340980f0ddc88d5e742dc" +
    "0000000000000000000000000000000000000000000000000000000000000000" +
    "73b30c5c06a3a9d1befc1225711e37b0e4288d93d840e920595cb1d3c11c4a7f" +
    "00000000000000000000000000000000000000000000000000000000ee7eeef8" +
    "00000000000000000000000000000000000000000000000000000000ee7eeef8" +
    "00000000000000000000000000000000000000000000000000000000ee7eeef8" +
    "0000000000000000000000000000000000000000000000056bc75e2d63100000" +
    "0000000000000000000000000000000000000000000000000000000000000000",
};
