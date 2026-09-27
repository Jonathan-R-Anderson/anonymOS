import { expect } from "chai";
import { ethers } from "hardhat";

// Delegated signing — P15.
//
// THE PROPERTY UNDER TEST IS NOT "DELEGATION WORKS".
// It is that a volunteer holding a delegate key gains the ability to CO-SIGN and
// gains nothing else: it never becomes a party, never becomes the payee, cannot
// touch its own authorization, and cannot reach the two operations that end a
// channel or take value out of one.
//
// So most of what follows is refusals. The happy path is three tests; the rest
// is the blast radius.

const PERIOD = 8 * 60 * 60;
const OP_STATE = 1, OP_COOP_CLOSE = 2, OP_CHECKPOINT = 3;
const BIT_STATE = 1 << OP_STATE;          // 2
const BIT_COOP = 1 << OP_COOP_CLOSE;      // 4
const BIT_CHECKPOINT = 1 << OP_CHECKPOINT; // 8

describe("AxonChannels delegation", () => {
  async function setup() {
    const s = await ethers.getSigners();
    // The contract makes the LOWER address partyA. Sorting here keeps `a` and
    // the contract's partyA from drifting apart.
    const [a, b] = s[0].address.toLowerCase() < s[1].address.toLowerCase()
      ? [s[0], s[1]] : [s[1], s[0]];
    const volunteer = s[2];      // holds a delegate key, never a party key
    const outsider = s[3];
    const other = s[4];

    const token = await (await ethers.getContractFactory("AxonToken")).deploy(s[0].address);
    await token.waitForDeployment();
    const cm = await (await ethers.getContractFactory("AxonChannels"))
      .deploy(await token.getAddress(), PERIOD);
    await cm.waitForDeployment();

    await token.connect(s[0]).mintGenesis(s[0].address, 1_000_000n);
    for (const who of [a, b, volunteer, outsider, other]) {
      if (who.address !== s[0].address) {
        await token.connect(s[0]).transfer(who.address, 100_000n);
      }
    }
    await token.connect(a).approve(await cm.getAddress(), 1_000_000n);
    await token.connect(b).approve(await cm.getAddress(), 1_000_000n);

    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);
    return { a, b, volunteer, outsider, other, token, cm, id };
  }

  async function digest(cm: any, op: number, id: string, nonce: number,
                        balA: bigint, balB: bigint, root = ethers.ZeroHash,
                        wA = 0n, wB = 0n) {
    return cm.stateDigest(op, id, nonce, balA, balB, root, wA, wB);
  }

  const sig = (who: any, d: string) => who.signMessage(ethers.getBytes(d));
  const future = async () =>
    BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 86_400n;

  // ---- digest separation ---------------------------------------------------

  describe("operation domains", () => {
    it("gives a different digest to every operation", async () => {
      const { cm, id } = await setup();
      const args = [id, 5, 400n, 100n, ethers.ZeroHash, 0n, 0n] as const;
      const state = await cm.stateDigest(OP_STATE, ...args);
      const coop = await cm.stateDigest(OP_COOP_CLOSE, ...args);
      const check = await cm.stateDigest(OP_CHECKPOINT, ...args);

      // Before this change `state` and `coop` were the same 32 bytes.
      expect(state).to.not.equal(coop);
      expect(state).to.not.equal(check);
      expect(coop).to.not.equal(check);
    });

    it("changes the digest when ONLY the domain changes", async () => {
      const { cm, id } = await setup();
      const a = await cm.stateDigest(OP_STATE, id, 7, 1n, 2n, ethers.ZeroHash, 0n, 0n);
      const b = await cm.stateDigest(OP_COOP_CLOSE, id, 7, 1n, 2n, ethers.ZeroHash, 0n, 0n);
      expect(a).to.not.equal(b);
    });

    it("refuses an ordinary state signature presented as a cooperative close", async () => {
      const { a, b, cm, id } = await setup();
      // Both parties honestly agree a balance. Nobody agreed to settle.
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await expect(
        cm.closeCooperative(id, 5, 400n, 100n, await sig(a, d), await sig(b, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("refuses a cooperative-close signature presented as a unilateral close", async () => {
      const { a, b, cm, id } = await setup();
      const d = await digest(cm, OP_COOP_CLOSE, id, 5, 400n, 100n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [], await sig(a, d), await sig(b, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("refuses a checkpoint signature presented as an ordinary state", async () => {
      const { a, b, cm, id } = await setup();
      const d = await digest(cm, OP_CHECKPOINT, id, 5, 400n, 25n, ethers.ZeroHash, 0n, 75n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 25n, [], await sig(a, d), await sig(b, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });
  });

  // ---- delegated state signing --------------------------------------------

  describe("a delegate may co-sign ordinary states", () => {
    it("accepts owner + delegate on a unilateral close", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);

      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      // b never signs. Its delegate does.
      await cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
        await sig(a, d), await sig(volunteer, d));

      const ch = await cm.channels(id);
      expect(ch.nonce).to.equal(5n);
    });

    it("still accepts the owner's own signature while a delegate exists", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
        await sig(a, d), await sig(b, d));
      expect((await cm.channels(id)).nonce).to.equal(5n);
    });

    it("refuses a delegate signing for the OTHER party", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      // volunteer is b's delegate; here it is offered as A's signature.
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
          await sig(volunteer, d), await sig(b, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("refuses a delegate signing BOTH sides", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
          await sig(volunteer, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("refuses an unrelated address", async () => {
      const { a, b, outsider, cm, id } = await setup();
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
          await sig(a, d), await sig(outsider, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("still requires BOTH signatures — a delegate cannot act alone", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      // Delegate signs b's side; nobody signs a's.
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
          await sig(volunteer, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });
  });

  // ---- what a delegate may NOT reach ---------------------------------------

  describe("operations a delegate cannot reach", () => {
    it("cannot cooperatively close, even with every bit it is allowed", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const d = await digest(cm, OP_COOP_CLOSE, id, 5, 400n, 100n);
      await expect(
        cm.closeCooperative(id, 5, 400n, 100n, await sig(a, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("has no cooperative-close bit to be granted", async () => {
      const { b, volunteer, cm } = await setup();
      await expect(
        cm.connect(b).setDelegate(volunteer.address, await future(), BIT_COOP),
      ).to.be.revertedWithCustomError(cm, "BadDelegateOps");
      await expect(
        cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE | BIT_COOP),
      ).to.be.revertedWithCustomError(cm, "BadDelegateOps");
    });

    it("cannot checkpoint in this iteration, and the bit is not grantable", async () => {
      const { b, volunteer, cm } = await setup();
      await expect(
        cm.connect(b).setDelegate(volunteer.address, await future(), BIT_CHECKPOINT),
      ).to.be.revertedWithCustomError(cm, "BadDelegateOps");
    });

    it("refuses a delegate signature on checkpoint", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const args = { id, nonce: 5, balanceA: 400n, balanceB: 25n, withdrawA: 0n, withdrawB: 75n };
      const d = await digest(cm, OP_CHECKPOINT, id, 5, 400n, 25n, ethers.ZeroHash, 0n, 75n);
      await expect(
        cm.checkpoint(args, [], await sig(a, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("cannot open a channel or deposit as the party", async () => {
      const { b, volunteer, other, token, cm } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      // openChannel authorises on msg.sender, so the volunteer can only ever
      // open a channel as ITSELF — spending its own tokens.
      await token.connect(volunteer).approve(await cm.getAddress(), 1_000n);
      await cm.connect(volunteer).openChannel(other.address, 10n);
      const made = await cm.channelId(volunteer.address, other.address);
      const ch = await cm.channels(made);
      expect([ch.partyA, ch.partyB]).to.not.include(b.address);
    });
  });

  // ---- authorization is the owner's alone ----------------------------------

  describe("delegation management", () => {
    it("lets an owner set, replace and revoke", async () => {
      const { b, volunteer, other, cm } = await setup();
      const exp = await future();
      await cm.connect(b).setDelegate(volunteer.address, exp, BIT_STATE);
      expect((await cm.delegations(b.address)).signer).to.equal(volunteer.address);

      await cm.connect(b).setDelegate(other.address, exp, BIT_STATE);
      const d = await cm.delegations(b.address);
      expect(d.signer).to.equal(other.address);
      expect(d.epoch).to.equal(2n);          // one slot, replaced not appended

      await cm.connect(b).revokeDelegate();
      expect((await cm.delegations(b.address)).signer).to.equal(ethers.ZeroAddress);
    });

    it("kills the previous delegate the moment it is replaced", async () => {
      const { a, b, volunteer, other, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      await cm.connect(b).setDelegate(other.address, await future(), BIT_STATE);

      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
          await sig(a, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("rejects a revoked delegate immediately", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      await cm.connect(b).revokeDelegate();

      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
          await sig(a, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("lets the owner carry on normally after revoking", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      await cm.connect(b).revokeDelegate();

      const d = await digest(cm, OP_STATE, id, 6, 400n, 100n);
      await cm.connect(a).closeUnilateral(id, 6, 400n, 100n, [],
        await sig(a, d), await sig(b, d));
      expect((await cm.channels(id)).nonce).to.equal(6n);
    });

    it("rejects a delegate once its authorization expires", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      const soon = BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 120n;
      await cm.connect(b).setDelegate(volunteer.address, soon, BIT_STATE);

      await ethers.provider.send("evm_increaseTime", [300]);
      await ethers.provider.send("evm_mine", []);

      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
          await sig(a, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BadSignature");
    });

    it("gives a delegate NO way to appoint, extend or revoke anything", async () => {
      const { b, volunteer, other, cm } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);

      // Every management call authorises on msg.sender, so a delegate calling
      // one only ever edits ITS OWN delegation — never the party's.
      await cm.connect(volunteer).setDelegate(other.address, await future(), BIT_STATE);
      expect((await cm.delegations(b.address)).signer).to.equal(volunteer.address);
      expect((await cm.delegations(volunteer.address)).signer).to.equal(other.address);

      await cm.connect(volunteer).revokeDelegate();
      expect((await cm.delegations(b.address)).signer).to.equal(volunteer.address);

      // And there is no signature-accepting variant to reach for. This is the
      // load-bearing check: the protection is that no such function EXISTS, so
      // it is asserted against the ABI rather than against behaviour.
      const fns = cm.interface.fragments.filter((f: any) => f.type === "function");
      const mgmt = fns.filter((f: any) => /delegat/i.test(f.name));
      expect(mgmt.map((f: any) => f.name).sort())
        .to.deep.equal(["delegations", "revokeDelegate", "setDelegate"]);
      for (const f of mgmt) {
        if (f.name === "delegations") continue;
        for (const input of f.inputs) {
          expect(input.type).to.not.equal("bytes");   // no signature to replay
        }
      }
    });

    it("refuses nonsensical delegations", async () => {
      const { b, volunteer, cm } = await setup();
      const exp = await future();
      await expect(cm.connect(b).setDelegate(ethers.ZeroAddress, exp, BIT_STATE))
        .to.be.revertedWithCustomError(cm, "BadDelegate");
      await expect(cm.connect(b).setDelegate(b.address, exp, BIT_STATE))
        .to.be.revertedWithCustomError(cm, "BadDelegate");
      await expect(cm.connect(b).setDelegate(await cm.getAddress(), exp, BIT_STATE))
        .to.be.revertedWithCustomError(cm, "BadDelegate");
      await expect(cm.connect(b).setDelegate(volunteer.address, exp, 0))
        .to.be.revertedWithCustomError(cm, "BadDelegateOps");
      await expect(cm.connect(b).setDelegate(volunteer.address, 1, BIT_STATE))
        .to.be.revertedWithCustomError(cm, "BadDelegateExpiry");
    });

    it("reports authority truthfully through canSign", async () => {
      const { b, volunteer, outsider, cm } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      expect(await cm.canSign(b.address, b.address, OP_STATE)).to.equal(true);
      expect(await cm.canSign(b.address, volunteer.address, OP_STATE)).to.equal(true);
      expect(await cm.canSign(b.address, volunteer.address, OP_CHECKPOINT)).to.equal(false);
      expect(await cm.canSign(b.address, volunteer.address, OP_COOP_CLOSE)).to.equal(false);
      expect(await cm.canSign(b.address, outsider.address, OP_STATE)).to.equal(false);
    });
  });

  // ---- the beneficiary never moves -----------------------------------------

  describe("beneficiary separation", () => {
    it("pays the PARTY when a delegate co-signed the state", async () => {
      const { a, b, volunteer, token, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);

      const before = {
        b: await token.balanceOf(b.address),
        v: await token.balanceOf(volunteer.address),
      };

      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
        await sig(a, d), await sig(volunteer, d));
      await ethers.provider.send("evm_increaseTime", [PERIOD + 60]);
      await ethers.provider.send("evm_mine", []);
      await cm.settle(id);

      // THE ASSERTION THIS WHOLE PHASE EXISTS FOR.
      expect(await token.balanceOf(b.address)).to.equal(before.b + 100n);
      expect(await token.balanceOf(volunteer.address)).to.equal(before.v);
    });

    it("pays the PARTY on checkpoint even when that party has a delegate", async () => {
      // Found by mutation: making checkpoint transfer to delegations[party].signer
      // survived the whole suite, because a delegate cannot checkpoint in this
      // iteration and nothing else watched that payout while a delegation
      // existed. The moment OP_CHECKPOINT is ever granted, this is the test that
      // notices the money going somewhere new.
      const { a, b, volunteer, token, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);

      const bBefore = await token.balanceOf(b.address);
      const vBefore = await token.balanceOf(volunteer.address);

      // Signed by the PARTIES — the delegate is merely present.
      const d = await digest(cm, OP_CHECKPOINT, id, 5, 400n, 25n, ethers.ZeroHash, 0n, 75n);
      await cm.checkpoint(
        { id, nonce: 5, balanceA: 400n, balanceB: 25n, withdrawA: 0n, withdrawB: 75n },
        [], await sig(a, d), await sig(b, d));

      expect(await token.balanceOf(b.address)).to.equal(bBefore + 75n);
      expect(await token.balanceOf(volunteer.address)).to.equal(vBefore);
      expect((await cm.channels(id)).status).to.equal(1n);   // still Open
    });

    it("never lets a delegate become a channel party", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
        await sig(a, d), await sig(volunteer, d));

      const ch = await cm.channels(id);
      expect(ch.partyA).to.equal(a.address);
      expect(ch.partyB).to.equal(b.address);
      expect([ch.partyA, ch.partyB]).to.not.include(volunteer.address);
    });

    it("keeps the channel struct free of any delegate field", async () => {
      const { cm } = await setup();
      const ch = cm.interface.getFunction("channels");
      const names = ch.outputs.map((o: any) => o.name);
      for (const n of names) expect(n.toLowerCase()).to.not.contain("delegate");
      for (const n of names) expect(n.toLowerCase()).to.not.contain("signer");
    });
  });

  // ---- channel invariants are untouched ------------------------------------

  describe("channel invariants under delegation", () => {
    it("keeps the nonce strictly increasing", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      const d5 = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
        await sig(a, d5), await sig(volunteer, d5));

      const stale = await digest(cm, OP_STATE, id, 4, 490n, 10n);
      await expect(
        cm.challenge(id, 4, 490n, 10n, [], await sig(a, stale), await sig(volunteer, stale)),
      ).to.be.revertedWithCustomError(cm, "StaleNonce");
    });

    it("still refuses a state that does not conserve", async () => {
      const { a, b, volunteer, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);
      // A delegate cannot manufacture value: conservation is checked against
      // the deposits the chain recorded, whoever signed.
      const d = await digest(cm, OP_STATE, id, 5, 400n, 900n);
      await expect(
        cm.connect(a).closeUnilateral(id, 5, 400n, 900n, [],
          await sig(a, d), await sig(volunteer, d)),
      ).to.be.revertedWithCustomError(cm, "BalanceMismatch");
    });

    it("behaves exactly as before for a party with no delegate", async () => {
      const { a, b, cm, id } = await setup();
      expect((await cm.delegations(b.address)).signer).to.equal(ethers.ZeroAddress);
      const d = await digest(cm, OP_STATE, id, 5, 400n, 100n);
      await cm.connect(a).closeUnilateral(id, 5, 400n, 100n, [],
        await sig(a, d), await sig(b, d));
      expect((await cm.channels(id)).nonce).to.equal(5n);
    });
  });

  // ---- the threat model, executed -------------------------------------------

  describe("a compromised volunteer", () => {
    it("can do exactly one thing, and it is bounded", async () => {
      const { a, b, volunteer, other, token, cm, id } = await setup();
      await cm.connect(b).setDelegate(volunteer.address, await future(), BIT_STATE);

      const bBefore = await token.balanceOf(b.address);
      const vBefore = await token.balanceOf(volunteer.address);

      // CANNOT: move b's wallet tokens. Nothing in this contract reaches them.
      // CANNOT: change the beneficiary — proved above, re-asserted after the act.
      // CANNOT: checkpoint.
      const cpArgs = { id, nonce: 6, balanceA: 400n, balanceB: 25n, withdrawA: 0n, withdrawB: 75n };
      const cpD = await digest(cm, OP_CHECKPOINT, id, 6, 400n, 25n, ethers.ZeroHash, 0n, 75n);
      await expect(cm.checkpoint(cpArgs, [], await sig(a, cpD), await sig(volunteer, cpD)))
        .to.be.revertedWithCustomError(cm, "BadSignature");

      // CANNOT: cooperatively close.
      const coopD = await digest(cm, OP_COOP_CLOSE, id, 6, 400n, 100n);
      await expect(cm.closeCooperative(id, 6, 400n, 100n, await sig(a, coopD), await sig(volunteer, coopD)))
        .to.be.revertedWithCustomError(cm, "BadSignature");

      // CANNOT: appoint itself elsewhere or revoke b's delegation.
      await cm.connect(volunteer).revokeDelegate();
      expect((await cm.delegations(b.address)).signer).to.equal(volunteer.address);

      // CANNOT: open a channel in b's name.
      await token.connect(volunteer).approve(await cm.getAddress(), 1_000n);
      await cm.connect(volunteer).openChannel(other.address, 10n);
      const rogue = await cm.channels(await cm.channelId(volunteer.address, other.address));
      expect([rogue.partyA, rogue.partyB]).to.not.include(b.address);

      // CAN: take part in a state the counterparty ALSO signs. Here the
      // counterparty colludes and gives b nothing — the residual risk, bounded
      // to this channel's un-withdrawn value.
      const rob = await digest(cm, OP_STATE, id, 9, 500n, 0n);
      await cm.connect(a).closeUnilateral(id, 9, 500n, 0n, [],
        await sig(a, rob), await sig(volunteer, rob));
      await ethers.provider.send("evm_increaseTime", [PERIOD + 60]);
      await ethers.provider.send("evm_mine", []);
      await cm.settle(id);

      // The loss is b's channel balance. It did NOT go to the volunteer, and
      // b's wallet was otherwise untouched.
      expect(await token.balanceOf(b.address)).to.equal(bBefore);
      expect(await token.balanceOf(volunteer.address)).to.equal(vBefore - 10n); // its own deposit
    });
  });
});
