import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

// V2 adds conditional payments. These tests target the ways a lock can lose
// somebody money: claimed twice, claimed with the wrong secret, claimed after it
// expired, refunded while it was still live, or quietly dropped from a state
// whose signature still verifies.
describe("AxonChannels", () => {
  const PERIOD = 3600;

  type Lock = {
    id: string; hash: string; amount: bigint; expiry: bigint; payerIsA: boolean;
  };

  async function setup() {
    // Sorted, because the contract makes the LOWER address partyA. Without this
    // the test's `a` and the contract's partyA drift apart and every balance
    // assertion silently checks the wrong party.
    const signers = await ethers.getSigners();
    const [a, b] = signers[0].address.toLowerCase() < signers[1].address.toLowerCase()
      ? [signers[0], signers[1]] : [signers[1], signers[0]];
    const outsider = signers[2];
    const token = await (await ethers.getContractFactory("AxonToken")).deploy(signers[0].address);
    await token.waitForDeployment();
    const cm = await (await ethers.getContractFactory("AxonChannels"))
      .deploy(await token.getAddress(), PERIOD);
    await cm.waitForDeployment();
    await token.connect(signers[0]).mintGenesis(signers[0].address, 100_000n);
    for (const who of [a, b, outsider]) {
      if (who.address !== signers[0].address) {
        await token.connect(signers[0]).transfer(who.address, 10_000n);
      }
      await token.connect(who).approve(await cm.getAddress(), 100_000n);
    }
    return { a, b, outsider, token, cm };
  }

  // The digest's first word is the operation domain. Defaulting to OP_STATE
  // keeps every ordinary-state test reading as before; the two paths that need
  // another domain pass it explicitly, which is the point of having it.
  const OP_STATE = 1, OP_COOP_CLOSE = 2, OP_CHECKPOINT = 3;

  async function sign(cm: any, a: any, b: any, id: string, nonce: number,
                      balA: bigint, balB: bigint, root: string,
                      wA: bigint = 0n, wB: bigint = 0n, op: number = OP_STATE) {
    const digest = await cm.stateDigest(op, id, nonce, balA, balB, root, wA, wB);
    return {
      sigA: await a.signMessage(ethers.getBytes(digest)),
      sigB: await b.signMessage(ethers.getBytes(digest)),
    };
  }

  function lockId(n: number): string {
    return ethers.zeroPadValue(ethers.toBeHex(n), 32);
  }

  function secretOf(word: string): { preimage: string; hash: string } {
    const preimage = ethers.keccak256(ethers.toUtf8Bytes(word));
    return { preimage, hash: ethers.keccak256(preimage) };
  }

  // ---- the digest binds the locks -----------------------------------------

  it("will not let a signed state be presented with its locks removed", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { hash } = secretOf("in flight");
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry: BigInt(await time.latest()) + 900n, payerIsA: true }];
    const root = await cm.htlcRoot(locks);

    // Both parties genuinely signed 400/50 with 50 locked.
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 400n, 50n, root);

    // Presenting the same state with no locks is the attack: the balances and
    // signatures are unchanged, and 50 AXON would simply cease to exist.
    await expect(cm.connect(a).closeUnilateral(id, 1, 400n, 50n, [], sigA, sigB))
      .to.be.revertedWithCustomError(cm, "BadSignature");

    // With the locks, it is accepted.
    await expect(cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, sigA, sigB)).to.not.be.reverted;
  });

  it("derives the locked total from the locks rather than trusting a signer", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { hash } = secretOf("x");
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry: BigInt(await time.latest()) + 900n, payerIsA: true }];
    const root = await cm.htlcRoot(locks);

    // 400 + 50 + 50 locked = 500. Correct.
    const ok = await sign(cm, a, b, id, 1, 400n, 50n, root);
    await cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, ok.sigA, ok.sigB);
    const ch = await cm.channels(id);
    expect(ch.lockedTotal).to.equal(50n);
  });

  it("refuses balances that do not conserve once locks are counted", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { hash } = secretOf("x");
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry: BigInt(await time.latest()) + 900n, payerIsA: true }];
    const root = await cm.htlcRoot(locks);

    // 450 + 50 + 50 locked = 550 out of a 500 deposit. Both parties signed it;
    // signatures are not what stops this.
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 450n, 50n, root);
    await expect(cm.connect(a).closeUnilateral(id, 1, 450n, 50n, locks, sigA, sigB))
      .to.be.revertedWithCustomError(cm, "BalanceMismatch");
  });

  it("requires locks sorted by id and free of duplicates", async () => {
    const { cm } = await setup();
    const { hash } = secretOf("x");
    const two: Lock = { id: lockId(2), hash, amount: 1n, expiry: 999n, payerIsA: true };
    const one: Lock = { id: lockId(1), hash, amount: 1n, expiry: 999n, payerIsA: true };

    await expect(cm.htlcRoot([two, one])).to.be.revertedWithCustomError(cm, "LocksUnsorted");
    await expect(cm.htlcRoot([one, one])).to.be.revertedWithCustomError(cm, "LocksUnsorted");
    expect(await cm.htlcRoot([])).to.equal(ethers.ZeroHash);
  });

  // ---- claiming ------------------------------------------------------------

  it("pays a lock to the payee on the preimage, once and only once", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { preimage, hash } = secretOf("the secret");
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry: BigInt(await time.latest()) + 900n, payerIsA: true }];
    const root = await cm.htlcRoot(locks);
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 400n, 50n, root);
    await cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, sigA, sigB);

    await cm.claimLock(id, locks, 0, preimage);
    const ch = await cm.channels(id);
    expect(ch.balanceB).to.equal(100n);   // 50 + the 50 claimed
    expect(ch.balanceA).to.equal(400n);
    expect(ch.lockedTotal).to.equal(0n);

    await expect(cm.claimLock(id, locks, 0, preimage))
      .to.be.revertedWithCustomError(cm, "LockAlreadyResolved");
  });

  it("refuses a claim with the wrong secret", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { hash } = secretOf("right");
    const wrong = secretOf("wrong").preimage;
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry: BigInt(await time.latest()) + 900n, payerIsA: true }];
    const root = await cm.htlcRoot(locks);
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 400n, 50n, root);
    await cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, sigA, sigB);

    await expect(cm.claimLock(id, locks, 0, wrong)).to.be.revertedWithCustomError(cm, "BadPreimage");
  });

  it("refuses a claim after the lock has expired", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { preimage, hash } = secretOf("late");
    const expiry = BigInt(await time.latest()) + 600n;
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry, payerIsA: true }];
    const root = await cm.htlcRoot(locks);
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 400n, 50n, root);
    await cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, sigA, sigB);

    await time.increaseTo(expiry + 1n);
    await expect(cm.claimLock(id, locks, 0, preimage))
      .to.be.revertedWithCustomError(cm, "LockHasExpired");
  });

  it("returns an expired lock to the payer, and not before", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { hash } = secretOf("never claimed");
    const expiry = BigInt(await time.latest()) + 600n;
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry, payerIsA: true }];
    const root = await cm.htlcRoot(locks);
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 400n, 50n, root);
    await cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, sigA, sigB);

    // While it is live the payer cannot take it back — that is the entire
    // guarantee the payee is relying on.
    await expect(cm.expireLock(id, locks, 0)).to.be.revertedWithCustomError(cm, "LockNotExpired");

    await time.increaseTo(expiry + 1n);
    await cm.expireLock(id, locks, 0);
    const ch = await cm.channels(id);
    expect(ch.balanceA).to.equal(450n);   // refunded to the payer
    expect(ch.balanceB).to.equal(50n);
    expect(ch.lockedTotal).to.equal(0n);
  });

  it("will not settle while a lock is unresolved", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { hash } = secretOf("pending");
    const expiry = BigInt(await time.latest()) + 10_000n;
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry, payerIsA: true }];
    const root = await cm.htlcRoot(locks);
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 400n, 50n, root);
    await cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, sigA, sigB);

    await time.increase(PERIOD + 1);
    // The window is over but the lock is still live and still claimable. Paying
    // out now would either strand it or steal it.
    await expect(cm.settle(id)).to.be.revertedWithCustomError(cm, "LocksOutstanding");

    await time.increaseTo(expiry + 1n);
    await cm.expireLock(id, locks, 0);
    await expect(cm.settle(id)).to.not.be.reverted;
  });

  it("refuses a lock set that does not match what was committed", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const { preimage, hash } = secretOf("s");
    const expiry = BigInt(await time.latest()) + 900n;
    const locks: Lock[] = [{ id: lockId(1), hash, amount: 50n, expiry, payerIsA: true }];
    const root = await cm.htlcRoot(locks);
    const { sigA, sigB } = await sign(cm, a, b, id, 1, 400n, 50n, root);
    await cm.connect(a).closeUnilateral(id, 1, 400n, 50n, locks, sigA, sigB);

    // Same shape, bigger amount. If the root were not rechecked this would pay
    // the payee 500 out of a lock worth 50.
    const inflated: Lock[] = [{ ...locks[0], amount: 500n }];
    await expect(cm.claimLock(id, inflated, 0, preimage))
      .to.be.revertedWithCustomError(cm, "LocksMismatch");
  });

  // ---- the ordinary path still works --------------------------------------

  it("cooperatively closes a channel that has no locks", async () => {
    const { a, b, token, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);
    const before = await token.balanceOf(b.address);

    const { sigA, sigB } = await sign(cm, a, b, id, 5, 340n, 160n, ethers.ZeroHash, 0n, 0n, OP_COOP_CLOSE);
    await cm.closeCooperative(id, 5, 340n, 160n, sigA, sigB);

    expect(await token.balanceOf(b.address)).to.equal(before + 160n);
  });

  it("still lets a newer state beat an older one", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 500n);
    const id = await cm.channelId(a.address, b.address);

    const stale = await sign(cm, a, b, id, 2, 490n, 10n, ethers.ZeroHash);
    const fresh = await sign(cm, a, b, id, 9, 300n, 200n, ethers.ZeroHash);

    // The payer force-closes on a state where they had paid almost nothing.
    await cm.connect(a).closeUnilateral(id, 2, 490n, 10n, [], stale.sigA, stale.sigB);
    // Anyone at all can answer with the newer one — the watchtower property.
    await cm.connect((await ethers.getSigners())[2])
      .challenge(id, 9, 300n, 200n, [], fresh.sigA, fresh.sigB);

    const ch = await cm.channels(id);
    expect(ch.nonce).to.equal(9n);
    expect(ch.balanceB).to.equal(200n);

    await expect(cm.challenge(id, 2, 490n, 10n, [], stale.sigA, stale.sigB))
      .to.be.revertedWithCustomError(cm, "StaleNonce");
  });

  // ---- the property the whole HTLC exists for ------------------------------

  it("leaves a forwarding intermediary whole", async () => {
    // tipper -> hub -> recipient, as two channels sharing one secret. The hub
    // pays the recipient only if it can then claim the same amount from the
    // tipper, and the preimage that lets the recipient take its money is what
    // makes that possible.
    const signers = await ethers.getSigners();
    const [tipper, hub, recipient] = [signers[0], signers[1], signers[2]];
    const token = await (await ethers.getContractFactory("AxonToken")).deploy(tipper.address);
    await token.waitForDeployment();
    const cm = await (await ethers.getContractFactory("AxonChannels"))
      .deploy(await token.getAddress(), PERIOD);
    await cm.waitForDeployment();
    await token.connect(tipper).mintGenesis(tipper.address, 100_000n);
    for (const who of [hub, recipient]) {
      await token.connect(tipper).transfer(who.address, 10_000n);
    }
    for (const who of [tipper, hub, recipient]) {
      await token.connect(who).approve(await cm.getAddress(), 100_000n);
    }

    const { preimage, hash } = secretOf("routed tip");
    const now = BigInt(await time.latest());

    // The upstream lock must outlive the downstream one, or the hub can be paid
    // downstream and find its own claim already expired.
    const upstreamExpiry = now + 4000n;
    const downstreamExpiry = now + 2000n;

    async function openAndClose(payer: any, payee: any, deposit: bigint, expiry: bigint) {
      await cm.connect(payer).openChannel(payee.address, deposit);
      const id = await cm.channelId(payer.address, payee.address);
      const payerIsA = payer.address.toLowerCase() < payee.address.toLowerCase();
      const locks: Lock[] = [{ id: lockId(1), hash, amount: 25n, expiry, payerIsA }];
      const root = await cm.htlcRoot(locks);
      const [balA, balB] = payerIsA ? [deposit - 25n, 0n] : [0n, deposit - 25n];
      const digest = await cm.stateDigest(OP_STATE, id, 1, balA, balB, root, 0n, 0n);
      const [lower, higher] = payerIsA ? [payer, payee] : [payee, payer];
      const sigA = await lower.signMessage(ethers.getBytes(digest));
      const sigB = await higher.signMessage(ethers.getBytes(digest));
      await cm.connect(payer).closeUnilateral(id, 1, balA, balB, locks, sigA, sigB);
      return { id, locks };
    }

    const upstream = await openAndClose(tipper, hub, 100n, upstreamExpiry);
    const downstream = await openAndClose(hub, recipient, 100n, downstreamExpiry);

    const hubBefore = await token.balanceOf(hub.address);

    // The recipient takes its 25 by revealing the secret...
    await cm.connect(recipient).claimLock(downstream.id, downstream.locks, 0, preimage);
    // ...which is now public, so the hub claims the same 25 upstream.
    await cm.connect(hub).claimLock(upstream.id, upstream.locks, 0, preimage);

    await time.increase(PERIOD + 1);
    await cm.settle(upstream.id);
    await cm.settle(downstream.id);

    // The hub forwarded 25 and recovered 25. It put up 100 and gets 100 back.
    expect(await token.balanceOf(hub.address)).to.equal(hubBefore + 100n);
  });

  // ---- checkpoint: taking value out without closing -------------------------

  type Args = {
    id: string; nonce: number; balanceA: bigint; balanceB: bigint;
    withdrawA: bigint; withdrawB: bigint;
  };

  it("lets a party draw down without closing the channel", async () => {
    const { a, b, token, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);

    // A has paid B 100 over the channel; B now takes 75 of it out.
    const args: Args = {
      id, nonce: 51, balanceA: 900n, balanceB: 25n, withdrawA: 0n, withdrawB: 75n,
    };
    const { sigA, sigB } = await sign(cm, a, b, id, 51, 900n, 25n, ethers.ZeroHash, 0n, 75n, OP_CHECKPOINT);

    const before = await token.balanceOf(b.address);
    await cm.checkpoint(args, [], sigA, sigB);

    expect(await token.balanceOf(b.address)).to.equal(before + 75n);

    const ch = await cm.channels(id);
    expect(ch.status).to.equal(1n);                       // still Open
    expect(ch.nonce).to.equal(51n);
    expect(ch.balanceA).to.equal(900n);
    expect(ch.balanceB).to.equal(25n);
    expect(ch.depositA + ch.depositB).to.equal(925n);     // collateral reduced
  });

  it("keeps the channel usable after a checkpoint", async () => {
    const { a, b, token, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);

    const first = await sign(cm, a, b, id, 51, 900n, 25n, ethers.ZeroHash, 0n, 75n, OP_CHECKPOINT);
    await cm.checkpoint(
      { id, nonce: 51, balanceA: 900n, balanceB: 25n, withdrawA: 0n, withdrawB: 75n },
      [], first.sigA, first.sigB);

    // Tipping continues against the NEW collateral of 925.
    const next = await sign(cm, a, b, id, 52, 800n, 125n, ethers.ZeroHash, 0n, 0n, OP_COOP_CLOSE);
    const before = await token.balanceOf(b.address);
    await cm.closeCooperative(id, 52, 800n, 125n, next.sigA, next.sigB);
    expect(await token.balanceOf(b.address)).to.equal(before + 125n);
  });

  // THE attack: a state signed for a small withdrawal, submitted asking for a
  // large one. The amounts are inside the digest, so the signatures simply do
  // not verify.
  it("will not pay a withdrawal the signatures did not authorise", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);

    // Both parties agreed to 25 leaving.
    const { sigA, sigB } = await sign(cm, a, b, id, 51, 900n, 75n, ethers.ZeroHash, 0n, 25n, OP_CHECKPOINT);

    // Submitted asking for 75.
    await expect(cm.checkpoint(
      { id, nonce: 51, balanceA: 900n, balanceB: 25n, withdrawA: 0n, withdrawB: 75n },
      [], sigA, sigB)).to.be.revertedWithCustomError(cm, "BadSignature");

    // The agreed one works.
    await expect(cm.checkpoint(
      { id, nonce: 51, balanceA: 900n, balanceB: 75n, withdrawA: 0n, withdrawB: 25n },
      [], sigA, sigB)).to.not.be.reverted;
  });

  it("enforces old collateral == new collateral + what leaves", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);

    // 900 + 100 + 75 out = 1075 from a 1000 deposit. Both parties signed it.
    const { sigA, sigB } = await sign(cm, a, b, id, 51, 900n, 100n, ethers.ZeroHash, 0n, 75n, OP_CHECKPOINT);
    await expect(cm.checkpoint(
      { id, nonce: 51, balanceA: 900n, balanceB: 100n, withdrawA: 0n, withdrawB: 75n },
      [], sigA, sigB)).to.be.revertedWithCustomError(cm, "BalanceMismatch");
  });

  it("refuses a stale or repeated checkpoint", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);

    const args: Args = { id, nonce: 51, balanceA: 900n, balanceB: 25n, withdrawA: 0n, withdrawB: 75n };
    const { sigA, sigB } = await sign(cm, a, b, id, 51, 900n, 25n, ethers.ZeroHash, 0n, 75n, OP_CHECKPOINT);
    await cm.checkpoint(args, [], sigA, sigB);

    // Replaying it would pay the 75 twice.
    await expect(cm.checkpoint(args, [], sigA, sigB))
      .to.be.revertedWithCustomError(cm, "StaleNonce");
  });

  it("refuses a checkpoint that withdraws nothing", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);
    const { sigA, sigB } = await sign(cm, a, b, id, 51, 900n, 100n, ethers.ZeroHash, OP_CHECKPOINT);
    await expect(cm.checkpoint(
      { id, nonce: 51, balanceA: 900n, balanceB: 100n, withdrawA: 0n, withdrawB: 0n },
      [], sigA, sigB)).to.be.revertedWithCustomError(cm, "NothingToWithdraw");
  });

  // A party can take out more than they put in — they earned it. Attributing
  // the reduction to their own deposit would underflow on a legitimate
  // withdrawal, which is why only the total is tracked.
  it("lets a party withdraw more than they deposited", async () => {
    const { a, b, token, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);   // A funds everything
    const id = await cm.channelId(a.address, b.address);

    // A has paid B 300; B deposited nothing and withdraws 300.
    const { sigA, sigB } = await sign(cm, a, b, id, 10, 700n, 0n, ethers.ZeroHash, 0n, 300n, OP_CHECKPOINT);
    const before = await token.balanceOf(b.address);
    await expect(cm.checkpoint(
      { id, nonce: 10, balanceA: 700n, balanceB: 0n, withdrawA: 0n, withdrawB: 300n },
      [], sigA, sigB)).to.not.be.reverted;

    expect(await token.balanceOf(b.address)).to.equal(before + 300n);
    const ch = await cm.channels(id);
    expect(ch.depositA + ch.depositB).to.equal(700n);
  });

  it("checkpoints around a live lock without touching it", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);

    const { hash } = secretOf("in flight");
    const locks: Lock[] = [{
      id: lockId(1), hash, amount: 50n,
      expiry: BigInt(await time.latest()) + 9000n, payerIsA: true,
    }];
    const root = await cm.htlcRoot(locks);

    // 800 + 75 + 50 locked + 75 out = 1000.
    const { sigA, sigB } = await sign(cm, a, b, id, 20, 800n, 75n, root, 0n, 75n, OP_CHECKPOINT);
    await cm.checkpoint(
      { id, nonce: 20, balanceA: 800n, balanceB: 75n, withdrawA: 0n, withdrawB: 75n },
      locks, sigA, sigB);

    const ch = await cm.channels(id);
    expect(ch.lockedTotal).to.equal(50n);       // the lock is untouched
    expect(ch.htlcRoot).to.equal(root);
    expect(ch.status).to.equal(1n);             // still Open
  });

  // A signature authorising a withdrawal must not be spendable as a close: the
  // close paths sign zeros, so the digests differ.
  it("will not let a checkpoint state be used to close", async () => {
    const { a, b, cm } = await setup();
    await cm.connect(a).openChannel(b.address, 1000n);
    const id = await cm.channelId(a.address, b.address);

    const { sigA, sigB } = await sign(cm, a, b, id, 51, 900n, 25n, ethers.ZeroHash, 0n, 75n, OP_CHECKPOINT);
    await expect(cm.closeCooperative(id, 51, 900n, 25n, sigA, sigB))
      .to.be.revertedWithCustomError(cm, "BadSignature");
  });
});
