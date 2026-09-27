import { expect } from "chai";
import { ethers, network } from "hardhat";

// Exercises the REAL deployed AxonChannels against a fork of mainnet.
//
// The V1 equivalent (ChannelManagerLive.test.ts) exists for the same reason and
// this follows it deliberately: a fork runs the deployed bytecode at its
// deployed address with the chain's actual state — the real AXON token, the
// real treasury balance — so this tests the contract that exists rather than a
// fresh copy of the source.
//
// WHY THIS MATTERS MORE FOR V2 THAN IT DID FOR V1
// -----------------------------------------------
// Tipping was validated end to end on Hardhat chain 31337. A deployed address
// is not evidence about that work: 31337 had a contract compiled from the same
// source, but not this contract, not this `challengePeriod`, and not the real
// token. Everything asserted below was true on devnet and is being re-asserted
// against mainnet state, which is the whole point of the exercise.
//
// It spends nothing. A fork is local; the impersonation and the token transfer
// happen in memory and are discarded when the test ends.
//
//   MAINNET_RPC_URL=https://… npx hardhat test test/AxonChannelsLive.test.ts

const CM = "0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c";
const TOKEN = "0x3ee18868078962f430A4Da5E827E8Cfc8b4066ac";
// Holds ~21M AXON on mainnet. This is the TOKEN treasury, and deliberately not
// 0xE36e04b6… which deployed the contract and holds ETH — conflating the two is
// an easy way to write a test that passes for the wrong reason.
const TREASURY = "0xE30f5daFB45823222dB08A721006b32D2cd9262b";
const RPC = process.env.MAINNET_RPC_URL!;

// The op tags from the contract. A digest carries the operation it authorises,
// so a state signed to pay cannot be replayed to close.
const OP_STATE = 1;
const OP_COOP_CLOSE = 2;

const NO_LOCKS = ethers.ZeroHash;

describe("AxonChannels (deployed, mainnet fork)", () => {
  before(async function () {
    this.timeout(120000);
    if (!RPC) this.skip();
    await network.provider.request({
      method: "hardhat_reset",
      params: [{ forking: { jsonRpcUrl: RPC } }],
    });
  });

  it("is the contract we think it is", async () => {
    const cm = await ethers.getContractAt("AxonChannels", CM);
    expect((await cm.token()).toLowerCase()).to.equal(TOKEN.toLowerCase());
    // The derived value, immutable. If this is ever not 28800 the deployment
    // record and half the documentation are wrong.
    expect(await cm.challengePeriod()).to.equal(28800n);
  });

  it("runs a full open → tip → cooperative close against real AXON", async function () {
    this.timeout(180000);
    const cm = await ethers.getContractAt("AxonChannels", CM);
    const token = await ethers.getContractAt("AxonToken", TOKEN);

    await network.provider.request({ method: "hardhat_impersonateAccount", params: [TREASURY] });
    await network.provider.send("hardhat_setBalance", [TREASURY, "0x56BC75E2D63100000"]);
    const treasury = await ethers.getSigner(TREASURY);

    // partyA is the numerically lower address — the contract sorts, so the test
    // must sort the same way or every balance assertion is inverted.
    const signers = await ethers.getSigners();
    const [a, b] = signers[0].address.toLowerCase() < signers[1].address.toLowerCase()
      ? [signers[0], signers[1]] : [signers[1], signers[0]];

    const deposit = ethers.parseEther("100");
    await token.connect(treasury).transfer(a.address, deposit);
    expect(await token.balanceOf(a.address)).to.equal(deposit);

    await token.connect(a).approve(CM, deposit);
    await cm.connect(a).openChannel(b.address, deposit);
    const id = await cm.channelId(a.address, b.address);

    // THE TIP. A pays B 30 of the 100, off chain: both sign the resulting state
    // and nothing is broadcast. This is what a tip IS — no transaction, no gas,
    // no block. The signature exchange is the payment.
    //
    // Asserted rather than asserted-about: the block number and both AXON
    // balances are captured before the tip and compared after. If tipping ever
    // acquires an on-chain step, this is what notices.
    const blockBefore = await ethers.provider.getBlockNumber();
    const aBefore = await token.balanceOf(a.address);
    const bBefore = await token.balanceOf(b.address);

    const balA = ethers.parseEther("70");
    const balB = ethers.parseEther("30");
    const stateDigest = await cm.stateDigest(OP_STATE, id, 1, balA, balB, NO_LOCKS, 0, 0);
    expect(stateDigest).to.not.equal(ethers.ZeroHash);
    const tipSigA = await a.signMessage(ethers.getBytes(stateDigest));
    const tipSigB = await b.signMessage(ethers.getBytes(stateDigest));
    expect(tipSigA).to.have.lengthOf(132);   // 65 bytes, 0x-prefixed
    expect(tipSigB).to.have.lengthOf(132);

    expect(await ethers.provider.getBlockNumber()).to.equal(
      blockBefore, "a tip must not produce a block — it is signatures, not a transaction");
    expect(await token.balanceOf(a.address)).to.equal(aBefore);
    expect(await token.balanceOf(b.address)).to.equal(bBefore);

    // Settle it cooperatively. A different op tag, so a different digest — the
    // state above cannot be handed to closeCooperative and vice versa.
    const closeDigest = await cm.stateDigest(OP_COOP_CLOSE, id, 1, balA, balB, NO_LOCKS, 0, 0);
    expect(closeDigest).to.not.equal(stateDigest);

    const sigA = await a.signMessage(ethers.getBytes(closeDigest));
    const sigB = await b.signMessage(ethers.getBytes(closeDigest));

    const beforeB = await token.balanceOf(b.address);
    await cm.connect(a).closeCooperative(id, 1, balA, balB, sigA, sigB);

    expect(await token.balanceOf(b.address)).to.equal(beforeB + balB);
    expect(await token.balanceOf(a.address)).to.equal(balA);
  });

  it("refuses a state signed for the wrong operation", async function () {
    this.timeout(180000);
    const cm = await ethers.getContractAt("AxonChannels", CM);
    const token = await ethers.getContractAt("AxonToken", TOKEN);

    await network.provider.request({ method: "hardhat_impersonateAccount", params: [TREASURY] });
    await network.provider.send("hardhat_setBalance", [TREASURY, "0x56BC75E2D63100000"]);
    const treasury = await ethers.getSigner(TREASURY);

    const signers = await ethers.getSigners();
    const [a, b] = signers[2].address.toLowerCase() < signers[3].address.toLowerCase()
      ? [signers[2], signers[3]] : [signers[3], signers[2]];

    const deposit = ethers.parseEther("10");
    await token.connect(treasury).transfer(a.address, deposit);
    await token.connect(a).approve(CM, deposit);
    await cm.connect(a).openChannel(b.address, deposit);
    const id = await cm.channelId(a.address, b.address);

    const balA = ethers.parseEther("6");
    const balB = ethers.parseEther("4");

    // Signed as an ordinary state, offered as a cooperative close. The op tag is
    // inside the digest precisely so this cannot work.
    const wrong = await cm.stateDigest(OP_STATE, id, 1, balA, balB, NO_LOCKS, 0, 0);
    const sigA = await a.signMessage(ethers.getBytes(wrong));
    const sigB = await b.signMessage(ethers.getBytes(wrong));

    await expect(
      cm.connect(a).closeCooperative(id, 1, balA, balB, sigA, sigB)
    ).to.be.revertedWithCustomError(cm, "BadSignature");
  });

  it("honours the real 8-hour challenge window on a unilateral close", async function () {
    this.timeout(180000);
    const cm = await ethers.getContractAt("AxonChannels", CM);
    const token = await ethers.getContractAt("AxonToken", TOKEN);

    await network.provider.request({ method: "hardhat_impersonateAccount", params: [TREASURY] });
    await network.provider.send("hardhat_setBalance", [TREASURY, "0x56BC75E2D63100000"]);
    const treasury = await ethers.getSigner(TREASURY);

    const signers = await ethers.getSigners();
    const [a, b] = signers[4].address.toLowerCase() < signers[5].address.toLowerCase()
      ? [signers[4], signers[5]] : [signers[5], signers[4]];

    const deposit = ethers.parseEther("10");
    await token.connect(treasury).transfer(a.address, deposit);
    await token.connect(a).approve(CM, deposit);
    await cm.connect(a).openChannel(b.address, deposit);
    const id = await cm.channelId(a.address, b.address);

    const balA = ethers.parseEther("7");
    const balB = ethers.parseEther("3");
    const digest = await cm.stateDigest(OP_STATE, id, 1, balA, balB, NO_LOCKS, 0, 0);
    const sigA = await a.signMessage(ethers.getBytes(digest));
    const sigB = await b.signMessage(ethers.getBytes(digest));

    await cm.connect(a).closeUnilateral(id, 1, balA, balB, [], sigA, sigB);

    // Settling before the window closes must fail. 28800 s is the deployed
    // value; a contract with a different one would pass this at the wrong time.
    await expect(cm.connect(a).settle(id)).to.be.reverted;

    await network.provider.send("evm_increaseTime", [28800]);
    await network.provider.send("evm_mine", []);

    const beforeB = await token.balanceOf(b.address);
    await cm.connect(a).settle(id);
    expect(await token.balanceOf(b.address)).to.equal(beforeB + balB);
  });
});
