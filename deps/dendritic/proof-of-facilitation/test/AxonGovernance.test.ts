import { expect } from "chai";
import { ethers } from "hardhat";

// G8 — the DAO vote on chain (§94).
//
// The three properties worth testing are E-G8 (a tally reconstructible from
// chain state alone), R-94.1 (jurisdictional categories permanently out of
// scope) and F-94.1 (a participation-only weighting must not be able to seize
// names). Everything else here is scaffolding for those.

const DAY = 86400;

async function deployWeightSource(available: boolean, weight: bigint) {
  const F = await ethers.getContractFactory("MockWeightSource");
  return await F.deploy(available, weight);
}

async function deployGov(minCoverageBps = 5000) {
  const [owner] = await ethers.getSigners();
  const F = await ethers.getContractFactory("AxonGovernance");
  return await F.deploy(owner.address, DAY, 6000, 0, minCoverageBps);
}

describe("AxonGovernance", () => {
  describe("R-94.1 — jurisdictional categories are permanently out of scope", () => {
    it("refuses ILLEGAL, EXTREMIST and COPYRIGHT at PROPOSAL time", async () => {
      const gov = await deployGov();
      const subject = ethers.keccak256(ethers.toUtf8Bytes("acme.axon"));
      const evidence = ethers.keccak256(ethers.toUtf8Bytes("cid"));
      // 4=ILLEGAL, 5=EXTREMIST, 6=COPYRIGHT
      for (const cat of [4, 5, 6]) {
        await expect(gov.propose(1, cat, subject, evidence))
          .to.be.revertedWithCustomError(gov, "JurisdictionalCategoryOutOfScope");
      }
      // Refused at CREATION, not execution: an out-of-scope proposal must never
      // exist to be voted on, or a majority can record a passed vote to
      // suppress content on jurisdictional grounds.
      expect(await gov.proposalCount()).to.equal(0);
    });

    it("allows the in-scope categories", async () => {
      const gov = await deployGov();
      const subject = ethers.keccak256(ethers.toUtf8Bytes("acme.axon"));
      const evidence = ethers.keccak256(ethers.toUtf8Bytes("cid"));
      for (const cat of [1, 2, 3]) {
        await expect(gov.propose(1, cat, subject, evidence)).to.not.be.reverted;
      }
      expect(await gov.proposalCount()).to.equal(3);
    });
  });

  describe("F-94.1 — a participation-only DAO must not be able to seize names", () => {
    it("refuses a coverage floor that a participation-only deployment would meet", async () => {
      const [owner] = await ethers.getSigners();
      const F = await ethers.getContractFactory("AxonGovernance");
      // W_PARTICIPATION alone is 2000 bps and is the only live source today.
      for (const bad of [0, 1000, 2000]) {
        await expect(F.deploy(owner.address, DAY, 6000, 0, bad))
          .to.be.revertedWithCustomError(F, "BadCoverage");
      }
      await expect(F.deploy(owner.address, DAY, 6000, 0, 2001)).to.not.be.reverted;
    });

    it("lets a participation-only DAO vote, and refuses to let it PRUNE", async () => {
      const [owner] = await ethers.getSigners();
      const gov = await deployGov(5000);
      const participation = await deployWeightSource(true, 1n);
      await gov.setWeightSource(2, await participation.getAddress());

      // Only participation is live: 20 of 100.
      expect(await gov.liveCoverageBps()).to.equal(2000);
      expect(await gov.weightOf(owner.address)).to.equal(1n);

      const subject = ethers.keccak256(ethers.toUtf8Bytes("acme.axon"));
      const evidence = ethers.keccak256(ethers.toUtf8Bytes("cid"));
      await gov.propose(1, 1, subject, evidence); // PRUNE / MALWARE
      await gov.castVote(0, true);
      await ethers.provider.send("evm_increaseTime", [DAY + 1]);
      await ethers.provider.send("evm_mine", []);
      await gov.finalise(0);

      // The vote PASSED. The authority is what is withheld.
      const t = await gov.tally(0);
      expect(t.status).to.equal(1); // PASSED
      expect(t.executable).to.equal(false);

      await expect(gov.execute(0))
        .to.be.revertedWithCustomError(gov, "CoverageTooLow")
        .withArgs(2000, 5000);
    });

    it("permits execution once enough of the scheme is live", async () => {
      const gov = await deployGov(5000);
      const [owner] = await ethers.getSigners();
      const infra = await deployWeightSource(true, 10n);
      const participation = await deployWeightSource(true, 1n);
      await gov.setWeightSource(0, await infra.getAddress());
      await gov.setWeightSource(2, await participation.getAddress());
      // 40 + 20 = 60 of 100.
      expect(await gov.liveCoverageBps()).to.equal(6000);

      const registry = await (await ethers.getContractFactory("MockRegistry")).deploy();
      await gov.setRegistry(await registry.getAddress());

      const subject = ethers.keccak256(ethers.toUtf8Bytes("acme.axon"));
      await gov.propose(1, 1, subject, ethers.keccak256(ethers.toUtf8Bytes("cid")));
      await gov.castVote(0, true);
      await ethers.provider.send("evm_increaseTime", [DAY + 1]);
      await ethers.provider.send("evm_mine", []);
      await gov.finalise(0);
      await expect(gov.execute(0)).to.emit(gov, "ProposalExecuted");
      expect(await registry.lastPruned()).to.equal(subject);
      expect(await registry.lastProposalId()).to.equal(0);
    });

    it("SIGNAL proposals execute regardless of coverage", async () => {
      const gov = await deployGov(5000);
      const participation = await deployWeightSource(true, 1n);
      await gov.setWeightSource(2, await participation.getAddress());
      await gov.propose(0, 0, ethers.ZeroHash, ethers.ZeroHash); // SIGNAL
      await gov.castVote(0, true);
      await ethers.provider.send("evm_increaseTime", [DAY + 1]);
      await ethers.provider.send("evm_mine", []);
      await gov.finalise(0);
      // A signal changes no state, so withholding it would accomplish nothing.
      await expect(gov.execute(0)).to.emit(gov, "ProposalExecuted");
    });
  });

  describe("E-G8 — the tally comes from chain state alone", () => {
    it("reconstructs a tally from storage with nothing else consulted", async () => {
      const gov = await deployGov(2001);
      const signers = await ethers.getSigners();
      const participation = await deployWeightSource(true, 1n);
      await gov.setWeightSource(2, await participation.getAddress());

      const subject = ethers.keccak256(ethers.toUtf8Bytes("acme.axon"));
      await gov.propose(1, 1, subject, ethers.keccak256(ethers.toUtf8Bytes("cid")));
      await gov.connect(signers[0]).castVote(0, true);
      await gov.connect(signers[1]).castVote(0, true);
      await gov.connect(signers[2]).castVote(0, false);

      // Rebuild the tally from raw storage reads only — no events, no server.
      let forW = 0n, againstW = 0n;
      for (const s of signers.slice(0, 3)) {
        const w = await gov.weightCast(0, s.address);
        if (w === 0n) continue;
        if (await gov.votedFor(0, s.address)) forW += w; else againstW += w;
      }
      const p = await gov.proposals(0);
      expect(forW).to.equal(p.forWeight);
      expect(againstW).to.equal(p.againstWeight);
      expect(forW).to.equal(2n);
      expect(againstW).to.equal(1n);
      expect(p.voterCount).to.equal(3n);
    });

    it("stores weight at voting time, so a moving source cannot rewrite a tally", async () => {
      const gov = await deployGov(2001);
      const [owner] = await ethers.getSigners();
      const participation = await deployWeightSource(true, 5n);
      await gov.setWeightSource(2, await participation.getAddress());
      await gov.propose(0, 0, ethers.ZeroHash, ethers.ZeroHash);
      await gov.castVote(0, true);
      expect((await gov.proposals(0)).forWeight).to.equal(5n);

      // The source's answer changes afterwards.
      await participation.setWeight(500n);
      // The recorded tally does not. A tally that moved without anybody voting
      // would not be reconstructible in the sense E-G8 requires.
      expect((await gov.proposals(0)).forWeight).to.equal(5n);
      expect(await gov.weightCast(0, owner.address)).to.equal(5n);
    });
  });

  describe("weight accounting", () => {
    it("treats a REVERTING source as dark, not as zero", async () => {
      const gov = await deployGov(2001);
      const [owner] = await ethers.getSigners();
      const good = await deployWeightSource(true, 4n);
      const broken = await (await ethers.getContractFactory("RevertingWeightSource")).deploy();
      await gov.setWeightSource(2, await good.getAddress());
      await gov.setWeightSource(0, await broken.getAddress());

      // Infra is broken, so it must not be counted as "live and scoring zero" —
      // that would silently change every tally by moving the denominator.
      expect(await gov.liveCoverageBps()).to.equal(2000);
      expect(await gov.weightOf(owner.address)).to.equal(4n);
    });

    it("reports an unavailable source as dark", async () => {
      const gov = await deployGov(2001);
      const off = await deployWeightSource(false, 99n);
      await gov.setWeightSource(0, await off.getAddress());
      expect(await gov.liveCoverageBps()).to.equal(0);
    });

    it("normalises by LIVE weight, not by W_TOTAL", async () => {
      const gov = await deployGov(2001);
      const [owner] = await ethers.getSigners();
      const infra = await deployWeightSource(true, 10n);
      await gov.setWeightSource(0, await infra.getAddress());
      // Only infra live: 10 * 40 / 40 = 10, not 10 * 40 / 100 = 4. Dividing by
      // W_TOTAL would scale everybody down alike and change no outcome, while
      // making a partial scheme look like a full one.
      expect(await gov.weightOf(owner.address)).to.equal(10n);
    });
  });

  describe("voting mechanics", () => {
    it("refuses a second vote and a zero-weight voter", async () => {
      const gov = await deployGov(2001);
      const signers = await ethers.getSigners();
      const src = await (await ethers.getContractFactory("SelectiveWeightSource")).deploy();
      await src.setWeight(signers[0].address, 3n);
      await gov.setWeightSource(2, await src.getAddress());
      await gov.propose(0, 0, ethers.ZeroHash, ethers.ZeroHash);
      await gov.castVote(0, true);
      await expect(gov.castVote(0, true)).to.be.revertedWithCustomError(gov, "AlreadyVoted");
      await expect(gov.connect(signers[1]).castVote(0, true))
        .to.be.revertedWithCustomError(gov, "NoWeight");
    });

    it("refuses a registry action with no subject or no evidence", async () => {
      const gov = await deployGov(2001);
      const subject = ethers.keccak256(ethers.toUtf8Bytes("acme.axon"));
      const cid = ethers.keccak256(ethers.toUtf8Bytes("cid"));
      await expect(gov.propose(1, 1, ethers.ZeroHash, cid))
        .to.be.revertedWithCustomError(gov, "RegistryActionNeedsSubject");
      // R-89.1 one layer up: evidence that is not content-addressed can be
      // withdrawn after the vote.
      await expect(gov.propose(1, 1, subject, ethers.ZeroHash))
        .to.be.revertedWithCustomError(gov, "RegistryActionNeedsEvidence");
    });

    it("finalise is permissionless and refuses to run early", async () => {
      const gov = await deployGov(2001);
      const signers = await ethers.getSigners();
      const src = await deployWeightSource(true, 1n);
      await gov.setWeightSource(2, await src.getAddress());
      await gov.propose(0, 0, ethers.ZeroHash, ethers.ZeroHash);
      await gov.castVote(0, true);
      await expect(gov.finalise(0)).to.be.revertedWithCustomError(gov, "VotingOpen");
      await ethers.provider.send("evm_increaseTime", [DAY + 1]);
      await ethers.provider.send("evm_mine", []);
      // Anyone may close it: requiring a privileged call to notice a deadline
      // would let inaction hold a proposal open indefinitely.
      await expect(gov.connect(signers[3]).finalise(0)).to.emit(gov, "ProposalFinalised");
    });

    it("rejects a proposal that failed the threshold", async () => {
      const gov = await deployGov(2001);
      const signers = await ethers.getSigners();
      const src = await (await ethers.getContractFactory("SelectiveWeightSource")).deploy();
      await src.setWeight(signers[0].address, 1n);
      await src.setWeight(signers[1].address, 1n);
      await gov.setWeightSource(2, await src.getAddress());
      await gov.propose(0, 0, ethers.ZeroHash, ethers.ZeroHash);
      await gov.castVote(0, true);
      await gov.connect(signers[1]).castVote(0, false);
      await ethers.provider.send("evm_increaseTime", [DAY + 1]);
      await ethers.provider.send("evm_mine", []);
      await gov.finalise(0);
      // 50% against a 60% threshold.
      expect((await gov.proposals(0)).status).to.equal(2); // REJECTED
      await expect(gov.execute(0)).to.be.revertedWithCustomError(gov, "NotPassed");
    });
  });

  describe("SCORE_WEIGHTS", () => {
    it("matches §94 and keeps stake the smallest term", async () => {
      const gov = await deployGov(2001);
      expect(await gov.W_INFRA()).to.equal(40);
      expect(await gov.W_REPUTATION()).to.equal(30);
      expect(await gov.W_PARTICIPATION()).to.equal(20);
      expect(await gov.W_STAKE()).to.equal(10);
      expect(await gov.W_TOTAL()).to.equal(100);
      // "The wealthiest party does not decide what the network suppresses."
      const stake = await gov.W_STAKE();
      for (const w of [await gov.W_INFRA(), await gov.W_REPUTATION(), await gov.W_PARTICIPATION()]) {
        expect(stake).to.be.lessThan(w);
      }
    });
  });
});
