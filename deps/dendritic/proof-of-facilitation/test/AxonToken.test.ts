import { expect } from "chai";
import { ethers } from "hardhat";

describe("AxonToken", function () {
  it("is Axon/AXON on-chain and AXONCoins on the site — one balance, one name", async function () {
    const [owner, treasury, alice] = await ethers.getSigners();
    const Token = await ethers.getContractFactory("AxonToken");
    const token = await Token.deploy(owner.address);
    await token.waitForDeployment();

    // On-chain identity is Axon/AXON, and the site writes the same balance
    // AXONCoins. The token was named Anonymous/ANON until the 2026-08-16 rename;
    // the deployed AxonChannels on mainnet still references the pre-rename
    // token, which is why `token_address()` keeps every generation in its
    // fallback chain rather than replacing one.
    expect(await token.name()).to.equal("Axon");
    expect(await token.symbol()).to.equal("AXON");

    // No treasury wired yet -> minting is impossible for anyone.
    await expect(token.connect(owner).mint(alice.address, 100n))
      .to.be.revertedWithCustomError(token, "NotTreasury");

    // Only the owner may set the treasury.
    await expect(token.connect(alice).setTreasury(treasury.address))
      .to.be.revertedWithCustomError(token, "OwnableUnauthorizedAccount");
    await token.connect(owner).setTreasury(treasury.address);
    expect(await token.treasury()).to.equal(treasury.address);

    // Treasury mints; nobody else can.
    await token.connect(treasury).mint(alice.address, 1000n);
    expect(await token.balanceOf(alice.address)).to.equal(1000n);
    await expect(token.connect(alice).mint(alice.address, 1n))
      .to.be.revertedWithCustomError(token, "NotTreasury");

    // The treasury burns its OWN balance and cannot touch anybody else's.
    // burn() takes no `from` on purpose: the earlier signature let whoever held
    // the treasury key destroy any holder's tokens at will.
    await token.connect(treasury).mint(treasury.address, 500n);
    await token.connect(treasury).burn(200n);
    expect(await token.balanceOf(treasury.address)).to.equal(300n);
    expect(await token.balanceOf(alice.address)).to.equal(1000n);
  });

  it("lets the owner genesis-mint to kickstart, then lock it forever", async function () {
    const [owner, treasury, alice] = await ethers.getSigners();
    const token = await (await ethers.getContractFactory("AxonToken")).deploy(owner.address);
    await token.waitForDeployment();

    // Owner seeds the initial supply into the treasury address to kickstart.
    await token.connect(owner).mintGenesis(treasury.address, ethers.parseEther("1000000"));
    expect(await token.balanceOf(treasury.address)).to.equal(ethers.parseEther("1000000"));
    expect(await token.genesisMinted()).to.equal(ethers.parseEther("1000000"));
    // Non-owner cannot genesis-mint.
    await expect(token.connect(alice).mintGenesis(alice.address, 1n))
      .to.be.revertedWithCustomError(token, "OwnableUnauthorizedAccount");

    // Close genesis -> no more owner minting, ever.
    await token.connect(owner).closeGenesis();
    expect(await token.genesisClosed()).to.equal(true);
    await expect(token.connect(owner).mintGenesis(treasury.address, 1n))
      .to.be.revertedWithCustomError(token, "GenesisIsClosed");
  });
});
