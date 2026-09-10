import { expect } from "chai";
import { ethers } from "hardhat";

describe("NodeRegistry", function () {
  const p2pKey = "0x" + "11".repeat(32); // a fake 32-byte Ed25519 pubkey
  const endpoint = ethers.keccak256(ethers.toUtf8Bytes("endpoint|secret|epoch"));

  it("registers a node, enforces uniqueness/capabilities/ownership, and rotates keys", async function () {
    const [owner, nodeOwner, other] = await ethers.getSigners();
    const Reg = await ethers.getContractFactory("NodeRegistry");
    const reg = await Reg.deploy(owner.address);
    await reg.waitForDeployment();

    const CAP_DHT = await reg.CAP_DHT();
    const CAP_STORAGE = await reg.CAP_STORAGE();
    const caps = CAP_DHT | CAP_STORAGE;
    const nodeId = ethers.keccak256(p2pKey);

    await expect(reg.connect(nodeOwner).register(p2pKey, caps, endpoint))
      .to.emit(reg, "NodeRegistered").withArgs(nodeId, nodeOwner.address, caps);
    expect(await reg.isRegistered(nodeId)).to.equal(true);
    expect(await reg.hasCapability(nodeId, CAP_DHT)).to.equal(true);
    expect(await reg.hasCapability(nodeId, await reg.CAP_GATEWAY())).to.equal(false);

    // Duplicate p2p key is rejected (no impersonating an existing node identity).
    await expect(reg.connect(other).register(p2pKey, caps, endpoint))
      .to.be.revertedWithCustomError(reg, "KeyAlreadyRegistered");

    // Empty/invalid capabilities are rejected.
    await expect(reg.connect(other).register("0x" + "22".repeat(32), 0, endpoint))
      .to.be.revertedWithCustomError(reg, "BadCapabilities");

    // Only the node owner can update it.
    await expect(reg.connect(other).updateNode(nodeId, CAP_DHT, endpoint))
      .to.be.revertedWithCustomError(reg, "NotNodeOwner");

    // Key rotation retires the old node id and activates the new one, same owner.
    const newKey = "0x" + "33".repeat(32);
    const newId = ethers.keccak256(newKey);
    await expect(reg.connect(nodeOwner).rotateKey(nodeId, newKey, endpoint))
      .to.emit(reg, "KeyRotated").withArgs(nodeId, newId, nodeOwner.address);
    expect((await reg.getNode(nodeId)).active).to.equal(false);
    expect((await reg.getNode(newId)).active).to.equal(true);
    expect(await reg.nodesOf(nodeOwner.address)).to.deep.equal([nodeId, newId]);
  });

  it("registers a lightweight node via a relayer signature, recovering the owner", async function () {
    const [owner, relayer] = await ethers.getSigners();
    const Reg = await ethers.getContractFactory("NodeRegistry");
    const reg = await Reg.deploy(owner.address);
    await reg.waitForDeployment();

    // The node holds a wallet key it signs with; it never sends a transaction.
    const nodeWallet = ethers.Wallet.createRandom();
    const key = "0x" + "44".repeat(32);
    const caps = await reg.CAP_DHT();
    const nonce = 1n;
    const nodeId = ethers.keccak256(key);

    const digest = await reg.registrationDigest(key, caps, endpoint, nonce);
    const sig = nodeWallet.signingKey.sign(digest); // raw ECDSA over the digest

    // The RELAYER (not the node) submits + pays gas; owner is recovered from the sig.
    await expect(reg.connect(relayer).registerWithSig(key, caps, endpoint, nonce, sig.v, sig.r, sig.s))
      .to.emit(reg, "NodeRegistered").withArgs(nodeId, nodeWallet.address, caps);
    expect((await reg.getNode(nodeId)).owner).to.equal(nodeWallet.address);
    expect(await reg.nodesOf(nodeWallet.address)).to.deep.equal([nodeId]);
  });
});

describe("NodeRegistry — AXON capability bits (§17.2)", function () {
  // The §17 blocker: CAP_ALL was (1 << 7) - 1, so every AXON role bit sat above
  // the validator's ceiling and `register` reverted with BadCapabilities. The
  // bitmap field was always uint256; the VALIDATOR was the compile-time
  // constant, which is why this was a small change and a hard blocker.
  it("admits every AXON role bit, and still rejects what is above them", async function () {
    const [owner] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("NodeRegistry")).deploy(owner.address);
    await reg.waitForDeployment();

    const bits = {
      CAP_RELAY: 1n << 7n,
      CAP_GUARD: 1n << 8n,
      CAP_RENDEZVOUS: 1n << 9n,
      CAP_INTRO: 1n << 10n,
      CAP_BOOTSTRAP: 1n << 11n,
      CAP_EXIT: 1n << 12n,
    };

    // Every constant is where §17.2 says it is. A renumber would silently
    // misattribute every receipt (internal/facilitation/receipt.go derives the
    // ServiceType index from the bit position), so this is checked by value.
    for (const [name, value] of Object.entries(bits)) {
      expect(await (reg as any)[name]()).to.equal(value);
    }
    // And the seven that existed before are untouched.
    expect(await reg.CAP_DHT()).to.equal(1n << 0n);
    expect(await reg.CAP_GATEWAY()).to.equal(1n << 1n);
    expect(await reg.CAP_STORAGE()).to.equal(1n << 2n);
    expect(await reg.CAP_LOADBALANCE()).to.equal(1n << 3n);
    expect(await reg.CAP_DOCKER_WORKER()).to.equal(1n << 4n);
    expect(await reg.CAP_DOCKER_CONTROLLER()).to.equal(1n << 5n);
    expect(await reg.CAP_WITNESS()).to.equal(1n << 6n);
    expect(await reg.CAP_ALL()).to.equal((1n << 13n) - 1n);

    // A relay registers. Under the old ceiling this call reverted.
    const key = (i: number) => ethers.hexlify(new Uint8Array(32).fill(i));
    let i = 1;
    for (const [name, value] of Object.entries(bits)) {
      const pk = key(i++);
      await reg.connect(owner).register(pk, value, ethers.ZeroHash);
      const node = await reg.getNode(ethers.keccak256(pk));
      expect(node.capabilities, `${name} did not survive registration`).to.equal(value);
    }

    // The ceiling still exists: bit 13 is above CAP_ALL and must be refused.
    // A validator that simply stopped checking would pass every test above and
    // let a node advertise capabilities nothing in the network defines.
    await expect(reg.connect(owner).register(key(99), 1n << 13n, ethers.ZeroHash))
      .to.be.revertedWithCustomError(reg, "BadCapabilities");
    // And an empty bitmap is still not a registration.
    await expect(reg.connect(owner).register(key(98), 0n, ethers.ZeroHash))
      .to.be.revertedWithCustomError(reg, "BadCapabilities");
  });

  it("has no CAP_SERVICE, and never will (§17.1)", async function () {
    // An on-chain advertisement that a node hosts an anonymous service is a
    // deanonymisation vector with no compensating benefit. This asserts the
    // absence, because absence is the design and a later "completeness" pass
    // adding it would look like tidying up.
    const [owner] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("NodeRegistry")).deploy(owner.address);
    await reg.waitForDeployment();
    expect((reg as any).CAP_SERVICE).to.equal(undefined);
    const abi = reg.interface.fragments.map((f: any) => f.name).filter(Boolean);
    expect(abi.filter((n: string) => /service/i.test(n))).to.deep.equal([]);
  });
});
