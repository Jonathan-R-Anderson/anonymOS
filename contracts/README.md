# zkSync Smart Contract Deployment

This directory contains the smart contract for AnonymOS system integrity verification on zkSync Era.

## Prerequisites

- Node.js v16+
- npm or yarn
- zkSync CLI tools
- Ethereum wallet with zkSync Era testnet ETH

## Installation

```bash
# Install dependencies
npm install --save-dev @matterlabs/hardhat-zksync-solc
npm install --save-dev @matterlabs/hardhat-zksync-deploy
npm install --save-dev @nomiclabs/hardhat-ethers
npm install --save-dev ethers
npm install --save-dev hardhat
```

## Configuration

Create `hardhat.config.js`:

```javascript
require("@matterlabs/hardhat-zksync-solc");
require("@matterlabs/hardhat-zksync-deploy");

module.exports = {
  zksolc: {
    version: "1.3.13",
    compilerSource: "binary",
    settings: {},
  },
  defaultNetwork: "zkSyncTestnet",
  networks: {
    zkSyncTestnet: {
      url: "https://testnet.era.zksync.dev",
      ethNetwork: "goerli",
      zksync: true,
    },
    zkSyncMainnet: {
      url: "https://mainnet.era.zksync.io",
      ethNetwork: "mainnet",
      zksync: true,
    },
  },
  solidity: {
    version: "0.8.17",
  },
};
```

## Deployment

### Testnet Deployment

```bash
# Compile contract
npx hardhat compile

# Deploy to zkSync testnet
npx hardhat deploy-zksync --script deploy.js --network zkSyncTestnet
```

### Mainnet Deployment

```bash
# Deploy to zkSync mainnet (CAUTION: uses real ETH)
npx hardhat deploy-zksync --script deploy.js --network zkSyncMainnet
```

## Deployment Script

Create `deploy/deploy.js`:

```javascript
const { Wallet, Provider } = require("zksync-web3");
const { Deployer } = require("@matterlabs/hardhat-zksync-deploy");
const hre = require("hardhat");

async function main() {
  console.log("Deploying SystemIntegrity contract to zkSync Era...");

  // Initialize provider
  const provider = new Provider(hre.config.networks.zkSyncTestnet.url);

  // Initialize wallet (use environment variable for private key)
  const wallet = new Wallet(process.env.PRIVATE_KEY, provider);

  // Create deployer
  const deployer = new Deployer(hre, wallet);

  // Load contract artifact
  const artifact = await deployer.loadArtifact("SystemIntegrity");

  // Deploy contract
  const contract = await deployer.deploy(artifact);

  console.log(`Contract deployed to: ${contract.address}`);
  console.log(`Transaction hash: ${contract.deployTransaction.hash}`);

  // Wait for deployment to be mined
  await contract.deployTransaction.wait();

  console.log("Deployment complete!");
  console.log("\nContract details:");
  console.log(`  Address: ${contract.address}`);
  console.log(`  Network: ${hre.network.name}`);
  console.log(`  Deployer: ${wallet.address}`);

  // Save contract address to file
  const fs = require("fs");
  const contractInfo = {
    address: contract.address,
    network: hre.network.name,
    deployer: wallet.address,
    deployedAt: new Date().toISOString(),
  };

  fs.writeFileSync(
    "deployed-contract.json",
    JSON.stringify(contractInfo, null, 2)
  );

  console.log("\nContract info saved to deployed-contract.json");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

## Interacting with the Contract

### Update Fingerprint

```javascript
const { ethers } = require("ethers");
const contractABI = require("./artifacts-zk/contracts/SystemIntegrity.sol/SystemIntegrity.json").abi;

async function updateFingerprint() {
  const provider = new ethers.providers.JsonRpcProvider("https://testnet.era.zksync.dev");
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  
  const contractAddress = "0x..."; // Your deployed contract address
  const contract = new ethers.Contract(contractAddress, contractABI, wallet);
  
  // Compute hashes (example values)
  const kernelHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("kernel-data"));
  const bootloaderHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("bootloader-data"));
  const initrdHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("initrd-data"));
  const manifestHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("manifest-data"));
  
  const tx = await contract.updateFingerprint(
    kernelHash,
    bootloaderHash,
    initrdHash,
    manifestHash,
    1, // version
    "Initial deployment"
  );
  
  await tx.wait();
  console.log("Fingerprint updated!");
}
```

### Query Fingerprint

```javascript
async function queryFingerprint(ownerAddress) {
  const provider = new ethers.providers.JsonRpcProvider("https://testnet.era.zksync.dev");
  
  const contractAddress = "0x...";
  const contract = new ethers.Contract(contractAddress, contractABI, provider);
  
  const fingerprint = await contract.getFingerprint(ownerAddress);
  
  console.log("Fingerprint:");
  console.log(`  Kernel Hash: ${fingerprint.kernelHash}`);
  console.log(`  Bootloader Hash: ${fingerprint.bootloaderHash}`);
  console.log(`  Initrd Hash: ${fingerprint.initrdHash}`);
  console.log(`  Manifest Hash: ${fingerprint.manifestHash}`);
  console.log(`  Timestamp: ${new Date(fingerprint.timestamp * 1000).toISOString()}`);
  console.log(`  Version: ${fingerprint.version}`);
  console.log(`  Frozen: ${fingerprint.frozen}`);
}
```

### Verify Fingerprint

```javascript
async function verifyFingerprint(ownerAddress, currentHashes) {
  const provider = new ethers.providers.JsonRpcProvider("https://testnet.era.zksync.dev");
  
  const contractAddress = "0x...";
  const contract = new ethers.Contract(contractAddress, contractABI, provider);
  
  const isValid = await contract.verifyFingerprint(
    ownerAddress,
    currentHashes.kernelHash,
    currentHashes.bootloaderHash,
    currentHashes.initrdHash,
    currentHashes.manifestHash
  );
  
  console.log(`Fingerprint valid: ${isValid}`);
  return isValid;
}
```

## Security Best Practices

### Private Key Management

**NEVER** commit your private key to version control!

Use environment variables:

```bash
export PRIVATE_KEY="0x..."
```

Or use a `.env` file (add to `.gitignore`):

```
PRIVATE_KEY=0x...
```

### Multi-Signature Setup

For production, use multi-signature authorization:

```javascript
// Authorize additional signers
await contract.authorizeUpdater("0x...");

// Update fingerprint from authorized address
await contract.updateFingerprintFor(
  ownerAddress,
  kernelHash,
  bootloaderHash,
  initrdHash,
  manifestHash,
  version,
  "Authorized update"
);
```

### Emergency Freeze

If you suspect compromise:

```javascript
// Freeze your fingerprint immediately
await contract.freezeFingerprint();

// Later, after investigation
await contract.unfreezeFingerprint();
```

## Gas Costs

Approximate gas costs on zkSync Era:

- Deploy contract: ~500,000 gas
- Update fingerprint: ~100,000 gas
- Query fingerprint: 0 gas (read-only)
- Freeze/unfreeze: ~50,000 gas

## Testing

Create `test/SystemIntegrity.test.js`:

```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SystemIntegrity", function () {
  let contract;
  let owner;
  let addr1;

  beforeEach(async function () {
    [owner, addr1] = await ethers.getSigners();
    
    const SystemIntegrity = await ethers.getContractFactory("SystemIntegrity");
    contract = await SystemIntegrity.deploy();
    await contract.deployed();
  });

  it("Should update and retrieve fingerprint", async function () {
    const kernelHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("kernel"));
    const bootloaderHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("bootloader"));
    const initrdHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("initrd"));
    const manifestHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("manifest"));

    await contract.updateFingerprint(
      kernelHash,
      bootloaderHash,
      initrdHash,
      manifestHash,
      1,
      "Test update"
    );

    const fingerprint = await contract.getFingerprint(owner.address);
    expect(fingerprint.kernelHash).to.equal(kernelHash);
    expect(fingerprint.version).to.equal(1);
  });

  it("Should verify matching fingerprint", async function () {
    const kernelHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("kernel"));
    const bootloaderHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("bootloader"));
    const initrdHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("initrd"));
    const manifestHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("manifest"));

    await contract.updateFingerprint(
      kernelHash,
      bootloaderHash,
      initrdHash,
      manifestHash,
      1,
      "Test"
    );

    const isValid = await contract.verifyFingerprint(
      owner.address,
      kernelHash,
      bootloaderHash,
      initrdHash,
      manifestHash
    );

    expect(isValid).to.be.true;
  });

  it("Should freeze and unfreeze fingerprint", async function () {
    await contract.freezeFingerprint();
    
    const fingerprint = await contract.getFingerprint(owner.address);
    expect(fingerprint.frozen).to.be.true;

    await contract.unfreezeFingerprint();
    
    const unfrozen = await contract.getFingerprint(owner.address);
    expect(unfrozen.frozen).to.be.false;
  });
});
```

Run tests:

```bash
npx hardhat test
```

## Troubleshooting

### "Insufficient funds" error

Ensure your wallet has enough zkSync Era ETH. Get testnet ETH from:
- zkSync Era Testnet Faucet: https://goerli.portal.zksync.io/faucet

### "Contract deployment failed"

Check:
1. Network configuration in `hardhat.config.js`
2. Private key is correctly set
3. Sufficient gas limit

### "Transaction reverted"

Common causes:
- Trying to update frozen fingerprint
- Global freeze is active
- Not authorized to update

## License

MIT
