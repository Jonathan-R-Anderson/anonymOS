import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";

dotenv.config();

// The default `hardhat` network runs plain-EVM so the standard toolbox
// (ethers + chai matchers) can unit-test these contracts fast. Everything
// compiles with plain solc through the standard toolbox; the contracts use no
// chain-specific
// features, so EVM tests are representative and the zksolc build is what ships.
const config: HardhatUserConfig = {
  zksolc: {
    version: "1.5.7",
    settings: {},
  },
  // ONE COMPILER. Everything this project wrote is 0.8.24.
  //
  // There used to be a second, pinned to 0.7.6, existing solely for the vendored
  // CryptoZombies contracts (`pragma >=0.7.0 <0.8.0`). Those are gone: the game
  // was unrelated to the rest of this stack and was deployable to ETHEREUM
  // MAINNET from the admin console, which is not a thing a tutorial ERC-721
  // should be one click away from. Removing it takes the second compiler, its
  // ten per-file overrides and the SafeMath-era dependency with it.
  solidity: {
    compilers: [
      {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 200 },
          // §12.5 makes the storage layout part of the INTERFACE, not an
          // implementation detail, and says it "must be confirmed with
          // `solc --storage-layout` before anything depends on it". Emitting it
          // is what makes that confirmable rather than aspirational: the
          // resolver's proof path costs ~2989 B per extra slot, so a silent
          // slot change is a silent cost change.
          outputSelection: { "*": { "*": ["storageLayout"] } },
        },
      },
    ],
  },
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {},
    // Ethereum MAINNET. Chosen because OUSD (Origin Dollar) is an Ethereum
    // ERC-20 with its liquidity on Curve there, and being swappable for OUSD
    // was the deciding requirement. An earlier version of this comment warned
    // that mainnet gas is "dollars where an L2 is cents" — that was true of the
    // old mainnet and is not true now. Post-Dencun, and with ~95% of activity on
    // L2s leaving L1 uncongested, average fees are roughly $0.16-0.22 and a
    // simple transfer is under a cent. Mainnet is the same order of magnitude as
    // the L2s, so choosing it for OUSD liquidity costs nothing per transaction.
    //
    // Plain solc through the standard toolbox. The `.transfer()` that an
    // earlier L2 compiler refused in the vendored CryptoZombies is legal here —
    // the `call{value:}` replacement is kept anyway, being the correct pattern
    // regardless of chain.
    mainnet: {
      url: process.env.MAINNET_RPC_URL || "https://eth.llamarpc.com",
      chainId: 1,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
    // Sepolia first, always. A contract cannot be patched after deployment and
    // mainnet gas makes a mistake expensive twice.
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com",
      chainId: 11155111,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
  },
};

export default config;
