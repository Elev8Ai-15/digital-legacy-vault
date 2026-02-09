require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/**
 * Digital Legacy Vault — Hardhat Configuration
 * 
 * Deployment targets:
 *   - Local: Hardhat Network (testing)
 *   - Testnet: Polygon Amoy (staging)
 *   - Mainnet: Polygon PoS (production)
 * 
 * Setup:
 *   1. Copy .env.example to .env
 *   2. Add your PRIVATE_KEY and POLYGONSCAN_API_KEY
 *   3. Run: npx hardhat compile
 *   4. Test: npx hardhat test
 *   5. Deploy: npx hardhat run scripts/deploy.js --network polygon_amoy
 */

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x0000000000000000000000000000000000000000000000000000000000000001";
const POLYGONSCAN_API_KEY = process.env.POLYGONSCAN_API_KEY || "";
const ALCHEMY_AMOY_URL = process.env.ALCHEMY_AMOY_URL || "https://polygon-amoy.g.alchemy.com/v2/demo";
const ALCHEMY_POLYGON_URL = process.env.ALCHEMY_POLYGON_URL || "https://polygon-mainnet.g.alchemy.com/v2/demo";

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200, // Optimize for deployment cost
      },
      viaIR: true, // Required for Groth16Verifier generated code
    },
  },

  networks: {
    // Local development
    hardhat: {
      chainId: 31337,
      mining: {
        auto: true,
        interval: 0,
      },
    },

    // Polygon Amoy Testnet (replaced Mumbai)
    polygon_amoy: {
      url: ALCHEMY_AMOY_URL,
      accounts: [PRIVATE_KEY],
      chainId: 80002,
      gasPrice: 30000000000, // 30 gwei
      confirmations: 2,
    },

    // Polygon Mainnet (Production)
    polygon: {
      url: ALCHEMY_POLYGON_URL,
      accounts: [PRIVATE_KEY],
      chainId: 137,
      gasPrice: 50000000000, // 50 gwei (adjust based on network conditions)
      confirmations: 5,
    },
  },

  etherscan: {
    apiKey: {
      polygon: POLYGONSCAN_API_KEY,
      polygonAmoy: POLYGONSCAN_API_KEY,
    },
    customChains: [
      {
        network: "polygonAmoy",
        chainId: 80002,
        urls: {
          apiURL: "https://api-amoy.polygonscan.com/api",
          browserURL: "https://amoy.polygonscan.com",
        },
      },
    ],
  },

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },

  mocha: {
    timeout: 60000, // 60 seconds for blockchain tests
  },
};
