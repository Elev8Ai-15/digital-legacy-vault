const hre = require("hardhat");

/**
 * Digital Legacy Vault — Phase 3 Deployment Script
 *
 * Deploys DigitalLegacyVaultV2 with Phase 3 (Digital Passcodes) enabled.
 * Phase 3 features (one-time passcodes + lifetime access tokens) are built
 * into the V2 contract — there is no separate V3 contract.
 *
 * This script is a convenience wrapper that deploys the full V2 stack
 * with passcode/lifetime-token constants logged for verification.
 *
 * Usage:
 *   Local:   npx hardhat run scripts/deploy-v3.js
 *   Testnet: npx hardhat run scripts/deploy-v3.js --network polygon_amoy
 */

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const network = hre.network.name;
  const isLocal = network === "hardhat" || network === "localhost";

  console.log("Deploying DigitalLegacyVaultV2 (with Phase 3: Digital Passcodes)...");
  console.log(`  Network:  ${network}`);
  console.log(`  Deployer: ${deployer.address}`);

  // Deploy MockOracle for local/test
  const MockOracle = await hre.ethers.getContractFactory("MockOracle");
  const oracle = await MockOracle.deploy();
  await oracle.waitForDeployment();
  console.log("  MockOracle:", await oracle.getAddress());

  // Deploy mock ZKP verifier
  const MockGroth16 = await hre.ethers.getContractFactory("MockGroth16Verifier");
  const mockGroth16 = await MockGroth16.deploy();
  await mockGroth16.waitForDeployment();

  const ZKPVerifier = await hre.ethers.getContractFactory("ZKPIdentityVerifier");
  const zkpVerifier = await ZKPVerifier.deploy(await mockGroth16.getAddress());
  await zkpVerifier.waitForDeployment();
  console.log("  ZKPIdentityVerifier:", await zkpVerifier.getAddress());

  // Deploy VaultV2 (includes Phase 3)
  const VaultV2 = await hre.ethers.getContractFactory("DigitalLegacyVaultV2");
  const vault = await VaultV2.deploy(
    await oracle.getAddress(),
    await zkpVerifier.getAddress()
  );
  await vault.waitForDeployment();

  const vaultAddr = await vault.getAddress();
  console.log("  DigitalLegacyVaultV2 deployed to:", vaultAddr);

  // Log Phase 3 constants
  console.log("\n  Phase 3 Constants:");
  console.log(`    DEFAULT_PASSCODE_DURATION:    ${await vault.DEFAULT_PASSCODE_DURATION()} seconds`);
  console.log(`    MAX_PASSCODE_DURATION:         ${await vault.MAX_PASSCODE_DURATION()} seconds`);
  console.log(`    MAX_LIFETIME_TOKENS_PER_VAULT: ${await vault.MAX_LIFETIME_TOKENS_PER_VAULT()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
