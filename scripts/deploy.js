const hre = require("hardhat");

/**
 * Digital Legacy Vault — Deployment Script
 * 
 * Usage:
 *   Local:   npx hardhat run scripts/deploy.js
 *   Testnet: npx hardhat run scripts/deploy.js --network polygon_amoy
 *   Mainnet: npx hardhat run scripts/deploy.js --network polygon
 * 
 * Post-deployment:
 *   Verify:  npx hardhat verify --network polygon_amoy <CONTRACT_ADDRESS> <ORACLE_ADDRESS>
 */

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const network = hre.network.name;

  console.log("═══════════════════════════════════════════════");
  console.log("  DIGITAL LEGACY VAULT — DEPLOYMENT");
  console.log("═══════════════════════════════════════════════");
  console.log(`  Network:  ${network}`);
  console.log(`  Deployer: ${deployer.address}`);
  
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`  Balance:  ${hre.ethers.formatEther(balance)} MATIC`);
  console.log("═══════════════════════════════════════════════\n");

  // ─── Step 1: Deploy Oracle ───
  console.log("1. Deploying Oracle...");
  
  let oracleAddress;
  
  if (network === "hardhat" || network === "localhost" || network === "polygon_amoy") {
    // Deploy MockOracle for testing/testnet
    const MockOracle = await hre.ethers.getContractFactory("MockOracle");
    const oracle = await MockOracle.deploy();
    await oracle.waitForDeployment();
    oracleAddress = await oracle.getAddress();
    console.log(`   MockOracle deployed: ${oracleAddress}`);
  } else {
    // For mainnet, use Chainlink or a production oracle address
    // This should be configured per-environment
    oracleAddress = process.env.PRODUCTION_ORACLE_ADDRESS;
    if (!oracleAddress) {
      throw new Error("PRODUCTION_ORACLE_ADDRESS not set in .env for mainnet deployment");
    }
    console.log(`   Using production oracle: ${oracleAddress}`);
  }

  // ─── Step 2: Deploy DigitalLegacyVault ───
  console.log("\n2. Deploying DigitalLegacyVault...");
  const Vault = await hre.ethers.getContractFactory("DigitalLegacyVault");
  const vault = await Vault.deploy(oracleAddress);
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();
  console.log(`   DigitalLegacyVault deployed: ${vaultAddress}`);

  // ─── Step 3: Verify Configuration ───
  console.log("\n3. Verifying deployment...");
  const adminAddress = await vault.admin();
  const oracleRef = await vault.oracle();
  console.log(`   Admin:  ${adminAddress}`);
  console.log(`   Oracle: ${oracleRef}`);
  console.log(`   Min check-in: ${await vault.MIN_CHECK_IN_INTERVAL()} seconds`);
  console.log(`   Min grace:    ${await vault.MIN_GRACE_PERIOD()} seconds`);
  console.log(`   Claim cooldown: ${await vault.CLAIM_COOLDOWN()} seconds`);

  // ─── Step 4: Output Deployment Info ───
  console.log("\n═══════════════════════════════════════════════");
  console.log("  DEPLOYMENT COMPLETE");
  console.log("═══════════════════════════════════════════════");
  
  const deploymentInfo = {
    network,
    deployer: deployer.address,
    contracts: {
      oracle: oracleAddress,
      vault: vaultAddress,
    },
    timestamp: new Date().toISOString(),
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString(),
  };

  console.log(JSON.stringify(deploymentInfo, null, 2));

  // Save deployment info to file
  const fs = require("fs");
  const dir = "./deployments";
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  fs.writeFileSync(
    `${dir}/${network}-${Date.now()}.json`,
    JSON.stringify(deploymentInfo, null, 2)
  );
  console.log(`\n  Saved to: ${dir}/${network}-${Date.now()}.json`);

  // ─── Step 5: Verify on Explorer (if not local) ───
  if (network !== "hardhat" && network !== "localhost") {
    console.log("\n4. Verifying contracts on explorer...");
    console.log("   Waiting 30 seconds for indexing...");
    await new Promise(r => setTimeout(r, 30000));

    try {
      await hre.run("verify:verify", {
        address: vaultAddress,
        constructorArguments: [oracleAddress],
      });
      console.log("   DigitalLegacyVault verified!");
    } catch (e) {
      console.log(`   Verification skipped: ${e.message}`);
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
