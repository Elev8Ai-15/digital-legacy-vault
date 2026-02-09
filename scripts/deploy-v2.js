const hre = require("hardhat");

/**
 * Digital Legacy Vault — Phase 2 Deployment Script
 * 
 * Deploys the full V2 contract stack:
 *   1. Groth16Verifier (on-chain ZKP verification)
 *   2. ZKPIdentityVerifier (identity proof wrapper)
 *   3. ChainlinkDeathOracle (production) OR MockOracle (test/staging)
 *   4. DigitalLegacyVaultV2 (upgraded vault with real ZKP + oracle)
 * 
 * Usage:
 *   Local:   npx hardhat run scripts/deploy-v2.js
 *   Testnet: npx hardhat run scripts/deploy-v2.js --network polygon_amoy
 *   Mainnet: npx hardhat run scripts/deploy-v2.js --network polygon
 * 
 * Post-deployment:
 *   Verify:  npx hardhat verify --network polygon_amoy <ADDRESS> <ARGS...>
 * 
 * Environment Variables (for mainnet):
 *   PRODUCTION_ORACLE_ADDRESS  - If using pre-deployed oracle
 *   CHAINLINK_ROUTER           - Chainlink Functions router address
 *   CHAINLINK_DON_ID           - Chainlink DON ID for Functions
 *   CHAINLINK_SUB_ID           - Chainlink Functions subscription ID
 *   ZKP_VERIFICATION_KEY_PATH  - Path to exported verification_key.json
 */

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const network = hre.network.name;
  const isLocal = network === "hardhat" || network === "localhost";
  const isTestnet = network === "polygon_amoy";
  const isMainnet = network === "polygon";

  console.log("═══════════════════════════════════════════════════════");
  console.log("  DIGITAL LEGACY VAULT V2 — FULL STACK DEPLOYMENT");
  console.log("═══════════════════════════════════════════════════════");
  console.log(`  Network:  ${network}`);
  console.log(`  Deployer: ${deployer.address}`);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`  Balance:  ${hre.ethers.formatEther(balance)} MATIC`);
  console.log("═══════════════════════════════════════════════════════\n");

  const deployed = {};

  // ─────────────────────────────────────────────────
  // STEP 1: Deploy Groth16Verifier
  // ─────────────────────────────────────────────────
  console.log("1. Deploying Groth16Verifier...");
  const Groth16Verifier = await hre.ethers.getContractFactory("Groth16Verifier");
  const groth16Verifier = await Groth16Verifier.deploy();
  await groth16Verifier.waitForDeployment();
  deployed.groth16Verifier = await groth16Verifier.getAddress();
  console.log(`   Groth16Verifier: ${deployed.groth16Verifier}`);

  // Set verification key if available
  const fs = require("fs");
  const vkPath = process.env.ZKP_VERIFICATION_KEY_PATH || "./circuits/verification_key.json";
  if (fs.existsSync(vkPath)) {
    console.log("   Loading verification key...");
    const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));

    // Extract key components for on-chain storage
    const alpha = [
      BigInt(vk.vk_alpha_1[0]),
      BigInt(vk.vk_alpha_1[1]),
    ];
    const beta = [
      [BigInt(vk.vk_beta_2[0][0]), BigInt(vk.vk_beta_2[0][1])],
      [BigInt(vk.vk_beta_2[1][0]), BigInt(vk.vk_beta_2[1][1])],
    ];
    const gamma = [
      [BigInt(vk.vk_gamma_2[0][0]), BigInt(vk.vk_gamma_2[0][1])],
      [BigInt(vk.vk_gamma_2[1][0]), BigInt(vk.vk_gamma_2[1][1])],
    ];
    const delta = [
      [BigInt(vk.vk_delta_2[0][0]), BigInt(vk.vk_delta_2[0][1])],
      [BigInt(vk.vk_delta_2[1][0]), BigInt(vk.vk_delta_2[1][1])],
    ];
    const ic = vk.IC.map(p => [BigInt(p[0]), BigInt(p[1])]);

    const tx = await groth16Verifier.setVerificationKey(
      alpha, beta, gamma, delta, ic
    );
    await tx.wait();
    console.log("   Verification key set on-chain.");
  } else {
    console.log("   ⚠ No verification key found. Set later with setVerificationKey().");
    console.log(`     Expected: ${vkPath}`);
  }

  // ─────────────────────────────────────────────────
  // STEP 2: Deploy ZKPIdentityVerifier
  // ─────────────────────────────────────────────────
  console.log("\n2. Deploying ZKPIdentityVerifier...");

  const ZKPVerifier = await hre.ethers.getContractFactory("ZKPIdentityVerifier");
  const zkpVerifier = await ZKPVerifier.deploy(deployed.groth16Verifier);
  await zkpVerifier.waitForDeployment();
  const zkpVerifierAddress = await zkpVerifier.getAddress();

  deployed.zkpVerifier = zkpVerifierAddress;
  console.log(`   ZKPIdentityVerifier: ${deployed.zkpVerifier}`);

  // ─────────────────────────────────────────────────
  // STEP 3: Deploy Oracle
  // ─────────────────────────────────────────────────
  console.log("\n3. Deploying Oracle...");

  let oracleAddress;

  if (isLocal) {
    // Local: Deploy MockOracle
    const MockOracle = await hre.ethers.getContractFactory("MockOracle");
    const oracle = await MockOracle.deploy();
    await oracle.waitForDeployment();
    oracleAddress = await oracle.getAddress();
    console.log(`   MockOracle: ${oracleAddress}`);
  } else if (isTestnet) {
    // Testnet: Deploy ChainlinkDeathOracle with test config
    // Polygon Amoy Chainlink Functions Router
    const routerAddress = process.env.CHAINLINK_ROUTER || "0xC22a79eBA640940ABB6dF0f7982cc119578E11De";
    const donId = process.env.CHAINLINK_DON_ID || "0x66756e2d706f6c79676f6e2d616d6f792d310000000000000000000000000000";
    const subId = process.env.CHAINLINK_SUB_ID || "0";

    try {
      const ChainlinkOracle = await hre.ethers.getContractFactory("ChainlinkDeathOracle");
      const oracle = await ChainlinkOracle.deploy(routerAddress, donId, subId);
      await oracle.waitForDeployment();
      oracleAddress = await oracle.getAddress();
      console.log(`   ChainlinkDeathOracle: ${oracleAddress}`);
    } catch (e) {
      console.log(`   ⚠ Chainlink deploy failed: ${e.message}`);
      console.log("   Falling back to MockOracle...");
      const MockOracle = await hre.ethers.getContractFactory("MockOracle");
      const oracle = await MockOracle.deploy();
      await oracle.waitForDeployment();
      oracleAddress = await oracle.getAddress();
      console.log(`   MockOracle (fallback): ${oracleAddress}`);
    }
  } else if (isMainnet) {
    // Mainnet: Use pre-deployed oracle or deploy fresh
    if (process.env.PRODUCTION_ORACLE_ADDRESS) {
      oracleAddress = process.env.PRODUCTION_ORACLE_ADDRESS;
      console.log(`   Using existing oracle: ${oracleAddress}`);
    } else {
      const routerAddress = process.env.CHAINLINK_ROUTER;
      const donId = process.env.CHAINLINK_DON_ID;
      const subId = process.env.CHAINLINK_SUB_ID;

      if (!routerAddress || !donId || !subId) {
        throw new Error(
          "Mainnet deployment requires either PRODUCTION_ORACLE_ADDRESS or " +
          "CHAINLINK_ROUTER + CHAINLINK_DON_ID + CHAINLINK_SUB_ID in .env"
        );
      }

      const ChainlinkOracle = await hre.ethers.getContractFactory("ChainlinkDeathOracle");
      const oracle = await ChainlinkOracle.deploy(routerAddress, donId, subId);
      await oracle.waitForDeployment();
      oracleAddress = await oracle.getAddress();
      console.log(`   ChainlinkDeathOracle: ${oracleAddress}`);
    }
  }

  deployed.oracle = oracleAddress;

  // ─────────────────────────────────────────────────
  // STEP 4: Deploy DigitalLegacyVaultV2
  // ─────────────────────────────────────────────────
  console.log("\n4. Deploying DigitalLegacyVaultV2...");
  const VaultV2 = await hre.ethers.getContractFactory("DigitalLegacyVaultV2");
  const vault = await VaultV2.deploy(oracleAddress, zkpVerifierAddress);
  await vault.waitForDeployment();
  deployed.vaultV2 = await vault.getAddress();
  console.log(`   DigitalLegacyVaultV2: ${deployed.vaultV2}`);

  // ─────────────────────────────────────────────────
  // STEP 5: Post-deployment configuration
  // ─────────────────────────────────────────────────
  console.log("\n5. Post-deployment configuration...");

  // Verify V2 contract settings
  const adminAddr = await vault.admin();
  const oracleRef = await vault.oracle();
  const zkpRef = await vault.zkpVerifier();
  const zkpEnabled = await vault.zkpEnabled();

  console.log(`   Admin:        ${adminAddr}`);
  console.log(`   Oracle:       ${oracleRef}`);
  console.log(`   ZKP Verifier: ${zkpRef}`);
  console.log(`   ZKP Enabled:  ${zkpEnabled}`);
  console.log(`   Min check-in: ${await vault.MIN_CHECK_IN_INTERVAL()} seconds`);
  console.log(`   Min grace:    ${await vault.MIN_GRACE_PERIOD()} seconds`);
  console.log(`   Claim cooldown: ${await vault.CLAIM_COOLDOWN()} seconds`);

  // If local/testnet, enable ZKP by default for testing
  if ((isLocal || isTestnet) && !zkpEnabled) {
    console.log("\n   Enabling ZKP verification for testing...");
    const tx = await vault.setZKPEnabled(true);
    await tx.wait();
    console.log("   ZKP verification enabled.");
  }

  // ─────────────────────────────────────────────────
  // STEP 6: Save deployment manifest
  // ─────────────────────────────────────────────────
  const deploymentInfo = {
    version: "2.0",
    network,
    deployer: deployer.address,
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString(),
    timestamp: new Date().toISOString(),
    contracts: {
      groth16Verifier: deployed.groth16Verifier,
      zkpIdentityVerifier: deployed.zkpVerifier,
      oracle: deployed.oracle,
      vaultV2: deployed.vaultV2,
    },
    configuration: {
      zkpEnabled: isLocal || isTestnet,
      oracleType: isLocal ? "MockOracle" : "ChainlinkDeathOracle",
      verificationKeyLoaded: fs.existsSync(vkPath),
    },
  };

  const dir = "./deployments";
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  const filename = `${dir}/${network}-v2-${Date.now()}.json`;
  fs.writeFileSync(filename, JSON.stringify(deploymentInfo, null, 2));

  console.log("\n═══════════════════════════════════════════════════════");
  console.log("  DEPLOYMENT COMPLETE — V2 FULL STACK");
  console.log("═══════════════════════════════════════════════════════");
  console.log(JSON.stringify(deploymentInfo, null, 2));
  console.log(`\n  Manifest saved: ${filename}`);

  // ─────────────────────────────────────────────────
  // STEP 7: Contract verification on explorer
  // ─────────────────────────────────────────────────
  if (!isLocal) {
    console.log("\n6. Verifying contracts on explorer...");
    console.log("   Waiting 30 seconds for indexing...");
    await new Promise(r => setTimeout(r, 30000));

    const contracts = [
      { name: "Groth16Verifier", address: deployed.groth16Verifier, args: [] },
      { name: "ZKPIdentityVerifier", address: deployed.zkpVerifier, args: [deployed.groth16Verifier] },
      { name: "DigitalLegacyVaultV2", address: deployed.vaultV2, args: [oracleAddress, zkpVerifierAddress] },
    ];

    for (const c of contracts) {
      try {
        await hre.run("verify:verify", {
          address: c.address,
          constructorArguments: c.args,
        });
        console.log(`   ✓ ${c.name} verified`);
      } catch (e) {
        console.log(`   ⚠ ${c.name}: ${e.message.slice(0, 80)}`);
      }
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
