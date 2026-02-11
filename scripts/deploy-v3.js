const hre = require("hardhat");

async function main() {
  console.log("Deploying DigitalLegacyVaultV3...");

  const DigitalLegacyVaultV3 = await hre.ethers.getContractFactory("DigitalLegacyVaultV3");
  const vaultV3 = await DigitalLegacyVaultV3.deploy();

  await vaultV3.waitForDeployment();

  console.log("✅ DigitalLegacyVaultV3 deployed to:", await vaultV3.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
