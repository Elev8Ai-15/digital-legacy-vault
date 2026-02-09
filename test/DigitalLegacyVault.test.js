const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

/**
 * Digital Legacy Vault — Smart Contract Test Suite
 * 
 * Coverage:
 *   - Vault creation and configuration
 *   - Guardian management
 *   - Beneficiary setup
 *   - Check-in (proof of life)
 *   - Dead man's switch state transitions
 *   - Oracle death certificate verification
 *   - Claim and share release flow
 *   - Edge cases and security
 * 
 * Run: npx hardhat test
 */

describe("DigitalLegacyVault", function () {
  let vault, oracle;
  let owner, beneficiary, guardian1, guardian2, guardian3, guardian4, guardian5, attacker;

  // Constants matching contract
  const THIRTY_DAYS = 30 * 24 * 60 * 60;
  const NINETY_DAYS = 90 * 24 * 60 * 60;
  const SIXTY_DAYS = 60 * 24 * 60 * 60;
  const FOURTEEN_DAYS = 14 * 24 * 60 * 60;

  // Dummy hashes for testing
  const ownerDID = ethers.keccak256(ethers.toUtf8Bytes("did:web:owner.example.com"));
  const beneficiaryDID = ethers.keccak256(ethers.toUtf8Bytes("did:web:beneficiary.example.com"));
  const shareHash1 = ethers.keccak256(ethers.toUtf8Bytes("share_1_data"));
  const shareHash2 = ethers.keccak256(ethers.toUtf8Bytes("share_2_data"));
  const shareHash3 = ethers.keccak256(ethers.toUtf8Bytes("share_3_data"));
  const shareHash4 = ethers.keccak256(ethers.toUtf8Bytes("share_4_data"));
  const shareHash5 = ethers.keccak256(ethers.toUtf8Bytes("share_5_data"));
  const deathCertHash = ethers.keccak256(ethers.toUtf8Bytes("death_certificate_FL_2026_001"));

  beforeEach(async function () {
    [owner, beneficiary, guardian1, guardian2, guardian3, guardian4, guardian5, attacker] =
      await ethers.getSigners();

    // Deploy MockOracle
    const MockOracle = await ethers.getContractFactory("MockOracle");
    oracle = await MockOracle.deploy();

    // Deploy DigitalLegacyVault
    const Vault = await ethers.getContractFactory("DigitalLegacyVault");
    vault = await Vault.deploy(await oracle.getAddress());
  });

  // ═══════════════════════════════════════════════
  // VAULT CREATION
  // ═══════════════════════════════════════════════

  describe("Vault Creation", function () {
    it("should create a vault with valid parameters", async function () {
      await expect(
        vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3)
      )
        .to.emit(vault, "VaultCreated")
        .withArgs(owner.address, NINETY_DAYS, 3);

      expect(await vault.hasVault(owner.address)).to.be.true;
      expect(await vault.getVaultState(owner.address)).to.equal(0); // Active
    });

    it("should reject duplicate vault creation", async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
      await expect(
        vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3)
      ).to.be.revertedWith("Vault already exists");
    });

    it("should reject check-in interval too short", async function () {
      await expect(
        vault.connect(owner).createVault(ownerDID, 86400, SIXTY_DAYS, 3) // 1 day
      ).to.be.revertedWith("Check-in interval out of range");
    });

    it("should reject check-in interval too long", async function () {
      await expect(
        vault.connect(owner).createVault(ownerDID, 366 * 86400, SIXTY_DAYS, 3)
      ).to.be.revertedWith("Check-in interval out of range");
    });

    it("should reject grace period too short", async function () {
      await expect(
        vault.connect(owner).createVault(ownerDID, NINETY_DAYS, 86400, 3) // 1 day grace
      ).to.be.revertedWith("Grace period too short");
    });

    it("should reject guardian count below minimum", async function () {
      await expect(
        vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 2)
      ).to.be.revertedWith("Guardian count out of range");
    });

    it("should reject guardian count above maximum", async function () {
      await expect(
        vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 8)
      ).to.be.revertedWith("Guardian count out of range");
    });
  });

  // ═══════════════════════════════════════════════
  // GUARDIAN MANAGEMENT
  // ═══════════════════════════════════════════════

  describe("Guardian Management", function () {
    beforeEach(async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
    });

    it("should add guardians", async function () {
      await expect(
        vault.connect(owner).addGuardian(guardian1.address, shareHash1)
      )
        .to.emit(vault, "GuardianAdded")
        .withArgs(owner.address, guardian1.address, 0);
    });

    it("should reject owner as guardian", async function () {
      await expect(
        vault.connect(owner).addGuardian(owner.address, shareHash1)
      ).to.be.revertedWith("Owner cannot be guardian");
    });

    it("should reject zero address guardian", async function () {
      await expect(
        vault.connect(owner).addGuardian(ethers.ZeroAddress, shareHash1)
      ).to.be.revertedWith("Invalid guardian address");
    });

    it("should reject non-owner adding guardians", async function () {
      await expect(
        vault.connect(attacker).addGuardian(guardian1.address, shareHash1)
      ).to.be.revertedWith("No vault found");
    });
  });

  // ═══════════════════════════════════════════════
  // BENEFICIARY
  // ═══════════════════════════════════════════════

  describe("Beneficiary", function () {
    beforeEach(async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
    });

    it("should set beneficiary", async function () {
      await expect(
        vault.connect(owner).setBeneficiary(beneficiary.address, beneficiaryDID)
      )
        .to.emit(vault, "BeneficiarySet")
        .withArgs(owner.address, beneficiary.address);
    });

    it("should reject owner as beneficiary", async function () {
      await expect(
        vault.connect(owner).setBeneficiary(owner.address, beneficiaryDID)
      ).to.be.revertedWith("Owner cannot be beneficiary");
    });
  });

  // ═══════════════════════════════════════════════
  // CHECK-IN (Proof of Life)
  // ═══════════════════════════════════════════════

  describe("Check-In", function () {
    beforeEach(async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
    });

    it("should accept check-in from owner", async function () {
      await expect(vault.connect(owner).checkIn())
        .to.emit(vault, "CheckIn");
    });

    it("should reset timer on check-in", async function () {
      // Advance time but stay within check-in window
      await time.increase(THIRTY_DAYS);
      await vault.connect(owner).checkIn();
      
      // Time since check-in should be small (just the block time)
      const timeSince = await vault.getTimeSinceCheckIn(owner.address);
      expect(timeSince).to.be.lessThan(10);
    });

    it("should reject check-in from non-owner", async function () {
      await expect(vault.connect(attacker).checkIn())
        .to.be.revertedWith("No vault found");
    });
  });

  // ═══════════════════════════════════════════════
  // DEAD MAN'S SWITCH — STATE TRANSITIONS
  // ═══════════════════════════════════════════════

  describe("Dead Man's Switch", function () {
    beforeEach(async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
    });

    it("should transition Active → Warning after check-in interval", async function () {
      await time.increase(NINETY_DAYS + 1);
      
      await expect(vault.evaluateVaultState(owner.address))
        .to.emit(vault, "StateChanged")
        .withArgs(owner.address, 0, 1); // Active → Warning

      expect(await vault.getVaultState(owner.address)).to.equal(1); // Warning
    });

    it("should transition Warning → Claimable after grace period", async function () {
      await time.increase(NINETY_DAYS + SIXTY_DAYS + 1);
      
      // First call moves to Warning, second evaluates to Claimable
      await vault.evaluateVaultState(owner.address);
      
      expect(await vault.getVaultState(owner.address)).to.equal(2); // Claimable
    });

    it("should allow check-in to recover from Warning → Active", async function () {
      await time.increase(NINETY_DAYS + 1);
      await vault.evaluateVaultState(owner.address);
      expect(await vault.getVaultState(owner.address)).to.equal(1); // Warning

      // Owner checks in during grace period
      await expect(vault.connect(owner).checkIn())
        .to.emit(vault, "StateChanged")
        .withArgs(owner.address, 1, 0); // Warning → Active

      expect(await vault.getVaultState(owner.address)).to.equal(0); // Active
    });

    it("should report claimable correctly via view function", async function () {
      expect(await vault.isClaimable(owner.address)).to.be.false;
      
      await time.increase(NINETY_DAYS + SIXTY_DAYS + 1);
      
      expect(await vault.isClaimable(owner.address)).to.be.true;
    });
  });

  // ═══════════════════════════════════════════════
  // ORACLE — DEATH CERTIFICATE VERIFICATION
  // ═══════════════════════════════════════════════

  describe("Oracle Verification", function () {
    beforeEach(async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
      await vault.connect(owner).setBeneficiary(beneficiary.address, beneficiaryDID);
    });

    it("should accept verified death certificate and transition to Claimable", async function () {
      // Register certificate in oracle
      await oracle.registerCertificate(deathCertHash, 98);

      // Beneficiary submits certificate
      await expect(
        vault.connect(beneficiary).submitDeathCertificate(
          owner.address,
          deathCertHash,
          ethers.toUtf8Bytes("proof_data")
        )
      ).to.emit(vault, "DeathCertificateVerified");

      expect(await vault.getVaultState(owner.address)).to.equal(2); // Claimable
    });

    it("should reject unverified death certificate", async function () {
      // Don't register — certificate unknown to oracle
      await expect(
        vault.connect(beneficiary).submitDeathCertificate(
          owner.address,
          deathCertHash,
          ethers.toUtf8Bytes("proof_data")
        )
      ).to.be.revertedWith("Death certificate not verified by oracle");
    });

    it("should reject low confidence certificate", async function () {
      await oracle.registerCertificate(deathCertHash, 50); // Below 95 threshold

      await expect(
        vault.connect(beneficiary).submitDeathCertificate(
          owner.address,
          deathCertHash,
          ethers.toUtf8Bytes("proof_data")
        )
      ).to.be.revertedWith("Verification confidence too low");
    });

    it("should reject certificate submission from non-beneficiary", async function () {
      await oracle.registerCertificate(deathCertHash, 98);

      await expect(
        vault.connect(attacker).submitDeathCertificate(
          owner.address,
          deathCertHash,
          ethers.toUtf8Bytes("proof_data")
        )
      ).to.be.revertedWith("Not authorized beneficiary");
    });
  });

  // ═══════════════════════════════════════════════
  // CLAIM & SHARE RELEASE
  // ═══════════════════════════════════════════════

  describe("Claim & Share Release", function () {
    beforeEach(async function () {
      // Full setup: vault + beneficiary + 5 guardians
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
      await vault.connect(owner).setBeneficiary(beneficiary.address, beneficiaryDID);
      await vault.connect(owner).addGuardian(guardian1.address, shareHash1);
      await vault.connect(owner).addGuardian(guardian2.address, shareHash2);
      await vault.connect(owner).addGuardian(guardian3.address, shareHash3);
      await vault.connect(owner).addGuardian(guardian4.address, shareHash4);
      await vault.connect(owner).addGuardian(guardian5.address, shareHash5);

      // Trigger dead man's switch
      await time.increase(NINETY_DAYS + SIXTY_DAYS + 1);
      await vault.evaluateVaultState(owner.address);
    });

    it("should allow beneficiary to initiate claim on claimable vault", async function () {
      await expect(
        vault.connect(beneficiary).initiateClaim(
          owner.address,
          ethers.toUtf8Bytes("zk_proof_data")
        )
      ).to.emit(vault, "ClaimInitiated");
    });

    it("should reject claim on non-claimable vault", async function () {
      // Create a fresh vault (Active state)
      await vault.connect(guardian1).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
      await vault.connect(guardian1).setBeneficiary(beneficiary.address, beneficiaryDID);
      
      await expect(
        vault.connect(beneficiary).initiateClaim(
          guardian1.address,
          ethers.toUtf8Bytes("zk_proof_data")
        )
      ).to.be.revertedWith("Vault not claimable");
    });

    it("should track guardian confirmations", async function () {
      // Beneficiary initiates claim
      await vault.connect(beneficiary).initiateClaim(
        owner.address,
        ethers.toUtf8Bytes("zk_proof_data")
      );

      // Guardian 1 confirms
      await expect(
        vault.connect(guardian1).confirmShareRelease(owner.address)
      ).to.emit(vault, "GuardianConfirmed");

      const [confirmed, required] = await vault.getGuardianConfirmations(owner.address);
      expect(confirmed).to.equal(1);
      expect(required).to.equal(3);
    });

    it("should release shares when threshold met (3 of 5)", async function () {
      await vault.connect(beneficiary).initiateClaim(
        owner.address,
        ethers.toUtf8Bytes("zk_proof_data")
      );

      // 3 guardians confirm
      await vault.connect(guardian1).confirmShareRelease(owner.address);
      await vault.connect(guardian2).confirmShareRelease(owner.address);
      
      await expect(
        vault.connect(guardian3).confirmShareRelease(owner.address)
      )
        .to.emit(vault, "SharesReleased")
        .withArgs(owner.address, beneficiary.address);

      expect(await vault.getVaultState(owner.address)).to.equal(3); // Claimed
    });

    it("should not release shares with only 2 of 5 confirmations", async function () {
      await vault.connect(beneficiary).initiateClaim(
        owner.address,
        ethers.toUtf8Bytes("zk_proof_data")
      );

      await vault.connect(guardian1).confirmShareRelease(owner.address);
      await vault.connect(guardian2).confirmShareRelease(owner.address);

      // Still Claimable, not Claimed
      expect(await vault.getVaultState(owner.address)).to.equal(2);
    });

    it("should reject duplicate guardian confirmation", async function () {
      await vault.connect(beneficiary).initiateClaim(
        owner.address,
        ethers.toUtf8Bytes("zk_proof_data")
      );

      await vault.connect(guardian1).confirmShareRelease(owner.address);
      await expect(
        vault.connect(guardian1).confirmShareRelease(owner.address)
      ).to.be.revertedWith("Already confirmed");
    });

    it("should reject confirmation from non-guardian", async function () {
      await vault.connect(beneficiary).initiateClaim(
        owner.address,
        ethers.toUtf8Bytes("zk_proof_data")
      );

      await expect(
        vault.connect(attacker).confirmShareRelease(owner.address)
      ).to.be.revertedWith("Not an active guardian");
    });

    it("should reject confirmation before beneficiary initiates claim", async function () {
      // Beneficiary hasn't initiated yet, so isVerified = false
      await expect(
        vault.connect(guardian1).confirmShareRelease(owner.address)
      ).to.be.revertedWith("Beneficiary not verified");
    });
  });

  // ═══════════════════════════════════════════════
  // VAULT REVOCATION
  // ═══════════════════════════════════════════════

  describe("Vault Revocation", function () {
    beforeEach(async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
    });

    it("should allow owner to revoke vault", async function () {
      await expect(vault.connect(owner).revokeVault())
        .to.emit(vault, "VaultRevoked")
        .withArgs(owner.address);

      expect(await vault.getVaultState(owner.address)).to.equal(4); // Revoked
    });

    it("should reject check-in on revoked vault", async function () {
      await vault.connect(owner).revokeVault();
      await expect(vault.connect(owner).checkIn())
        .to.be.revertedWith("Vault revoked");
    });

    it("should reject revocation by non-owner", async function () {
      await expect(vault.connect(attacker).revokeVault())
        .to.be.revertedWith("No vault found");
    });
  });

  // ═══════════════════════════════════════════════
  // CONTENT ARCHIVE
  // ═══════════════════════════════════════════════

  describe("Content Archive", function () {
    beforeEach(async function () {
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
    });

    it("should store IPFS content archive CIDs", async function () {
      const cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
      
      await expect(vault.connect(owner).addContentArchive(cid))
        .to.emit(vault, "ContentArchiveAdded")
        .withArgs(owner.address, cid);

      const archives = await vault.getContentArchives(owner.address);
      expect(archives.length).to.equal(1);
      expect(archives[0]).to.equal(cid);
    });
  });

  // ═══════════════════════════════════════════════
  // FULL FLOW — END TO END
  // ═══════════════════════════════════════════════

  describe("Full Inheritance Flow (E2E)", function () {
    it("should complete the entire inheritance process via dead man's switch", async function () {
      // 1. Create vault
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
      
      // 2. Set beneficiary
      await vault.connect(owner).setBeneficiary(beneficiary.address, beneficiaryDID);
      
      // 3. Add 5 guardians
      await vault.connect(owner).addGuardian(guardian1.address, shareHash1);
      await vault.connect(owner).addGuardian(guardian2.address, shareHash2);
      await vault.connect(owner).addGuardian(guardian3.address, shareHash3);
      await vault.connect(owner).addGuardian(guardian4.address, shareHash4);
      await vault.connect(owner).addGuardian(guardian5.address, shareHash5);
      
      // 4. Owner checks in for a while
      await time.increase(SIXTY_DAYS);
      await vault.connect(owner).checkIn();
      
      // 5. Owner stops checking in (simulating death)
      await time.increase(NINETY_DAYS + 1);
      await vault.evaluateVaultState(owner.address);
      expect(await vault.getVaultState(owner.address)).to.equal(1); // Warning
      
      // 6. Grace period expires
      await time.increase(SIXTY_DAYS + 1);
      await vault.evaluateVaultState(owner.address);
      expect(await vault.getVaultState(owner.address)).to.equal(2); // Claimable
      
      // 7. Beneficiary initiates claim
      await vault.connect(beneficiary).initiateClaim(
        owner.address,
        ethers.toUtf8Bytes("zk_proof_identity")
      );
      
      // 8. Guardians confirm share release (3 of 5 needed)
      await vault.connect(guardian2).confirmShareRelease(owner.address);
      await vault.connect(guardian4).confirmShareRelease(owner.address);
      await vault.connect(guardian5).confirmShareRelease(owner.address);
      
      // 9. Shares released, vault claimed
      expect(await vault.getVaultState(owner.address)).to.equal(3); // Claimed
      
      const [confirmed, required] = await vault.getGuardianConfirmations(owner.address);
      expect(confirmed).to.equal(3);
      expect(required).to.equal(3);
    });

    it("should complete the entire inheritance process via oracle death certificate", async function () {
      // Setup
      await vault.connect(owner).createVault(ownerDID, NINETY_DAYS, SIXTY_DAYS, 3);
      await vault.connect(owner).setBeneficiary(beneficiary.address, beneficiaryDID);
      await vault.connect(owner).addGuardian(guardian1.address, shareHash1);
      await vault.connect(owner).addGuardian(guardian2.address, shareHash2);
      await vault.connect(owner).addGuardian(guardian3.address, shareHash3);
      
      // Register death certificate in oracle
      await oracle.registerCertificate(deathCertHash, 99);
      
      // Submit death certificate (no need to wait for timer)
      await vault.connect(beneficiary).submitDeathCertificate(
        owner.address,
        deathCertHash,
        ethers.toUtf8Bytes("notarized_proof")
      );
      expect(await vault.getVaultState(owner.address)).to.equal(2); // Claimable
      
      // Claim and release
      await vault.connect(beneficiary).initiateClaim(
        owner.address,
        ethers.toUtf8Bytes("zk_proof_identity")
      );
      await vault.connect(guardian1).confirmShareRelease(owner.address);
      await vault.connect(guardian2).confirmShareRelease(owner.address);
      await vault.connect(guardian3).confirmShareRelease(owner.address);
      
      expect(await vault.getVaultState(owner.address)).to.equal(3); // Claimed
    });
  });
});
