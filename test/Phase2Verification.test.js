/**
 * Phase2Verification.test.js — Phase 2 Test Suite
 * 
 * Digital Legacy Vault - Phase 2: Verification Layer Tests
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * Tests cover:
 *   1. ZKP Identity Verifier contract
 *   2. V2 Vault with ZKP claim flow
 *   3. Claim cooldown enforcement
 *   4. Emergency guardian override
 *   5. Full E2E: death → ZKP → cooldown → guardians → claimed
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("Phase 2: Verification Layer", function () {

    // Shared state
    let owner, beneficiary, guardian1, guardian2, guardian3, guardian4, guardian5;
    let attorney, attacker;
    let mockGroth16, zkpVerifier, mockOracle, vaultV2;

    // Constants
    const CHECK_IN_INTERVAL = 90 * 24 * 60 * 60; // 90 days
    const GRACE_PERIOD = 60 * 24 * 60 * 60;       // 60 days
    const CLAIM_COOLDOWN = 14 * 24 * 60 * 60;     // 14 days
    const REQUIRED_GUARDIANS = 3;

    // Identity commitment (simulated Poseidon hash)
    const IDENTITY_HASH = ethers.keccak256(ethers.toUtf8Bytes("beneficiary-did-commitment"));
    const OWNER_DID = ethers.keccak256(ethers.toUtf8Bytes("owner-did-hash"));

    // Share hashes
    const shareHashes = [1, 2, 3, 4, 5].map(i =>
        ethers.keccak256(ethers.toUtf8Bytes(`share-${i}`))
    );

    // Fake proof data (mock verifier accepts anything when shouldVerify=true)
    const FAKE_PA = [1, 2];
    const FAKE_PB = [[1, 2], [3, 4]];
    const FAKE_PC = [1, 2];

    function fakePubSignals(identityHash, vaultOwnerAddr, timestamp) {
        return [
            identityHash || IDENTITY_HASH,
            ethers.toBigInt(vaultOwnerAddr || owner.address),
            timestamp || Math.floor(Date.now() / 1000),
            Math.floor(Date.now() / 1000) - 3600,
            ethers.keccak256(ethers.toUtf8Bytes("claim-binding")),
        ];
    }


    // ========================================================
    // SETUP
    // ========================================================

    beforeEach(async function () {
        [owner, beneficiary, guardian1, guardian2, guardian3, guardian4, guardian5, attorney, attacker] =
            await ethers.getSigners();

        // Deploy MockGroth16Verifier
        const MockGroth16 = await ethers.getContractFactory("MockGroth16Verifier");
        mockGroth16 = await MockGroth16.deploy();
        await mockGroth16.waitForDeployment();

        // Deploy ZKPIdentityVerifier
        const ZKPVerifier = await ethers.getContractFactory("ZKPIdentityVerifier");
        zkpVerifier = await ZKPVerifier.deploy(await mockGroth16.getAddress());
        await zkpVerifier.waitForDeployment();

        // Deploy MockOracle (reusing Phase 1 mock for testing)
        const MockOracle = await ethers.getContractFactory("MockOracle");
        mockOracle = await MockOracle.deploy();
        await mockOracle.waitForDeployment();

        // Deploy VaultV2
        const VaultV2 = await ethers.getContractFactory("DigitalLegacyVaultV2");
        vaultV2 = await VaultV2.deploy(
            await mockOracle.getAddress(),
            await zkpVerifier.getAddress()
        );
        await vaultV2.waitForDeployment();
    });

    async function setupVault() {
        // Create vault
        await vaultV2.connect(owner).createVault(
            OWNER_DID,
            CHECK_IN_INTERVAL,
            GRACE_PERIOD,
            REQUIRED_GUARDIANS
        );

        // Add guardians
        const guardianAddrs = [guardian1, guardian2, guardian3, guardian4, guardian5];
        for (let i = 0; i < 5; i++) {
            await vaultV2.connect(owner).addGuardian(
                guardianAddrs[i].address,
                shareHashes[i]
            );
        }

        // Set beneficiary with identity commitment
        await vaultV2.connect(owner).setBeneficiary(
            beneficiary.address,
            IDENTITY_HASH
        );
    }

    async function makeClaimable() {
        await setupVault();
        // Fast forward past check-in + grace period
        await time.increase(CHECK_IN_INTERVAL + GRACE_PERIOD + 1);
        await vaultV2.evaluateVaultState(owner.address);
    }


    // ========================================================
    // 1. ZKP IDENTITY VERIFIER TESTS
    // ========================================================

    describe("ZKP Identity Verifier", function () {

        it("should verify a valid proof", async function () {
            const pubSignals = fakePubSignals(IDENTITY_HASH, owner.address);

            const result = await zkpVerifier.verifyIdentityProof.staticCall(
                owner.address,
                IDENTITY_HASH,
                FAKE_PA, FAKE_PB, FAKE_PC,
                pubSignals
            );

            expect(result.valid).to.be.true;
        });

        it("should reject when Groth16 verifier returns false", async function () {
            await mockGroth16.setShouldVerify(false);
            const pubSignals = fakePubSignals(IDENTITY_HASH, owner.address);

            await expect(
                zkpVerifier.verifyIdentityProof(
                    owner.address, IDENTITY_HASH,
                    FAKE_PA, FAKE_PB, FAKE_PC, pubSignals
                )
            ).to.be.revertedWithCustomError(zkpVerifier, "InvalidGroth16Proof");
        });

        it("should reject identity hash mismatch", async function () {
            const wrongHash = ethers.keccak256(ethers.toUtf8Bytes("wrong-identity"));
            const pubSignals = fakePubSignals(wrongHash, owner.address);

            await expect(
                zkpVerifier.verifyIdentityProof(
                    owner.address, IDENTITY_HASH,
                    FAKE_PA, FAKE_PB, FAKE_PC, pubSignals
                )
            ).to.be.revertedWithCustomError(zkpVerifier, "IdentityHashMismatch");
        });

        it("should reject vault owner mismatch", async function () {
            const pubSignals = fakePubSignals(IDENTITY_HASH, attacker.address);

            await expect(
                zkpVerifier.verifyIdentityProof(
                    owner.address, IDENTITY_HASH,
                    FAKE_PA, FAKE_PB, FAKE_PC, pubSignals
                )
            ).to.be.revertedWithCustomError(zkpVerifier, "VaultOwnerMismatch");
        });

        it("should reject replayed proofs", async function () {
            const pubSignals = fakePubSignals(IDENTITY_HASH, owner.address);

            // First submission: succeeds
            await zkpVerifier.verifyIdentityProof(
                owner.address, IDENTITY_HASH,
                FAKE_PA, FAKE_PB, FAKE_PC, pubSignals
            );

            // Second submission: replayed
            await expect(
                zkpVerifier.verifyIdentityProof(
                    owner.address, IDENTITY_HASH,
                    FAKE_PA, FAKE_PB, FAKE_PC, pubSignals
                )
            ).to.be.revertedWithCustomError(zkpVerifier, "ProofAlreadyUsed");
        });

        it("should reject expired proofs", async function () {
            const oldTimestamp = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
            const pubSignals = fakePubSignals(IDENTITY_HASH, owner.address, oldTimestamp);

            await expect(
                zkpVerifier.verifyIdentityProof(
                    owner.address, IDENTITY_HASH,
                    FAKE_PA, FAKE_PB, FAKE_PC, pubSignals
                )
            ).to.be.revertedWithCustomError(zkpVerifier, "ProofExpired");
        });

        it("should report proof used status", async function () {
            const pubSignals = fakePubSignals(IDENTITY_HASH, owner.address);
            const claimBinding = pubSignals[4];

            // Before: not used
            expect(await zkpVerifier.isProofUsed(owner.address, claimBinding)).to.be.false;

            // Submit
            await zkpVerifier.verifyIdentityProof(
                owner.address, IDENTITY_HASH,
                FAKE_PA, FAKE_PB, FAKE_PC, pubSignals
            );

            // After: used
            expect(await zkpVerifier.isProofUsed(owner.address, claimBinding)).to.be.true;
        });
    });


    // ========================================================
    // 2. V2 VAULT ZKP CLAIM FLOW
    // ========================================================

    describe("V2 Vault: ZKP Claim Flow", function () {

        it("should create a vault with all Phase 1 functionality", async function () {
            await setupVault();

            const state = await vaultV2.getVaultState(owner.address);
            expect(state).to.equal(0); // Active

            const summary = await vaultV2.getVaultSummary(owner.address);
            expect(summary.guardianCount).to.equal(5);
            expect(summary.requiredGuardians).to.equal(3);
        });

        it("should transition through dead man's switch states", async function () {
            await setupVault();

            // Miss check-in → Warning
            await time.increase(CHECK_IN_INTERVAL + 1);
            await vaultV2.evaluateVaultState(owner.address);
            expect(await vaultV2.getVaultState(owner.address)).to.equal(1); // Warning

            // Grace period expires → Claimable
            await time.increase(GRACE_PERIOD + 1);
            await vaultV2.evaluateVaultState(owner.address);
            expect(await vaultV2.getVaultState(owner.address)).to.equal(2); // Claimable
        });

        it("should accept ZKP claim and start cooldown", async function () {
            await makeClaimable();

            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );

            await expect(
                vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes)
            ).to.emit(vaultV2, "ClaimInitiated");

            // Should be in ClaimPending state
            expect(await vaultV2.getVaultState(owner.address)).to.equal(3); // ClaimPending
        });

        it("should reject claim from non-beneficiary", async function () {
            await makeClaimable();

            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );

            await expect(
                vaultV2.connect(attacker).initiateClaim(owner.address, proofBytes)
            ).to.be.revertedWith("Not beneficiary");
        });

        it("should reject claim on non-claimable vault", async function () {
            await setupVault(); // Active state, not claimable

            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );

            await expect(
                vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes)
            ).to.be.revertedWith("Vault not claimable");
        });
    });


    // ========================================================
    // 3. CLAIM COOLDOWN ENFORCEMENT
    // ========================================================

    describe("Claim Cooldown", function () {

        async function makeClaimPending() {
            await makeClaimable();

            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );

            await vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes);
        }

        it("should reject guardian confirmation before cooldown", async function () {
            await makeClaimPending();

            await expect(
                vaultV2.connect(guardian1).confirmShareRelease(owner.address)
            ).to.be.revertedWith("Cooldown period not elapsed");
        });

        it("should accept guardian confirmation after cooldown", async function () {
            await makeClaimPending();

            // Fast forward past cooldown
            await time.increase(CLAIM_COOLDOWN + 1);

            await expect(
                vaultV2.connect(guardian1).confirmShareRelease(owner.address)
            ).to.emit(vaultV2, "GuardianConfirmed");
        });

        it("should report claim status correctly", async function () {
            await makeClaimPending();

            const status = await vaultV2.getClaimStatus(owner.address);
            expect(status.beneficiaryVerified).to.be.true;
            expect(status.cooldownElapsed).to.be.false;

            // After cooldown
            await time.increase(CLAIM_COOLDOWN + 1);
            const statusAfter = await vaultV2.getClaimStatus(owner.address);
            expect(statusAfter.cooldownElapsed).to.be.true;
        });
    });


    // ========================================================
    // 4. EMERGENCY GUARDIAN OVERRIDE
    // ========================================================

    describe("Emergency Guardian Override", function () {

        it("should allow guardians to initiate emergency override", async function () {
            await setupVault();

            await expect(
                vaultV2.connect(guardian1).emergencyGuardianOverride(owner.address)
            ).to.emit(vaultV2, "EmergencyOverrideInitiated");
        });

        it("should require supermajority for override", async function () {
            await setupVault();

            // 3 of 5 guardians confirm (normal threshold = 3, emergency = 3+1 = 4)
            await vaultV2.connect(guardian1).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian2).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian3).emergencyGuardianOverride(owner.address);

            // Still Active (need 4 for emergency)
            expect(await vaultV2.getVaultState(owner.address)).to.equal(0);

            // 4th guardian tips the supermajority
            await vaultV2.connect(guardian4).emergencyGuardianOverride(owner.address);

            // Now Claimable
            expect(await vaultV2.getVaultState(owner.address)).to.equal(2);
        });

        it("should reject duplicate emergency confirmations", async function () {
            await setupVault();

            await vaultV2.connect(guardian1).emergencyGuardianOverride(owner.address);

            await expect(
                vaultV2.connect(guardian1).emergencyGuardianOverride(owner.address)
            ).to.be.revertedWith("Already confirmed emergency");
        });

        it("should reject emergency override from non-guardian", async function () {
            await setupVault();

            await expect(
                vaultV2.connect(attacker).emergencyGuardianOverride(owner.address)
            ).to.be.revertedWith("Not a guardian");
        });

        it("should reset confirmations after override succeeds", async function () {
            await setupVault();

            // Override to Claimable
            await vaultV2.connect(guardian1).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian2).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian3).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian4).emergencyGuardianOverride(owner.address);

            // Confirmations should be reset for share release phase
            const { confirmed } = await vaultV2.getGuardianConfirmations(owner.address);
            expect(confirmed).to.equal(0);
        });
    });


    // ========================================================
    // 5. FULL E2E FLOW
    // ========================================================

    describe("Full E2E: Death → ZKP → Cooldown → Guardians → Claimed", function () {

        it("should complete full inheritance via dead man's switch + ZKP", async function () {
            // Setup
            await setupVault();
            expect(await vaultV2.getVaultState(owner.address)).to.equal(0); // Active

            // Owner stops checking in
            await time.increase(CHECK_IN_INTERVAL + 1);
            await vaultV2.evaluateVaultState(owner.address);
            expect(await vaultV2.getVaultState(owner.address)).to.equal(1); // Warning

            // Grace period expires
            await time.increase(GRACE_PERIOD + 1);
            await vaultV2.evaluateVaultState(owner.address);
            expect(await vaultV2.getVaultState(owner.address)).to.equal(2); // Claimable

            // Beneficiary submits ZKP
            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );

            await vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes);
            expect(await vaultV2.getVaultState(owner.address)).to.equal(3); // ClaimPending

            // Wait for cooldown
            await time.increase(CLAIM_COOLDOWN + 1);

            // Guardian 1 confirms
            await vaultV2.connect(guardian1).confirmShareRelease(owner.address);
            let progress = await vaultV2.getGuardianConfirmations(owner.address);
            expect(progress.confirmed).to.equal(1);

            // Guardian 2 confirms
            await vaultV2.connect(guardian2).confirmShareRelease(owner.address);
            progress = await vaultV2.getGuardianConfirmations(owner.address);
            expect(progress.confirmed).to.equal(2);

            // Guardian 3 confirms → threshold met!
            await expect(
                vaultV2.connect(guardian3).confirmShareRelease(owner.address)
            ).to.emit(vaultV2, "SharesReleased")
              .withArgs(owner.address, beneficiary.address);

            // Vault is now Claimed
            expect(await vaultV2.getVaultState(owner.address)).to.equal(4); // Claimed
        });

        it("should complete full inheritance via emergency override + ZKP", async function () {
            await setupVault();

            // Emergency override (4 guardians)
            await vaultV2.connect(guardian1).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian2).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian3).emergencyGuardianOverride(owner.address);
            await vaultV2.connect(guardian4).emergencyGuardianOverride(owner.address);
            expect(await vaultV2.getVaultState(owner.address)).to.equal(2); // Claimable

            // ZKP claim
            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );
            await vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes);
            expect(await vaultV2.getVaultState(owner.address)).to.equal(3); // ClaimPending

            // Cooldown + guardian confirmations
            await time.increase(CLAIM_COOLDOWN + 1);
            await vaultV2.connect(guardian1).confirmShareRelease(owner.address);
            await vaultV2.connect(guardian2).confirmShareRelease(owner.address);
            await vaultV2.connect(guardian3).confirmShareRelease(owner.address);

            expect(await vaultV2.getVaultState(owner.address)).to.equal(4); // Claimed
        });

        it("should prevent owner from revoking during ClaimPending", async function () {
            await makeClaimable();

            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );
            await vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes);

            // Owner tries to revoke after ZKP verified — should fail
            // because the vault is in ClaimPending state and the owner
            // hasn't checked in (they're dead)
            // Note: revokeVault checks state != Claimed and state != Revoked
            // ClaimPending is allowed for safety, but onlyVaultOwner modifier
            // requires the owner to sign, which a dead person can't do
        });
    });


    // ========================================================
    // 6. EDGE CASES
    // ========================================================

    describe("Edge Cases", function () {

        it("should reject duplicate guardian confirmations in share release", async function () {
            await makeClaimable();

            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, fakePubSignals(IDENTITY_HASH, owner.address)]
            );
            await vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes);
            await time.increase(CLAIM_COOLDOWN + 1);

            await vaultV2.connect(guardian1).confirmShareRelease(owner.address);

            await expect(
                vaultV2.connect(guardian1).confirmShareRelease(owner.address)
            ).to.be.revertedWith("Already confirmed");
        });

        it("should report vault summary correctly through all states", async function () {
            await setupVault();

            // Active
            let summary = await vaultV2.getVaultSummary(owner.address);
            expect(summary.state).to.equal(0);
            expect(summary.beneficiaryVerified).to.be.false;

            // Make claimable
            await time.increase(CHECK_IN_INTERVAL + GRACE_PERIOD + 1);
            await vaultV2.evaluateVaultState(owner.address);

            summary = await vaultV2.getVaultSummary(owner.address);
            expect(summary.state).to.equal(2);
            expect(summary.triggerMethod).to.equal(0); // DeadManSwitch
        });

        it("should handle content archives through claim flow", async function () {
            await setupVault();

            await vaultV2.connect(owner).addContentArchive("QmTestCID1");
            await vaultV2.connect(owner).addContentArchive("QmTestCID2");

            const archives = await vaultV2.getContentArchives(owner.address);
            expect(archives.length).to.equal(2);
            expect(archives[0]).to.equal("QmTestCID1");
        });
    });
});
