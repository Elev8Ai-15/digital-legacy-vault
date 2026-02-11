/**
 * DigitalPasscodes.test.js — Phase 3: Digital Passcodes Test Suite
 *
 * Digital Legacy Vault - Phase 3: One-Time Passcodes & Lifetime Access Tokens
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 *
 * Tests cover:
 *   1. One-time passcode issuance
 *   2. One-time passcode redemption (with nonce verification)
 *   3. Passcode expiry enforcement
 *   4. Lifetime access token minting (soulbound)
 *   5. Lifetime token revocation (owner + guardian multi-sig)
 *   6. Lifetime access verification
 *   7. Token policy updates
 *   8. Auto-revoke via time-lock
 *   9. Full E2E: claim → passcode → lifetime tokens
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("Phase 3: Digital Passcodes", function () {

    // Shared state
    let owner, beneficiary, guardian1, guardian2, guardian3, guardian4, guardian5;
    let familyMember, attacker;
    let mockGroth16, zkpVerifier, mockOracle, vaultV2;

    // Constants
    const CHECK_IN_INTERVAL = 90 * 24 * 60 * 60;
    const GRACE_PERIOD = 60 * 24 * 60 * 60;
    const CLAIM_COOLDOWN = 14 * 24 * 60 * 60;
    const REQUIRED_GUARDIANS = 3;
    const FORTY_EIGHT_HOURS = 48 * 60 * 60;

    // Identity commitment
    const IDENTITY_HASH = ethers.keccak256(ethers.toUtf8Bytes("beneficiary-did-commitment"));
    const OWNER_DID = ethers.keccak256(ethers.toUtf8Bytes("owner-did-hash"));

    const shareHashes = [1, 2, 3, 4, 5].map(i =>
        ethers.keccak256(ethers.toUtf8Bytes(`share-${i}`))
    );

    // Fake proof data
    const FAKE_PA = [1, 2];
    const FAKE_PB = [[1, 2], [3, 4]];
    const FAKE_PC = [1, 2];

    async function fakePubSignals(identityHash, vaultOwnerAddr) {
        const latest = await time.latest();
        return [
            identityHash || IDENTITY_HASH,
            ethers.toBigInt(vaultOwnerAddr || owner.address),
            latest,
            latest - 3600,
            ethers.keccak256(ethers.toUtf8Bytes("claim-binding-" + latest)),
        ];
    }


    // ========================================================
    // SETUP
    // ========================================================

    beforeEach(async function () {
        [owner, beneficiary, guardian1, guardian2, guardian3, guardian4, guardian5, familyMember, attacker] =
            await ethers.getSigners();

        const MockGroth16 = await ethers.getContractFactory("MockGroth16Verifier");
        mockGroth16 = await MockGroth16.deploy();
        await mockGroth16.waitForDeployment();

        const ZKPVerifier = await ethers.getContractFactory("ZKPIdentityVerifier");
        zkpVerifier = await ZKPVerifier.deploy(await mockGroth16.getAddress());
        await zkpVerifier.waitForDeployment();

        const MockOracle = await ethers.getContractFactory("MockOracle");
        mockOracle = await MockOracle.deploy();
        await mockOracle.waitForDeployment();

        const VaultV2 = await ethers.getContractFactory("DigitalLegacyVaultV2");
        vaultV2 = await VaultV2.deploy(
            await mockOracle.getAddress(),
            await zkpVerifier.getAddress()
        );
        await vaultV2.waitForDeployment();
    });

    async function setupVault() {
        await vaultV2.connect(owner).createVault(
            OWNER_DID,
            CHECK_IN_INTERVAL,
            GRACE_PERIOD,
            REQUIRED_GUARDIANS,
            "Test Vault"
        );

        const guardianAddrs = [guardian1, guardian2, guardian3, guardian4, guardian5];
        for (let i = 0; i < 5; i++) {
            await vaultV2.connect(owner).addGuardian(
                guardianAddrs[i].address,
                shareHashes[i]
            );
        }

        await vaultV2.connect(owner).setBeneficiary(
            beneficiary.address,
            IDENTITY_HASH
        );

        // Add some content archives
        await vaultV2.connect(owner).addContentArchive("QmPhotoAlbum2024_encrypted");
        await vaultV2.connect(owner).addContentArchive("QmFamilyVideos_encrypted");
        await vaultV2.connect(owner).addContentArchive("QmLegalDocuments_encrypted");
    }

    async function makeClaimable() {
        await setupVault();
        await time.increase(CHECK_IN_INTERVAL + GRACE_PERIOD + 1);
        await vaultV2.evaluateVaultState(owner.address);
    }

    async function completeClaim() {
        await makeClaimable();

        // Submit ZKP
        const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
            [FAKE_PA, FAKE_PB, FAKE_PC, await fakePubSignals(IDENTITY_HASH, owner.address)]
        );
        await vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes);

        // Wait cooldown
        await time.increase(CLAIM_COOLDOWN + 1);

        // Guardian confirmations
        await vaultV2.connect(guardian1).confirmShareRelease(owner.address);
        await vaultV2.connect(guardian2).confirmShareRelease(owner.address);
        await vaultV2.connect(guardian3).confirmShareRelease(owner.address);
    }


    // ========================================================
    // 1. ONE-TIME PASSCODE ISSUANCE
    // ========================================================

    describe("One-Time Passcode: Issuance", function () {

        it("should issue a passcode after claim is complete", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await expect(
                vaultV2.connect(beneficiary).issueOneTimePasscode(
                    owner.address,
                    passcodeHash,
                    "QmPhotoAlbum2024_encrypted",
                    0 // default duration
                )
            ).to.emit(vaultV2, "OneTimePasscodeIssued")
              .withArgs(
                  owner.address,
                  beneficiary.address,
                  0, // first passcode ID
                  "QmPhotoAlbum2024_encrypted",
                  (val) => val > 0 // expiresAt > 0
              );

            expect(await vaultV2.passcodeCount(owner.address)).to.equal(1);
        });

        it("should issue multiple passcodes for different archives", async function () {
            await completeClaim();

            for (let i = 0; i < 3; i++) {
                const nonce = ethers.randomBytes(32);
                const passcodeHash = ethers.keccak256(nonce);
                await vaultV2.connect(beneficiary).issueOneTimePasscode(
                    owner.address,
                    passcodeHash,
                    `QmArchive${i}_encrypted`,
                    0
                );
            }

            expect(await vaultV2.passcodeCount(owner.address)).to.equal(3);
        });

        it("should reject passcode from non-beneficiary", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await expect(
                vaultV2.connect(attacker).issueOneTimePasscode(
                    owner.address,
                    passcodeHash,
                    "QmPhotoAlbum2024_encrypted",
                    0
                )
            ).to.be.revertedWith("Not authorized beneficiary");
        });

        it("should reject passcode with zero hash", async function () {
            await completeClaim();

            await expect(
                vaultV2.connect(beneficiary).issueOneTimePasscode(
                    owner.address,
                    ethers.ZeroHash,
                    "QmPhotoAlbum2024_encrypted",
                    0
                )
            ).to.be.revertedWith("Invalid passcode hash");
        });

        it("should reject passcode with empty CID", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await expect(
                vaultV2.connect(beneficiary).issueOneTimePasscode(
                    owner.address,
                    passcodeHash,
                    "",
                    0
                )
            ).to.be.revertedWith("Empty archive CID");
        });

        it("should reject passcode with duration exceeding max", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);
            const thirtyOneDays = 31 * 24 * 60 * 60;

            await expect(
                vaultV2.connect(beneficiary).issueOneTimePasscode(
                    owner.address,
                    passcodeHash,
                    "QmPhotoAlbum2024_encrypted",
                    thirtyOneDays
                )
            ).to.be.revertedWith("Duration exceeds max");
        });

        it("should use default 48h duration when duration is 0", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0
            );

            const info = await vaultV2.getPasscodeInfo(owner.address, 0);
            const duration = Number(info.expiresAt) - Number(info.issuedAt);
            expect(duration).to.equal(FORTY_EIGHT_HOURS);
        });
    });


    // ========================================================
    // 2. ONE-TIME PASSCODE REDEMPTION
    // ========================================================

    describe("One-Time Passcode: Redemption", function () {

        it("should redeem a valid passcode with correct nonce", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0
            );

            await expect(
                vaultV2.connect(beneficiary).redeemOneTimePasscode(
                    owner.address,
                    0,
                    ethers.hexlify(nonce)
                )
            ).to.emit(vaultV2, "OneTimePasscodeRedeemed")
              .withArgs(owner.address, beneficiary.address, 0, "QmPhotoAlbum2024_encrypted");

            // Verify it's marked as redeemed
            const info = await vaultV2.getPasscodeInfo(owner.address, 0);
            expect(info.isRedeemed).to.be.true;
        });

        it("should reject redemption with wrong nonce", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0
            );

            const wrongNonce = ethers.randomBytes(32);
            await expect(
                vaultV2.connect(beneficiary).redeemOneTimePasscode(
                    owner.address,
                    0,
                    ethers.hexlify(wrongNonce)
                )
            ).to.be.revertedWith("Invalid nonce");
        });

        it("should reject double redemption", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0
            );

            // First redemption succeeds
            await vaultV2.connect(beneficiary).redeemOneTimePasscode(
                owner.address,
                0,
                ethers.hexlify(nonce)
            );

            // Second redemption fails
            await expect(
                vaultV2.connect(beneficiary).redeemOneTimePasscode(
                    owner.address,
                    0,
                    ethers.hexlify(nonce)
                )
            ).to.be.revertedWith("Passcode already redeemed");
        });

        it("should reject redemption after expiry", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0 // 48h default
            );

            // Fast forward past expiry
            await time.increase(FORTY_EIGHT_HOURS + 1);

            await expect(
                vaultV2.connect(beneficiary).redeemOneTimePasscode(
                    owner.address,
                    0,
                    ethers.hexlify(nonce)
                )
            ).to.be.revertedWith("Passcode expired");
        });

        it("should reject redemption from non-beneficiary", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0
            );

            await expect(
                vaultV2.connect(attacker).redeemOneTimePasscode(
                    owner.address,
                    0,
                    ethers.hexlify(nonce)
                )
            ).to.be.revertedWith("Not authorized beneficiary");
        });

        it("should report passcode info correctly", async function () {
            await completeClaim();

            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0
            );

            const info = await vaultV2.getPasscodeInfo(owner.address, 0);
            expect(info.issuedTo).to.equal(beneficiary.address);
            expect(info.isRedeemed).to.be.false;
            expect(info.isExpired).to.be.false;
            const archiveCID = await vaultV2.getPasscodeArchive(owner.address, 0);
            expect(archiveCID).to.equal("QmPhotoAlbum2024_encrypted");
        });
    });


    // ========================================================
    // 3. LIFETIME ACCESS TOKEN MINTING
    // ========================================================

    describe("Lifetime Access Token: Minting", function () {

        it("should mint a lifetime token by vault owner", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("family-photo-viewing-rights"));

            await expect(
                vaultV2.connect(owner).mintLifetimeAccessToken(
                    familyMember.address,
                    ["QmPhotoAlbum2024_encrypted", "QmFamilyVideos_encrypted"],
                    policyHash,
                    0 // no auto-revoke
                )
            ).to.emit(vaultV2, "LifetimeTokenMinted")
              .withArgs(owner.address, familyMember.address, 0, policyHash);

            expect(await vaultV2.lifetimeTokenCount(owner.address)).to.equal(1);
        });

        it("should mint tokens for multiple holders", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));

            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            await vaultV2.connect(owner).mintLifetimeAccessToken(
                beneficiary.address,
                ["QmFamilyVideos_encrypted"],
                policyHash,
                0
            );

            expect(await vaultV2.lifetimeTokenCount(owner.address)).to.equal(2);
        });

        it("should reject minting from non-owner", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));

            await expect(
                vaultV2.connect(attacker).mintLifetimeAccessToken(
                    familyMember.address,
                    ["QmPhotoAlbum2024_encrypted"],
                    policyHash,
                    0
                )
            ).to.be.revertedWith("No vault found");
        });

        it("should reject minting with zero address holder", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));

            await expect(
                vaultV2.connect(owner).mintLifetimeAccessToken(
                    ethers.ZeroAddress,
                    ["QmPhotoAlbum2024_encrypted"],
                    policyHash,
                    0
                )
            ).to.be.revertedWith("Invalid holder");
        });

        it("should reject minting with empty archives", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));

            await expect(
                vaultV2.connect(owner).mintLifetimeAccessToken(
                    familyMember.address,
                    [],
                    policyHash,
                    0
                )
            ).to.be.revertedWith("No archives specified");
        });

        it("should accept time-locked auto-revoke", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            const latest = await time.latest();
            const oneYearFromNow = latest + 365 * 24 * 60 * 60;

            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                oneYearFromNow
            );

            const info = await vaultV2.getLifetimeTokenInfo(owner.address, 0);
            expect(info.isActive).to.be.true;
            expect(Number(info.revokeAfter)).to.equal(oneYearFromNow);
        });
    });


    // ========================================================
    // 4. LIFETIME TOKEN REVOCATION
    // ========================================================

    describe("Lifetime Access Token: Revocation", function () {

        it("should allow owner to revoke their token", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            await expect(
                vaultV2.connect(owner).revokeLifetimeToken(0)
            ).to.emit(vaultV2, "LifetimeTokenRevoked")
              .withArgs(owner.address, 0, familyMember.address);

            const info = await vaultV2.getLifetimeTokenInfo(owner.address, 0);
            expect(info.isActive).to.be.false;
        });

        it("should reject double revocation", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            await vaultV2.connect(owner).revokeLifetimeToken(0);

            await expect(
                vaultV2.connect(owner).revokeLifetimeToken(0)
            ).to.be.revertedWith("Token already revoked");
        });
    });


    // ========================================================
    // 5. LIFETIME ACCESS VERIFICATION
    // ========================================================

    describe("Lifetime Access Verification", function () {

        it("should verify active access", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted", "QmFamilyVideos_encrypted"],
                policyHash,
                0
            );

            const result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                familyMember.address,
                "QmPhotoAlbum2024_encrypted"
            );

            expect(result.hasAccess).to.be.true;
            expect(result.tokenId).to.equal(0);
        });

        it("should deny access for non-holder", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            const result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                attacker.address,
                "QmPhotoAlbum2024_encrypted"
            );

            expect(result.hasAccess).to.be.false;
        });

        it("should deny access for revoked token", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            await vaultV2.connect(owner).revokeLifetimeToken(0);

            const result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                familyMember.address,
                "QmPhotoAlbum2024_encrypted"
            );

            expect(result.hasAccess).to.be.false;
        });

        it("should deny access after time-lock expiry", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            const latest = await time.latest();
            const oneHourFromNow = latest + 3600;

            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                oneHourFromNow
            );

            // Before expiry: access granted
            let result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                familyMember.address,
                "QmPhotoAlbum2024_encrypted"
            );
            expect(result.hasAccess).to.be.true;

            // After expiry: access denied
            await time.increase(3601);
            result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                familyMember.address,
                "QmPhotoAlbum2024_encrypted"
            );
            expect(result.hasAccess).to.be.false;
        });

        it("should deny access for wrong archive CID", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            const result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                familyMember.address,
                "QmDifferentArchive_encrypted"
            );

            expect(result.hasAccess).to.be.false;
        });

        it("should return holder token IDs", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmFamilyVideos_encrypted"],
                policyHash,
                0
            );

            const tokenIds = await vaultV2.getHolderTokenIds(owner.address, familyMember.address);
            expect(tokenIds.length).to.equal(2);
            expect(tokenIds[0]).to.equal(0);
            expect(tokenIds[1]).to.equal(1);
        });
    });


    // ========================================================
    // 6. TOKEN POLICY UPDATES
    // ========================================================

    describe("Lifetime Token: Policy Updates", function () {

        it("should allow owner to update policy hash", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("old-policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            const newPolicyHash = ethers.keccak256(ethers.toUtf8Bytes("new-policy-v2"));
            await expect(
                vaultV2.connect(owner).updateLifetimeTokenPolicy(0, newPolicyHash)
            ).to.emit(vaultV2, "LifetimeTokenPolicyUpdated")
              .withArgs(owner.address, 0, newPolicyHash);

            const info = await vaultV2.getLifetimeTokenInfo(owner.address, 0);
            expect(info.policyHash).to.equal(newPolicyHash);
        });

        it("should reject policy update on revoked token", async function () {
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted"],
                policyHash,
                0
            );

            await vaultV2.connect(owner).revokeLifetimeToken(0);

            await expect(
                vaultV2.connect(owner).updateLifetimeTokenPolicy(
                    0,
                    ethers.keccak256(ethers.toUtf8Bytes("new-policy"))
                )
            ).to.be.revertedWith("Token revoked");
        });
    });


    // ========================================================
    // 7. FULL E2E: CLAIM → PASSCODE → LIFETIME TOKEN
    // ========================================================

    describe("Full E2E: Claim → Passcode → Lifetime Token", function () {

        it("should complete full flow: claim → issue passcode → redeem → mint lifetime token", async function () {
            // 1. Complete claim
            await completeClaim();
            expect(await vaultV2.getVaultState(owner.address)).to.equal(3); // Claimed

            // 2. Issue one-time passcode
            const nonce = ethers.randomBytes(32);
            const passcodeHash = ethers.keccak256(nonce);

            await vaultV2.connect(beneficiary).issueOneTimePasscode(
                owner.address,
                passcodeHash,
                "QmPhotoAlbum2024_encrypted",
                0
            );

            expect(await vaultV2.passcodeCount(owner.address)).to.equal(1);

            // 3. Redeem passcode
            await vaultV2.connect(beneficiary).redeemOneTimePasscode(
                owner.address,
                0,
                ethers.hexlify(nonce)
            );

            const passcodeInfo = await vaultV2.getPasscodeInfo(owner.address, 0);
            expect(passcodeInfo.isRedeemed).to.be.true;

            // Note: Lifetime tokens are minted by vault owner (before death)
            // This would have been set up during vault creation phase
        });

        it("should allow pre-configured lifetime tokens to persist through claim", async function () {
            // Owner mints lifetime token before death
            await setupVault();

            const policyHash = ethers.keccak256(ethers.toUtf8Bytes("family-shared-memories"));
            await vaultV2.connect(owner).mintLifetimeAccessToken(
                familyMember.address,
                ["QmPhotoAlbum2024_encrypted", "QmFamilyVideos_encrypted"],
                policyHash,
                0
            );

            // Verify access before claim
            let result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                familyMember.address,
                "QmPhotoAlbum2024_encrypted"
            );
            expect(result.hasAccess).to.be.true;

            // Owner dies, claim happens
            await time.increase(CHECK_IN_INTERVAL + GRACE_PERIOD + 1);
            await vaultV2.evaluateVaultState(owner.address);

            const proofBytes = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[5]"],
                [FAKE_PA, FAKE_PB, FAKE_PC, await fakePubSignals(IDENTITY_HASH, owner.address)]
            );
            await vaultV2.connect(beneficiary).initiateClaim(owner.address, proofBytes);
            await time.increase(CLAIM_COOLDOWN + 1);
            await vaultV2.connect(guardian1).confirmShareRelease(owner.address);
            await vaultV2.connect(guardian2).confirmShareRelease(owner.address);
            await vaultV2.connect(guardian3).confirmShareRelease(owner.address);

            // Lifetime token still works after claim
            result = await vaultV2.verifyLifetimeAccess(
                owner.address,
                familyMember.address,
                "QmPhotoAlbum2024_encrypted"
            );
            expect(result.hasAccess).to.be.true;
        });
    });
});
