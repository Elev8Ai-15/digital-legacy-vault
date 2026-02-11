/**
 * claim-flow.js — Beneficiary Claim Orchestrator
 * 
 * Digital Legacy Vault - Phase 2: Full Claim Pipeline
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * This is the MASTER ORCHESTRATOR for the entire inheritance claim flow.
 * It coordinates between:
 *   - Death certificate verification (oracle)
 *   - ZKP identity proof generation
 *   - Smart contract claim submission
 *   - Guardian notification and confirmation tracking
 *   - SSS share collection and credential reconstruction
 * 
 * FLOW:
 *   Phase A: Death Verification
 *     1. Beneficiary submits death certificate → oracle
 *     2. (Optional) Attorney submits notarized attestation
 *     3. Wait for oracle verification (95%+ confidence)
 *     4. Vault transitions to Claimable
 * 
 *   Phase B: Identity Proof
 *     5. Beneficiary generates ZKP identity proof (client-side)
 *     6. Proof submitted to vault contract
 *     7. Vault transitions to ClaimPending
 *     8. Cooldown period starts (14 days default)
 * 
 *   Phase C: Guardian Confirmation
 *     9. Guardians notified (off-chain via backend)
 *     10. Each guardian reviews and confirms share release on-chain
 *     11. When threshold met (e.g., 3 of 5), vault transitions to Claimed
 * 
 *   Phase D: Share Reconstruction
 *     12. Beneficiary collects SSS shares from guardians (off-chain)
 *     13. Shares reconstructed client-side → decrypted credentials
 *     14. Credentials available ONLY on beneficiary's device
 * 
 * DEPENDENCIES:
 *   - proof-generator.js (ZKP)
 *   - death-cert-manager.js (oracle)
 *   - vault-client.js (Phase 1 blockchain client)
 *   - vault-crypto.js (Phase 1 SSS + AES)
 */

import { ethers } from 'ethers';
import { generateIdentityProof, verifyProofLocally, encodeProofBytes } from '../zkp/proof-generator.js';
import { DeathCertificateManager } from './death-cert-manager.js';


// ============================================================
// CLAIM STATES
// ============================================================

const ClaimPhase = {
    NOT_STARTED: 'not_started',
    DEATH_VERIFICATION: 'death_verification',
    DEATH_VERIFIED: 'death_verified',
    GENERATING_PROOF: 'generating_proof',
    PROOF_SUBMITTED: 'proof_submitted',
    COOLDOWN: 'cooldown',
    AWAITING_GUARDIANS: 'awaiting_guardians',
    SHARES_RELEASED: 'shares_released',
    COLLECTING_SHARES: 'collecting_shares',
    RECONSTRUCTING: 'reconstructing',
    COMPLETE: 'complete',
    FAILED: 'failed',
    // Phase 3: Digital Passcodes
    ISSUING_PASSCODE: 'issuing_passcode',
    PASSCODE_ISSUED: 'passcode_issued',
    REDEEMING_PASSCODE: 'redeeming_passcode',
    PASSCODE_REDEEMED: 'passcode_redeemed',
};


// ============================================================
// VAULT V2 ABI FRAGMENTS
// ============================================================

const VAULT_V2_ABI = [
    // State reads
    'function getVaultState(address owner) view returns (uint8)',
    'function getClaimStatus(address owner) view returns (bool beneficiaryVerified, bytes32 claimBinding, uint256 claimInitiatedAt, uint256 cooldownEnds, bool cooldownElapsed)',
    'function getGuardianConfirmations(address owner) view returns (uint8 confirmed, uint8 required)',
    'function getVaultSummary(address owner) view returns (uint8 state, uint256 lastCheckIn, uint256 checkInInterval, uint256 gracePeriod, uint8 guardianCount, uint8 requiredGuardians, string vaultName, uint8 platformCount, bool zkpActive)',
    'function getContentArchives(address owner) view returns (string[])',

    // Claim actions
    'function initiateClaim(address vaultOwner, bytes zkProof) external',
    'function confirmShareRelease(address vaultOwner) external',
    'function submitDeathCertificate(address vaultOwner, bytes32 certificateHash, bytes proof) external',

    // Phase 3: Digital Passcodes
    'function issueOneTimePasscode(address vaultOwner, bytes32 passcodeHash, string archiveCID, uint256 duration) external returns (uint256 passcodeId)',
    'function redeemOneTimePasscode(address vaultOwner, uint256 passcodeId, bytes32 nonce) external returns (string)',
    'function getPasscodeInfo(address vaultOwner, uint256 passcodeId) view returns (address issuedTo, uint256 issuedAt, uint256 expiresAt, bool isRedeemed, bool isExpired)',
    'function getPasscodeArchive(address vaultOwner, uint256 passcodeId) view returns (string)',
    'function passcodeCount(address) view returns (uint256)',
    'function verifyLifetimeAccess(address vaultOwner, address holder, string archiveCID) view returns (bool hasAccess, uint256 tokenId)',
    'function getLifetimeTokenInfo(address vaultOwner, uint256 tokenId) view returns (address holder, uint256 issuedAt, bool isActive, uint256 revokeAfter, bytes32 policyHash)',
    'function getLifetimeTokenArchives(address vaultOwner, uint256 tokenId) view returns (string[])',
    'function isLifetimeTokenExpired(address vaultOwner, uint256 tokenId) view returns (bool)',
    'function getHolderTokenIds(address vaultOwner, address holder) view returns (uint256[])',
    'function lifetimeTokenCount(address) view returns (uint256)',

    // Events
    'event ZKPVerificationResult(address indexed beneficiary, bool success)',
    'event ClaimInitiated(address indexed owner, address indexed beneficiary, uint8 method)',
    'event ClaimNonceIncremented(address indexed owner, uint256 newNonce)',
    'event GuardianConfirmed(address indexed owner, address indexed guardian)',
    'event SharesReleased(address indexed owner, address indexed beneficiary)',
    'event StateChanged(address indexed owner, uint8 oldState, uint8 newState)',
    'event OneTimePasscodeIssued(address indexed vaultOwner, address indexed beneficiary, uint256 passcodeId, string archiveCID, uint256 expiresAt)',
    'event OneTimePasscodeRedeemed(address indexed vaultOwner, address indexed beneficiary, uint256 passcodeId, string archiveCID)',
    'event LifetimeTokenMinted(address indexed vaultOwner, address indexed holder, uint256 tokenId, bytes32 policyHash)',
    'event LifetimeTokenRevoked(address indexed vaultOwner, uint256 tokenId, address indexed holder)',
];


// ============================================================
// CLAIM FLOW MANAGER
// ============================================================

class ClaimFlowManager {

    /**
     * @param {Object} config
     * @param {ethers.Signer} config.signer        - Beneficiary's connected wallet
     * @param {string} config.vaultAddress          - DigitalLegacyVaultV2 contract
     * @param {string} config.oracleAddress         - ChainlinkDeathOracle contract
     * @param {string} config.vaultOwner            - Address of the deceased
     * @param {Object} config.zkpArtifacts          - Paths to circuit artifacts
     * @param {string} config.zkpArtifacts.wasmPath - identity_proof.wasm
     * @param {string} config.zkpArtifacts.zkeyPath - identity_proof_final.zkey
     * @param {string} config.zkpArtifacts.vkeyPath - verification_key.json
     */
    constructor(config) {
        this.signer = config.signer;
        this.vaultOwner = config.vaultOwner;
        this.zkpArtifacts = config.zkpArtifacts;

        // Contracts
        this.vault = new ethers.Contract(config.vaultAddress, VAULT_V2_ABI, config.signer);

        // Sub-managers
        this.deathCertMgr = new DeathCertificateManager({
            signer: config.signer,
            oracleAddress: config.oracleAddress,
            vaultAddress: config.vaultAddress,
        });

        // State
        this.phase = ClaimPhase.NOT_STARTED;
        this.claimData = {
            certHash: null,
            proof: null,
            claimBinding: null,
            guardianConfirmations: 0,
            requiredConfirmations: 0,
            shares: [],
            reconstructedCredentials: null,
        };

        // Callbacks
        this._listeners = {};
    }


    // --------------------------------------------------------
    // PHASE A: DEATH VERIFICATION
    // --------------------------------------------------------

    /**
     * Submit death certificate and wait for oracle verification.
     * 
     * @param {Object} params
     * @param {File|ArrayBuffer} params.document - Death certificate
     * @param {Object} params.metadata - Certificate details
     * @returns {Promise<{verified: boolean, confidence: number}>}
     */
    async submitDeathCertificate({ document, metadata }) {
        this._setPhase(ClaimPhase.DEATH_VERIFICATION);

        try {
            // Forward status events
            this.deathCertMgr.on('status', (data) => this._emit('status', data));

            // Run the death cert pipeline
            const result = await this.deathCertMgr.runFullPipeline({
                vaultOwner: this.vaultOwner,
                document,
                metadata,
            });

            if (result.verified) {
                this.claimData.certHash = result.certHash;
                this._setPhase(ClaimPhase.DEATH_VERIFIED);
            } else {
                this._emit('status', {
                    phase: 'insufficient_verification',
                    message: result.suggestion,
                    confidence: result.confidence,
                });
            }

            return result;
        } catch (error) {
            this._setPhase(ClaimPhase.FAILED);
            this._emit('error', { phase: 'death_verification', error });
            throw error;
        }
    }

    /**
     * Submit attorney attestation for additional confidence.
     */
    async submitAttestation({ attestationDocument, attestorDIDHash }) {
        return this.deathCertMgr.submitAttestation({
            vaultOwner: this.vaultOwner,
            attestationDocument,
            attestorDIDHash,
        });
    }


    // --------------------------------------------------------
    // PHASE B: ZKP IDENTITY PROOF
    // --------------------------------------------------------

    /**
     * Generate and submit ZKP identity proof.
     * 
     * @param {Object} params
     * @param {string} params.didString - Beneficiary's DID
     * @param {string} params.nonce - Blinding nonce from vault setup
     * @param {string} params.identityHash - On-chain identity commitment
     * 
     * @returns {Promise<{txHash: string, claimBinding: string}>}
     */
    async submitIdentityProof({ didString, nonce, identityHash }) {
        this._setPhase(ClaimPhase.GENERATING_PROOF);

        try {
            // Get current block timestamp for the proof
            const provider = this.signer.provider;
            const block = await provider.getBlock('latest');
            const claimTimestamp = block.timestamp;
            const minTimestamp = claimTimestamp - 3600; // 1 hour ago

            // Convert vault owner address to uint256
            const vaultOwnerUint = BigInt(this.vaultOwner);

            this._emit('status', {
                phase: 'generating',
                message: 'Generating zero-knowledge proof... (this may take 10-30 seconds)',
            });

            // Generate the ZKP
            const proofResult = await generateIdentityProof({
                didString,
                nonce,
                identityHash,
                vaultOwner: vaultOwnerUint.toString(),
                claimTimestamp,
                minTimestamp,
                wasmPath: this.zkpArtifacts.wasmPath,
                zkeyPath: this.zkpArtifacts.zkeyPath,
            });

            this._emit('status', {
                phase: 'proof_generated',
                message: `Proof generated in ${proofResult.proofTimeSeconds}s. Verifying locally...`,
            });

            // Verify locally before submitting
            const localValid = await verifyProofLocally(
                proofResult.proof,
                proofResult.publicSignals,
                this.zkpArtifacts.vkeyPath
            );

            if (!localValid) {
                throw new Error('Proof failed local verification — this should not happen');
            }

            // Encode proof for contract
            const proofBytes = encodeProofBytes(proofResult.calldata);

            this._emit('status', {
                phase: 'submitting_proof',
                message: 'Submitting proof to smart contract...',
            });

            // Submit to vault contract
            const tx = await this.vault.initiateClaim(this.vaultOwner, proofBytes);
            console.log('[ClaimFlow] ZKP submission tx:', tx.hash);
            const receipt = await tx.wait();

            // Extract claim binding from ClaimInitiated event
            const claimEvent = receipt.logs.find(log => {
                try {
                    return this.vault.interface.parseLog(log)?.name === 'ClaimInitiated';
                } catch { return false; }
            });

            // Retrieve claim binding from on-chain state
            const claimStatus = await this.vault.getClaimStatus(this.vaultOwner);
            const claimBinding = claimStatus.claimBinding || null;

            this.claimData.proof = proofResult;
            this.claimData.claimBinding = claimBinding;

            this._setPhase(ClaimPhase.PROOF_SUBMITTED);
            this._setPhase(ClaimPhase.COOLDOWN);

            // Get cooldown end time
            const claimStatus = await this.vault.getClaimStatus(this.vaultOwner);
            const cooldownEnds = new Date(Number(claimStatus.cooldownEnds) * 1000);

            this._emit('status', {
                phase: 'cooldown_started',
                message: `Cooldown period started. Guardians can confirm after ${cooldownEnds.toLocaleString()}`,
                cooldownEnds: cooldownEnds.toISOString(),
            });

            return { txHash: tx.hash, claimBinding, cooldownEnds };
        } catch (error) {
            this._setPhase(ClaimPhase.FAILED);
            this._emit('error', { phase: 'identity_proof', error });
            throw error;
        }
    }


    // --------------------------------------------------------
    // PHASE C: GUARDIAN CONFIRMATION TRACKING
    // --------------------------------------------------------

    /**
     * Get current guardian confirmation progress.
     * 
     * @returns {Promise<{confirmed: number, required: number, complete: boolean}>}
     */
    async getGuardianProgress() {
        const { confirmed, required } = await this.vault.getGuardianConfirmations(this.vaultOwner);
        const c = Number(confirmed);
        const r = Number(required);

        this.claimData.guardianConfirmations = c;
        this.claimData.requiredConfirmations = r;

        return { confirmed: c, required: r, complete: c >= r };
    }

    /**
     * Monitor guardian confirmations in real-time.
     * 
     * @param {Function} callback - Called each time a guardian confirms
     * @returns {Function} Unsubscribe function
     */
    watchGuardianConfirmations(callback) {
        const filter = this.vault.filters.GuardianConfirmed(this.vaultOwner);

        const handler = async (owner, guardian) => {
            const progress = await this.getGuardianProgress();
            callback({
                guardian,
                ...progress,
            });

            if (progress.complete) {
                this._setPhase(ClaimPhase.SHARES_RELEASED);
                this._emit('status', {
                    phase: 'shares_released',
                    message: 'Guardian threshold met! Shares have been released.',
                });
            }
        };

        this.vault.on(filter, handler);

        // Return unsubscribe function
        return () => this.vault.off(filter, handler);
    }

    /**
     * Wait for cooldown period to elapse.
     * 
     * @returns {Promise<boolean>} True when cooldown is over
     */
    async waitForCooldown() {
        const claimStatus = await this.vault.getClaimStatus(this.vaultOwner);

        if (claimStatus.cooldownElapsed) {
            this._setPhase(ClaimPhase.AWAITING_GUARDIANS);
            return true;
        }

        const cooldownEnds = Number(claimStatus.cooldownEnds);
        const now = Math.floor(Date.now() / 1000);
        const waitMs = (cooldownEnds - now) * 1000;

        if (waitMs > 0) {
            this._emit('status', {
                phase: 'waiting_cooldown',
                message: `Cooldown ends in ${Math.ceil(waitMs / 86400000)} days`,
                cooldownEnds: new Date(cooldownEnds * 1000).toISOString(),
            });
        }

        return false;
    }


    // --------------------------------------------------------
    // PHASE D: SHARE COLLECTION & RECONSTRUCTION
    // --------------------------------------------------------

    /**
     * Collect a SSS share from a guardian.
     * 
     * In production, shares are transmitted via encrypted channels
     * (e.g., end-to-end encrypted messaging, in-person exchange,
     * or attorney-mediated transfer).
     * 
     * The share is stored in memory only — NEVER persisted.
     * 
     * @param {Object} share - SSS share object { index, data }
     */
    addShare(share) {
        if (!share || !share.data) {
            throw new Error('Invalid share format');
        }

        // Check for duplicates
        const existing = this.claimData.shares.find(s => s.index === share.index);
        if (existing) {
            throw new Error(`Share #${share.index} already collected`);
        }

        this.claimData.shares.push(share);

        this._emit('status', {
            phase: 'share_collected',
            message: `Share #${share.index} collected (${this.claimData.shares.length} total)`,
            sharesCollected: this.claimData.shares.length,
        });
    }

    /**
     * Reconstruct credentials from collected shares.
     * 
     * This calls the Phase 1 Shamir reconstruction + AES decryption.
     * EVERYTHING happens client-side.
     * 
     * @param {Function} reconstructFn - Phase 1 reconstructAndDecrypt function
     * @param {string} masterPassword - Beneficiary's master password (from nonce/share)
     * 
     * @returns {Promise<Object>} Decrypted credentials
     */
    async reconstructCredentials(reconstructFn, masterPassword) {
        this._setPhase(ClaimPhase.RECONSTRUCTING);

        try {
            const shares = this.claimData.shares.map(s => s.data);

            this._emit('status', {
                phase: 'reconstructing',
                message: 'Reconstructing credentials from shares...',
            });

            const credentials = await reconstructFn(shares, masterPassword);

            this.claimData.reconstructedCredentials = credentials;
            this._setPhase(ClaimPhase.COMPLETE);

            this._emit('status', {
                phase: 'complete',
                message: 'Credentials reconstructed successfully. Available on your device only.',
            });

            return credentials;
        } catch (error) {
            this._setPhase(ClaimPhase.FAILED);
            this._emit('error', { phase: 'reconstruction', error });
            throw error;
        }
    }


    // --------------------------------------------------------
    // PHASE 3: DIGITAL PASSCODES
    // --------------------------------------------------------

    /**
     * Issue a one-time passcode for a specific IPFS archive.
     * Generates a random nonce client-side, hashes it, and submits
     * the hash on-chain. The nonce is returned for the beneficiary
     * to redeem later (wallet-signed).
     *
     * @param {Object} params
     * @param {string} params.archiveCID - IPFS CID to unlock
     * @param {number} [params.duration] - Passcode validity in seconds (0 = default 48h)
     * @returns {Promise<{passcodeId: number, nonce: string, expiresAt: Date, txHash: string}>}
     */
    async issueOneTimePasscode({ archiveCID, duration = 0 }) {
        this._setPhase(ClaimPhase.ISSUING_PASSCODE);

        try {
            // Generate random nonce client-side (32 bytes)
            const nonceBytes = ethers.randomBytes(32);
            const nonce = ethers.hexlify(nonceBytes);
            const passcodeHash = ethers.keccak256(nonceBytes);

            this._emit('status', {
                phase: 'issuing_passcode',
                message: `Issuing one-time passcode for archive ${archiveCID.slice(0, 12)}...`,
            });

            const tx = await this.vault.issueOneTimePasscode(
                this.vaultOwner,
                passcodeHash,
                archiveCID,
                duration
            );
            const receipt = await tx.wait();

            // Extract passcode ID from event
            const event = receipt.logs.find(log => {
                try {
                    return this.vault.interface.parseLog(log)?.name === 'OneTimePasscodeIssued';
                } catch { return false; }
            });

            const parsedEvent = event ? this.vault.interface.parseLog(event) : null;
            const passcodeId = parsedEvent ? Number(parsedEvent.args.passcodeId) : null;
            const expiresAt = parsedEvent
                ? new Date(Number(parsedEvent.args.expiresAt) * 1000)
                : null;

            this._setPhase(ClaimPhase.PASSCODE_ISSUED);

            this._emit('status', {
                phase: 'passcode_issued',
                message: `Passcode #${passcodeId} issued. Expires: ${expiresAt?.toLocaleString()}`,
                passcodeId,
                nonce,
                expiresAt: expiresAt?.toISOString(),
            });

            return { passcodeId, nonce, expiresAt, txHash: tx.hash };
        } catch (error) {
            this._emit('error', { phase: 'issuing_passcode', error });
            throw error;
        }
    }

    /**
     * Redeem a one-time passcode using the nonce.
     * The beneficiary provides the nonce (preimage of the on-chain hash)
     * to prove they hold the passcode.
     *
     * @param {Object} params
     * @param {number} params.passcodeId - The passcode to redeem
     * @param {string} params.nonce      - The original nonce (hex string)
     * @returns {Promise<{archiveCID: string, txHash: string}>}
     */
    async redeemOneTimePasscode({ passcodeId, nonce }) {
        this._setPhase(ClaimPhase.REDEEMING_PASSCODE);

        try {
            this._emit('status', {
                phase: 'redeeming_passcode',
                message: `Redeeming passcode #${passcodeId}...`,
            });

            // Sign the redemption message with beneficiary wallet
            const redemptionMessage = ethers.solidityPackedKeccak256(
                ['address', 'uint256', 'bytes32'],
                [this.vaultOwner, passcodeId, nonce]
            );
            const walletSignature = await this.signer.signMessage(
                ethers.getBytes(redemptionMessage)
            );

            this._emit('status', {
                phase: 'wallet_signed',
                message: 'Wallet signature obtained. Submitting redemption...',
                signature: walletSignature.slice(0, 20) + '...',
            });

            const tx = await this.vault.redeemOneTimePasscode(
                this.vaultOwner,
                passcodeId,
                nonce
            );
            const receipt = await tx.wait();

            // Extract archive CID from event
            const event = receipt.logs.find(log => {
                try {
                    return this.vault.interface.parseLog(log)?.name === 'OneTimePasscodeRedeemed';
                } catch { return false; }
            });

            const parsedEvent = event ? this.vault.interface.parseLog(event) : null;
            const archiveCID = parsedEvent ? parsedEvent.args.archiveCID : null;

            this._setPhase(ClaimPhase.PASSCODE_REDEEMED);

            this._emit('status', {
                phase: 'passcode_redeemed',
                message: `Passcode #${passcodeId} redeemed. Archive: ${archiveCID}`,
                archiveCID,
            });

            return { archiveCID, txHash: tx.hash };
        } catch (error) {
            this._emit('error', { phase: 'redeeming_passcode', error });
            throw error;
        }
    }

    /**
     * Get information about a specific passcode.
     *
     * @param {number} passcodeId
     * @returns {Promise<Object>}
     */
    async getPasscodeInfo(passcodeId) {
        const [info, archiveCID] = await Promise.all([
            this.vault.getPasscodeInfo(this.vaultOwner, passcodeId),
            this.vault.getPasscodeArchive(this.vaultOwner, passcodeId),
        ]);
        return {
            issuedTo: info.issuedTo,
            issuedAt: new Date(Number(info.issuedAt) * 1000),
            expiresAt: new Date(Number(info.expiresAt) * 1000),
            isRedeemed: info.isRedeemed,
            isExpired: info.isExpired,
            archiveCID,
        };
    }

    /**
     * Get all passcodes issued for this vault.
     *
     * @returns {Promise<Object[]>}
     */
    async getAllPasscodes() {
        const count = Number(await this.vault.passcodeCount(this.vaultOwner));
        const results = [];
        for (let i = 0; i < count; i++) {
            results.push(await this.getPasscodeInfo(i));
        }
        return results;
    }

    /**
     * Verify if a holder has lifetime access to a specific archive.
     *
     * @param {string} holderAddress
     * @param {string} archiveCID
     * @returns {Promise<{hasAccess: boolean, tokenId: number}>}
     */
    async verifyLifetimeAccess(holderAddress, archiveCID) {
        const result = await this.vault.verifyLifetimeAccess(
            this.vaultOwner,
            holderAddress,
            archiveCID
        );
        return {
            hasAccess: result.hasAccess,
            tokenId: Number(result.tokenId),
        };
    }

    /**
     * Get all lifetime access tokens for a specific holder under this vault.
     *
     * @param {string} holderAddress
     * @returns {Promise<Object[]>}
     */
    async getHolderLifetimeTokens(holderAddress) {
        const tokenIds = await this.vault.getHolderTokenIds(this.vaultOwner, holderAddress);
        const tokens = [];
        for (const id of tokenIds) {
            const tid = Number(id);
            const [info, archives, isExpired] = await Promise.all([
                this.vault.getLifetimeTokenInfo(this.vaultOwner, tid),
                this.vault.getLifetimeTokenArchives(this.vaultOwner, tid),
                this.vault.isLifetimeTokenExpired(this.vaultOwner, tid),
            ]);
            tokens.push({
                tokenId: tid,
                holder: info.holder,
                issuedAt: new Date(Number(info.issuedAt) * 1000),
                isActive: info.isActive,
                isExpired,
                revokeAfter: Number(info.revokeAfter) > 0
                    ? new Date(Number(info.revokeAfter) * 1000)
                    : null,
                policyHash: info.policyHash,
                archiveCIDs: archives,
            });
        }
        return tokens;
    }


    // --------------------------------------------------------
    // COMPREHENSIVE STATUS
    // --------------------------------------------------------

    /**
     * Get the full claim status from the blockchain.
     * 
     * @returns {Promise<Object>} Complete claim state
     */
    async getFullStatus() {
        const [vaultSummary, claimStatus, guardianProgress, archives] = await Promise.all([
            this.vault.getVaultSummary(this.vaultOwner),
            this.vault.getClaimStatus(this.vaultOwner),
            this.getGuardianProgress(),
            this.vault.getContentArchives(this.vaultOwner),
        ]);

        const stateNames = ['Active', 'Warning', 'Claimable', 'Claimed', 'Revoked'];
        const methodNames = ['DeadManSwitch', 'OracleVerified', 'MultiSigConfirmed', 'EmergencyOverride'];

        return {
            vault: {
                state: stateNames[Number(vaultSummary.state)] || 'Unknown',
                stateCode: Number(vaultSummary.state),
                lastCheckIn: new Date(Number(vaultSummary.lastCheckIn) * 1000),
                checkInInterval: Number(vaultSummary.checkInInterval),
                gracePeriod: Number(vaultSummary.gracePeriod),
                guardianCount: Number(vaultSummary.guardianCount),
                requiredGuardians: Number(vaultSummary.requiredGuardians),
                vaultName: vaultSummary.vaultName,
                platformCount: Number(vaultSummary.platformCount),
                zkpActive: vaultSummary.zkpActive,
            },
            claim: {
                beneficiaryVerified: claimStatus.beneficiaryVerified,
                claimBinding: claimStatus.claimBinding,
                claimInitiatedAt: Number(claimStatus.claimInitiatedAt) > 0
                    ? new Date(Number(claimStatus.claimInitiatedAt) * 1000)
                    : null,
                cooldownEnds: Number(claimStatus.cooldownEnds) > 0
                    ? new Date(Number(claimStatus.cooldownEnds) * 1000)
                    : null,
                cooldownElapsed: claimStatus.cooldownElapsed,
            },
            guardians: guardianProgress,
            archives: archives,
            localPhase: this.phase,
            sharesCollected: this.claimData.shares.length,
            passcodes: await this.getAllPasscodes().catch(() => []),
        };
    }


    // --------------------------------------------------------
    // EVENT SYSTEM
    // --------------------------------------------------------

    on(event, callback) {
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(callback);
    }

    off(event, callback) {
        if (!this._listeners[event]) return;
        this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
    }

    _emit(event, data) {
        const listeners = this._listeners[event] || [];
        listeners.forEach(cb => cb(data));
    }

    _setPhase(phase) {
        const oldPhase = this.phase;
        this.phase = phase;
        this._emit('phase', { from: oldPhase, to: phase });
    }


    // --------------------------------------------------------
    // CLEANUP
    // --------------------------------------------------------

    /**
     * Clean up: remove listeners, zero out sensitive data.
     */
    destroy() {
        this.vault.removeAllListeners();
        this.deathCertMgr.removeAllListeners();

        // Zero out any sensitive data in memory
        if (this.claimData.reconstructedCredentials) {
            this.claimData.reconstructedCredentials = null;
        }
        this.claimData.shares = [];
        this._listeners = {};
    }
}


// ============================================================
// EXPORTS
// ============================================================

export { ClaimFlowManager, ClaimPhase };
export default ClaimFlowManager;
