/**
 * death-cert-manager.js — Death Certificate Verification Pipeline
 * 
 * Digital Legacy Vault - Phase 2: Verification Layer
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * Manages the end-to-end death certificate verification flow:
 *   1. Document hashing (client-side, nothing leaves the browser)
 *   2. Oracle request submission (Chainlink Functions)
 *   3. Notarized attestation submission (fallback path)
 *   4. Verification status polling
 *   5. Smart contract state transition triggers
 * 
 * DEPENDENCIES:
 *   - ethers.js (contract interaction)
 *   - ChainlinkDeathOracle contract ABI
 *   - DigitalLegacyVaultV2 contract ABI
 */

import { ethers } from 'ethers';


// ============================================================
// ABI FRAGMENTS (only the functions we need)
// ============================================================

const ORACLE_ABI = [
    'function requestVerification(address _vaultOwner, bytes32 _certificateHash, string _decedentName, string _dateOfDeath, string _stateOfDeath, string _ssnLast4) external returns (bytes32)',
    'function submitAttestation(address _vaultOwner, bytes32 _attestationHash, bytes32 _attestorDIDHash) external',
    'function getVerificationStatus(address _vaultOwner) external view returns (bool verified, uint256 confidence)',
    'function getLatestRequest(address _vaultOwner) external view returns (bytes32 requestId, bool fulfilled, bool verified, uint256 confidence, uint256 requestedAt)',
    'function isVerified(address) external view returns (bool)',
    'function verificationConfidence(address) external view returns (uint256)',
    'event VerificationRequested(bytes32 indexed requestId, address indexed vaultOwner, address requester, bytes32 certificateHash)',
    'event VerificationFulfilled(bytes32 indexed requestId, address indexed vaultOwner, bool verified, uint256 confidence, uint8 sourcesConfirmed)',
    'event AttestationSubmitted(address indexed vaultOwner, address indexed attestor, bytes32 attestationHash)',
];

const VAULT_ABI = [
    'function submitDeathCertificate(address vaultOwner, bytes32 _certHash) external',
    'function getVaultState(address owner) external view returns (uint8)',
    'event DeathCertificateVerified(address indexed owner, uint256 confidence)',
    'event StateChanged(address indexed owner, uint8 oldState, uint8 newState)',
];


// ============================================================
// DEATH CERT MANAGER
// ============================================================

class DeathCertificateManager {

    /**
     * @param {Object} config
     * @param {ethers.Signer} config.signer - Connected wallet signer
     * @param {string} config.oracleAddress - ChainlinkDeathOracle contract address
     * @param {string} config.vaultAddress - DigitalLegacyVaultV2 contract address
     */
    constructor({ signer, oracleAddress, vaultAddress }) {
        this.signer = signer;
        this.oracle = new ethers.Contract(oracleAddress, ORACLE_ABI, signer);
        this.vault = new ethers.Contract(vaultAddress, VAULT_ABI, signer);

        // Event callbacks
        this._onStatusChange = null;
        this._onVerified = null;
        this._onError = null;
    }


    // --------------------------------------------------------
    // DOCUMENT PROCESSING (all client-side)
    // --------------------------------------------------------

    /**
     * Hash a death certificate document.
     * 
     * The actual document NEVER leaves the client. Only the hash
     * is sent to the oracle for verification matching.
     * 
     * @param {File|ArrayBuffer|Uint8Array} document - Death certificate file
     * @returns {Promise<string>} Hex string of SHA-256 hash (bytes32)
     */
    async hashDocument(document) {
        let data;

        if (document instanceof File) {
            data = await document.arrayBuffer();
        } else if (document instanceof ArrayBuffer) {
            data = document;
        } else if (document instanceof Uint8Array) {
            data = document.buffer;
        } else {
            throw new Error('Document must be File, ArrayBuffer, or Uint8Array');
        }

        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        const hashHex = '0x' + Array.from(hashArray)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        return hashHex;
    }

    /**
     * Extract metadata from a death certificate for oracle verification.
     * 
     * In production, this would use OCR or structured form parsing.
     * For MVP, the beneficiary enters this information manually.
     * 
     * @param {Object} metadata
     * @param {string} metadata.decedentName - Full legal name of deceased
     * @param {string} metadata.dateOfDeath  - YYYY-MM-DD format
     * @param {string} metadata.stateOfDeath - 2-letter US state code
     * @param {string} metadata.ssnLast4     - Last 4 digits of SSN
     * @returns {Object} Validated metadata
     */
    validateMetadata(metadata) {
        const { decedentName, dateOfDeath, stateOfDeath, ssnLast4 } = metadata;

        // Name validation
        if (!decedentName || decedentName.trim().length < 3) {
            throw new Error('Decedent name must be at least 3 characters');
        }

        // Date validation (YYYY-MM-DD)
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateOfDeath || !dateRegex.test(dateOfDeath)) {
            throw new Error('Date of death must be in YYYY-MM-DD format');
        }
        const deathDate = new Date(dateOfDeath);
        if (deathDate > new Date()) {
            throw new Error('Date of death cannot be in the future');
        }
        // Reasonable range: within last 2 years
        const twoYearsAgo = new Date();
        twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
        if (deathDate < twoYearsAgo) {
            throw new Error('Date of death is more than 2 years ago — contact support');
        }

        // State validation
        const validStates = [
            'AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA',
            'HI','ID','IL','IN','IA','KS','KY','LA','ME','MD',
            'MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ',
            'NM','NY','NC','ND','OH','OK','OR','PA','RI','SC',
            'SD','TN','TX','UT','VT','VA','WA','WV','WI','WY','DC',
        ];
        if (!stateOfDeath || !validStates.includes(stateOfDeath.toUpperCase())) {
            throw new Error('Invalid US state code');
        }

        // SSN last 4 validation
        if (!ssnLast4 || !/^\d{4}$/.test(ssnLast4)) {
            throw new Error('SSN last 4 must be exactly 4 digits');
        }

        return {
            decedentName: decedentName.trim(),
            dateOfDeath,
            stateOfDeath: stateOfDeath.toUpperCase(),
            ssnLast4,
        };
    }


    // --------------------------------------------------------
    // ORACLE VERIFICATION REQUEST
    // --------------------------------------------------------

    /**
     * Submit a death certificate for oracle verification.
     * 
     * This sends a request to the Chainlink DON, which will:
     * 1. Query SSA Death Master File
     * 2. Query state vital records (if available)
     * 3. Query third-party death indices
     * 4. Return aggregated confidence score
     * 
     * @param {Object} params
     * @param {address} params.vaultOwner     - Address of the deceased's vault
     * @param {File|ArrayBuffer} params.document - Death certificate document
     * @param {Object} params.metadata        - Certificate metadata
     * 
     * @returns {Promise<{requestId: string, txHash: string}>}
     */
    async requestOracleVerification({ vaultOwner, document, metadata }) {
        // Hash the document client-side
        const certHash = await this.hashDocument(document);
        console.log('[DeathCert] Document hashed:', certHash.slice(0, 20) + '...');

        // Validate metadata
        const validated = this.validateMetadata(metadata);
        console.log('[DeathCert] Metadata validated for:', validated.decedentName);

        // Submit to oracle
        this._emit('status', { phase: 'submitting', message: 'Submitting to oracle network...' });

        const tx = await this.oracle.requestVerification(
            vaultOwner,
            certHash,
            validated.decedentName,
            validated.dateOfDeath,
            validated.stateOfDeath,
            validated.ssnLast4
        );

        console.log('[DeathCert] Oracle request tx:', tx.hash);
        this._emit('status', { phase: 'pending', message: 'Waiting for oracle confirmation...' });

        const receipt = await tx.wait();

        // Extract requestId from event
        const event = receipt.logs.find(log => {
            try {
                return this.oracle.interface.parseLog(log)?.name === 'VerificationRequested';
            } catch { return false; }
        });

        const requestId = event
            ? this.oracle.interface.parseLog(event).args.requestId
            : null;

        console.log('[DeathCert] Request submitted. ID:', requestId);
        this._emit('status', {
            phase: 'verifying',
            message: 'Oracle is verifying against death records...',
            requestId,
        });

        return { requestId, txHash: tx.hash, certHash };
    }


    // --------------------------------------------------------
    // NOTARIZED ATTESTATION (FALLBACK)
    // --------------------------------------------------------

    /**
     * Submit a notarized attorney attestation.
     * 
     * This is the fallback path when API-based verification
     * doesn't reach 95% confidence. An authorized attorney
     * or notary attests to the death, adding +15% confidence.
     * 
     * @param {Object} params
     * @param {string} params.vaultOwner - Vault owner address
     * @param {File|ArrayBuffer} params.attestationDocument - Notarized document
     * @param {string} params.attestorDIDHash - DID hash of the attorney/notary
     * 
     * @returns {Promise<{txHash: string}>}
     */
    async submitAttestation({ vaultOwner, attestationDocument, attestorDIDHash }) {
        const attestationHash = await this.hashDocument(attestationDocument);
        console.log('[DeathCert] Attestation hashed:', attestationHash.slice(0, 20) + '...');

        const tx = await this.oracle.submitAttestation(
            vaultOwner,
            attestationHash,
            attestorDIDHash
        );

        console.log('[DeathCert] Attestation tx:', tx.hash);
        const receipt = await tx.wait();

        this._emit('status', {
            phase: 'attestation_submitted',
            message: 'Attorney attestation submitted (+15% confidence boost)',
        });

        return { txHash: tx.hash };
    }


    // --------------------------------------------------------
    // VERIFICATION STATUS
    // --------------------------------------------------------

    /**
     * Check current verification status for a vault owner.
     * 
     * @param {string} vaultOwner - Vault owner address
     * @returns {Promise<{verified: boolean, confidence: number, request: Object}>}
     */
    async getVerificationStatus(vaultOwner) {
        const [status, request] = await Promise.all([
            this.oracle.getVerificationStatus(vaultOwner),
            this.oracle.getLatestRequest(vaultOwner),
        ]);

        return {
            verified: status.verified,
            confidence: Number(status.confidence),
            request: {
                requestId: request.requestId,
                fulfilled: request.fulfilled,
                verified: request.verified,
                confidence: Number(request.confidence),
                requestedAt: Number(request.requestedAt),
            },
        };
    }

    /**
     * Poll verification status until fulfilled or timeout.
     * 
     * Chainlink Functions typically respond within 1-5 minutes.
     * 
     * @param {string} vaultOwner - Vault owner address
     * @param {Object} options
     * @param {number} options.intervalMs - Poll interval (default: 15000ms)
     * @param {number} options.timeoutMs - Max wait time (default: 600000ms = 10min)
     * 
     * @returns {Promise<{verified: boolean, confidence: number}>}
     */
    async waitForVerification(vaultOwner, { intervalMs = 15000, timeoutMs = 600000 } = {}) {
        const startTime = Date.now();

        return new Promise((resolve, reject) => {
            const poll = async () => {
                try {
                    if (Date.now() - startTime > timeoutMs) {
                        reject(new Error('Verification timeout — oracle may be unavailable'));
                        return;
                    }

                    const status = await this.getVerificationStatus(vaultOwner);

                    if (status.request.fulfilled) {
                        this._emit('status', {
                            phase: 'fulfilled',
                            message: `Verification complete: ${status.confidence}% confidence`,
                            verified: status.verified,
                            confidence: status.confidence,
                        });

                        if (status.verified) {
                            this._emit('verified', status);
                        }

                        resolve(status);
                        return;
                    }

                    // Not yet fulfilled, keep polling
                    this._emit('status', {
                        phase: 'waiting',
                        message: `Waiting for oracle response... (${Math.round((Date.now() - startTime) / 1000)}s)`,
                    });

                    setTimeout(poll, intervalMs);
                } catch (error) {
                    reject(error);
                }
            };

            poll();
        });
    }


    // --------------------------------------------------------
    // VAULT STATE TRANSITION
    // --------------------------------------------------------

    /**
     * Trigger the vault state transition after oracle verification.
     * 
     * Once the oracle confirms the death with 95%+ confidence,
     * the beneficiary calls this to move the vault to Claimable state.
     * 
     * @param {string} vaultOwner - Vault owner address
     * @param {string} certHash - Certificate hash (from requestOracleVerification)
     * 
     * @returns {Promise<{txHash: string, newState: number}>}
     */
    async triggerVaultTransition(vaultOwner, certHash) {
        // Verify oracle has confirmed
        const status = await this.getVerificationStatus(vaultOwner);
        if (!status.verified) {
            throw new Error(
                `Death not verified by oracle. Current confidence: ${status.confidence}%. ` +
                'Need 95%+. Consider submitting a notarized attestation for +15% boost.'
            );
        }

        this._emit('status', {
            phase: 'transitioning',
            message: 'Submitting death certificate to vault contract...',
        });

        const tx = await this.vault.submitDeathCertificate(vaultOwner, certHash);
        console.log('[DeathCert] Vault transition tx:', tx.hash);
        const receipt = await tx.wait();

        // Get new state
        const newState = await this.vault.getVaultState(vaultOwner);

        this._emit('status', {
            phase: 'transitioned',
            message: 'Vault is now Claimable. Beneficiary can submit ZKP identity proof.',
            newState: Number(newState),
        });

        return { txHash: tx.hash, newState: Number(newState) };
    }


    // --------------------------------------------------------
    // FULL PIPELINE
    // --------------------------------------------------------

    /**
     * Run the complete death verification pipeline.
     * 
     * 1. Hash document
     * 2. Submit to oracle
     * 3. Wait for verification
     * 4. Trigger vault state transition
     * 
     * @param {Object} params - Same as requestOracleVerification
     * @returns {Promise<{verified: boolean, confidence: number, vaultState: number}>}
     */
    async runFullPipeline({ vaultOwner, document, metadata }) {
        console.log('[DeathCert] Starting full verification pipeline...');

        // Step 1: Submit to oracle
        const { certHash } = await this.requestOracleVerification({
            vaultOwner, document, metadata,
        });

        // Step 2: Wait for oracle response
        const status = await this.waitForVerification(vaultOwner);

        if (!status.verified) {
            console.log('[DeathCert] Verification insufficient:', status.confidence, '%');
            return {
                verified: false,
                confidence: status.confidence,
                vaultState: null,
                suggestion: status.confidence >= 60
                    ? 'Submit a notarized attorney attestation for +15% confidence boost'
                    : 'Oracle could not verify death — check certificate details',
            };
        }

        // Step 3: Trigger vault transition
        const { newState } = await this.triggerVaultTransition(vaultOwner, certHash);

        console.log('[DeathCert] Pipeline complete. Vault state:', newState);
        return {
            verified: true,
            confidence: status.confidence,
            vaultState: newState,
        };
    }


    // --------------------------------------------------------
    // EVENT SYSTEM
    // --------------------------------------------------------

    /**
     * Subscribe to status change events.
     * @param {'status'|'verified'|'error'} event
     * @param {Function} callback
     */
    on(event, callback) {
        switch (event) {
            case 'status':  this._onStatusChange = callback; break;
            case 'verified': this._onVerified = callback; break;
            case 'error':   this._onError = callback; break;
        }
    }

    /** @private */
    _emit(event, data) {
        switch (event) {
            case 'status':  this._onStatusChange?.(data); break;
            case 'verified': this._onVerified?.(data); break;
            case 'error':   this._onError?.(data); break;
        }
    }


    // --------------------------------------------------------
    // BLOCKCHAIN EVENT LISTENERS
    // --------------------------------------------------------

    /**
     * Listen for oracle verification events on-chain.
     * @param {string} vaultOwner - Filter by vault owner
     * @param {Function} callback - Called with event data
     */
    listenForVerification(vaultOwner, callback) {
        this.oracle.on(
            this.oracle.filters.VerificationFulfilled(null, vaultOwner),
            (requestId, owner, verified, confidence, sources) => {
                callback({
                    requestId,
                    vaultOwner: owner,
                    verified,
                    confidence: Number(confidence),
                    sourcesConfirmed: Number(sources),
                });
            }
        );
    }

    /**
     * Stop all event listeners.
     */
    removeAllListeners() {
        this.oracle.removeAllListeners();
        this.vault.removeAllListeners();
    }
}


// ============================================================
// EXPORTS
// ============================================================

export { DeathCertificateManager };
export default DeathCertificateManager;
