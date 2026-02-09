/**
 * proof-generator.js — Zero-Knowledge Proof Generator
 * 
 * Digital Legacy Vault - Phase 2: ZKP Client Module
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * Generates Groth16 proofs client-side using snarkjs.
 * The beneficiary runs this in their browser to prove their identity
 * without revealing their DID or nonce to anyone.
 * 
 * DEPENDENCIES:
 *   - snarkjs (npm install snarkjs)
 *   - circomlibjs (npm install circomlibjs) — for Poseidon hashing
 * 
 * REQUIRED ARTIFACTS (from circuit compilation):
 *   - identity_proof.wasm  — Circuit WASM (from circom --wasm)
 *   - identity_proof_final.zkey — Proving key (from trusted setup)
 *   - verification_key.json — Verification key (for local pre-check)
 * 
 * FLOW:
 *   1. Beneficiary provides their DID string + nonce (received at vault setup)
 *   2. DID is hashed and split into 4x 64-bit chunks
 *   3. Poseidon(chunks, nonce) is computed to verify it matches on-chain hash
 *   4. snarkjs generates Groth16 proof with private inputs
 *   5. Proof is ABI-encoded for smart contract submission
 * 
 * ALL COMPUTATION HAPPENS CLIENT-SIDE. Nothing leaves the browser.
 */

import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';


// ============================================================
// POSEIDON HASHER
// ============================================================

let poseidonInstance = null;

/**
 * Initialize the Poseidon hash function.
 * Must be called once before any hashing operations.
 * 
 * Poseidon is a ZK-friendly hash function designed for efficient
 * proof generation inside arithmetic circuits. It operates natively
 * over the BN128 scalar field, unlike SHA-256 which requires
 * expensive bit decomposition in ZK circuits.
 */
async function initPoseidon() {
    if (!poseidonInstance) {
        poseidonInstance = await buildPoseidon();
    }
    return poseidonInstance;
}

/**
 * Compute Poseidon hash of inputs.
 * 
 * @param {BigInt[]} inputs - Array of field elements
 * @returns {BigInt} Poseidon hash as BigInt
 */
async function poseidonHash(inputs) {
    const poseidon = await initPoseidon();
    const hash = poseidon(inputs.map(x => BigInt(x)));
    return poseidon.F.toObject(hash);
}


// ============================================================
// DID PROCESSING
// ============================================================

/**
 * Convert a DID string into 4x 64-bit field element chunks.
 * 
 * The Circom circuit expects the DID as 4 separate signals,
 * each constrained to 64 bits. We hash the DID with SHA-256
 * first (to get a fixed 256-bit value regardless of DID length),
 * then split the hash into 4x 64-bit chunks.
 * 
 * @param {string} didString - The beneficiary's DID (e.g., "did:key:z...")
 * @returns {Promise<BigInt[]>} Array of 4 BigInt values, each < 2^64
 */
async function didToComponents(didString) {
    // SHA-256 hash of the DID string → 32 bytes
    const encoder = new TextEncoder();
    const data = encoder.encode(didString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);

    // Split 32 bytes into 4x 8-byte (64-bit) chunks
    const components = [];
    for (let i = 0; i < 4; i++) {
        let value = BigInt(0);
        for (let j = 0; j < 8; j++) {
            value = (value << BigInt(8)) | BigInt(hashArray[i * 8 + j]);
        }
        components.push(value);
    }

    return components;
}


// ============================================================
// IDENTITY COMMITMENT
// ============================================================

/**
 * Compute the identity commitment that gets stored on-chain.
 * 
 * Called ONCE during vault setup when the beneficiary is designated.
 * The resulting commitment is stored in the smart contract as identityHash.
 * 
 * @param {string} didString - Beneficiary's DID string
 * @param {BigInt} nonce - Random blinding nonce (must be saved by beneficiary!)
 * @returns {Promise<{commitment: BigInt, components: BigInt[]}>}
 */
async function computeIdentityCommitment(didString, nonce) {
    const components = await didToComponents(didString);
    const commitment = await poseidonHash([...components, BigInt(nonce)]);

    return {
        commitment,
        components,
        nonce: BigInt(nonce),
    };
}

/**
 * Generate a cryptographically secure random nonce.
 * 
 * This nonce MUST be saved by the beneficiary (e.g., in their
 * password manager or written down). Without it, they cannot
 * generate the identity proof needed to claim the vault.
 * 
 * @returns {BigInt} 128-bit random nonce
 */
function generateNonce() {
    const bytes = new Uint8Array(16); // 128 bits
    crypto.getRandomValues(bytes);
    let nonce = BigInt(0);
    for (const byte of bytes) {
        nonce = (nonce << BigInt(8)) | BigInt(byte);
    }
    return nonce;
}


// ============================================================
// PROOF GENERATION
// ============================================================

/**
 * Generate a Groth16 identity proof for vault claiming.
 * 
 * This is the core function. The beneficiary calls this with their
 * DID and nonce. The proof demonstrates they know the preimage of
 * the identity commitment stored on-chain.
 * 
 * @param {Object} params
 * @param {string} params.didString      - Beneficiary's DID string
 * @param {BigInt|string} params.nonce   - Blinding nonce from vault setup
 * @param {BigInt|string} params.identityHash - On-chain identity commitment
 * @param {string} params.vaultOwner     - Vault owner's address (as uint256 string)
 * @param {number} params.claimTimestamp - Current block.timestamp
 * @param {number} params.minTimestamp   - Earliest acceptable timestamp
 * @param {string} params.wasmPath       - Path to identity_proof.wasm
 * @param {string} params.zkeyPath       - Path to identity_proof_final.zkey
 * 
 * @returns {Promise<{proof: Object, publicSignals: string[], calldata: Object}>}
 * 
 * @example
 *   const result = await generateIdentityProof({
 *     didString: "did:key:zDnae...",
 *     nonce: "12345678901234567890",
 *     identityHash: "9876543210987654321",
 *     vaultOwner: "0x1234...address-as-uint256",
 *     claimTimestamp: 1707400000,
 *     minTimestamp: 1707396400,
 *     wasmPath: "/artifacts/identity_proof.wasm",
 *     zkeyPath: "/artifacts/identity_proof_final.zkey",
 *   });
 *   // result.calldata contains ABI-encoded proof for smart contract
 */
async function generateIdentityProof({
    didString,
    nonce,
    identityHash,
    vaultOwner,
    claimTimestamp,
    minTimestamp,
    wasmPath,
    zkeyPath,
}) {
    // Step 1: Process DID into components
    const didComponents = await didToComponents(didString);

    // Step 2: Verify commitment locally before generating proof
    // This catches errors early (wrong DID, wrong nonce) without
    // wasting time on proof generation
    const localCommitment = await poseidonHash([
        ...didComponents,
        BigInt(nonce),
    ]);

    if (localCommitment !== BigInt(identityHash)) {
        throw new Error(
            'Identity commitment mismatch. Either the DID or nonce is incorrect. ' +
            `Expected: ${identityHash}, Got: ${localCommitment.toString()}`
        );
    }

    // Step 3: Prepare circuit inputs
    const circuitInputs = {
        // Private inputs
        did_components: didComponents.map(c => c.toString()),
        nonce: BigInt(nonce).toString(),

        // Public inputs
        identity_hash: BigInt(identityHash).toString(),
        vault_owner: BigInt(vaultOwner).toString(),
        claim_timestamp: claimTimestamp.toString(),
        min_timestamp: minTimestamp.toString(),
    };

    console.log('[ZKP] Generating Groth16 proof...');
    console.log('[ZKP] Private inputs: [DID components hidden, nonce hidden]');
    console.log('[ZKP] Public inputs:', {
        identity_hash: circuitInputs.identity_hash.slice(0, 20) + '...',
        vault_owner: circuitInputs.vault_owner.slice(0, 20) + '...',
        claim_timestamp: circuitInputs.claim_timestamp,
        min_timestamp: circuitInputs.min_timestamp,
    });

    // Step 4: Generate the Groth16 proof
    const startTime = performance.now();

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        wasmPath,
        zkeyPath
    );

    const proofTime = ((performance.now() - startTime) / 1000).toFixed(2);
    console.log(`[ZKP] Proof generated in ${proofTime}s`);

    // Step 5: Format for smart contract
    const calldata = await formatForContract(proof, publicSignals);

    return {
        proof,
        publicSignals,
        calldata,
        proofTimeSeconds: parseFloat(proofTime),
    };
}


// ============================================================
// PROOF VERIFICATION (local pre-check)
// ============================================================

/**
 * Verify a proof locally before submitting on-chain.
 * 
 * This saves gas costs if the proof is invalid. The on-chain
 * Groth16 verifier will perform the same check, but checking
 * locally first prevents wasted transactions.
 * 
 * @param {Object} proof - Groth16 proof object
 * @param {string[]} publicSignals - Public signal values
 * @param {string} vkeyPath - Path to verification_key.json
 * @returns {Promise<boolean>}
 */
async function verifyProofLocally(proof, publicSignals, vkeyPath) {
    try {
        const vkey = await fetch(vkeyPath).then(r => r.json());
        const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
        console.log(`[ZKP] Local verification: ${valid ? 'VALID' : 'INVALID'}`);
        return valid;
    } catch (error) {
        console.error('[ZKP] Local verification error:', error);
        return false;
    }
}


// ============================================================
// CONTRACT CALLDATA FORMATTING
// ============================================================

/**
 * Format proof and public signals for Solidity contract call.
 * 
 * Converts snarkjs proof format to the ABI-encoded format
 * expected by the on-chain Groth16 verifier.
 * 
 * @param {Object} proof - snarkjs proof object
 * @param {string[]} publicSignals - Public signal values
 * @returns {Promise<Object>} { pA, pB, pC, pubSignals }
 */
async function formatForContract(proof, publicSignals) {
    // snarkjs exports proof as:
    //   proof.pi_a = [x, y, 1]  (G1 point, projective)
    //   proof.pi_b = [[x0, x1], [y0, y1], [1, 0]]  (G2 point, projective)
    //   proof.pi_c = [x, y, 1]  (G1 point, projective)

    // Solidity verifier expects affine coordinates (drop the '1')
    const pA = [proof.pi_a[0], proof.pi_a[1]];

    // Note: snarkjs outputs pi_b with coordinates swapped for the pairing
    const pB = [
        [proof.pi_b[0][1], proof.pi_b[0][0]],
        [proof.pi_b[1][1], proof.pi_b[1][0]],
    ];

    const pC = [proof.pi_c[0], proof.pi_c[1]];

    // Public signals: [identity_hash, vault_owner, claim_timestamp, min_timestamp, claim_binding]
    const pubSignals = publicSignals.map(s => s.toString());

    return { pA, pB, pC, pubSignals };
}

/**
 * Encode proof as ABI bytes for the V2 vault contract's initiateClaim().
 * 
 * The V2 contract's simpler interface accepts a single `bytes calldata zkProof`
 * parameter. This encodes the full Groth16 proof into that format.
 * 
 * @param {Object} calldata - From formatForContract()
 * @returns {string} ABI-encoded bytes string
 */
function encodeProofBytes(calldata) {
    // ABI encode: (uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[5] pubSignals)
    const abiCoder = new ethers.AbiCoder();

    return abiCoder.encode(
        ['uint256[2]', 'uint256[2][2]', 'uint256[2]', 'uint256[5]'],
        [
            calldata.pA,
            calldata.pB,
            calldata.pC,
            calldata.pubSignals,
        ]
    );
}


// ============================================================
// SETUP UTILITIES
// ============================================================

/**
 * Generate identity commitment for vault setup.
 * 
 * Called when the vault owner designates a beneficiary.
 * Returns the commitment (stored on-chain) and the nonce
 * (given to the beneficiary to save securely).
 * 
 * @param {string} beneficiaryDID - Beneficiary's DID string
 * @returns {Promise<{commitment: string, nonce: string, components: string[]}>}
 */
async function setupBeneficiaryIdentity(beneficiaryDID) {
    const nonce = generateNonce();
    const result = await computeIdentityCommitment(beneficiaryDID, nonce);

    return {
        // This goes on-chain as the identityHash
        commitment: result.commitment.toString(),

        // This is given ONLY to the beneficiary (they must save it!)
        nonce: nonce.toString(),

        // Debug info (not needed for production)
        components: result.components.map(c => c.toString()),
    };
}


// ============================================================
// EXPORTS
// ============================================================

export {
    // Core
    generateIdentityProof,
    verifyProofLocally,

    // Setup
    setupBeneficiaryIdentity,
    computeIdentityCommitment,
    generateNonce,

    // Utilities
    didToComponents,
    poseidonHash,
    initPoseidon,
    formatForContract,
    encodeProofBytes,
};
