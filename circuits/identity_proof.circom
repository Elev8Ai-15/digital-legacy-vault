/**
 * identity_proof.circom — Zero-Knowledge Identity Proof Circuit
 * 
 * Digital Legacy Vault - Phase 2: Verification Layer
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * WHAT THIS DOES:
 *   Allows a beneficiary to PROVE they are the designated heir
 *   WITHOUT revealing their actual DID or personal information.
 *   The smart contract stores a hash of the beneficiary's identity.
 *   This circuit proves: "I know a secret (my DID + nonce) that hashes 
 *   to the value stored on-chain" — without revealing the secret.
 * 
 * ARCHITECTURE:
 *   Private inputs (known only to beneficiary):
 *     - did_components[4]: 4x 64-bit chunks of the beneficiary's DID string hash
 *     - nonce: random blinding factor chosen at vault setup
 *   
 *   Public inputs (visible on-chain):
 *     - identity_hash: Poseidon hash of (did_components, nonce) stored in smart contract
 *     - vault_owner: address of the vault being claimed (prevents proof replay)
 *     - claim_timestamp: block.timestamp at claim time (prevents stale proof reuse)
 * 
 * SECURITY PROPERTIES:
 *   1. Zero-Knowledge: Verifier learns nothing about the DID or nonce
 *   2. Soundness: Cannot produce valid proof without knowing DID + nonce
 *   3. Replay Protection: Proof bound to specific vault + timestamp
 *   4. Non-transferable: Only the person who set up the vault knows the nonce
 * 
 * COMPILE:
 *   circom identity_proof.circom --r1cs --wasm --sym --c
 * 
 * PROVING KEY SETUP (trusted setup):
 *   snarkjs groth16 setup identity_proof.r1cs pot_final.ptau identity_proof_0000.zkey
 *   snarkjs zkey contribute identity_proof_0000.zkey identity_proof_final.zkey
 *   snarkjs zkey export verificationkey identity_proof_final.zkey verification_key.json
 * 
 * GENERATE SOLIDITY VERIFIER:
 *   snarkjs zkey export solidityverifier identity_proof_final.zkey Groth16Verifier.sol
 */

pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// ============================================================
// IDENTITY COMMITMENT - Hash DID components + nonce
// ============================================================

/**
 * IdentityCommitment
 * 
 * Computes: commitment = Poseidon(did[0], did[1], did[2], did[3], nonce)
 * 
 * The DID string is pre-hashed client-side into 4x 64-bit field elements
 * to fit within the BN128 scalar field used by Groth16.
 * 
 * The nonce prevents rainbow table attacks on common DID formats.
 */
template IdentityCommitment() {
    // Private: beneficiary's DID components (4x 64-bit chunks)
    signal input did_components[4];
    
    // Private: random blinding nonce (256-bit, chosen at vault setup)
    signal input nonce;
    
    // Output: Poseidon hash commitment
    signal output commitment;
    
    // Poseidon hash with 5 inputs
    component hasher = Poseidon(5);
    hasher.inputs[0] <== did_components[0];
    hasher.inputs[1] <== did_components[1];
    hasher.inputs[2] <== did_components[2];
    hasher.inputs[3] <== did_components[3];
    hasher.inputs[4] <== nonce;
    
    commitment <== hasher.out;
}


// ============================================================
// CLAIM BINDING - Prevent proof replay across vaults/times
// ============================================================

/**
 * ClaimBinding
 * 
 * Computes: binding = Poseidon(commitment, vault_owner, claim_timestamp)
 * 
 * This binds the identity proof to a specific vault and time window,
 * preventing an attacker from replaying a stolen proof on a different
 * vault or after the claim window has expired.
 */
template ClaimBinding() {
    signal input commitment;
    signal input vault_owner;
    signal input claim_timestamp;
    
    signal output binding;
    
    component hasher = Poseidon(3);
    hasher.inputs[0] <== commitment;
    hasher.inputs[1] <== vault_owner;
    hasher.inputs[2] <== claim_timestamp;
    
    binding <== hasher.out;
}


// ============================================================
// RANGE CHECK - Ensure DID components fit in 64 bits
// ============================================================

/**
 * RangeCheck64
 * 
 * Constrains input to be a valid 64-bit unsigned integer.
 * Prevents malicious inputs that could exploit field arithmetic.
 */
template RangeCheck64() {
    signal input value;
    
    component bits = Num2Bits(64);
    bits.in <== value;
    
    // Num2Bits constrains value to fit in 64 bits
    // If value >= 2^64, the constraint system is unsatisfiable
}


// ============================================================
// TIMESTAMP FRESHNESS - Proof must be recent
// ============================================================

/**
 * TimestampCheck
 * 
 * Ensures claim_timestamp is within an acceptable range.
 * Prevents use of proofs generated far in the past.
 * 
 * In practice, the smart contract also checks block.timestamp
 * against the claim_timestamp, but this adds a circuit-level
 * constraint as defense in depth.
 */
template TimestampCheck() {
    signal input claim_timestamp;
    signal input min_timestamp;  // Public: earliest acceptable timestamp
    
    // claim_timestamp >= min_timestamp
    component gte = GreaterEqThan(64);
    gte.in[0] <== claim_timestamp;
    gte.in[1] <== min_timestamp;
    gte.out === 1;
}


// ============================================================
// MAIN CIRCUIT - Full Identity Proof
// ============================================================

/**
 * IdentityProof (Main)
 * 
 * PRIVATE INPUTS:
 *   did_components[4] - Beneficiary's DID hashed into 4x 64-bit chunks
 *   nonce             - Random blinding factor from vault setup
 * 
 * PUBLIC INPUTS:
 *   identity_hash     - Poseidon(did_components, nonce) stored on-chain
 *   vault_owner       - Address of vault being claimed (as uint256)
 *   claim_timestamp   - Current block.timestamp (freshness)
 *   min_timestamp     - Earliest acceptable timestamp (anti-replay)
 * 
 * PUBLIC OUTPUTS:
 *   claim_binding     - Hash binding proof to this specific claim context
 * 
 * CONSTRAINTS:
 *   1. Each did_component fits in 64 bits
 *   2. Poseidon(did_components, nonce) === identity_hash
 *   3. claim_timestamp >= min_timestamp
 *   4. claim_binding = Poseidon(commitment, vault_owner, claim_timestamp)
 */
template IdentityProof() {
    // ---- Private Inputs ----
    signal input did_components[4];
    signal input nonce;
    
    // ---- Public Inputs ----
    signal input identity_hash;       // On-chain stored hash
    signal input vault_owner;         // Vault address as uint256
    signal input claim_timestamp;     // Current time
    signal input min_timestamp;       // Anti-replay cutoff
    
    // ---- Public Output ----
    signal output claim_binding;      // Contextual proof binding
    
    // ========================================
    // STEP 1: Range check DID components
    // ========================================
    component range_checks[4];
    for (var i = 0; i < 4; i++) {
        range_checks[i] = RangeCheck64();
        range_checks[i].value <== did_components[i];
    }
    
    // ========================================
    // STEP 2: Compute identity commitment
    // ========================================
    component id_commitment = IdentityCommitment();
    id_commitment.did_components[0] <== did_components[0];
    id_commitment.did_components[1] <== did_components[1];
    id_commitment.did_components[2] <== did_components[2];
    id_commitment.did_components[3] <== did_components[3];
    id_commitment.nonce <== nonce;
    
    // ========================================
    // STEP 3: Verify commitment matches on-chain hash
    // ========================================
    // This is THE core constraint:
    // The beneficiary proves they know (did, nonce) that produces
    // the identity_hash stored in the smart contract
    id_commitment.commitment === identity_hash;
    
    // ========================================
    // STEP 4: Timestamp freshness check
    // ========================================
    component ts_check = TimestampCheck();
    ts_check.claim_timestamp <== claim_timestamp;
    ts_check.min_timestamp <== min_timestamp;
    
    // ========================================
    // STEP 5: Compute claim binding
    // ========================================
    component binding = ClaimBinding();
    binding.commitment <== id_commitment.commitment;
    binding.vault_owner <== vault_owner;
    binding.claim_timestamp <== claim_timestamp;
    
    claim_binding <== binding.binding;
}

// Main component declaration
component main {public [identity_hash, vault_owner, claim_timestamp, min_timestamp]} = IdentityProof();
