// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Groth16Verifier.sol
 * 
 * Digital Legacy Vault - Phase 2: On-Chain ZKP Verification
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * Standard Groth16 verifier for BN128 curve (Polygon compatible).
 * Generated verification keys are set during deployment after
 * the trusted setup ceremony for the BeneficiaryIdentityProof circuit.
 * 
 * Gas cost: ~200,000 per verification (< $0.01 on Polygon)
 * 
 * Architecture:
 *   1. Circom circuit compiled → generates verification key (vk)
 *   2. Trusted setup ceremony → generates proving key (pk) and vk
 *   3. vk parameters deployed to this contract
 *   4. Beneficiary generates proof client-side using SnarkJS + pk
 *   5. Proof submitted to this contract for on-chain verification
 *   6. DigitalLegacyVault calls this verifier during claim flow
 */

contract Groth16Verifier {

    // ============================================================
    // BN128 CURVE PARAMETERS
    // ============================================================

    // BN128 field modulus
    uint256 constant FIELD_MODULUS = 
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    // BN128 scalar field modulus    
    uint256 constant SCALAR_MODULUS = 
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Generator points for G1 and G2
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    // ============================================================
    // VERIFICATION KEY (Set after trusted setup)
    // ============================================================

    struct VerificationKey {
        // G1 points
        uint256[2] alpha;       // [alpha]_1
        uint256[2][2] beta;     // [beta]_2  (G2 point)
        uint256[2][2] gamma;    // [gamma]_2 (G2 point)
        uint256[2][2] delta;    // [delta]_2 (G2 point)
        uint256[2][] ic;        // IC points (one per public input + 1)
    }

    struct Proof {
        uint256[2] a;           // [A]_1
        uint256[2][2] b;       // [B]_2  
        uint256[2] c;           // [C]_1
    }

    // Storage for verification key parameters
    uint256[2] public vk_alpha;
    uint256[2][2] public vk_beta;
    uint256[2][2] public vk_gamma;
    uint256[2][2] public vk_delta;
    uint256[2][] public vk_ic;

    address public admin;
    bool public isKeySet;
    
    // Number of public inputs for IdentityProof circuit:
    // identity_hash, vault_owner, claim_timestamp, min_timestamp, claim_binding = 5 public inputs
    uint256 public constant NUM_PUBLIC_INPUTS = 5;

    // ============================================================
    // EVENTS
    // ============================================================

    event VerificationKeySet(address indexed setter, uint256 icLength);
    event ProofVerified(address indexed prover, bool result);

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor() {
        admin = msg.sender;
        isKeySet = false;
    }

    // ============================================================
    // VERIFICATION KEY MANAGEMENT
    // ============================================================

    /**
     * @notice Set the verification key from the trusted setup
     * @dev Called once after circuit compilation and ceremony
     * @param _alpha Alpha G1 point [x, y]
     * @param _beta Beta G2 point [[x0,x1],[y0,y1]]  
     * @param _gamma Gamma G2 point
     * @param _delta Delta G2 point
     * @param _ic IC points array (length = NUM_PUBLIC_INPUTS + 1)
     */
    function setVerificationKey(
        uint256[2] calldata _alpha,
        uint256[2][2] calldata _beta,
        uint256[2][2] calldata _gamma,
        uint256[2][2] calldata _delta,
        uint256[2][] calldata _ic
    ) external {
        require(msg.sender == admin, "Only admin");
        require(!isKeySet, "Key already set");
        require(_ic.length == NUM_PUBLIC_INPUTS + 1, "Invalid IC length");

        vk_alpha = _alpha;
        vk_beta = _beta;
        vk_gamma = _gamma;
        vk_delta = _delta;
        
        // Copy IC points
        delete vk_ic;
        for (uint256 i = 0; i < _ic.length; i++) {
            vk_ic.push(_ic[i]);
        }

        isKeySet = true;
        emit VerificationKeySet(msg.sender, _ic.length);
    }

    // ============================================================
    // PROOF VERIFICATION
    // ============================================================

    /**
     * @notice Verify a Groth16 proof against public inputs
     * @param _pA Proof point A (G1)
     * @param _pB Proof point B (G2)
     * @param _pC Proof point C (G1)
     * @param _pubSignals Public signals [identity_hash, vault_owner, claim_timestamp, min_timestamp, claim_binding]
     * @return True if proof is valid
     * 
     * Verification equation:
     *   e(A, B) == e(alpha, beta) * e(IC, gamma) * e(C, delta)
     * where IC = ic[0] + sum(pubSignals[i] * ic[i+1])
     */
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
    ) public view returns (bool) {
        require(isKeySet, "Verification key not set");

        // Validate inputs are in the scalar field
        for (uint256 i = 0; i < NUM_PUBLIC_INPUTS; i++) {
            require(_pubSignals[i] < SCALAR_MODULUS, "Input exceeds field");
        }

        // Compute IC = ic[0] + pubSignals[0]*ic[1] + ... + pubSignals[4]*ic[5]
        uint256[2] memory vk_x = vk_ic[0];
        
        for (uint256 i = 0; i < NUM_PUBLIC_INPUTS; i++) {
            // Scalar multiplication: pubSignals[i] * ic[i+1]
            (uint256 sx, uint256 sy) = scalarMul(vk_ic[i+1], _pubSignals[i]);
            // Point addition: vk_x = vk_x + result
            (vk_x[0], vk_x[1]) = pointAdd(vk_x[0], vk_x[1], sx, sy);
        }

        // Pairing check
        // e(-A, B) * e(alpha, beta) * e(IC, gamma) * e(C, delta) == 1
        
        return pairingCheck(
            // Negate A (negate y coordinate)
            _pA[0], (FIELD_MODULUS - _pA[1]) % FIELD_MODULUS,
            _pB[0][0], _pB[0][1], _pB[1][0], _pB[1][1],
            // Alpha
            vk_alpha[0], vk_alpha[1],
            vk_beta[0][0], vk_beta[0][1], vk_beta[1][0], vk_beta[1][1],
            // IC
            vk_x[0], vk_x[1],
            vk_gamma[0][0], vk_gamma[0][1], vk_gamma[1][0], vk_gamma[1][1],
            // C
            _pC[0], _pC[1],
            vk_delta[0][0], vk_delta[0][1], vk_delta[1][0], vk_delta[1][1]
        );
    }

    // ============================================================
    // BN128 PRECOMPILE WRAPPERS
    // ============================================================

    /**
     * @notice Elliptic curve point addition using EVM precompile (0x06)
     */
    function pointAdd(
        uint256 x1, uint256 y1,
        uint256 x2, uint256 y2
    ) internal view returns (uint256 x3, uint256 y3) {
        uint256[4] memory input;
        input[0] = x1;
        input[1] = y1;
        input[2] = x2;
        input[3] = y2;

        uint256[2] memory result;
        bool success;

        assembly {
            success := staticcall(gas(), 0x06, input, 0x80, result, 0x40)
        }
        require(success, "Point addition failed");

        return (result[0], result[1]);
    }

    /**
     * @notice Scalar multiplication using EVM precompile (0x07)
     */
    function scalarMul(
        uint256[2] memory point,
        uint256 scalar
    ) internal view returns (uint256 x, uint256 y) {
        uint256[3] memory input;
        input[0] = point[0];
        input[1] = point[1];
        input[2] = scalar;

        uint256[2] memory result;
        bool success;

        assembly {
            success := staticcall(gas(), 0x07, input, 0x60, result, 0x40)
        }
        require(success, "Scalar multiplication failed");

        return (result[0], result[1]);
    }

    /**
     * @notice BN128 pairing check using EVM precompile (0x08)
     * @dev Checks e(a1,b1)*e(a2,b2)*e(a3,b3)*e(a4,b4) == 1
     */
    function pairingCheck(
        uint256 a1x, uint256 a1y,
        uint256 b1x0, uint256 b1x1, uint256 b1y0, uint256 b1y1,
        uint256 a2x, uint256 a2y,
        uint256 b2x0, uint256 b2x1, uint256 b2y0, uint256 b2y1,
        uint256 a3x, uint256 a3y,
        uint256 b3x0, uint256 b3x1, uint256 b3y0, uint256 b3y1,
        uint256 a4x, uint256 a4y,
        uint256 b4x0, uint256 b4x1, uint256 b4y0, uint256 b4y1
    ) internal view returns (bool) {
        uint256[24] memory input;
        
        // Pair 1: (-A, B)
        input[0] = a1x;
        input[1] = a1y;
        input[2] = b1x1;  // Note: G2 coords are in reverse order for precompile
        input[3] = b1x0;
        input[4] = b1y1;
        input[5] = b1y0;
        
        // Pair 2: (alpha, beta)
        input[6] = a2x;
        input[7] = a2y;
        input[8] = b2x1;
        input[9] = b2x0;
        input[10] = b2y1;
        input[11] = b2y0;
        
        // Pair 3: (IC, gamma)
        input[12] = a3x;
        input[13] = a3y;
        input[14] = b3x1;
        input[15] = b3x0;
        input[16] = b3y1;
        input[17] = b3y0;
        
        // Pair 4: (C, delta)
        input[18] = a4x;
        input[19] = a4y;
        input[20] = b4x1;
        input[21] = b4x0;
        input[22] = b4y1;
        input[23] = b4y0;

        uint256[1] memory result;
        bool success;

        assembly {
            success := staticcall(gas(), 0x08, input, 0x300, result, 0x20)
        }
        require(success, "Pairing check failed");

        return result[0] == 1;
    }

    // ============================================================
    // VIEW HELPERS
    // ============================================================

    function getICLength() external view returns (uint256) {
        return vk_ic.length;
    }

    function getICPoint(uint256 index) external view returns (uint256[2] memory) {
        require(index < vk_ic.length, "Index out of bounds");
        return vk_ic[index];
    }
}
