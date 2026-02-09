// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * MockOracle.sol — Death Certificate Verification Oracle (Test/Dev)
 * 
 * In production, this would be replaced by:
 *   - Chainlink Functions calling a death records API
 *   - A decentralized oracle network aggregating from multiple sources
 *   - A notarized death certificate verification service
 * 
 * This mock allows controlled testing of the full inheritance flow.
 */

interface IOracle {
    function verifyDeathCertificate(
        bytes32 certificateHash,
        bytes calldata proof
    ) external view returns (bool verified, uint256 confidence);
}

contract MockOracle is IOracle {
    
    // Admin who can register verified certificates
    address public admin;
    
    // Mapping of certificate hashes to verification status
    mapping(bytes32 => bool) public verifiedCertificates;
    mapping(bytes32 => uint256) public certificateConfidence;
    
    // Events
    event CertificateRegistered(bytes32 indexed certHash, uint256 confidence);
    event CertificateRevoked(bytes32 indexed certHash);
    
    constructor() {
        admin = msg.sender;
    }
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }
    
    /**
     * @notice Register a death certificate as verified (admin only)
     * @param certHash Hash of the death certificate
     * @param confidence Confidence score (0-100)
     */
    function registerCertificate(
        bytes32 certHash, 
        uint256 confidence
    ) external onlyAdmin {
        require(confidence <= 100, "Confidence must be 0-100");
        verifiedCertificates[certHash] = true;
        certificateConfidence[certHash] = confidence;
        emit CertificateRegistered(certHash, confidence);
    }
    
    /**
     * @notice Revoke a previously verified certificate
     */
    function revokeCertificate(bytes32 certHash) external onlyAdmin {
        verifiedCertificates[certHash] = false;
        certificateConfidence[certHash] = 0;
        emit CertificateRevoked(certHash);
    }
    
    /**
     * @notice Verify a death certificate (called by DigitalLegacyVault)
     * @param certificateHash Hash of the certificate to verify
     * @param proof Additional proof data (unused in mock, required by interface)
     * @return verified Whether the certificate is verified
     * @return confidence Confidence score (0-100)
     */
    function verifyDeathCertificate(
        bytes32 certificateHash,
        bytes calldata proof
    ) external view override returns (bool verified, uint256 confidence) {
        // In production: call external API via Chainlink, verify signatures, etc.
        // In mock: check our registered certificates mapping
        return (
            verifiedCertificates[certificateHash],
            certificateConfidence[certificateHash]
        );
    }
}
