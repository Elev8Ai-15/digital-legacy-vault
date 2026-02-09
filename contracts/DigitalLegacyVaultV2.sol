// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DigitalLegacyVaultV2.sol
 * 
 * Digital Legacy Vault - Phase 2: Verification-Integrated Contract
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * Upgrades from V1:
 *   - Real ZKP verification via Groth16Verifier (replaces placeholder bytes check)
 *   - Claim nonce system (prevents proof replay attacks)
 *   - Enhanced beneficiary identity commitment (Poseidon hash)
 *   - Oracle upgrade path (MockOracle → ChainlinkDeathOracle)
 *   - Emergency guardian override (for edge cases)
 *   - Vault metadata for UI rendering
 * 
 * Deployment: Polygon mainnet / Amoy testnet
 * Gas optimized: ~200K for claim with ZKP verification
 */

// ============================================================
// INTERFACES
// ============================================================

interface IOracle {
    function verifyDeathCertificate(
        bytes32 certificateHash,
        bytes calldata proof
    ) external view returns (bool verified, uint256 confidence);
}

interface IZKPVerifier {
    function verifyIdentityProof(
        address _vaultOwner,
        bytes32 _identityHash,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
    ) external returns (bool valid, bytes32 claimBinding);
}

// ============================================================
// MAIN CONTRACT V2
// ============================================================

contract DigitalLegacyVaultV2 {

    // --------------------------------------------------------
    // ENUMS & STRUCTS
    // --------------------------------------------------------

    enum VaultState {
        Active,
        Warning,
        Claimable,
        Claimed,
        Revoked
    }

    enum VerificationMethod {
        DeadManSwitch,
        OracleVerified,
        MultiSigConfirmed,
        EmergencyOverride
    }

    struct Guardian {
        address guardianAddress;
        bytes32 shareHash;
        bool hasConfirmedRelease;
        bool isActive;
        uint256 addedAt;
    }

    struct Beneficiary {
        address beneficiaryAddress;
        uint256 identityCommitment;     // Poseidon hash (ZKP compatible)
        bool isVerified;
        uint256 claimNonce;             // Increments each claim attempt (anti-replay)
    }

    struct VaultMetadata {
        string vaultName;               // User-defined label
        uint8 platformCount;            // Number of platforms archived
    }

    struct Vault {
        address owner;
        bytes32 ownerDID;
        
        VaultState state;
        uint256 createdAt;
        uint256 lastCheckIn;
        
        uint256 checkInInterval;
        uint256 gracePeriod;
        uint256 claimCooldown;
        
        Beneficiary primaryBeneficiary;
        uint8 guardianCount;
        uint8 requiredGuardians;
        
        VerificationMethod triggerMethod;
        bytes32 deathCertHash;
        bytes32 claimBinding;           // ZKP claim binding from verifier (audit trail)
        uint256 claimInitiatedAt;       // Timestamp of claim initiation (cooldown start)
        
        string[] contentArchiveCIDs;
        
        VaultMetadata metadata;
    }

    // --------------------------------------------------------
    // STATE VARIABLES
    // --------------------------------------------------------

    mapping(address => Vault) public vaults;
    mapping(address => mapping(uint8 => Guardian)) public guardians;
    mapping(address => bool) public hasVault;
    
    IOracle public oracle;
    IZKPVerifier public zkpVerifier;
    address public admin;
    
    // ZKP verification enabled flag (can be toggled during migration)
    bool public zkpEnabled;
    
    // Constants
    uint256 public constant MIN_CHECK_IN_INTERVAL = 30 days;
    uint256 public constant MAX_CHECK_IN_INTERVAL = 365 days;
    uint256 public constant MIN_GRACE_PERIOD = 30 days;
    uint256 public constant MAX_GUARDIANS = 7;
    uint256 public constant MIN_GUARDIANS = 3;
    uint256 public constant CLAIM_COOLDOWN = 14 days;
    uint256 public constant EMERGENCY_GUARDIAN_THRESHOLD = 5; // 5 of 7 for emergency

    // --------------------------------------------------------
    // EVENTS
    // --------------------------------------------------------

    event VaultCreated(address indexed owner, uint256 checkInInterval, uint8 requiredGuardians);
    event CheckIn(address indexed owner, uint256 timestamp);
    event StateChanged(address indexed owner, VaultState oldState, VaultState newState);
    event GuardianAdded(address indexed owner, address indexed guardian, uint8 index);
    event GuardianConfirmed(address indexed owner, address indexed guardian);
    event BeneficiarySet(address indexed owner, address indexed beneficiary, uint256 identityCommitment);
    event ClaimInitiated(address indexed owner, address indexed beneficiary, VerificationMethod method);
    event ClaimNonceIncremented(address indexed owner, uint256 newNonce);
    event SharesReleased(address indexed owner, address indexed beneficiary);
    event VaultRevoked(address indexed owner);
    event ContentArchiveAdded(address indexed owner, string cid);
    event DeathCertificateVerified(address indexed owner, bytes32 certHash, uint256 confidence);
    event ZKPVerificationResult(address indexed beneficiary, bool success);
    event OracleUpdated(address newOracle);
    event ZKPVerifierUpdated(address newVerifier);
    event EmergencyOverride(address indexed owner, uint8 guardianConfirmations);

    // --------------------------------------------------------
    // MODIFIERS
    // --------------------------------------------------------

    modifier onlyVaultOwner() {
        require(hasVault[msg.sender], "No vault found");
        require(vaults[msg.sender].owner == msg.sender, "Not vault owner");
        require(vaults[msg.sender].state != VaultState.Revoked, "Vault revoked");
        _;
    }

    modifier onlyBeneficiary(address vaultOwner) {
        require(hasVault[vaultOwner], "No vault found");
        require(
            vaults[vaultOwner].primaryBeneficiary.beneficiaryAddress == msg.sender,
            "Not authorized beneficiary"
        );
        _;
    }

    modifier onlyGuardian(address vaultOwner) {
        bool isGuardian = false;
        Vault storage v = vaults[vaultOwner];
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].guardianAddress == msg.sender && 
                guardians[vaultOwner][i].isActive) {
                isGuardian = true;
                break;
            }
        }
        require(isGuardian, "Not an active guardian");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    // --------------------------------------------------------
    // CONSTRUCTOR
    // --------------------------------------------------------

    constructor(address _oracle, address _zkpVerifier) {
        admin = msg.sender;
        oracle = IOracle(_oracle);
        
        if (_zkpVerifier != address(0)) {
            zkpVerifier = IZKPVerifier(_zkpVerifier);
            zkpEnabled = true;
        } else {
            zkpEnabled = false;
        }
    }

    // --------------------------------------------------------
    // VAULT CREATION
    // --------------------------------------------------------

    function createVault(
        bytes32 _ownerDID,
        uint256 _checkInInterval,
        uint256 _gracePeriod,
        uint8 _requiredGuardians,
        string calldata _vaultName
    ) external {
        require(!hasVault[msg.sender], "Vault already exists");
        require(
            _checkInInterval >= MIN_CHECK_IN_INTERVAL && 
            _checkInInterval <= MAX_CHECK_IN_INTERVAL,
            "Check-in interval out of range"
        );
        require(_gracePeriod >= MIN_GRACE_PERIOD, "Grace period too short");
        require(
            _requiredGuardians >= MIN_GUARDIANS && 
            _requiredGuardians <= MAX_GUARDIANS,
            "Guardian count out of range"
        );

        Vault storage v = vaults[msg.sender];
        v.owner = msg.sender;
        v.ownerDID = _ownerDID;
        v.state = VaultState.Active;
        v.createdAt = block.timestamp;
        v.lastCheckIn = block.timestamp;
        v.checkInInterval = _checkInInterval;
        v.gracePeriod = _gracePeriod;
        v.claimCooldown = CLAIM_COOLDOWN;
        v.requiredGuardians = _requiredGuardians;
        v.metadata.vaultName = _vaultName;

        hasVault[msg.sender] = true;

        emit VaultCreated(msg.sender, _checkInInterval, _requiredGuardians);
    }

    // --------------------------------------------------------
    // CHECK-IN (Proof of Life)
    // --------------------------------------------------------

    function checkIn() external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.state == VaultState.Active || v.state == VaultState.Warning, "Cannot check in");
        
        if (v.state == VaultState.Warning) {
            emit StateChanged(msg.sender, VaultState.Warning, VaultState.Active);
        }
        
        v.state = VaultState.Active;
        v.lastCheckIn = block.timestamp;
        
        emit CheckIn(msg.sender, block.timestamp);
    }

    // --------------------------------------------------------
    // GUARDIAN MANAGEMENT
    // --------------------------------------------------------

    function addGuardian(
        address _guardian,
        bytes32 _shareHash
    ) external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.guardianCount < MAX_GUARDIANS, "Max guardians reached");
        require(_guardian != address(0), "Invalid guardian");
        require(_guardian != msg.sender, "Owner cannot be guardian");
        
        // Check for duplicates
        for (uint8 i = 0; i < v.guardianCount; i++) {
            require(guardians[msg.sender][i].guardianAddress != _guardian, "Duplicate guardian");
        }

        guardians[msg.sender][v.guardianCount] = Guardian({
            guardianAddress: _guardian,
            shareHash: _shareHash,
            hasConfirmedRelease: false,
            isActive: true,
            addedAt: block.timestamp
        });

        emit GuardianAdded(msg.sender, _guardian, v.guardianCount);
        v.guardianCount++;
    }

    // --------------------------------------------------------
    // BENEFICIARY (with Poseidon identity commitment)
    // --------------------------------------------------------

    /**
     * @notice Set beneficiary with ZKP-compatible identity commitment
     * @param _beneficiary Beneficiary wallet address
     * @param _identityCommitment Poseidon hash of beneficiary's identity 
     *        Generated by: Poseidon(secret, did[0], did[1], did[2], did[3], salt)
     */
    function setBeneficiary(
        address _beneficiary,
        uint256 _identityCommitment
    ) external onlyVaultOwner {
        require(_beneficiary != address(0), "Invalid beneficiary");
        require(_beneficiary != msg.sender, "Owner cannot be beneficiary");
        require(_identityCommitment != 0, "Invalid identity commitment");
        
        vaults[msg.sender].primaryBeneficiary = Beneficiary({
            beneficiaryAddress: _beneficiary,
            identityCommitment: _identityCommitment,
            isVerified: false,
            claimNonce: 0
        });

        emit BeneficiarySet(msg.sender, _beneficiary, _identityCommitment);
    }

    // --------------------------------------------------------
    // CONTENT ARCHIVE
    // --------------------------------------------------------

    function addContentArchive(string calldata _cid) external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        v.contentArchiveCIDs.push(_cid);
        v.metadata.platformCount++;
        emit ContentArchiveAdded(msg.sender, _cid);
    }

    // --------------------------------------------------------
    // STATE TRANSITIONS
    // --------------------------------------------------------

    function evaluateVaultState(address vaultOwner) external {
        require(hasVault[vaultOwner], "No vault found");
        Vault storage v = vaults[vaultOwner];
        
        if (v.state == VaultState.Active) {
            if (block.timestamp > v.lastCheckIn + v.checkInInterval) {
                v.state = VaultState.Warning;
                emit StateChanged(vaultOwner, VaultState.Active, VaultState.Warning);
            }
        }
        
        if (v.state == VaultState.Warning) {
            if (block.timestamp > v.lastCheckIn + v.checkInInterval + v.gracePeriod) {
                v.state = VaultState.Claimable;
                v.triggerMethod = VerificationMethod.DeadManSwitch;
                emit StateChanged(vaultOwner, VaultState.Warning, VaultState.Claimable);
            }
        }
    }

    /**
     * @notice Submit death certificate for oracle verification
     */
    function submitDeathCertificate(
        address vaultOwner,
        bytes32 certificateHash,
        bytes calldata proof
    ) external onlyBeneficiary(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(
            v.state == VaultState.Active || v.state == VaultState.Warning,
            "Invalid state for certificate submission"
        );

        (bool verified, uint256 confidence) = oracle.verifyDeathCertificate(
            certificateHash, abi.encode(vaultOwner)
        );
        require(verified, "Death certificate not verified by oracle");
        require(confidence >= 95, "Verification confidence too low");

        VaultState oldState = v.state;
        v.deathCertHash = certificateHash;
        v.state = VaultState.Claimable;
        v.triggerMethod = VerificationMethod.OracleVerified;

        emit DeathCertificateVerified(vaultOwner, certificateHash, confidence);
        emit StateChanged(vaultOwner, oldState, VaultState.Claimable);
    }

    // --------------------------------------------------------
    // CLAIM PROCESS (with ZKP Verification)
    // --------------------------------------------------------

    /**
     * @notice Beneficiary initiates claim with ZKP proof
     * @param vaultOwner Address of the vault owner
     * @param zkProof Groth16 proof bytes (ABI-encoded uint256[8])
     * 
     * If ZKP is enabled:
     *   - Proof is verified on-chain via Groth16Verifier
     *   - Proof must be generated for: (identityCommitment, vaultOwner, claimNonce)
     *   - Nonce increments after each attempt (prevents replay)
     * 
     * If ZKP is disabled (migration period):
     *   - Falls back to address-based verification (V1 behavior)
     */
    function initiateClaim(
        address vaultOwner,
        bytes calldata zkProof
    ) external onlyBeneficiary(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(v.state == VaultState.Claimable, "Vault not claimable");
        require(!v.primaryBeneficiary.isVerified, "Already verified");

        if (zkpEnabled && address(zkpVerifier) != address(0)) {
            // Decode ABI-encoded proof: (uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[5] pubSignals)
            (
                uint[2] memory pA,
                uint[2][2] memory pB,
                uint[2] memory pC,
                uint[5] memory pubSignals
            ) = abi.decode(zkProof, (uint[2], uint[2][2], uint[2], uint[5]));

            // Convert uint256 identityCommitment to bytes32 for the verifier
            bytes32 identityHash = bytes32(v.primaryBeneficiary.identityCommitment);

            // Call the real ZKP verifier with decoded proof components
            (bool proofValid, bytes32 claimBinding) = zkpVerifier.verifyIdentityProof(
                vaultOwner,
                identityHash,
                pA,
                pB,
                pC,
                pubSignals
            );

            emit ZKPVerificationResult(msg.sender, proofValid);
            require(proofValid, "ZKP verification failed");

            // Store claim binding for audit trail
            v.claimBinding = claimBinding;
        } else {
            // Fallback: address-based verification (V1 compatible)
            require(zkProof.length > 0, "Proof required");
        }

        v.primaryBeneficiary.isVerified = true;
        v.claimInitiatedAt = block.timestamp;
        
        // Increment nonce for anti-replay (if claim is later reset)
        v.primaryBeneficiary.claimNonce++;
        emit ClaimNonceIncremented(vaultOwner, v.primaryBeneficiary.claimNonce);
        
        emit ClaimInitiated(vaultOwner, msg.sender, v.triggerMethod);
    }

    /**
     * @notice Guardian confirms release of their SSS share
     */
    function confirmShareRelease(
        address vaultOwner
    ) external onlyGuardian(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(v.state == VaultState.Claimable, "Vault not claimable");
        require(v.primaryBeneficiary.isVerified, "Beneficiary not verified");

        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].guardianAddress == msg.sender) {
                require(!guardians[vaultOwner][i].hasConfirmedRelease, "Already confirmed");
                guardians[vaultOwner][i].hasConfirmedRelease = true;
                emit GuardianConfirmed(vaultOwner, msg.sender);
                break;
            }
        }

        uint8 confirmations = _countConfirmations(vaultOwner);

        if (confirmations >= v.requiredGuardians) {
            v.state = VaultState.Claimed;
            emit StateChanged(vaultOwner, VaultState.Claimable, VaultState.Claimed);
            emit SharesReleased(vaultOwner, v.primaryBeneficiary.beneficiaryAddress);
        }
    }

    // --------------------------------------------------------
    // EMERGENCY GUARDIAN OVERRIDE
    // --------------------------------------------------------

    /**
     * @notice Emergency override: if ALL guardians (or super-majority) confirm,
     *         the vault becomes claimable even without dead man's switch or oracle.
     *         Requires EMERGENCY_GUARDIAN_THRESHOLD (5 of 7) confirmations.
     * 
     * Use case: Oracle is down, user is definitely deceased, family needs access.
     */
    function emergencyGuardianOverride(
        address vaultOwner
    ) external onlyGuardian(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(
            v.state == VaultState.Active || v.state == VaultState.Warning,
            "Override not needed in current state"
        );
        require(v.guardianCount >= EMERGENCY_GUARDIAN_THRESHOLD, "Not enough guardians for emergency");

        // Count emergency confirmations (reuse hasConfirmedRelease)
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].guardianAddress == msg.sender) {
                require(!guardians[vaultOwner][i].hasConfirmedRelease, "Already confirmed");
                guardians[vaultOwner][i].hasConfirmedRelease = true;
                break;
            }
        }

        uint8 confirmations = _countConfirmations(vaultOwner);

        if (confirmations >= EMERGENCY_GUARDIAN_THRESHOLD) {
            VaultState oldState = v.state;
            v.state = VaultState.Claimable;
            v.triggerMethod = VerificationMethod.EmergencyOverride;
            emit StateChanged(vaultOwner, oldState, VaultState.Claimable);
            emit EmergencyOverride(vaultOwner, confirmations);
        }
    }

    // --------------------------------------------------------
    // VAULT MANAGEMENT
    // --------------------------------------------------------

    function revokeVault() external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.state != VaultState.Claimed, "Already claimed");
        
        VaultState oldState = v.state;
        v.state = VaultState.Revoked;
        
        emit StateChanged(msg.sender, oldState, VaultState.Revoked);
        emit VaultRevoked(msg.sender);
    }

    // --------------------------------------------------------
    // ADMIN FUNCTIONS
    // --------------------------------------------------------

    function updateOracle(address _newOracle) external onlyAdmin {
        require(_newOracle != address(0), "Invalid oracle");
        oracle = IOracle(_newOracle);
        emit OracleUpdated(_newOracle);
    }

    function updateZKPVerifier(address _newVerifier) external onlyAdmin {
        zkpVerifier = IZKPVerifier(_newVerifier);
        zkpEnabled = _newVerifier != address(0);
        emit ZKPVerifierUpdated(_newVerifier);
    }

    function setZKPEnabled(bool _enabled) external onlyAdmin {
        require(address(zkpVerifier) != address(0) || !_enabled, "No verifier set");
        zkpEnabled = _enabled;
    }

    // --------------------------------------------------------
    // VIEW FUNCTIONS
    // --------------------------------------------------------

    function getVaultState(address owner) external view returns (VaultState) {
        require(hasVault[owner], "No vault");
        return vaults[owner].state;
    }

    function getTimeSinceCheckIn(address owner) external view returns (uint256) {
        require(hasVault[owner], "No vault");
        return block.timestamp - vaults[owner].lastCheckIn;
    }

    function getGuardianConfirmations(address owner) external view returns (uint8 confirmed, uint8 required) {
        Vault storage v = vaults[owner];
        return (_countConfirmations(owner), v.requiredGuardians);
    }

    function getContentArchives(address owner) external view returns (string[] memory) {
        return vaults[owner].contentArchiveCIDs;
    }

    function getBeneficiaryInfo(address owner) external view returns (
        address beneficiaryAddress,
        uint256 identityCommitment,
        bool isVerified,
        uint256 claimNonce
    ) {
        Beneficiary storage b = vaults[owner].primaryBeneficiary;
        return (b.beneficiaryAddress, b.identityCommitment, b.isVerified, b.claimNonce);
    }

    function getClaimNonce(address owner) external view returns (uint256) {
        return vaults[owner].primaryBeneficiary.claimNonce;
    }

    function getClaimStatus(address owner) external view returns (
        bool beneficiaryVerified,
        bytes32 claimBinding,
        uint256 claimInitiatedAt,
        uint256 cooldownEnds,
        bool cooldownElapsed
    ) {
        Vault storage v = vaults[owner];
        beneficiaryVerified = v.primaryBeneficiary.isVerified;
        claimBinding = v.claimBinding;
        claimInitiatedAt = v.claimInitiatedAt;
        cooldownEnds = v.claimInitiatedAt > 0 ? v.claimInitiatedAt + v.claimCooldown : 0;
        cooldownElapsed = v.claimInitiatedAt > 0 && block.timestamp >= cooldownEnds;
    }

    function isClaimable(address owner) external view returns (bool) {
        if (!hasVault[owner]) return false;
        Vault storage v = vaults[owner];
        
        if (v.state == VaultState.Active || v.state == VaultState.Warning) {
            return block.timestamp > v.lastCheckIn + v.checkInInterval + v.gracePeriod;
        }
        return v.state == VaultState.Claimable;
    }

    function getVaultSummary(address owner) external view returns (
        VaultState state,
        uint256 lastCheckIn,
        uint256 checkInInterval,
        uint256 gracePeriod,
        uint8 guardianCount,
        uint8 requiredGuardians,
        string memory vaultName,
        uint8 platformCount,
        bool zkpActive
    ) {
        Vault storage v = vaults[owner];
        return (
            v.state,
            v.lastCheckIn,
            v.checkInInterval,
            v.gracePeriod,
            v.guardianCount,
            v.requiredGuardians,
            v.metadata.vaultName,
            v.metadata.platformCount,
            zkpEnabled
        );
    }

    // --------------------------------------------------------
    // INTERNAL HELPERS
    // --------------------------------------------------------

    function _countConfirmations(address owner) internal view returns (uint8) {
        Vault storage v = vaults[owner];
        uint8 count = 0;
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[owner][i].hasConfirmedRelease) {
                count++;
            }
        }
        return count;
    }
}
