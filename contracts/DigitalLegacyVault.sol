// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DigitalLegacyVault.sol
 * 
 * Digital Legacy Vault - Inheritance Protocol Smart Contract
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * This contract manages the dead man's switch and inheritance claim flow
 * for the Digital Legacy Platform. It does NOT store any credentials -
 * only manages the state machine for inheritance triggers and SSS share
 * release authorization.
 * 
 * Deployment target: Polygon (EVM compatible, low gas)
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

// ============================================================
// MAIN CONTRACT
// ============================================================

contract DigitalLegacyVault {

    // --------------------------------------------------------
    // ENUMS & STRUCTS
    // --------------------------------------------------------

    enum VaultState {
        Active,         // User is alive, checking in regularly
        Warning,        // Check-in missed, grace period active
        Claimable,      // Dead man's switch triggered OR death verified
        Claimed,        // Beneficiary has claimed, shares released
        Revoked         // User revoked the vault
    }

    enum VerificationMethod {
        DeadManSwitch,      // Inactivity-based trigger
        OracleVerified,     // Death certificate verified via oracle
        MultiSigConfirmed   // Multiple guardians confirmed
    }

    struct Guardian {
        address guardianAddress;
        bytes32 shareHash;          // Hash of their SSS share (proof they hold it)
        bool hasConfirmedRelease;   // Whether they've approved release
        bool isActive;
    }

    struct Beneficiary {
        address beneficiaryAddress;
        bytes32 identityHash;       // Hash of their DID for ZKP verification
        bool isVerified;
    }

    struct Vault {
        // Owner
        address owner;
        bytes32 ownerDID;           // Decentralized Identifier hash
        
        // State
        VaultState state;
        uint256 createdAt;
        uint256 lastCheckIn;
        
        // Timing Configuration
        uint256 checkInInterval;    // How often user must check in (seconds)
        uint256 gracePeriod;        // Additional time after missed check-in
        uint256 claimCooldown;      // Wait period after claimable before release
        
        // Participants
        Beneficiary primaryBeneficiary;
        uint8 guardianCount;
        uint8 requiredGuardians;    // SSS threshold (e.g., 3 of 5)
        
        // Verification
        VerificationMethod triggerMethod;
        bytes32 deathCertHash;      // Stored only after oracle verification
        
        // Content metadata (no credentials - just IPFS CIDs for encrypted archives)
        string[] contentArchiveCIDs;
    }

    // --------------------------------------------------------
    // STATE VARIABLES
    // --------------------------------------------------------

    mapping(address => Vault) internal vaults;
    mapping(address => mapping(uint8 => Guardian)) public guardians;
    mapping(address => bool) public hasVault;
    
    IOracle public oracle;
    address public admin;
    
    uint256 public constant MIN_CHECK_IN_INTERVAL = 30 days;
    uint256 public constant MAX_CHECK_IN_INTERVAL = 365 days;
    uint256 public constant MIN_GRACE_PERIOD = 30 days;
    uint256 public constant MAX_GUARDIANS = 7;
    uint256 public constant MIN_GUARDIANS = 3;
    // --------------------------------------------------------
    // EVENTS
    // --------------------------------------------------------

    event VaultCreated(address indexed owner, uint256 checkInInterval, uint8 requiredGuardians);
    event CheckIn(address indexed owner, uint256 timestamp);
    event StateChanged(address indexed owner, VaultState oldState, VaultState newState);
    event GuardianAdded(address indexed owner, address indexed guardian, uint8 index);
    event GuardianConfirmed(address indexed owner, address indexed guardian);
    event BeneficiarySet(address indexed owner, address indexed beneficiary);
    event ClaimInitiated(address indexed owner, address indexed beneficiary, VerificationMethod method);
    event SharesReleased(address indexed owner, address indexed beneficiary);
    event VaultRevoked(address indexed owner);
    event ContentArchiveAdded(address indexed owner, string cid);
    event DeathCertificateVerified(address indexed owner, bytes32 certHash, uint256 confidence);

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

    // --------------------------------------------------------
    // CONSTRUCTOR
    // --------------------------------------------------------

    constructor(address _oracle) {
        require(_oracle != address(0), "Invalid oracle address");
        admin = msg.sender;
        oracle = IOracle(_oracle);
    }

    // --------------------------------------------------------
    // VAULT CREATION
    // --------------------------------------------------------

    /**
     * @notice Create a new Digital Legacy Vault
     * @param _ownerDID Hash of the owner's Decentralized Identifier
     * @param _checkInInterval How often the owner must prove they're alive (seconds)
     * @param _gracePeriod Additional grace period after missed check-in
     * @param _requiredGuardians SSS threshold - how many guardians needed to reconstruct
     */
    function createVault(
        bytes32 _ownerDID,
        uint256 _checkInInterval,
        uint256 _gracePeriod,
        uint8 _requiredGuardians
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
        v.requiredGuardians = _requiredGuardians;

        hasVault[msg.sender] = true;

        emit VaultCreated(msg.sender, _checkInInterval, _requiredGuardians);
    }

    // --------------------------------------------------------
    // CHECK-IN (Proof of Life)
    // --------------------------------------------------------

    /**
     * @notice Owner checks in to prove they're alive. Resets the dead man's switch.
     */
    function checkIn() external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        
        // If in Warning state, return to Active
        if (v.state == VaultState.Warning) {
            emit StateChanged(msg.sender, VaultState.Warning, VaultState.Active);
            v.state = VaultState.Active;
        }
        
        require(v.state == VaultState.Active, "Vault not in active state");
        
        v.lastCheckIn = block.timestamp;
        emit CheckIn(msg.sender, block.timestamp);
    }

    // --------------------------------------------------------
    // GUARDIAN MANAGEMENT
    // --------------------------------------------------------

    /**
     * @notice Add a guardian who holds an SSS share
     * @param _guardian Address of the guardian
     * @param _shareHash Hash proving they hold a valid SSS share
     */
    function addGuardian(
        address _guardian,
        bytes32 _shareHash
    ) external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.guardianCount < MAX_GUARDIANS, "Max guardians reached");
        require(_guardian != address(0), "Invalid guardian address");
        require(_guardian != msg.sender, "Owner cannot be guardian");

        // Check for duplicates
        for (uint8 i = 0; i < v.guardianCount; i++) {
            require(guardians[msg.sender][i].guardianAddress != _guardian, "Duplicate guardian");
        }

        uint8 idx = v.guardianCount;
        guardians[msg.sender][idx] = Guardian({
            guardianAddress: _guardian,
            shareHash: _shareHash,
            hasConfirmedRelease: false,
            isActive: true
        });
        v.guardianCount++;

        emit GuardianAdded(msg.sender, _guardian, idx);
    }

    /**
     * @notice Set the primary beneficiary
     * @param _beneficiary Address of the beneficiary
     * @param _identityHash Hash of their DID for ZKP verification
     */
    function setBeneficiary(
        address _beneficiary,
        bytes32 _identityHash
    ) external onlyVaultOwner {
        require(_beneficiary != address(0), "Invalid beneficiary");
        require(_beneficiary != msg.sender, "Owner cannot be beneficiary");
        
        vaults[msg.sender].primaryBeneficiary = Beneficiary({
            beneficiaryAddress: _beneficiary,
            identityHash: _identityHash,
            isVerified: false
        });

        emit BeneficiarySet(msg.sender, _beneficiary);
    }

    // --------------------------------------------------------
    // CONTENT ARCHIVE (IPFS CIDs only - no credentials)
    // --------------------------------------------------------

    /**
     * @notice Register an encrypted content archive on IPFS
     * @param _cid The IPFS Content Identifier of the encrypted archive
     */
    function addContentArchive(string calldata _cid) external onlyVaultOwner {
        vaults[msg.sender].contentArchiveCIDs.push(_cid);
        emit ContentArchiveAdded(msg.sender, _cid);
    }

    // --------------------------------------------------------
    // STATE TRANSITIONS
    // --------------------------------------------------------

    /**
     * @notice Check if a vault's dead man's switch has triggered
     * @dev Anyone can call this to update state based on timing
     */
    function evaluateVaultState(address vaultOwner) external {
        require(hasVault[vaultOwner], "No vault found");
        Vault storage v = vaults[vaultOwner];
        
        if (v.state == VaultState.Active) {
            // Check if check-in interval has passed
            if (block.timestamp > v.lastCheckIn + v.checkInInterval) {
                v.state = VaultState.Warning;
                emit StateChanged(vaultOwner, VaultState.Active, VaultState.Warning);
            }
        }
        
        if (v.state == VaultState.Warning) {
            // Check if grace period has also passed
            if (block.timestamp > v.lastCheckIn + v.checkInInterval + v.gracePeriod) {
                v.state = VaultState.Claimable;
                v.triggerMethod = VerificationMethod.DeadManSwitch;
                emit StateChanged(vaultOwner, VaultState.Warning, VaultState.Claimable);
            }
        }
    }

    /**
     * @notice Submit a death certificate for oracle verification
     * @param vaultOwner Address of the vault owner
     * @param certificateHash Hash of the death certificate
     * @param proof Oracle-compatible proof data
     */
    function submitDeathCertificate(
        address vaultOwner,
        bytes32 certificateHash,
        bytes calldata proof
    ) external onlyBeneficiary(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(
            v.state == VaultState.Active || 
            v.state == VaultState.Warning,
            "Invalid state for certificate submission"
        );

        // Verify via oracle
        (bool verified, uint256 confidence) = oracle.verifyDeathCertificate(
            certificateHash, proof
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
    // CLAIM PROCESS
    // --------------------------------------------------------

    /**
     * @notice Beneficiary initiates a claim on a claimable vault
     * @param vaultOwner Address of the vault owner
     * @param zkProof Zero-knowledge proof of beneficiary identity
     */
    function initiateClaim(
        address vaultOwner,
        bytes calldata zkProof
    ) external onlyBeneficiary(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(v.state == VaultState.Claimable, "Vault not claimable");
        
        // In production, zkProof would be verified against the stored identityHash
        // using a ZKP verifier contract (Groth16 or PLONK)
        // For MVP, we verify the beneficiary address matches
        require(zkProof.length > 0, "ZK proof required");
        
        v.primaryBeneficiary.isVerified = true;
        
        emit ClaimInitiated(vaultOwner, msg.sender, v.triggerMethod);
    }

    /**
     * @notice Guardian confirms release of their SSS share
     * @param vaultOwner Address of the vault owner
     */
    function confirmShareRelease(
        address vaultOwner
    ) external onlyGuardian(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(v.state == VaultState.Claimable, "Vault not claimable");
        require(v.primaryBeneficiary.isVerified, "Beneficiary not verified");

        // Find and update guardian
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].guardianAddress == msg.sender) {
                require(!guardians[vaultOwner][i].hasConfirmedRelease, "Already confirmed");
                guardians[vaultOwner][i].hasConfirmedRelease = true;
                emit GuardianConfirmed(vaultOwner, msg.sender);
                break;
            }
        }

        // Check if threshold met
        uint8 confirmations = 0;
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].hasConfirmedRelease) {
                confirmations++;
            }
        }

        // If enough guardians have confirmed, release shares
        if (confirmations >= v.requiredGuardians) {
            v.state = VaultState.Claimed;
            emit StateChanged(vaultOwner, VaultState.Claimable, VaultState.Claimed);
            emit SharesReleased(vaultOwner, v.primaryBeneficiary.beneficiaryAddress);
        }
    }

    // --------------------------------------------------------
    // VAULT MANAGEMENT
    // --------------------------------------------------------

    /**
     * @notice Owner revokes their vault (emergency or changed mind)
     */
    function revokeVault() external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.state != VaultState.Claimed, "Already claimed");
        
        VaultState oldState = v.state;
        v.state = VaultState.Revoked;
        
        emit StateChanged(msg.sender, oldState, VaultState.Revoked);
        emit VaultRevoked(msg.sender);
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
        uint8 count = 0;
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[owner][i].hasConfirmedRelease) {
                count++;
            }
        }
        return (count, v.requiredGuardians);
    }

    function getContentArchives(address owner) external view returns (string[] memory) {
        return vaults[owner].contentArchiveCIDs;
    }

    function isClaimable(address owner) external view returns (bool) {
        if (!hasVault[owner]) return false;
        Vault storage v = vaults[owner];
        
        // Check if should be claimable based on timing
        if (v.state == VaultState.Active || v.state == VaultState.Warning) {
            return block.timestamp > v.lastCheckIn + v.checkInInterval + v.gracePeriod;
        }
        return v.state == VaultState.Claimable;
    }
}
